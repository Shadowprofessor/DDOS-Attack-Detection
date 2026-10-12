# -*- coding: utf-8 -*-
"""
Dashboard Broadcaster & WebSocket Connection Manager.

Decouples real-time event streaming from the /score/flow hot path via a bounded
async queue, batching/sampling flow events at ~10Hz to prevent network jitter.
Enforces first-message authentication and ensures the WebSocket is server-to-client only.
"""
import asyncio
import json
import logging
import time
from collections import deque
from typing import Dict, Any, Optional, Set
from starlette.websockets import WebSocket, WebSocketDisconnect

logger = logging.getLogger("DashboardBroadcaster")


class DashboardBroadcaster:
    """
    Manages active authenticated WebSocket connections and dispatches
    telemetry events without degrading scoring service latency.
    """

    def __init__(self, queue_maxsize: int = 5000, sample_interval: float = 0.1):
        self.queue_maxsize = queue_maxsize
        self.sample_interval = sample_interval
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self._flow_queue: asyncio.Queue = asyncio.Queue(maxsize=queue_maxsize)
        self._recent_flows: deque = deque(maxlen=50)
        self._taxonomy_counts: Dict[str, int] = {}
        self._total_flows_scored: int = 0
        self._total_attacks_detected: int = 0
        self._worker_task: Optional[asyncio.Task] = None
        self._flow_timestamps: deque = deque(maxlen=2000)

    async def start(self):
        """Start background broadcast worker loop."""
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = asyncio.create_task(self._broadcast_loop())
            logger.info("Dashboard broadcaster worker started.")

    async def stop(self):
        """Cancel and clean up broadcast worker."""
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
            logger.info("Dashboard broadcaster worker stopped.")

    def enqueue_flow(self, flow_data: Dict[str, Any]):
        """
        FIRE-AND-FORGET HOT PATH ENQUEUE:
        Called directly from /score/flow.
        Never blocks the scoring call: drops oldest on backpressure.
        Sub-microsecond execution overhead.
        """
        now = time.monotonic()
        self._total_flows_scored += 1
        self._flow_timestamps.append(now)

        is_attack = bool(flow_data.get("is_attack", False))
        label = str(flow_data.get("label", "Benign"))
        if is_attack:
            self._total_attacks_detected += 1
        self._taxonomy_counts[label] = self._taxonomy_counts.get(label, 0) + 1

        self._recent_flows.append(flow_data)

        # Non-blocking enqueue to bounded queue
        try:
            self._flow_queue.put_nowait(flow_data)
        except asyncio.QueueFull:
            try:
                self._flow_queue.get_nowait()  # Drop oldest
                self._flow_queue.put_nowait(flow_data)
            except Exception:
                pass  # Discard on race condition

    def get_current_flow_rate(self) -> float:
        """Calculate recent flows per second over a 1-second sliding window."""
        now = time.monotonic()
        cutoff = now - 1.0
        while self._flow_timestamps and self._flow_timestamps[0] < cutoff:
            self._flow_timestamps.popleft()
        return float(len(self._flow_timestamps))

    async def _broadcast_loop(self):
        """
        Background worker draining flows and broadcasting sampled updates
        at ~10Hz (sample_interval = 0.1s) to avoid client flood.
        """
        while True:
            try:
                await asyncio.sleep(self.sample_interval)
                if not self._connections:
                    # Drain queue to avoid memory build-up if no clients connected
                    while not self._flow_queue.empty():
                        try:
                            self._flow_queue.get_nowait()
                        except Exception:
                            break
                    continue

                drained_flows = []
                while not self._flow_queue.empty() and len(drained_flows) < 50:
                    try:
                        drained_flows.append(self._flow_queue.get_nowait())
                    except Exception:
                        break

                if not drained_flows:
                    continue

                # Sample/aggregate flows to send at ~10Hz
                # Take the latest flow or highest-confidence attack flow in the batch
                attack_flows = [f for f in drained_flows if f.get("is_attack")]
                sample = attack_flows[-1] if attack_flows else drained_flows[-1]

                msg = {
                    "type": "flow_scored",
                    "timestamp": time.time(),
                    "flow_rate": self.get_current_flow_rate(),
                    "total_flows": self._total_flows_scored,
                    "total_attacks": self._total_attacks_detected,
                    "batch_size": len(drained_flows),
                    "flow": sample,
                }
                await self.broadcast_message(msg)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("Error in dashboard broadcaster loop: %s", e)

    async def broadcast_message(self, message: Dict[str, Any]):
        """Send a JSON message to all active WebSocket clients."""
        text = json.dumps(message)
        dead_conns = []
        async with self._lock:
            conns = list(self._connections)

        for ws in conns:
            try:
                await ws.send_text(text)
            except Exception:
                dead_conns.append(ws)

        if dead_conns:
            async with self._lock:
                for ws in dead_conns:
                    self._connections.discard(ws)

    def broadcast_burst_alert(self, alert_data: Dict[str, Any]):
        """Immediate 1:1 broadcast for high-priority burst alerts."""
        msg = {
            "type": "burst_alert",
            "timestamp": time.time(),
            "alert": alert_data,
        }
        asyncio.create_task(self.broadcast_message(msg))

    def broadcast_pending_update(self, pending_actions: list, pending_count: int):
        """Immediate 1:1 broadcast for action queue state changes."""
        msg = {
            "type": "pending_update",
            "timestamp": time.time(),
            "pending_count": pending_count,
            "pending_actions": pending_actions,
        }
        asyncio.create_task(self.broadcast_message(msg))

    async def get_initial_state(self, pending_actions: list) -> Dict[str, Any]:
        """Construct initial state payload delivered immediately upon authenticated connection."""
        return {
            "type": "initial_state",
            "timestamp": time.time(),
            "flow_rate": self.get_current_flow_rate(),
            "total_flows": self._total_flows_scored,
            "total_attacks": self._total_attacks_detected,
            "taxonomy_counts": dict(self._taxonomy_counts),
            "pending_count": len(pending_actions),
            "pending_actions": pending_actions,
            "recent_flows": list(self._recent_flows),
        }

    async def handle_connection(
        self,
        websocket: WebSocket,
        valid_keys: Set[str],
        get_pending_fn,
        auth_timeout: float = 5.0,
    ):
        """
        Handle incoming WebSocket client lifecycle:
        1. Accept connection.
        2. Require first-message {"type": "auth", "key": "..."} within auth_timeout.
        3. If invalid or timed out: close with code 1008 (Policy Violation).
        4. If valid: send auth_ok + initial_state.
        5. Maintain server-to-client loop; IGNORE any subsequent inbound messages.
        """
        await websocket.accept()

        # 1. First-message authentication (Condition 1)
        authenticated = False
        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=auth_timeout)
            data = json.loads(raw)
            if data.get("type") == "auth" and data.get("key") in valid_keys:
                authenticated = True
        except (asyncio.TimeoutError, json.JSONDecodeError, Exception) as e:
            logger.info("WS auth handshake failed or timed out: %s", e)

        if not authenticated:
            logger.warning("Rejecting unauthenticated WebSocket connection with code 1008.")
            await websocket.close(code=1008)
            return

        # 2. Register connection
        async with self._lock:
            self._connections.add(websocket)
        logger.info("WebSocket client authenticated. Total clients: %d", len(self._connections))

        # 3. Send auth_ok & initial state
        try:
            await websocket.send_text(json.dumps({"type": "auth_ok", "status": "authenticated"}))
            pending = get_pending_fn()
            initial_state = await self.get_initial_state(pending)
            await websocket.send_text(json.dumps(initial_state))
        except Exception as e:
            logger.warning("Failed to send initial state to client: %s", e)
            async with self._lock:
                self._connections.discard(websocket)
            return

        # 4. Inbound message loop (Condition 3: Server-to-Client ONLY)
        try:
            while True:
                msg_text = await websocket.receive_text()
                # Condition 3: Channel is server-to-client only.
                # Any inbound message from client (arbitrary or approve/reject shaped)
                # is intentionally IGNORED and NEVER processed!
                logger.debug("Received and ignored inbound client message: %s", msg_text[:120])
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.debug("WebSocket error: %s", e)
        finally:
            async with self._lock:
                self._connections.discard(websocket)
            logger.info("WebSocket client disconnected. Total clients: %d", len(self._connections))


# Global singleton instance
_default_broadcaster: Optional[DashboardBroadcaster] = None


def get_broadcaster() -> DashboardBroadcaster:
    """Retrieve or initialize the default DashboardBroadcaster singleton."""
    global _default_broadcaster
    if _default_broadcaster is None:
        _default_broadcaster = DashboardBroadcaster()
    return _default_broadcaster
