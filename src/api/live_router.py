# -*- coding: utf-8 -*-
"""
Live attack API (v5.2.0): a sensor (scripts/live_bridge.py) pushes 1 s windows, relayed ML verdicts
and OVS port counters; the SOC app's Live Attack view reads /api/live/state and listens on /ws/live.

* Every route needs a key (analyst or admin); writes have their own rate limit.
* Input is untrusted: strict schemas, bounded sizes, IPv4/port formats checked.
* Nothing here proposes, approves or executes mitigation. Incidents are opened by the sensor through
  the normal IR API (`POST /api/incidents`).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field

from src.api.analyst_router import _KeyRateLimiter
from src.api.rbac import Principal, principal_for_key, require_analyst
from src.ir.runtime import IncidentHub
from src.live.state import LiveState
from src.obs import metrics as m
from src.obs.logging import log_safe

logger = logging.getLogger("live.api")
router = APIRouter(tags=["live"])

IPV4 = r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$"
NAME = r"^[A-Za-z0-9_.:-]{1,64}$"

LIVE_PPS = m.REGISTRY.gauge("ddos_live_window_pps", "Packets/s to a victim in the latest 1 s live window.")
LIVE_BPS = m.REGISTRY.gauge("ddos_live_window_bps", "Bits/s to a victim in the latest 1 s live window.")
LIVE_ALERTS = m.REGISTRY.counter("ddos_live_alerts_total", "Live L1 alert episodes opened, by status.")
LIVE_WINDOWS = m.REGISTRY.counter("ddos_live_windows_total", "Live windows ingested.")
OVS_PPS = m.REGISTRY.gauge("ddos_ovs_port_pps", "OVS port packet rate from dump-ports deltas, by switch/port/dir.")
OVS_DROPPED = m.REGISTRY.gauge("ddos_ovs_port_dropped", "OVS port dropped-packet counter, by switch/port/dir.")

live_write_limiter = _KeyRateLimiter(int(os.environ.get("DDOS_LIVE_RATE_PER_MIN", "600")))
_state = LiveState()
hub = IncidentHub()  # same thread-safe fan-out as /ws/incidents, separate subscriber set


def get_live_state() -> LiveState:
    return _state


def require_live_write(p: Principal = Depends(require_analyst)) -> Principal:
    if not live_write_limiter.allow(p.actor):
        raise HTTPException(status_code=429, detail="Live write rate limit exceeded; retry later.")
    return p


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Talker(_Strict):
    ip: str = Field(..., pattern=IPV4)
    packets: int = Field(..., ge=0, le=10**9)


class PortCount(_Strict):
    port: int = Field(..., ge=0, le=65535)
    packets: int = Field(..., ge=0, le=10**9)


Ratio = Field(..., ge=0.0, le=1.0)


class LiveWindow(_Strict):
    start: float = Field(..., ge=0)
    end: float = Field(..., ge=0)
    dst: str = Field(..., pattern=IPV4)
    packets: int = Field(..., ge=0, le=10**9)
    bytes: int = Field(..., ge=0, le=10**12)
    pps: float = Field(..., ge=0, le=1e9)
    bps: float = Field(..., ge=0, le=1e13)
    unique_src: int = Field(..., ge=0, le=10**7)
    src_entropy: float = Field(..., ge=0, le=64)
    proto_mix: Dict[Literal["tcp", "udp", "icmp", "other"], float] = Field(default_factory=dict)
    tcp_flags: Dict[Literal["syn", "synack", "ack_only", "rst", "fin", "psh"], float] = Field(default_factory=dict)
    syn_rate: float = Field(0.0, ge=0, le=1e9)
    conn_rate: float = Field(0.0, ge=0, le=1e9)
    pkt_size: Dict[Literal["mean", "p50", "p95", "max"], float] = Field(default_factory=dict)
    top_talkers: List[Talker] = Field(default_factory=list, max_length=10)
    top_dst_ports: List[PortCount] = Field(default_factory=list, max_length=10)
    top_src_ports: List[PortCount] = Field(default_factory=list, max_length=10)
    land: int = Field(0, ge=0, le=10**9)
    tcp_payload: Optional[float] = Field(None, ge=0.0, le=1.0)
    slow_conns: int = Field(0, ge=0, le=10**7)  # established low-and-slow connections (bridge, all live flows)


class WindowsBody(_Strict):
    sensor: str = Field(..., pattern=NAME)
    windows: List[LiveWindow] = Field(..., min_length=1, max_length=200)


class LiveFlow(_Strict):
    src: str = Field(..., pattern=IPV4)
    dst: str = Field(..., pattern=IPV4)
    proto: int = Field(..., ge=0, le=255)
    sport: int = Field(..., ge=0, le=65535)
    dport: int = Field(..., ge=0, le=65535)
    packets: int = Field(..., ge=0, le=10**9)
    start: float = Field(..., ge=0)
    end: float = Field(..., ge=0)
    final: bool
    label: str = Field(..., max_length=64, pattern=r"^[A-Za-z0-9 _./()-]{1,64}$")
    is_attack: bool
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    ood_suspected: Optional[bool] = None
    # what decided the verdict: the ML ensemble, or /score/flow's multi-layer rate corroboration
    basis: Optional[Literal["ml", "multi_layer"]] = None
    ml_label: Optional[str] = Field(None, max_length=64, pattern=r"^[A-Za-z0-9 _./()-]{1,64}$")
    proposed_action_id: Optional[str] = Field(None, pattern=NAME)


class FlowsBody(_Strict):
    sensor: str = Field(..., pattern=NAME)
    flows: List[LiveFlow] = Field(..., min_length=1, max_length=100)


class OvsPort(_Strict):
    port: str = Field(..., pattern=r"^[A-Za-z0-9_-]{1,16}$")
    rx_packets: int = Field(..., ge=0)
    tx_packets: int = Field(..., ge=0)
    rx_bytes: int = Field(..., ge=0)
    tx_bytes: int = Field(..., ge=0)
    rx_dropped: int = Field(0, ge=0)
    tx_dropped: int = Field(0, ge=0)
    host: Optional[str] = Field(None, pattern=r"^[A-Za-z0-9_-]{1,32}$")  # lab role on that port


class OvsBody(_Strict):
    sensor: str = Field(..., pattern=NAME)
    switch: str = Field(..., pattern=r"^[A-Za-z0-9_-]{1,32}$")
    ts: float = Field(..., ge=0)
    ports: List[OvsPort] = Field(..., min_length=1, max_length=64)


@router.post("/api/live/windows")
def post_windows(body: WindowsBody, p: Principal = Depends(require_live_write)):
    st = get_live_state()
    opened, cleared = [], []
    for w in body.windows:
        for ev in st.ingest_window(w.model_dump(), body.sensor):
            hub.publish(ev)
            if ev["type"] == "live.window":
                row = ev["window"]
                LIVE_PPS.set(row["pps"], dst=row["dst"])
                LIVE_BPS.set(row["bps"], dst=row["dst"])
                LIVE_WINDOWS.inc()
            elif ev["type"] == "live.alert":
                opened.append(ev["episode"])
                LIVE_ALERTS.inc(status=ev["episode"]["status"])
                logger.info("live L1 alert %s dst=%s", log_safe(ev["episode"]["id"]), log_safe(ev["episode"]["dst"]))
            elif ev["type"] == "live.clear":
                cleared.append(ev["episode"])
    return {"accepted": len(body.windows), "alerts_opened": opened, "alerts_cleared": cleared,
            "open_alerts": [e["dst"] for e in st.snapshot(last=0)["open_alerts"]]}


@router.post("/api/live/flows")
def post_flows(body: FlowsBody, p: Principal = Depends(require_live_write)):
    st = get_live_state()
    for f in body.flows:
        hub.publish(st.ingest_flow(f.model_dump(), body.sensor))
    return {"accepted": len(body.flows)}


@router.post("/api/live/ovs")
def post_ovs(body: OvsBody, p: Principal = Depends(require_live_write)):
    ev = get_live_state().ingest_ovs(body.switch, body.ts, [x.model_dump() for x in body.ports])
    for r in ev["ports"]:
        if r["rx_pps"] is not None:
            OVS_PPS.set(r["rx_pps"], switch=body.switch, port=r["port"], dir="rx")
            OVS_PPS.set(r["tx_pps"], switch=body.switch, port=r["port"], dir="tx")
        OVS_DROPPED.set(r["rx_dropped"], switch=body.switch, port=r["port"], dir="rx")
        OVS_DROPPED.set(r["tx_dropped"], switch=body.switch, port=r["port"], dir="tx")
    hub.publish(ev)
    return {"accepted": len(body.ports)}


@router.get("/api/live/state")
def live_state(last: int = Query(120, ge=0, le=300), p: Principal = Depends(require_analyst)):
    return get_live_state().snapshot(last=last)


@router.post("/api/live/reset", status_code=204)
def live_reset(p: Principal = Depends(require_live_write)):
    """Clear the live view between demo runs (history only; incidents are untouched)."""
    get_live_state().reset()
    hub.publish({"type": "live.reset"})


@router.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    """Server->client live events. Same auth as /ws/incidents (key header, session cookie, or a first
    {"type": "auth", "key": "..."} message within 5 s). Inbound messages are ignored."""
    from src.api.rbac import ws_session_key

    await websocket.accept()
    key = websocket.headers.get("x-admin-key") or websocket.headers.get("x-api-key") or ws_session_key(websocket)
    if not key:
        try:
            data = json.loads(await asyncio.wait_for(websocket.receive_text(), timeout=5.0))
            key = data.get("key") if isinstance(data, dict) and data.get("type") == "auth" else None
        except Exception:
            key = None
    principal = principal_for_key(key if isinstance(key, str) else None)
    if principal is None:
        try:  # the client may already have gone (it disconnected during the auth wait): nothing to close
            await websocket.close(code=1008)
        except RuntimeError:
            pass
        return
    hub.add(websocket, asyncio.get_running_loop())
    try:
        await websocket.send_text(json.dumps({"type": "auth_ok", "role": principal.role}))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug("ws/live error: %s", log_safe(type(e).__name__))
    finally:
        hub.remove(websocket)
