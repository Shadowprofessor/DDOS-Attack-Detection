// One authenticated WebSocket per tab (session cookie, same origin). Server -> client only.
// Each event invalidates the affected queries; if the socket is down, the queries' own
// refetchInterval keeps polling, so the UI degrades gracefully.
import { useEffect, useSyncExternalStore } from "react";
import { useQueryClient, type QueryClient } from "@tanstack/react-query";

export type LiveStatus = "connecting" | "live" | "offline";

let status: LiveStatus = "connecting";
const listeners = new Set<() => void>();
function setStatus(s: LiveStatus) {
  if (s !== status) {
    status = s;
    listeners.forEach((l) => l());
  }
}

export function useLiveStatus(): LiveStatus {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => status,
    () => status,
  );
}

export interface LiveEvent {
  type: string;
  incident_id?: string;
  incident?: { id: string };
}

/** Which queries an event makes stale. Exported for unit tests. */
export function keysFor(ev: LiveEvent): string[][] {
  const id = ev.incident_id ?? ev.incident?.id;
  const keys: string[][] = [["overview"], ["incidents"]];
  if (id) keys.push(["incident", id]);
  if (ev.type.startsWith("rollback.") || ev.type === "incident.created") keys.push(["approvals"]);
  return keys;
}

export function backoffMs(attempt: number): number {
  return Math.min(30_000, 1_000 * 2 ** Math.min(attempt, 5));
}

function wsUrl(): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/ws/incidents`;
}

function apply(qc: QueryClient, ev: LiveEvent) {
  for (const key of keysFor(ev)) void qc.invalidateQueries({ queryKey: key });
}

export function useLiveUpdates(enabled: boolean): void {
  const qc = useQueryClient();
  useEffect(() => {
    if (!enabled) return;
    let ws: WebSocket | null = null;
    let attempt = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let closed = false;

    const connect = () => {
      setStatus("connecting");
      ws = new WebSocket(wsUrl());
      ws.onmessage = (m) => {
        let ev: LiveEvent;
        try {
          ev = JSON.parse(String(m.data)) as LiveEvent;
        } catch {
          return;
        }
        if (ev.type === "auth_ok") {
          attempt = 0;
          setStatus("live");
          return;
        }
        apply(qc, ev);
      };
      ws.onclose = () => {
        setStatus("offline");
        if (!closed) timer = setTimeout(connect, backoffMs(attempt++));
      };
    };
    connect();
    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      ws?.close();
    };
  }, [enabled, qc]);
}
