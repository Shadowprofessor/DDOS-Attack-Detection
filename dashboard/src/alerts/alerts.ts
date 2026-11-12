// v6.0.0 SOC alerts in the browser: toasts, a sound cued by severity, and (opt-in) browser
// notifications. The server already deduplicates and rate-limits; here we only drop exact repeats
// (same alert id, e.g. after a WebSocket reconnect) and cap how many toasts are on screen.
import { useSyncExternalStore } from "react";

export type AlertLevel = "critical" | "high" | "medium" | "low" | "info";

export interface SocAlert {
  id: string;
  ts: number;
  kind: "incident" | "cert_in" | "analysis" | "rollback" | "test";
  severity: number;
  level: AlertLevel;
  title: string;
  reason: string;
  incident_id: string | null;
  sound: boolean;
  suppressed: number;
}

export const MAX_TOASTS = 4;
/** How long a toast stays (ms). Critical alerts stay until dismissed. */
export const TOAST_MS: Record<AlertLevel, number | null> = { critical: null, high: 15_000, medium: 10_000, low: 8_000, info: 8_000 };

let toasts: SocAlert[] = [];
const seen = new Set<string>();
const listeners = new Set<() => void>();
const timers = new Map<string, ReturnType<typeof setTimeout>>();

function emit() {
  listeners.forEach((l) => l());
}

export function useToasts(): SocAlert[] {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => toasts,
    () => toasts,
  );
}

export const currentToasts = (): SocAlert[] => toasts;

export function dismiss(id: string): void {
  const t = timers.get(id);
  if (t) clearTimeout(t);
  timers.delete(id);
  toasts = toasts.filter((a) => a.id !== id);
  emit();
}

/** Show one alert. Returns false if it was a repeat. Exported for unit tests. */
export function pushAlert(a: SocAlert, opts: { sound?: boolean; notify?: boolean } = {}): boolean {
  if (!a || typeof a.id !== "string" || seen.has(a.id)) return false;
  seen.add(a.id);
  toasts = [a, ...toasts].slice(0, MAX_TOASTS);
  const ms = TOAST_MS[a.level] ?? null;
  if (ms !== null) timers.set(a.id, setTimeout(() => dismiss(a.id), ms));
  emit();
  if ((opts.sound ?? prefs().sound) && a.sound) playCue(a.level);
  if (opts.notify ?? prefs().notify) showNotification(a);
  return true;
}

export function _resetForTests(): void {
  timers.forEach((t) => clearTimeout(t));
  timers.clear();
  seen.clear();
  toasts = [];
  current = { sound: true, notify: null };
  emit();
}

// ------------------------------------------------------------------ preferences (this page only)
// Nothing is kept in browser storage (repo policy: the session lives in an HttpOnly cookie only).
// Sound defaults to on. Notifications are on once the browser has granted permission (that grant is
// the opt-in), and can be switched off for this page.
export interface AlertPrefs {
  sound: boolean;
  notify: boolean;
}
let current: { sound: boolean; notify: boolean | null } = { sound: true, notify: null };

export function prefs(): AlertPrefs {
  const granted = notificationsSupported() && Notification.permission === "granted";
  return { sound: current.sound, notify: current.notify ?? granted };
}

export function setPrefs(p: Partial<AlertPrefs>): AlertPrefs {
  current = { sound: p.sound ?? current.sound, notify: p.notify ?? current.notify };
  return prefs();
}

// ------------------------------------------------------------------ sound
/** Beeps per level: critical 3 high-pitched, high 2, medium 1, low/info none. Exported for tests. */
export const CUES: Record<AlertLevel, { hz: number; beeps: number }> = {
  critical: { hz: 880, beeps: 3 },
  high: { hz: 660, beeps: 2 },
  medium: { hz: 520, beeps: 1 },
  low: { hz: 0, beeps: 0 },
  info: { hz: 0, beeps: 0 },
};

let ctx: AudioContext | null = null;

export function playCue(level: AlertLevel): void {
  const cue = CUES[level];
  if (!cue || cue.beeps === 0) return;
  try {
    const AC = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!AC) return;
    ctx = ctx ?? new AC();
    void ctx.resume();
    for (let i = 0; i < cue.beeps; i++) {
      const t = ctx.currentTime + i * 0.25;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.frequency.value = cue.hz;
      gain.gain.setValueAtTime(0.0001, t);
      gain.gain.exponentialRampToValueAtTime(0.2, t + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.18);
      osc.connect(gain).connect(ctx.destination);
      osc.start(t);
      osc.stop(t + 0.2);
    }
  } catch {
    /* no audio device or autoplay blocked: the toast is still shown */
  }
}

// ------------------------------------------------------------------ browser notifications
export function notificationsSupported(): boolean {
  return typeof window !== "undefined" && "Notification" in window;
}

export async function requestNotifications(): Promise<NotificationPermission | "unsupported"> {
  if (!notificationsSupported()) return "unsupported";
  const p = await Notification.requestPermission();
  setPrefs({ notify: p === "granted" });
  return p;
}

function showNotification(a: SocAlert): void {
  if (!notificationsSupported() || Notification.permission !== "granted" || a.level === "info") return;
  try {
    new Notification(`[${a.level.toUpperCase()}] ${a.title}`, { body: a.reason, tag: a.id });
  } catch {
    /* some browsers only allow notifications from a service worker */
  }
}
