import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CUES, MAX_TOASTS, currentToasts, TOAST_MS, _resetForTests, dismiss, prefs, pushAlert, setPrefs, type SocAlert } from "./alerts";
import { keysFor } from "../live/useLive";

const mk = (id: string, level: SocAlert["level"] = "high"): SocAlert => ({
  id, ts: 1, kind: "incident", severity: 4, level, title: `t ${id}`, reason: "r", incident_id: "INC-1", sound: true, suppressed: 0,
});

let store: Record<string, string>;
beforeEach(() => {
  _resetForTests();
  store = {};
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => store[k] ?? null,
    setItem: (k: string, v: string) => { store[k] = v; },
  });
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("alerts", () => {
  it("drops exact repeats (same id) and caps toasts", () => {
    expect(pushAlert(mk("a"), { sound: false, notify: false })).toBe(true);
    expect(pushAlert(mk("a"), { sound: false, notify: false })).toBe(false);
    for (let i = 0; i < 10; i++) pushAlert(mk(`b${i}`), { sound: false, notify: false });
    expect(currentToasts()).toHaveLength(MAX_TOASTS);
    expect(currentToasts()[0]?.id).toBe("b9"); // newest first
  });

  it("critical stays until dismissed; high auto-dismisses", () => {
    expect(TOAST_MS.critical).toBeNull();
    expect(TOAST_MS.high).toBe(15_000);
    pushAlert(mk("c", "critical"), { sound: false, notify: false });
    pushAlert(mk("h", "high"), { sound: false, notify: false });
    vi.advanceTimersByTime(16_000);
    expect(currentToasts().map((t) => t.id)).toEqual(["c"]);
    dismiss("c");
    expect(currentToasts()).toEqual([]);
  });

  it("sound cue rises with severity and is silent for info", () => {
    expect([CUES.critical.beeps, CUES.high.beeps, CUES.medium.beeps, CUES.info.beeps]).toEqual([3, 2, 1, 0]);
  });

  it("prefs default to sound on, notifications off, and persist", () => {
    expect(prefs()).toEqual({ sound: true, notify: false });
    setPrefs({ sound: false });
    expect(prefs()).toEqual({ sound: false, notify: false });
  });

  it("an alert event refreshes only the alerts list", () => {
    expect(keysFor({ type: "alert", alert: mk("x") })).toEqual([["alerts"]]);
  });
});
