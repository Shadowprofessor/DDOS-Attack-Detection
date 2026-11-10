import { describe, expect, it } from "vitest";
import { backoffMs, keysFor } from "./useLive";

describe("live updates", () => {
  it("invalidates the incident, lists and overview for an incident event", () => {
    expect(keysFor({ type: "incident.transition", incident_id: "INC-1" })).toEqual([["overview"], ["incidents"], ["incident", "INC-1"]]);
  });
  it("created events also refresh approvals (new proposals may follow)", () => {
    const keys = keysFor({ type: "incident.created", incident: { id: "INC-2" } });
    expect(keys).toContainEqual(["incident", "INC-2"]);
    expect(keys).toContainEqual(["approvals"]);
  });
  it("rollback events refresh approvals", () => {
    expect(keysFor({ type: "rollback.done", incident_id: "INC-3" })).toContainEqual(["approvals"]);
  });
  it("backs off exponentially with a 30 s cap", () => {
    expect([0, 1, 2, 3, 10].map(backoffMs)).toEqual([1000, 2000, 4000, 8000, 30000]);
  });
});
