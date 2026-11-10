import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatDuration, formatPercent, severityTone } from "./format";

describe("severity colour mapping", () => {
  it("uses the critical (red) tone ONLY for severity 5", () => {
    expect(severityTone(5)).toBe("critical");
    for (const s of [1, 2, 3, 4]) expect(severityTone(s)).not.toBe("critical");
  });

  it("maps 4 amber/high, 3 violet/medium, 2 cyan/low, 1 info", () => {
    expect([4, 3, 2, 1].map(severityTone)).toEqual(["high", "medium", "low", "info"]);
  });

  it("badge renders class + text, never HTML", () => {
    render(<SeverityBadge severity={5} />);
    const el = screen.getByText(/5 · Critical/);
    expect(el).toHaveClass("sev-critical");
  });
});

describe("formatters", () => {
  it("formats durations and overdue", () => {
    expect(formatDuration(3725)).toBe("1h 02m");
    expect(formatDuration(75)).toBe("1m 15s");
    expect(formatDuration(-60)).toBe("overdue 1m 00s");
    expect(formatDuration(null)).toBe("—");
  });

  it("formats percentages", () => {
    expect(formatPercent(0.1234)).toBe("12.3%");
    expect(formatPercent(null)).toBe("—");
  });
});
