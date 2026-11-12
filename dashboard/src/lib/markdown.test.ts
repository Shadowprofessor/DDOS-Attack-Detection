import { describe, expect, it } from "vitest";
import { parseInline, parseMarkdown } from "./markdown";

describe("parseInline", () => {
  it("splits text, inline code and bold, keeping values as plain strings", () => {
    expect(parseInline("block `10.99.0.10` with **SYN 50%** now")).toEqual([
      { t: "text", v: "block " },
      { t: "code", v: "10.99.0.10" },
      { t: "text", v: " with " },
      { t: "strong", v: "SYN 50%" },
      { t: "text", v: " now" },
    ]);
  });
  it("returns a single text run when there is no markup", () => {
    expect(parseInline("just text")).toEqual([{ t: "text", v: "just text" }]);
  });
});

describe("parseMarkdown", () => {
  it("reads headings, paragraphs, bullet and numbered lists", () => {
    const b = parseMarkdown("## Status\nAll quiet now.\n\n- one\n- two\n\n1. first\n2. second");
    expect(b).toEqual([
      { t: "h", text: "Status" },
      { t: "p", text: "All quiet now." },
      { t: "ul", items: ["one", "two"] },
      { t: "ol", items: ["first", "second"] },
    ]);
  });

  it("reads a Markdown table", () => {
    const b = parseMarkdown("| Metric | Value |\n|---|---|\n| Live alerts | **none** |\n| Incidents | 4 |");
    expect(b).toEqual([
      { t: "table", head: ["Metric", "Value"], rows: [["Live alerts", "**none**"], ["Incidents", "4"]] },
    ]);
  });

  it("keeps a fenced code block verbatim, including its lines", () => {
    const b = parseMarkdown("Try:\n```\nsysctl -w net.ipv4.tcp_syncookies=1\nss -s\n```\ndone");
    expect(b).toEqual([
      { t: "p", text: "Try:" },
      { t: "code", text: "sysctl -w net.ipv4.tcp_syncookies=1\nss -s" },
      { t: "p", text: "done" },
    ]);
  });

  it("joins wrapped plain lines into one paragraph and never emits HTML", () => {
    const b = parseMarkdown("line one\nline two <script>");
    expect(b).toEqual([{ t: "p", text: "line one line two <script>" }]);
  });
});
