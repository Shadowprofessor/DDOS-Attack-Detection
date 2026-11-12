import { Fragment } from "react";
import { parseInline, parseMarkdown, type Inline } from "../lib/markdown";

// Renders the AI analyst's Markdown reply as React elements only. All text goes through React
// children, which escape it, so model/telemetry output can never inject HTML: no raw-HTML sink is
// used here, which the CSP and the repo's hardening tests require.

function Inlines({ parts }: { parts: Inline[] }) {
  return (
    <>
      {parts.map((p, i) => {
        if (p.t === "code") return <code key={i} className="md-code">{p.v}</code>;
        if (p.t === "strong") return <strong key={i}>{p.v}</strong>;
        return <Fragment key={i}>{p.v}</Fragment>;
      })}
    </>
  );
}

export function Markdown({ source }: { source: string }) {
  const blocks = parseMarkdown(source);
  return (
    <div className="md">
      {blocks.map((b, i) => {
        switch (b.t) {
          case "h":
            return <p key={i} className="md-h"><Inlines parts={parseInline(b.text)} /></p>;
          case "code":
            return <pre key={i} className="md-pre"><code>{b.text}</code></pre>;
          case "ul":
            return <ul key={i} className="md-list">{b.items.map((it, j) => <li key={j}><Inlines parts={parseInline(it)} /></li>)}</ul>;
          case "ol":
            return <ol key={i} className="md-list">{b.items.map((it, j) => <li key={j}><Inlines parts={parseInline(it)} /></li>)}</ol>;
          case "table":
            return (
              <div key={i} className="md-tablewrap">
                <table className="md-table">
                  <thead><tr>{b.head.map((h, j) => <th key={j}><Inlines parts={parseInline(h)} /></th>)}</tr></thead>
                  <tbody>{b.rows.map((r, j) => <tr key={j}>{r.map((c, k) => <td key={k}><Inlines parts={parseInline(c)} /></td>)}</tr>)}</tbody>
                </table>
              </div>
            );
          default:
            return <p key={i}><Inlines parts={parseInline(b.text)} /></p>;
        }
      })}
    </div>
  );
}
