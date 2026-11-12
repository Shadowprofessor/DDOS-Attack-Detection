// A small, SAFE Markdown parser for the AI analyst's replies (v6.1.1). It returns plain data only
// (never HTML, never React) so the renderer can build React elements, which escape all text. It
// deliberately supports just what the assistant emits: headings, paragraphs, bold, inline code,
// fenced code blocks, bullet/numbered lists and tables. Unknown syntax falls through as literal text.

export type Inline =
  | { t: "text"; v: string }
  | { t: "code"; v: string }
  | { t: "strong"; v: string };

export type Block =
  | { t: "h"; text: string }
  | { t: "p"; text: string }
  | { t: "ul"; items: string[] }
  | { t: "ol"; items: string[] }
  | { t: "code"; text: string }
  | { t: "table"; head: string[]; rows: string[][] };

const INLINE = /(`[^`]+`)|(\*\*[^*]+\*\*)/g;

/** Split one line into text / `code` / **strong** runs. Everything stays a string value. */
export function parseInline(text: string): Inline[] {
  const out: Inline[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  INLINE.lastIndex = 0;
  while ((m = INLINE.exec(text)) !== null) {
    if (m.index > last) out.push({ t: "text", v: text.slice(last, m.index) });
    if (m[1]) out.push({ t: "code", v: m[1].slice(1, -1) });
    else if (m[2]) out.push({ t: "strong", v: m[2].slice(2, -2) });
    last = INLINE.lastIndex;
  }
  if (last < text.length) out.push({ t: "text", v: text.slice(last) });
  return out.length ? out : [{ t: "text", v: text }];
}

const splitRow = (line: string): string[] =>
  line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());

const isTableSep = (line: string): boolean => {
  if (!line.includes("-") || !line.includes("|")) return false;
  const cells = splitRow(line);
  return cells.length > 0 && cells.every((c) => /^:?-{1,}:?$/.test(c));
};

const H = /^\s{0,3}#{1,6}\s+(.*)$/;
const UL = /^\s{0,3}[-*]\s+(.*)$/;
const OL = /^\s{0,3}\d+[.)]\s+(.*)$/;
const FENCE = /^\s*```/;

/** Parse Markdown text into a flat list of blocks. Pure; unit-tested. */
export function parseMarkdown(src: string): Block[] {
  const lines = (src ?? "").replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  const at = (k: number): string => lines[k] ?? "";
  const n = lines.length;
  const blocks: Block[] = [];
  let i = 0;
  while (i < n) {
    const line = at(i);

    if (FENCE.test(line)) {
      const body: string[] = [];
      i++;
      while (i < n && !FENCE.test(at(i))) body.push(at(i++));
      if (i < n) i++; // closing fence
      blocks.push({ t: "code", text: body.join("\n") });
      continue;
    }

    if (line.includes("|") && isTableSep(at(i + 1))) {
      const head = splitRow(line);
      i += 2;
      const rows: string[][] = [];
      while (i < n && at(i).includes("|") && at(i).trim() !== "") {
        const cells = splitRow(at(i));
        while (cells.length < head.length) cells.push("");
        rows.push(cells.slice(0, head.length));
        i++;
      }
      blocks.push({ t: "table", head, rows });
      continue;
    }

    const h = line.match(H);
    if (h) {
      blocks.push({ t: "h", text: (h[1] ?? "").trim() });
      i++;
      continue;
    }

    if (UL.test(line)) {
      const items: string[] = [];
      while (i < n && UL.test(at(i))) items.push(at(i++).match(UL)?.[1] ?? "");
      blocks.push({ t: "ul", items });
      continue;
    }

    if (OL.test(line)) {
      const items: string[] = [];
      while (i < n && OL.test(at(i))) items.push(at(i++).match(OL)?.[1] ?? "");
      blocks.push({ t: "ol", items });
      continue;
    }

    if (line.trim() === "") {
      i++;
      continue;
    }

    // paragraph: join consecutive plain lines until a blank line or the start of another block
    const para: string[] = [];
    while (
      i < n &&
      at(i).trim() !== "" &&
      !FENCE.test(at(i)) &&
      !H.test(at(i)) &&
      !UL.test(at(i)) &&
      !OL.test(at(i)) &&
      !(at(i).includes("|") && isTableSep(at(i + 1)))
    ) {
      para.push(at(i).trim());
      i++;
    }
    blocks.push({ t: "p", text: para.join(" ") });
  }
  return blocks;
}
