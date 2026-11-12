# -*- coding: utf-8 -*-
"""
Citation check: every URL and arXiv id cited in the report / README / GRC docs must resolve.

    python scripts/check_citations.py            # exits 1 if any citation is dead

* FAIL  - DNS / connection error, 404 / 410, or a 5xx that persists across retries.
* WARN  - 401 / 403 / 429: the site exists but blocks automated clients. Reported, not failed.
* OK    - 2xx / 3xx.
Placeholders and documentation-only hosts (localhost, example.com, TEST-NET, ...) are skipped.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Tuple

REPO = Path(__file__).resolve().parent.parent
FILES = ["REPORT.md", "README.md", "docs/grc/control_mapping.md", "docs/grc/risk_register.md",
         "docs/DATASETS.md", "docs/IR.md", "docs/eval/cross_dataset.md", "docs/purple_team/README.md", "docs/REFERENCE.md"]
URL_RE = re.compile(r"https?://[^\s<>\)\]\"'`|]+")
ARXIV_RE = re.compile(r"arXiv:(\d{4}\.\d{4,5})(v\d+)?", re.I)
SKIP_HOSTS = ("localhost", "127.0.0.1", "example.com", "example.org", "evil.example", "192.0.2.", "198.51.100.",
              "203.0.113.", "10.", "testserver", "api.cloudflare.com/client")
WARN_CODES = {401, 403, 429}


def extract(text: str) -> List[str]:
    urls = [u.rstrip(".,;:") for u in URL_RE.findall(text)]
    urls += [f"https://arxiv.org/abs/{m.group(1)}" for m in ARXIV_RE.finditer(text)]
    out, seen = [], set()
    for u in urls:
        host = u.split("://", 1)[1]
        if any(host.startswith(h) or f".{h}" in host.split("/")[0] for h in SKIP_HOSTS) or "<" in u or "{" in u:
            continue
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _fetch(url: str) -> int:  # pragma: no cover - network
    import requests

    headers = {"User-Agent": "citation-check/1.0 (+https://github.com/Shadowprofessor/DDOS-Attack-Detection)"}
    r = requests.head(url, allow_redirects=True, timeout=(15, 60), headers=headers)
    if r.status_code in (403, 405, 501) or r.status_code >= 400:
        # slow government/standards sites (e.g. cert-in.org.in) can take >30 s to start a PDF
        r = requests.get(url, allow_redirects=True, timeout=(15, 90), headers=headers, stream=True)
    return r.status_code


def check(urls: Iterable[str], fetch: Callable[[str], int] = _fetch, retries: int = 3,
          sleep: Callable[[float], None] = time.sleep) -> Dict[str, Tuple[str, str]]:
    results = {}
    for u in urls:
        verdict, detail = "FAIL", ""
        for attempt in range(retries):
            try:
                code = fetch(u)
            except Exception as e:  # DNS, TLS, connection
                verdict, detail = "FAIL", type(e).__name__
                sleep(2 * (attempt + 1))
                continue
            if code < 400:
                verdict, detail = "OK", str(code)
                break
            if code in WARN_CODES:
                verdict, detail = "WARN", f"{code} (blocks automated clients)"
                break
            if code in (404, 410):
                verdict, detail = "FAIL", str(code)
                break
            verdict, detail = "FAIL", str(code)  # 5xx: retry
            sleep(2 * (attempt + 1))
        results[u] = (verdict, detail)
    return results


def main() -> int:  # pragma: no cover - CLI
    urls: List[str] = []
    for f in FILES:
        p = REPO / f
        if p.is_file():
            urls += [u for u in extract(p.read_text(encoding="utf-8")) if u not in urls]
    res = check(urls)
    for u, (v, d) in res.items():
        print(f"{v:4}  {d:34}  {u}")
    fails = [u for u, (v, _) in res.items() if v == "FAIL"]
    print(f"\n{len(res)} citations: {sum(v == 'OK' for v, _ in res.values())} OK, "
          f"{sum(v == 'WARN' for v, _ in res.values())} WARN, {len(fails)} FAIL")
    return 1 if fails else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
