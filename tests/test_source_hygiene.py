# -*- coding: utf-8 -*-
"""
Trojan-Source guard (CVE-2021-42574): no raw bidirectional, zero-width or control characters in
source, tests or prompts. Such characters can make code render differently from how it runs.
Write them as escape sequences (e.g. a backslash-u escape) inside string literals instead.
Bandit B613 covers src/ in CI; this also covers tests/ and prompts/.
"""
import glob
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _dangerous(c: str) -> bool:
    o = ord(c)
    return ((o < 32 and c not in "\t\n\r") or 0x7F <= o <= 0x9F or 0x200B <= o <= 0x200F
            or 0x202A <= o <= 0x202E or 0x2060 <= o <= 0x2064 or 0x2066 <= o <= 0x2069 or o == 0xFEFF)


def test_no_hidden_unicode_in_source():
    patterns = ["src/**/*.py", "tests/**/*.py", "prompts/**/*.md", "Codes/**/*.py"]
    offenders = []
    for pat in patterns:
        for path in glob.glob(os.path.join(ROOT, pat), recursive=True):
            with open(path, encoding="utf-8", errors="replace") as f:
                for lineno, line in enumerate(f, 1):
                    bad = [f"U+{ord(c):04X}" for c in line if _dangerous(c)]
                    if bad:
                        offenders.append(f"{os.path.relpath(path, ROOT)}:{lineno} {bad}")
    assert not offenders, "hidden/bidi characters found:\n" + "\n".join(offenders)
