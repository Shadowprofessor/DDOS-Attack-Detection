# -*- coding: utf-8 -*-
"""
Telemetry sanitisation for LLM prompts (prompt-injection defence, layer 1 of 3).

Everything derived from packets, headers or logs is attacker-controlled. Before it reaches the
LLM we:
  1. strip control, zero-width and bidi-override characters (hidden-instruction carriers),
  2. escape ``<`` / ``>`` so a payload cannot close ``</telemetry>`` or forge tags,
  3. truncate every string to a small bound,
  4. JSON-encode the whole aggregate and wrap it in ``<telemetry>`` tags,
  5. optionally replace IPs with stable HMAC tokens (data minimisation).

Instruction-like text is COUNTED and surfaced (``suspicious_telemetry``), not deleted —
regex deletion is an arms race. The real guarantees come from layers 2 (system prompt) and
3 (code-enforced output policy in ``threat_analyst.py``).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from typing import Any, Dict, Optional, Tuple

# C0/C1 controls (except \t \n), zero-width chars, BOM, bidi embeddings/overrides/isolates.
_INVISIBLE_CODEPOINTS = [
    *range(0x00, 0x09), 0x0B, 0x0C, *range(0x0E, 0x20), *range(0x7F, 0xA0),
    *range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2060, 0x2065),
    *range(0x2066, 0x206A), 0xFEFF,
]
_INVISIBLE_TABLE = dict.fromkeys(_INVISIBLE_CODEPOINTS)  # str.translate: None = delete


def strip_invisible(text: str) -> str:
    """Remove control, zero-width and bidi-override characters."""
    return text.translate(_INVISIBLE_TABLE)
_WS_RE = re.compile(r"\s+")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

INSTRUCTION_PATTERNS = [
    # override / role-play / chat-template markers
    r"ignore (all |any |the )?(previous|prior|above|earlier)? ?(instructions|rules|prompts?)",
    r"disregard (the |all )?(previous|prior|above|system)",
    r"\bnew (system )?instructions?\b",
    r"\byou are now\b",
    r"\b(system|assistant|developer)\s*:",
    r"\[\[?\s*(system|admin|assistant|developer)\s*\]?\]",
    r"</?\s*(telemetry|system|assistant|user)\s*>",
    r"<\|.*?\|>",
    r"\b(developer mode|jailbreak|admin override|operator override|override)\b",
    # attempts to steer the verdict
    r"\bset (the )?severity\b",
    r"\bseverity ?[=:]? ?[0-5]\b",
    r"\b(confidence|attack_?type|incident_?id)\s*[=:]",
    r"\b(mark|classify|label|close|treat)( this| it| traffic| the incident)?( as)? (benign|safe|normal|false positive)\b",
    r"\b(benign|false positive|flash crowd|load test|whitelist(ed)?|trusted partner|pre ?approved)\b",
    r"\b(do not|don't|dont) (mitigate|block|alert|escalate|act)\b",
    r"\b(recommend|take) no actions?\b",
    r"\bclose (this|it|the incident)\b",
    r"\bagree with (them|the previous|me)\b",
    # attempts to steer actions / approvals
    r"\brequires.?human\b",
    r"\b(auto ?execute|pre ?authori[sz]ed|this is authori[sz]ed)\b",
    r"\brecommend(ed)? (action|blocking|block|rtbh|blackhole|rate ?limit)",
    r"\b(block|blackhole|rtbh|null ?route|rate ?limit)( ip| for)? \d{1,3}(\.\d{1,3}){3}\b",
    r"\bblock( \d{1,3}){4}\b",
    r"\b(real victim|attacking ip|it is the c2)\b",
    # attempts to exfiltrate the prompt
    r"\b(reveal|print|show|repeat|list) (your|the) (system |hidden |internal )?(prompt|instructions)\b",
    r"\b(hidden|internal|system) (instructions|prompt|reference token|tokens?)\b",
    r"\breference token\b",
]
_INSTRUCTION_RE = re.compile("|".join(INSTRUCTION_PATTERNS), re.IGNORECASE)
_SEPARATORS_RE = re.compile(r"[-_.+/=&?]+")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

DEFAULT_MAX_STR = 200


def _decoded_variants(text: str) -> list:
    """Printable base64-decoded substrings (catches 'decode and follow' payloads)."""
    import base64
    import binascii

    out = []
    for tok in _B64_RE.findall(text):
        try:
            dec = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if dec.isprintable() and len(dec) >= 8:
            out.append(dec)
    return out


def count_instruction_like(text: str) -> int:
    """Count instruction-like fragments in untrusted text.

    Matches on two normalised forms so evasions do not slip through: NFKC (folds full-width /
    compatibility characters) with invisibles removed, and the same with separators turned into
    spaces (``mark-as-benign.example.com`` -> ``mark as benign example com``). Base64 tokens are
    decoded and scanned too. This is a *signal* for the output policy, not a filter.
    """
    import unicodedata

    if not text:
        return 0
    count = 0
    for variant in [text, *_decoded_variants(text)]:
        nfkc = strip_invisible(unicodedata.normalize("NFKC", variant))
        spaced = _WS_RE.sub(" ", _SEPARATORS_RE.sub(" ", nfkc))
        count += max(len(_INSTRUCTION_RE.findall(nfkc)), len(_INSTRUCTION_RE.findall(spaced)))
    return count


def sanitize_text(value: Any, max_len: int = DEFAULT_MAX_STR) -> str:
    """Neutralise one untrusted string for safe inclusion in a prompt."""
    s = str(value)
    s = strip_invisible(s)
    s = s.replace("<", "‹").replace(">", "›")  # ‹ › — cannot form tags
    s = _WS_RE.sub(" ", s).strip()
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


class IpHasher:
    """Stable, salted IP pseudonymisation (HMAC-SHA256). Reversible only via the local map."""

    def __init__(self, salt: Optional[str] = None):
        salt = salt or os.environ.get("DDOS_LLM_IP_SALT") or secrets.token_hex(16)
        self._key = salt.encode()
        self.token_to_ip: Dict[str, str] = {}

    def token(self, ip: str) -> str:
        tok = "ip_" + hmac.new(self._key, ip.encode(), hashlib.sha256).hexdigest()[:10]
        self.token_to_ip[tok] = ip
        return tok

    def replace_in_text(self, text: str) -> str:
        return IPV4_RE.sub(lambda m: self.token(m.group(0)), text)

    def restore_in_text(self, text: str) -> str:
        for tok, ip in self.token_to_ip.items():
            text = text.replace(tok, ip)
        return text


def _walk(obj: Any, fn) -> Any:
    if isinstance(obj, dict):
        return {k: _walk(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(v, fn) for v in obj]
    if isinstance(obj, str):
        return fn(obj)
    return obj


def untrusted_strings(data: Dict[str, Any]) -> list:
    """Attacker-controllable free-text fields of an IncidentAggregate dump.

    For any other dict shape (e.g. the chat assistant's context) every string is untrusted.
    """
    if not ("incident_id" in data and "window_start" in data):
        found: list = []
        _walk(data, lambda s: found.append(s) or s)
        return found
    out = []
    for group in ("top_src_ips", "top_src_asns", "top_src_countries", "dst_ports"):
        out += [s.get("label") for s in data.get(group) or [] if s.get("label")]
    for sect, keys in (("l7", ("top_user_agents", "top_hosts", "top_uris")), ("dns", ("top_qnames",))):
        for k in keys:
            out += list((data.get(sect) or {}).get(k) or [])
    out += [a.get("detail", "") for a in data.get("alert_history") or []]
    return [s for s in out if isinstance(s, str)]


def build_telemetry_block(
    aggregate: Dict[str, Any], hash_ips: bool = False, hasher: Optional[IpHasher] = None
) -> Tuple[str, int, Optional[IpHasher]]:
    """Return (prompt_block, suspicious_count, hasher).

    ``aggregate`` is an ``IncidentAggregate.model_dump()``. The incident_id is kept verbatim
    (it is validated against a strict pattern upstream) so the model can echo it.
    """
    # Count instruction-like text on the RAW attacker-controlled strings only (not on our own
    # structured fields such as ml.label, which can legitimately be "Benign").
    suspicious = sum(count_instruction_like(s) for s in untrusted_strings(aggregate))

    if hash_ips:
        hasher = hasher or IpHasher()
        incident_id = aggregate.get("incident_id")
        aggregate = _walk(aggregate, hasher.replace_in_text)
        aggregate["incident_id"] = incident_id
    clean = _walk(aggregate, sanitize_text)
    body = json.dumps(clean, ensure_ascii=False, sort_keys=True)
    return f"<telemetry>\n{body}\n</telemetry>", suspicious, (hasher if hash_ips else None)
