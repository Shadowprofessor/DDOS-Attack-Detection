# -*- coding: utf-8 -*-
"""Live-demo helper (v5.4.0): does the ANALYST steps so a human admin only has to approve.

    $env:DDOS_LIVE_KEY = "demo-analyst-key-01"; python scripts/demo_assist.py

When a new `[LIVE]` incident opens it (1) runs the read-only agent and (2) proposes the plan's
top-ranked LAB step, which creates a PENDING action. It cannot approve anything: it uses an analyst
key, and `/actions/approve/{id}` needs an admin (PendingActionManager.approve()). The admin approves
on the website's Approvals page. Stop with Ctrl+C.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


def step(http, seen: set, log=print) -> list:
    """One poll. Returns the (incident_id, action_id) pairs proposed in this pass."""
    status, page = http.get("/api/incidents?limit=10&include_replay=false")
    if status != 200:
        return []
    out = []
    for inc in page.get("items", []):
        iid = inc["id"]
        if iid in seen or not str(inc.get("title", "")).startswith("[LIVE]"):
            continue
        seen.add(iid)
        st, full = http.post(f"/api/incidents/{iid}/agent")
        plan = (((full or {}).get("analysis") or {}).get("agent") or {}) if st == 200 else {}
        lab = [s for s in plan.get("plan") or [] if str(s.get("action", "")).startswith("LAB_")]
        if not lab:
            log(f"{iid}: agent ({plan.get('source')}) proposes no lab step: {plan.get('attack_type')}")
            continue
        top = lab[0]
        st, prop = http.post(f"/api/incidents/{iid}/agent/propose/{top['rank']}")
        if st == 201:
            out.append((iid, prop["action_id"]))
            log(f"{iid}: agent ({plan.get('source')}) says {plan.get('attack_type')}. Proposed {top['action']} "
                f"{top['target']} (TTL {top['ttl_s']} s) as PENDING action {prop['action_id']}. "
                f">>> An ADMIN must approve it on the Approvals page. <<<")
        else:
            log(f"{iid}: proposing step {top['rank']} failed (HTTP {st}): {prop}")
    return out


def main() -> None:  # pragma: no cover - CLI
    from src.live.bridge import RequestsHttp

    key = os.environ.get("DDOS_LIVE_KEY") or (os.environ.get("DDOS_API_KEYS") or "").split(",")[0].strip()
    if not key:
        raise SystemExit("set DDOS_LIVE_KEY to an ANALYST key")
    http = RequestsHttp(os.environ.get("DDOS_API_URL", "http://127.0.0.1:8000"), key, timeout=120.0)
    status, page = http.get("/api/incidents?limit=50&include_replay=false")
    seen = {i["id"] for i in (page or {}).get("items", [])}  # only incidents that open from now on
    print(f"watching for new [LIVE] incidents ({len(seen)} existing ignored); Ctrl+C to stop", flush=True)
    try:
        while True:
            step(http, seen)
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
