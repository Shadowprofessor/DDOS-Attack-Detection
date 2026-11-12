# -*- coding: utf-8 -*-
"""v5.4.0 LAB-ONLY containment, end to end with a fake OVS:
propose (validated) -> PENDING -> admin approve() -> queued (nothing runs on the platform) ->
bridge relay -> enforcer re-checks + installs a hard_timeout drop rule -> report -> expiry/revert/kill."""
import ast
import json
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import src.api.live_router as live_router
import src.api.scoring_service as api_module
from lab.containment import cookie_for, validate_target
from lab.traffic.enforcer import Enforcer, Refused, build_rule
from src.api.analyst_router import _KeyRateLimiter
from src.api.scoring_service import app
from src.live.bridge import Bridge
from src.mitigation.manager import PendingActionManager

KEY, ADMIN = "lab-cont-analyst", "lab-cont-admin-1"


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeOVS:
    def __init__(self):
        self.calls, self.flows = [], {}

    def __call__(self, args):
        self.calls.append(args)
        if args[1] == "show":
            return subprocess.CompletedProcess(args, 0, " 1(s1-eth1): addr:aa\n 2(s1-eth2): addr:bb\n", "")
        if args[1] == "add-flow":
            self.flows[args[3].split(",")[0]] = args[3]
        if args[1] == "del-flows":
            sel = args[3]
            self.flows = {} if "/0xffff" in sel else {k: v for k, v in self.flows.items() if not sel.startswith(k)}
        return subprocess.CompletedProcess(args, 0, "", "")


def test_targets_are_checked_never_victim_management_or_outside():
    assert validate_target("LAB_OVS_DROP", "10.99.0.105")[0]
    for bad in ("10.99.0.10", "10.99.0.254", "10.99.0.255", "8.8.8.8", "192.168.1.5", "nope"):
        assert not validate_target("LAB_OVS_DROP", bad)[0], bad
    assert validate_target("LAB_OVS_PORT_DROP", "attacker")[0]
    assert not validate_target("LAB_OVS_PORT_DROP", "victim")[0]
    assert not validate_target("OPENFLOW_DROP", "10.99.0.105")[0]


def test_enforcer_rebuilds_and_rechecks_every_rule():
    ports, roles = {"s1-eth1": "1", "s1-eth2": "2"}, {"s1-eth1": "victim", "s1-eth2": "attacker"}
    r = build_rule({"action_id": "a1b2c3d4", "action_type": "LAB_OVS_DROP", "target": "10.99.0.105", "ttl_s": 120,
                    "cookie": hex(cookie_for("a1b2c3d4"))}, ports, roles)
    assert r["flow"] == f"cookie={hex(cookie_for('a1b2c3d4'))},priority=200,ip,nw_src=10.99.0.105,hard_timeout=120,actions=drop"
    p = build_rule({"action_id": "x", "action_type": "LAB_OVS_PORT_DROP", "target": "attacker", "ttl_s": 99999}, ports, roles)
    assert p["match"] == "in_port=2" and p["ttl_s"] == 3600  # TTL clamped
    for bad in ({"action_id": "v", "action_type": "LAB_OVS_DROP", "target": "10.99.0.10"},
                {"action_id": "w", "action_type": "LAB_OVS_PORT_DROP", "target": "victim"},
                {"action_id": "c", "action_type": "LAB_OVS_DROP", "target": "10.99.0.105", "cookie": "0x1"}):
        with pytest.raises(Refused):
            build_rule(bad, ports, roles)


def test_manager_refuses_bad_lab_targets_at_proposal(tmp_path):
    mgr = PendingActionManager(str(tmp_path / "a.json"))
    with pytest.raises(ValueError):
        mgr.propose("LAB_OVS_DROP", "10.99.0.10", "10.99.0.10", "would block the victim")
    aid = mgr.propose("LAB_OVS_DROP", "10.99.0.105", "10.99.0.10", "SYN flood top source", ttl_s=10)
    a = mgr.get_action(aid)
    assert a["status"] == "PENDING" and a["lab"] == {"state": "proposed", "ttl_s": 30}  # TTL clamped to >= 30
    assert "hard_timeout=30" in a["proposed_commands"][0] and mgr.lab_queue() == []  # not approved: not queued


@pytest.fixture
def c(tmp_path, monkeypatch):
    storage = str(tmp_path / "actions.json")
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", storage)
    mgr = PendingActionManager.get_instance(storage)
    mgr.clear()
    o1, o2 = set(api_module.API_KEYS), set(api_module.ADMIN_KEYS)
    api_module.API_KEYS.add(KEY)
    api_module.ADMIN_KEYS.add(ADMIN)
    monkeypatch.setattr(live_router, "live_write_limiter", _KeyRateLimiter(1000))
    try:
        with TestClient(app) as client:
            yield client, mgr
    finally:
        api_module.API_KEYS, api_module.ADMIN_KEYS = o1, o2
        mgr.clear()


class ClientHttp:
    def __init__(self, c):
        self.c = c

    def post(self, path, body=None):
        r = self.c.post(path, headers={"X-API-Key": KEY}, json=body or {})
        return r.status_code, (r.json() if r.content else {})

    def get(self, path):
        r = self.c.get(path, headers={"X-API-Key": KEY})
        return r.status_code, (r.json() if r.content else {})


def test_approved_action_flows_to_the_enforcer_and_back(c, tmp_path):
    client, mgr = c
    run = tmp_path / "live3"
    run.mkdir()
    (run / "manifest.json").write_text(json.dumps({"switch_ports": {"s1-eth1": "victim", "s1-eth2": "attacker"}}))
    clk = Clock()
    bridge = Bridge(run, ClientHttp(client), clock=clk, flows_per_s=0)
    ovs = FakeOVS()
    enf = Enforcer(run, run=ovs, clock=clk, kill_file=tmp_path / "KILL")

    aid = mgr.propose("LAB_OVS_DROP", "10.99.0.105", "10.99.0.10", "SYN flood top source", ttl_s=60)
    bridge.tick()
    assert enf.tick() and ovs.calls == []  # PENDING: nothing reaches the lab
    assert client.post(f"/actions/approve/{aid}", headers={"X-API-Key": KEY}).status_code == 403  # analyst cannot
    r = client.post(f"/actions/approve/{aid}", headers={"X-Admin-Key": ADMIN})
    assert r.status_code == 200 and mgr.get_action(aid)["lab"]["state"] == "queued"
    assert mgr.get_action(aid)["execution_result"]["executed"][0]["status"] == "QUEUED_FOR_LAB_ENFORCER"

    bridge.tick()  # relay: queue -> file
    enf.tick()     # enforcer installs the rule
    flow = [a for a in ovs.calls if a[1] == "add-flow"][0][3]
    assert "nw_src=10.99.0.105" in flow and "hard_timeout=60" in flow and "actions=drop" in flow
    bridge.tick()  # relay: report -> platform
    assert mgr.get_action(aid)["lab"]["state"] == "applied" and mgr.lab_queue() == []
    assert not mgr.is_ip_blocked("10.99.0.105")  # lab rules do not short-circuit scoring

    clk.t += 61.5
    enf.tick()
    bridge.tick()
    assert mgr.get_action(aid)["lab"]["state"] == "expired"  # OVS hard_timeout reached

    aid2 = mgr.propose("LAB_OVS_PORT_DROP", "attacker", "10.99.0.10", "spoofed sources: drop the attacker port", ttl_s=300)
    client.post(f"/actions/approve/{aid2}", headers={"X-Admin-Key": ADMIN})
    bridge.tick(), enf.tick(), bridge.tick()
    assert mgr.get_action(aid2)["lab"]["state"] == "applied"
    ok, _, _ = mgr.revert(aid2, actor="admin", reason="attack over")
    assert ok and mgr.lab_queue()[0]["op"] == "remove"
    bridge.tick(), enf.tick(), bridge.tick()
    assert mgr.get_action(aid2)["lab"]["state"] == "removed" and hex(cookie_for(aid2)) not in str(ovs.flows)

    aid3 = mgr.propose("LAB_OVS_DROP", "10.99.0.106", "10.99.0.10", "another source", ttl_s=300)
    client.post(f"/actions/approve/{aid3}", headers={"X-Admin-Key": ADMIN})
    bridge.tick(), enf.tick(), bridge.tick()
    (tmp_path / "KILL").write_text("stop")
    assert enf.tick() is False  # kill switch: every 0x5AB0 rule removed, enforcer stops
    assert any(a[1] == "del-flows" and "0x5ab0000000000000/0xffff000000000000" in a[3] for a in ovs.calls)
    bridge.tick()
    assert mgr.get_action(aid3)["lab"]["state"] == "removed"
    log = [json.loads(x) for x in (run / "enforcer_log.jsonl").read_text().splitlines()]
    assert [e["event"] for e in log].count("applied") == 3 and log[-1]["event"] in ("removed", "kill_switch")


def test_reports_cannot_skip_approval(c):
    client, mgr = c
    aid = mgr.propose("LAB_OVS_DROP", "10.99.0.105", "10.99.0.10", "pending only")
    r = client.post("/api/lab/enforcement/report", headers={"X-API-Key": KEY}, json={"action_id": aid, "state": "applied"})
    assert r.status_code == 409 and mgr.get_action(aid)["status"] == "PENDING"


def test_no_approve_or_execute_in_lab_code_paths():
    for path in ("src/api/lab_router.py", "lab/traffic/enforcer.py", "lab/containment.py", "src/live/bridge.py"):
        tree = ast.parse(Path(path).read_text(encoding="utf-8"))
        calls = {n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
                 for n in ast.walk(tree) if isinstance(n, ast.Call)}
        assert not calls & {"approve", "_execute_action", "propose"}, path


def test_stale_approvals_expire_and_are_never_handed_to_a_later_enforcer(tmp_path, monkeypatch):
    """live5: two actions approved after the run ended sat in the queue for the next run's enforcer."""
    import time as _t

    mgr = PendingActionManager(str(tmp_path / "a.json"))
    aid = mgr.propose("LAB_OVS_DROP", "10.99.0.111", "10.99.0.10", "late approval", ttl_s=60)
    mgr.approve(aid, approver="admin")
    assert [q["action_id"] for q in mgr.lab_queue()] == [aid]
    real = _t.time
    monkeypatch.setattr("src.mitigation.manager.time.time", lambda: real() + 61)
    assert mgr.lab_queue() == []
    assert mgr.get_action(aid)["lab"]["state"] == "expired_unapplied"


def test_stale_lab_proposal_cannot_be_approved(tmp_path, monkeypatch):
    """live6: PENDING proposals from an earlier run must not be approvable into the next run."""
    import time as _t

    mgr = PendingActionManager(str(tmp_path / "a.json"))
    aid = mgr.propose("LAB_OVS_DROP", "10.99.0.111", "10.99.0.10", "old proposal", ttl_s=60)
    real = _t.time
    monkeypatch.setattr("src.mitigation.manager.time.time", lambda: real() + 61)
    ok, msg, action = mgr.approve(aid, approver="admin")
    assert not ok and "older than its TTL" in msg
    assert action["status"] == "FAILED"
    assert mgr.lab_queue() == []


def test_enforcer_refuses_approvals_from_an_earlier_run(tmp_path):
    """live8: two IP drops approved minutes before the run (still within TTL) reached the new enforcer."""
    run = tmp_path / "live8"
    run.mkdir()
    (run / "manifest.json").write_text(json.dumps({"switch_ports": {"s1-eth1": "victim", "s1-eth2": "attacker"}}))
    clk = Clock()
    ovs = FakeOVS()
    enf = Enforcer(run, run=ovs, clock=clk, kill_file=tmp_path / "KILL")
    old = {"action_id": "old1", "op": "apply", "action_type": "LAB_OVS_DROP", "target": "10.99.0.149",
           "victim_ip": "10.99.0.10", "ttl_s": 300, "approved_at": clk.t - 223}
    new = {**old, "action_id": "new1", "target": "10.99.0.150", "approved_at": clk.t + 5}
    (run / "enforce_queue.jsonl").write_text(json.dumps(old) + "\n" + json.dumps(new) + "\n")
    enf.tick()
    flows = [a[3] for a in ovs.calls if a[1] == "add-flow"]
    assert len(flows) == 1 and "10.99.0.150" in flows[0]
    status = [json.loads(x) for x in (run / "enforce_status.jsonl").read_text().splitlines()]
    assert {(s["action_id"], s["state"]) for s in status} >= {("old1", "refused"), ("new1", "applied")}
