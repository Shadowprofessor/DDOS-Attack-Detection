# -*- coding: utf-8 -*-
"""v4.2.0 incident-response backend: lifecycle, timeline, playbooks, CERT-In, export, rollback, replay."""
import ast
import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import text

from src.ir.cert_in import build_draft, mark_reported
from src.ir.export import md_escape, to_markdown, to_pdf
from src.ir.lifecycle import (STATES, TRANSITIONS, IllegalTransition, NotFound, ValidationFailed)
from src.ir.playbooks import (PLAYBOOK_DIR, PlaybookError, family_from_text, load_playbooks,
                              parse_playbook, run_step)
from src.ir.replay import get_dry_run_manager, list_scenarios, load_scenario
from src.ir.runtime import IRRuntime
from src.mitigation.manager import PendingActionManager

REPO = Path(__file__).resolve().parent.parent
T0 = 1_762_761_700.0


class FakeClock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


AGG = {
    "incident_id": "agg-1", "window_start": T0 - 30, "pps": 250000.0, "unique_src_ips": 900,
    "top_src_ips": [{"key": "10.10.0.21", "share": 0.08}], "dst_ips": ["10.0.0.4"],
    "dst_ports": [{"key": "443", "share": 0.9}], "protocol_mix": {"tcp": 0.98},
    "tcp_flag_ratios": {"syn": 0.93}, "ml": {"label": "Syn", "confidence": 0.97},
}


@pytest.fixture
def mgr(tmp_path):
    m = PendingActionManager.get_instance(str(tmp_path / "actions.json"))
    m.clear()
    return m


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def rt(tmp_path, mgr, clock):
    r = IRRuntime({}, database_url=f"sqlite:///{(tmp_path / 'ir.db').as_posix()}", clock=clock,
                  manager_factory=lambda: mgr)
    get_dry_run_manager().clear()
    yield r
    r.close()


def _new(rt, severity=4, **kw):
    return rt.service.create_incident(title="SYN flood on web", severity=severity, actor="analyst:t",
                                      aggregate=kw.pop("aggregate", AGG), **kw)


def _walk(rt, inc_id, path, **kw):
    for st in path:
        rt.service.transition(inc_id, st, "admin:t", justification="manual containment via upstream ACL")


PATH_TO = {
    "new": [], "triage": ["triage"], "investigating": ["triage", "investigating"],
    "contained": ["triage", "investigating", "contained"],
    "eradicated": ["triage", "investigating", "contained", "eradicated"],
    "recovered": ["triage", "investigating", "contained", "eradicated", "recovered"],
    "closed": ["triage", "investigating", "contained", "eradicated", "recovered", "closed"],
    "false_positive": ["false_positive"],
}


# ----------------------------------------------------------------------------- lifecycle
class TestLifecycle:
    def test_id_format_and_initial_state(self, rt):
        inc = _new(rt)
        assert re.match(r"^INC-\d{8}-[0-9a-f]{4}$", inc["id"])
        assert inc["status"] == "new" and inc["attack_family"] == "syn_flood"

    def test_full_happy_path_sets_timestamps(self, rt, clock):
        inc = _new(rt)
        _walk(rt, inc["id"], PATH_TO["closed"])
        got = rt.service.get(inc["id"])
        assert got["status"] == "closed" and got["contained_at"] and got["closed_at"]
        kinds = [e["kind"] for e in got["events"]]
        assert kinds == ["created"] + ["transition"] * 6

    def test_false_positive_path(self, rt):
        inc = _new(rt)
        _walk(rt, inc["id"], ["false_positive", "closed"])
        assert rt.service.get(inc["id"])["status"] == "closed"

    @pytest.mark.parametrize("state", STATES)
    def test_every_illegal_transition_raises_and_writes_nothing(self, rt, state):
        inc = _new(rt)
        _walk(rt, inc["id"], PATH_TO[state])
        before = rt.service.get(inc["id"])
        for target in STATES:
            if target in TRANSITIONS[state]:
                continue
            with pytest.raises(IllegalTransition):
                rt.service.transition(inc["id"], target, "admin:t", justification="x" * 20)
        after = rt.service.get(inc["id"])
        assert after["status"] == state
        assert len(after["events"]) == len(before["events"])

    def test_contained_requires_action_or_justification(self, rt):
        inc = _new(rt)
        _walk(rt, inc["id"], ["triage", "investigating"])
        n = len(rt.service.get(inc["id"])["events"])
        with pytest.raises(ValidationFailed):
            rt.service.transition(inc["id"], "contained", "admin:t")
        with pytest.raises(ValidationFailed):
            rt.service.transition(inc["id"], "contained", "admin:t", justification="short")
        assert len(rt.service.get(inc["id"])["events"]) == n

    def test_contained_with_approved_action(self, rt, mgr):
        inc = _new(rt)
        _walk(rt, inc["id"], ["triage", "investigating"])
        aid = mgr.propose("BLOCK", "10.10.0.21", "10.0.0.4", "test")
        rt.service.link_action(inc["id"], aid, "analyst:t")
        with pytest.raises(ValidationFailed):  # linked but still PENDING
            rt.service.transition(inc["id"], "contained", "admin:t")
        mgr.approve(aid, approver="test_admin")
        out = rt.service.transition(inc["id"], "contained", "admin:t")
        assert out["status"] == "contained"

    def test_unknown_incident(self, rt):
        with pytest.raises(NotFound):
            rt.service.transition("INC-00000000-0000", "triage", "a")

    def test_family_mapping(self):
        assert family_from_text("TCP SYN flood") == "syn_flood"
        assert family_from_text("DrDoS_NTP") == "udp_reflection_amplification"
        assert family_from_text("DrDoS_DNS") == "dns_amplification"
        assert family_from_text("Slowloris / low-and-slow HTTP (L7)") == "l7_low_and_slow"
        assert family_from_text("zero-day (OOD)") == "zero_day_ood"
        assert family_from_text("???") == "other"


# ----------------------------------------------------------------------------- hash chain
class TestHashChain:
    def _incident_with_events(self, rt):
        inc = _new(rt)
        for i in range(3):
            rt.service.add_note(inc["id"], "analyst:t", f"note {i}")
        assert rt.service.verify_chain(inc["id"]) == {"ok": True, "events": 4, "broken_at": None}
        return inc["id"]

    @pytest.mark.parametrize("sql", [
        "UPDATE incident_events SET detail='{\"text\": \"forged\"}' WHERE seq=2",
        "UPDATE incident_events SET actor='admin:evil' WHERE seq=3",
        "UPDATE incident_events SET ts=ts+1 WHERE seq=1",
        "UPDATE incident_events SET hash='" + "a" * 64 + "' WHERE seq=4",
        "DELETE FROM incident_events WHERE seq=2",
    ])
    def test_tampering_breaks_chain(self, rt, sql):
        iid = self._incident_with_events(rt)
        with rt.db.engine.begin() as c:
            c.execute(text(sql))
        res = rt.service.verify_chain(iid)
        assert res["ok"] is False and res["broken_at"] is not None


# ----------------------------------------------------------------------------- playbooks
GOOD_PB = """
id: test_pb
name: Test playbook
version: "1.0"
attack_families: [syn_flood]
steps:
  - {id: s1, title: Check things, kind: check}
"""


class TestPlaybooks:
    def test_all_shipped_playbooks_validate(self):
        pbs = load_playbooks()
        assert {"syn_flood", "udp_reflection_amplification", "l7_low_and_slow", "dns_amplification",
                "zero_day_ood"} <= set(pbs)
        assert len(list(PLAYBOOK_DIR.glob("*.yaml"))) == len(pbs)

    @pytest.mark.parametrize("bad, needle", [
        ("id: [unclosed", "malformed YAML"),
        ("- just a list", "mapping"),
        (GOOD_PB.replace("kind: check", "kind: execute"), "kind"),
        (GOOD_PB.replace("kind: check}", "kind: propose_action}"), "requires an 'action'"),
        (GOOD_PB + "  - {id: s1, title: Dup step, kind: check}\n", "duplicate step"),
        (GOOD_PB.replace("[syn_flood]", "[not_a_family]"), "attack_families"),
        (GOOD_PB + "extra_field: 1\n", "extra"),
    ])
    def test_malformed_playbook_rejected_with_clear_error(self, bad, needle):
        with pytest.raises(PlaybookError) as ei:
            parse_playbook(bad, source="bad.yaml")
        assert "bad.yaml" in str(ei.value) and needle.lower() in str(ei.value).lower()

    def test_propose_action_step_only_creates_pending(self, rt, mgr):
        inc = _new(rt)
        pb = rt.playbooks["syn_flood"]
        with patch.object(mgr, "_execute_action") as ex, patch.object(mgr, "approve") as ap, \
                patch("subprocess.run") as sp:
            res = run_step(rt.service, inc["id"], pb, "rate_limit_top_source", actor="analyst:t", role="analyst")
            ex.assert_not_called()
            ap.assert_not_called()
            sp.assert_not_called()
        action = mgr.get_action(res["result"]["action_id"])
        assert action["status"] == "PENDING" and action["auto_execute"] is False
        assert action["attacker_ip"] == "10.10.0.21"
        detail = rt.service.get(inc["id"])
        assert detail["actions"][0]["action_id"] == action["action_id"]
        assert detail["playbook_runs"][0]["step"] == "rate_limit_top_source"

    def test_step_role_enforced(self, rt):
        inc = _new(rt)
        with pytest.raises(PermissionError):
            run_step(rt.service, inc["id"], rt.playbooks["syn_flood"], "record_root_cause", "analyst:t", "analyst")
        run_step(rt.service, inc["id"], rt.playbooks["syn_flood"], "record_root_cause", "admin:t", "admin")

    def test_closed_incident_cannot_run_steps(self, rt):
        inc = _new(rt)
        _walk(rt, inc["id"], ["false_positive"])
        with pytest.raises(IllegalTransition):
            run_step(rt.service, inc["id"], rt.playbooks["syn_flood"], "confirm_syn_ratio", "a", "analyst")


class TestNoDirectEnforcement:
    """AST guard: src/ir/ never approves or executes; only rollback.py may call revert()."""

    BANNED_ATTRS = {"approve", "_execute_action", "execute", "apply", "block", "send_msg", "system",
                    "popen", "Popen", "_revert_action"}
    DB_HANDLES = {"s", "c", "session", "conn"}

    def test_ast_scan(self):
        for path in sorted((REPO / "src" / "ir").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                    assert not any(m.split(".")[0] in ("subprocess", "pty") for m in mods), path.name
                if isinstance(node, ast.Call):
                    f = node.func
                    name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                    receiver = getattr(getattr(f, "value", None), "id", None)
                    if name == "execute" and receiver in self.DB_HANDLES:  # SQLAlchemy session/conn
                        continue
                    assert name not in self.BANNED_ATTRS, f"{path.name}: illegal call {name}()"
                    if name == "revert":
                        assert path.name == "rollback.py", f"{path.name}: revert() only allowed in rollback.py"


# ----------------------------------------------------------------------------- CERT-In
class TestCertIn:
    def test_deadline_is_detected_plus_6h(self, rt):
        inc = _new(rt, severity=4, detected_at=T0 - 100)
        assert inc["cert_in_deadline"] == pytest.approx(T0 - 100 + 6 * 3600)

    def test_below_threshold_has_no_deadline(self, rt):
        assert _new(rt, severity=3)["cert_in_deadline"] is None

    def test_warnings_fire_once_at_1h_15m_and_breach(self, rt, clock):
        inc = _new(rt, severity=5)
        published = []
        rt.service._publish = published.append
        assert rt.cert_in.check() == []
        clock.advance(5 * 3600)          # 1 h left
        assert [w["warning"] for w in rt.cert_in.check()] == ["1h"]
        assert rt.cert_in.check() == []  # not repeated
        clock.advance(45 * 60)           # 15 min left
        assert [w["warning"] for w in rt.cert_in.check()] == ["15m"]
        clock.advance(15 * 60 + 1)       # breached
        assert [w["warning"] for w in rt.cert_in.check()] == ["breach"]
        kinds = [e["kind"] for e in rt.service.get(inc["id"])["events"]]
        assert kinds.count("cert_in_warning") == 3
        assert [p["warning"] for p in published if p["type"] == "cert_in.warning"] == ["1h", "15m", "breach"]

    def test_reported_stops_warnings(self, rt, clock):
        inc = _new(rt, severity=5)
        mark_reported(rt.service, inc["id"], "admin:t", "CERTIN-ACK-123")
        clock.advance(7 * 3600)
        assert rt.cert_in.check() == []
        with pytest.raises(ValidationFailed):
            mark_reported(rt.service, _new(rt, severity=1)["id"], "admin:t", "ref-1")

    def test_draft_has_required_fields(self, rt):
        inc = rt.service.get(_new(rt, severity=5)["id"])
        d = build_draft(inc, rt.settings.cert_in, rt.service.clock())
        assert d["draft"] is True and "Not submitted" in d["notice"]
        for k in ("reporting_entity", "incident", "affected_systems", "indicators_of_compromise",
                  "actions_taken", "reporting_deadline", "legal_basis", "source_url"):
            assert k in d
        assert d["incident"]["time_of_detection"] and d["incident"]["type_of_incident"].startswith("Denial")
        assert d["affected_systems"]["ip_addresses"] == ["10.0.0.4"]
        assert d["indicators_of_compromise"]["source_ips"] == ["10.10.0.21"]

    def test_draft_hashes_iocs_when_configured(self, rt):
        rt.settings.cert_in.hash_iocs = True
        d = build_draft(rt.service.get(_new(rt, severity=5)["id"]), rt.settings.cert_in, T0)
        assert d["indicators_of_compromise"]["source_ips"][0].startswith("sha256:")


# ----------------------------------------------------------------------------- export
EVIL = "<script>alert(1)</script> [click](http://evil) # Heading\n| col |"


class TestExport:
    def _evil_incident(self, rt):
        inc = rt.service.create_incident(title=EVIL, severity=4, actor="analyst:t", aggregate=AGG)
        rt.service.add_note(inc["id"], "analyst:t", EVIL)
        return rt.service.get(inc["id"])

    def test_markdown_escapes_untrusted(self, rt):
        md = to_markdown(self._evil_incident(rt))
        assert "<script>" not in md and "&lt;script&gt;" in md
        assert "[click](http://evil)" not in md
        assert "\n# Heading" not in md
        assert "Hash chain over 2 events: **VERIFIED**" in md

    def test_md_escape_unit(self):
        assert md_escape("a\nb") == "a b"
        assert md_escape("[x](y)") == "\\[x\\]\\(y\\)"

    def test_pdf_generates_and_has_pages(self, rt):
        pdf = to_pdf(self._evil_incident(rt))
        assert pdf.startswith(b"%PDF")
        assert len(re.findall(rb"/Type\s*/Page[^s]", pdf)) >= 1

    def test_ai_output_is_labelled(self, rt):
        from src.agent.schemas import IncidentAggregate
        from src.agent.threat_analyst import rule_based_analysis
        a = rule_based_analysis(IncidentAggregate.model_validate(AGG)).model_dump()
        inc = rt.service.create_incident(title="t1", severity=4, actor="a",
                                         analysis={"analysis": a, "source": "rules"})
        assert "AI-generated recommendation" in to_markdown(rt.service.get(inc["id"]))


# ----------------------------------------------------------------------------- rollback
class TestRollback:
    def _approved(self, rt, mgr, ttl=None):
        inc = _new(rt)
        aid = mgr.propose("BLOCK", "10.10.0.21", "10.0.0.4", "test")
        rt.service.link_action(inc["id"], aid, "analyst:t", ttl_s=ttl)
        mgr.approve(aid, approver="test_admin")
        mgr.get_action(aid)["approved_at"] = rt.service.clock()  # align manager time with fake clock
        mgr._save_to_disk()
        return inc["id"], aid

    def test_reverts_after_ttl(self, rt, mgr, clock):
        iid, aid = self._approved(rt, mgr)
        assert rt.rollback.tick() == []
        assert rt.rollback.status(aid)["rollback_state"] == "scheduled"
        assert mgr.is_ip_blocked("10.10.0.21")
        clock.advance(599)
        assert rt.rollback.tick() == []
        clock.advance(2)
        assert [r["type"] for r in rt.rollback.tick()] == ["rollback.done"]
        assert mgr.get_action(aid)["status"] == "ROLLED_BACK"
        assert not mgr.is_ip_blocked("10.10.0.21")
        kinds = [e["kind"] for e in rt.service.get(iid)["events"]]
        assert "rollback_scheduled" in kinds and "rollback_done" in kinds

    def test_per_action_ttl(self, rt, mgr, clock):
        _, aid = self._approved(rt, mgr, ttl=60)
        rt.rollback.tick()
        clock.advance(61)
        rt.rollback.tick()
        assert mgr.get_action(aid)["status"] == "ROLLED_BACK"

    def test_extend_and_permanent(self, rt, mgr, clock):
        _, aid = self._approved(rt, mgr)
        rt.rollback.tick()
        rt.rollback.extend(aid, "admin:t", "attack still ongoing", seconds=600)
        clock.advance(900)
        rt.rollback.tick()
        assert mgr.get_action(aid)["status"] == "EXECUTED"
        rt.rollback.extend(aid, "admin:t", "known-bad botnet range", permanent=True)
        clock.advance(10 ** 6)
        rt.rollback.tick()
        assert mgr.get_action(aid)["status"] == "EXECUTED"
        assert rt.rollback.status(aid)["rollback_state"] == "permanent"
        with pytest.raises(ValidationFailed):
            rt.rollback.extend(aid, "admin:t", "x")

    def test_survives_restart(self, rt, mgr, clock, tmp_path):
        _, aid = self._approved(rt, mgr)
        rt.rollback.tick()
        url = rt.db.url
        rt.close()
        rt2 = IRRuntime({}, database_url=url, clock=clock, manager_factory=lambda: mgr)
        try:
            clock.advance(601)
            assert [r["type"] for r in rt2.rollback.tick()] == ["rollback.done"]
            assert mgr.get_action(aid)["status"] == "ROLLED_BACK"
        finally:
            rt2.close()

    def test_failure_is_retried_with_backoff_and_recorded(self, rt, mgr, clock):
        iid, aid = self._approved(rt, mgr)
        rt.rollback.tick()
        clock.advance(601)
        real = mgr.revert
        with patch.object(mgr, "revert", return_value=(False, "enforcer unreachable", None)):
            assert rt.rollback.tick()[0]["type"] == "rollback.failed"
            assert rt.rollback.tick() == []  # backoff: not yet due
            st = rt.rollback.status(aid)
            assert st["attempts"] == 1 and st["last_error"] == "enforcer unreachable"
        clock.advance(rt.settings.rollback_backoff_s + 1)
        with patch.object(mgr, "revert", side_effect=real):
            assert rt.rollback.tick()[0]["type"] == "rollback.done"
        kinds = [e["kind"] for e in rt.service.get(iid)["events"]]
        assert kinds.count("rollback_failed") == 1 and "rollback_done" in kinds

    def test_gives_up_after_max_attempts(self, rt, mgr, clock):
        _, aid = self._approved(rt, mgr)
        rt.rollback.tick()
        clock.advance(601)
        with patch.object(mgr, "revert", side_effect=RuntimeError("boom")):
            for _ in range(rt.settings.rollback_max_attempts):
                rt.rollback.tick()
                clock.advance(10 ** 4)
        st = rt.rollback.status(aid)
        assert st["rollback_state"] == "failed" and st["attempts"] == rt.settings.rollback_max_attempts

    def test_pending_actions_never_scheduled(self, rt, mgr, clock):
        inc = _new(rt)
        aid = mgr.propose("BLOCK", "10.10.0.30", "10.0.0.4", "test")
        rt.service.link_action(inc["id"], aid, "analyst:t")
        clock.advance(10 ** 5)
        rt.rollback.tick()
        assert rt.rollback.status(aid)["rollback_state"] == "linked"
        assert mgr.get_action(aid)["status"] == "PENDING"


class TestManagerRevert:
    def test_only_executed_can_be_reverted(self, mgr):
        aid = mgr.propose("BLOCK", "10.1.1.1", "10.0.0.1", "t")
        ok, _, _ = mgr.revert(aid, actor="t")
        assert not ok and mgr.get_action(aid)["status"] == "PENDING"
        mgr.approve(aid, approver="t")
        ok, _, a = mgr.revert(aid, actor="t")
        assert ok and a["status"] == "ROLLED_BACK" and a["rolled_back_by"] == "t"
        assert mgr.revert(aid, actor="t")[0] is False


# ----------------------------------------------------------------------------- replay
class TestReplay:
    def test_scenarios_shipped(self):
        assert {"syn_flood", "udp_reflection_ntp"} <= set(list_scenarios())
        with pytest.raises(KeyError):
            load_scenario("../../etc/passwd")

    def test_syn_flood_replay_creates_replay_incident_and_no_real_actions(self, rt, mgr):
        rt.replay.sleep = lambda s: None
        out = rt.replay.replay(load_scenario("syn_flood"), speed=1000, scenario="syn_flood")
        inc = out["incident"]
        assert inc["is_replay"] is True and inc["attack_family"] == "syn_flood"
        assert inc["cert_in_deadline"] is None
        assert [s["layer"] for s in out["stages"]] == ["L1", "L1", "L1", "L2", "L3"]
        # playbook on a replay incident goes to the dry-run manager only
        res = run_step(rt.service, inc["id"], rt.playbooks["syn_flood"], "rate_limit_top_source", "a", "analyst")
        assert res["result"]["action_id"].startswith("dry-")
        assert mgr.get_action_log() == []
        assert len(get_dry_run_manager().all()) == 1

    def test_ntp_replay_family(self, rt):
        rt.replay.sleep = lambda s: None
        inc = rt.replay.replay(load_scenario("udp_reflection_ntp"))["incident"]
        assert inc["attack_family"] == "udp_reflection_amplification"

    def test_replay_excluded_from_metrics_gauge(self, rt):
        from src.obs import metrics
        rt.replay.sleep = lambda s: None
        _new(rt)
        rt.replay.replay(load_scenario("syn_flood"))
        assert metrics.INCIDENTS_BY_STATE.samples[(("state", "new"),)] == 1.0
