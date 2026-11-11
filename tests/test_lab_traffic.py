# -*- coding: utf-8 -*-
"""v4.6.1 gated lab traffic generator: safety gating, per-packet guards, caps, kill switch, AST gating.

Runs in CI with fake emitters (nothing is sent). The real emitters are only reachable inside a
Mininet host namespace, and only through GatedTrafficRunner.run()."""
import ast
from dataclasses import replace
from types import SimpleNamespace
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from lab.library import load_scenarios  # noqa: E402
from lab.safety import EnvReport, KillSwitch, SafetyError, load_scope  # noqa: E402
from lab.traffic.generator import GatedTrafficRunner  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
GEN = REPO / "lab" / "traffic" / "generator.py"


def in_lab():
    return EnvReport(wsl2=True, mininet=True, reasons=[])


def not_lab():
    return EnvReport(wsl2=False, mininet=False, reasons=["CI"])


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


@pytest.fixture
def kill(tmp_path, monkeypatch):
    monkeypatch.delenv("DDOS_LAB_KILL", raising=False)
    return KillSwitch(file=tmp_path / "KILL", env="DDOS_LAB_KILL")


def _runner(scope, kill, probe=in_lab, **emit):
    clk = Clock()
    sent = {"raw": [], "http": [], "slow": []}
    r = GatedTrafficRunner(scope, probe, kill, sleep=clk.sleep, clock=clk, seed=7,
                           emit_raw=emit.get("raw", lambda p: sent["raw"].append(p)),
                           emit_http=emit.get("http", lambda s, d, port: sent["http"].append((s, d, port))),
                           emit_slow_open=lambda s, d, port: sent["slow"].append((s, d, port)) or SimpleNamespace(close=lambda: None),
                           emit_slow_keepalive=lambda sock: None)
    return r, sent, clk


def _short(sc, **kw):
    return sc.model_copy(update={"profile": sc.profile.model_copy(update=kw)})


def test_nothing_is_built_or_sent_outside_the_lab(kill):
    r, sent, _ = _runner(load_scope(), kill, probe=not_lab)
    with pytest.raises(SafetyError, match="outside the lab"):
        r.run(load_scenarios()["syn_flood"])
    assert sent == {"raw": [], "http": [], "slow": []}


def test_syn_flood_only_targets_the_lab_victim_from_lab_sources(kill):
    scope = load_scope()
    sc = _short(load_scenarios()["syn_flood"], duration_s=2, rate_pps=200)
    r, sent, _ = _runner(scope, kill)
    rep = r.run(sc)
    from scapy.all import IP, TCP  # noqa: E402
    assert rep.packets == len(sent["raw"]) <= 200 * 2
    assert {p[IP].dst for p in sent["raw"]} == {"10.99.0.10"}
    assert all(p[IP].src.startswith("10.99.0.") and 100 <= int(p[IP].src.split(".")[-1]) <= 149 for p in sent["raw"])
    assert all(p[TCP].flags == "S" for p in sent["raw"])


def test_total_packets_capped_at_rate_times_duration(kill):
    sc = _short(load_scenarios()["udp_flood"], duration_s=3, rate_pps=150)
    r, sent, _ = _runner(load_scope(), kill)
    assert r.run(sc).packets <= 450 and len(sent["raw"]) <= 450


def test_reflection_uses_reflector_source_and_service_port(kill):
    sc = _short(load_scenarios()["ntp_reflection_sim"], duration_s=1, rate_pps=50)
    r, sent, _ = _runner(load_scope(), kill)
    r.run(sc)
    from scapy.all import IP, UDP  # noqa: E402
    assert {p[IP].src for p in sent["raw"]} == {"10.99.0.30"} and {p[UDP].sport for p in sent["raw"]} == {123}


def test_http_flash_crowd_uses_real_connections_to_the_victim(kill):
    sc = _short(load_scenarios()["flash_crowd"], duration_s=2, rate_pps=100)
    r, sent, _ = _runner(load_scope(), kill)
    rep = r.run(sc)
    assert sent["raw"] == [] and rep.connections == len(sent["http"]) > 0
    assert {d for _, d, _ in sent["http"]} == {"10.99.0.10"}


def test_slowloris_holds_connections_up_to_profile(kill):
    sc = _short(load_scenarios()["http_low_and_slow"], duration_s=2, slow_connections=20)
    r, sent, _ = _runner(load_scope(), kill)
    rep = r.run(sc)
    assert len(sent["slow"]) == 20 == rep.connections


def test_kill_switch_stops_within_one_tick(kill):
    sc = _short(load_scenarios()["syn_flood"], duration_s=30, rate_pps=100)
    holder = {}

    def raw(p):
        holder.setdefault("n", 0)
        holder["n"] += 1
        if holder["n"] == 150:  # mid-way through tick 2
            kill.trip()

    r, _, _ = _runner(load_scope(), kill, raw=raw)
    rep = r.run(sc)
    assert rep.stopped_by == "kill_switch" and holder["n"] <= 200  # at most the rest of that tick


def test_per_packet_guard_blocks_a_tampered_target(kill):
    scope = load_scope()
    tampered = replace(scope, hosts={**scope.hosts})
    r, sent, _ = _runner(tampered, kill)
    with pytest.raises(SafetyError):
        r._guard("10.99.0.100", "8.8.8.8", "8.8.8.8")  # public: refused even if it were "the plan"
    with pytest.raises(SafetyError):
        r._guard("10.99.0.100", "10.99.0.11", "10.99.0.10")  # not the planned target
    with pytest.raises(SafetyError):
        r._guard("203.0.113.5", "10.99.0.10", "10.99.0.10")  # source outside the lab
    assert sent["raw"] == []


def test_emitters_are_only_called_through_the_gated_runner():
    tree = ast.parse(GEN.read_text(encoding="utf-8"))
    sending = {"send", "sendp", "sr", "sr1", "srp", "create_connection", "sendall", "sendto"}
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for call in [c for c in ast.walk(fn) if isinstance(c, ast.Call)]:
            name = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
            if name in sending:
                assert fn.name.startswith("_emit"), f"{fn.name} sends directly via {name}()"
            if name.startswith("_emit"):
                pytest.fail(f"{fn.name} calls emitter {name} directly (must go through injected runner hooks)")
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "GatedTrafficRunner")
    init = next(f for f in cls.body if isinstance(f, ast.FunctionDef) and f.name == "__init__")
    refs = {n.id for n in ast.walk(init) if isinstance(n, ast.Name) and n.id.startswith("_emit")}
    assert refs == {"_emit_raw", "_emit_http_get", "_emit_http_slow_open", "_emit_http_slow_keepalive"}
    run = next(f for f in cls.body if isinstance(f, ast.FunctionDef) and f.name == "run")
    first = run.body[0] if not isinstance(run.body[0], ast.Expr) else run.body[1]
    assert "plan" in ast.unparse(first), "run() must call the safety planner before anything else"


# ----------------------------------------------------------------------------- v5.1.0 scenarios
def _sent(kill, sid, **kw):
    sc = _short(load_scenarios()[sid], duration_s=1, rate_pps=50, **kw)
    r, sent, _ = _runner(load_scope(), kill)
    rep = r.run(sc)
    return rep, sent["raw"]


def test_icmp_flood_is_echo_requests_to_the_victim(kill):
    from scapy.all import ICMP, IP  # noqa: E402
    rep, pkts = _sent(kill, "icmp_flood")
    assert rep.packets == len(pkts) > 0
    assert {p[IP].dst for p in pkts} == {"10.99.0.10"} and all(p[ICMP].type == 8 for p in pkts)


def test_ack_and_rst_floods_carry_only_their_flag(kill):
    from scapy.all import IP, TCP  # noqa: E402
    for sid, flag in (("tcp_ack_flood", "A"), ("tcp_rst_flood", "R")):
        _, pkts = _sent(kill, sid)
        assert pkts and all(p[TCP].flags == flag for p in pkts), sid
        assert all(100 <= int(p[IP].src.split(".")[-1]) <= 149 for p in pkts)  # lab attacker pool only


def test_land_packets_have_source_equal_destination_and_stay_in_the_lab(kill):
    from scapy.all import IP, TCP  # noqa: E402
    _, pkts = _sent(kill, "land_attack")
    assert pkts
    for p in pkts:
        assert p[IP].src == p[IP].dst == "10.99.0.10" and p[TCP].sport == p[TCP].dport == 80
