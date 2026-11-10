# -*- coding: utf-8 -*-
"""v4.6.0 purple-team lab safety layer (runs in CI; sends no traffic)."""
import ast
from pathlib import Path

import pytest

from lab.library import ScenarioError, load_scenarios, parse_scenario
from lab.runner import MockRunner, to_aggregate
from lab.safety import (EnvReport, KillSwitch, SafetyError, check_profile, check_target, load_scope,
                        require_lab_environment)

REPO = Path(__file__).resolve().parent.parent


def in_lab():
    return EnvReport(wsl2=True, mininet=True, reasons=[])


def not_lab():
    return EnvReport(wsl2=False, mininet=False, reasons=["CI runner"])


@pytest.fixture
def scope():
    return load_scope()


@pytest.fixture
def kill(tmp_path, monkeypatch):
    monkeypatch.delenv("DDOS_LAB_KILL", raising=False)
    return KillSwitch(file=tmp_path / "KILL", env="DDOS_LAB_KILL")


class TestTargets:
    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888",
                                    "142.250.183.14", "13.107.42.14"])
    def test_public_addresses_refused(self, scope, ip):
        with pytest.raises(SafetyError, match="public"):
            check_target(scope, ip)

    @pytest.mark.parametrize("ip", ["10.0.0.4", "192.168.1.10", "172.16.5.5", "10.99.1.10", "fd00::1"])
    def test_private_but_not_allowlisted_refused(self, scope, ip):
        with pytest.raises(SafetyError, match="not in allowed_networks"):
            check_target(scope, ip)

    @pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "not-an-ip", "::1"])
    def test_special_addresses_refused(self, scope, ip):
        with pytest.raises(SafetyError):
            check_target(scope, ip)

    def test_lab_hosts_allowed(self, scope):
        for ip in scope.hosts.values():
            assert check_target(scope, str(ip)) == ip


class TestScopeValidation:
    @pytest.mark.parametrize("net, msg", [("8.8.8.0/24", "public"), ("10.0.0.0/8", "larger than"),
                                          ("127.0.0.0/24", "loopback"), ("2001:db8::/64", "only IPv4"),
                                          ("10.99.0.1/24", "invalid")])
    def test_bad_networks_rejected(self, tmp_path, net, msg):
        p = tmp_path / "scope.yaml"
        p.write_text(f"allowed_networks: ['{net}']\ncaps: {{max_pps: 10, max_duration_s: 10, max_concurrent: 1}}\n")
        with pytest.raises(SafetyError, match=msg):
            load_scope(p)

    def test_host_outside_networks_rejected(self, tmp_path):
        p = tmp_path / "scope.yaml"
        p.write_text("allowed_networks: ['10.99.0.0/24']\nhosts: {victim: 10.0.0.4}\n"
                     "caps: {max_pps: 10, max_duration_s: 10, max_concurrent: 1}\n")
        with pytest.raises(SafetyError, match="outside allowed_networks"):
            load_scope(p)


class TestCaps:
    def test_over_cap_refused(self, scope):
        with pytest.raises(SafetyError, match="rate"):
            check_profile(scope, scope.caps.max_pps + 1, 10)
        with pytest.raises(SafetyError, match="duration"):
            check_profile(scope, 10, scope.caps.max_duration_s + 1)
        with pytest.raises(SafetyError, match="already running"):
            check_profile(scope, 10, 10, running=scope.caps.max_concurrent)
        check_profile(scope, scope.caps.max_pps, scope.caps.max_duration_s)


class TestEnvironmentAndKillSwitch:
    def test_refuses_outside_lab(self, scope):
        with pytest.raises(SafetyError, match="refusing to run outside the lab"):
            require_lab_environment(scope, not_lab)
        with pytest.raises(SafetyError, match="Mininet"):
            require_lab_environment(scope, lambda: EnvReport(True, False, ["no mn"]))

    def test_runner_refuses_outside_lab_before_anything(self, scope, kill):
        sc = load_scenarios()["syn_flood"]
        with pytest.raises(SafetyError):
            MockRunner(scope, not_lab, kill, sleep=lambda s: None).run(sc)

    def test_kill_switch_stops_within_one_tick(self, scope, kill):
        sc = load_scenarios()["syn_flood"]
        calls = []

        def sleep(_s):
            calls.append(1)
            if len(calls) == 3:
                kill.trip()  # e.g. from a SIGTERM handler

        rep = MockRunner(scope, in_lab, kill, sleep=sleep).run(sc)
        assert rep.stopped_by == "kill_switch" and rep.ticks_run == 3 and rep.planned_ticks == 60

    @pytest.mark.parametrize("how", ["file", "env"])
    def test_tripped_switch_blocks_start(self, scope, kill, how, monkeypatch):
        if how == "file":
            kill.file.write_text("stop")
        else:
            monkeypatch.setenv("DDOS_LAB_KILL", "1")
        with pytest.raises(SafetyError, match="kill switch"):
            MockRunner(scope, in_lab, kill, sleep=lambda s: None).run(load_scenarios()["udp_flood"])

    def test_completed_run(self, scope, kill):
        rep = MockRunner(scope, in_lab, kill, sleep=lambda s: None).run(load_scenarios()["flash_crowd"])
        assert rep.stopped_by == "completed" and rep.ticks_run == rep.planned_ticks


BAD_SCENARIOS = [
    ("id: x1x\nname: bad\nattack: true\ndescription: missing mitre here\n"
     "profile: {protocol: udp, rate_pps: 1, duration_s: 1, sources: 1, source_role: attacker}\n"
     "expected: {incident: true, family: other, layers: [L1]}", "ATT&CK"),
    ("id: x2x\nname: bad\nattack: false\ndescription: benign expects family\n"
     "profile: {protocol: udp, rate_pps: 1, duration_s: 1, sources: 1, source_role: client}\n"
     "expected: {incident: false, family: other}", "benign"),
    ("id: x3x\nname: bad\nattack: false\ndescription: has a shell command field\ncommand: run-something\n"
     "profile: {protocol: udp, rate_pps: 1, duration_s: 1, sources: 1, source_role: client}\n"
     "expected: {incident: false}", "extra"),
]


class TestScenarioLibrary:
    def test_all_scenarios_valid_and_within_caps(self, scope):
        scs = load_scenarios()
        assert {"benign_baseline", "flash_crowd", "syn_flood", "udp_flood", "ntp_reflection_sim",
                "dns_reflection_sim", "http_low_and_slow", "novel_ood_mix"} <= set(scs)
        for sc in scs.values():
            check_profile(scope, sc.profile.rate_pps, sc.profile.duration_s)
            assert sc.profile.source_role in scope.hosts

    @pytest.mark.parametrize("text, needle", BAD_SCENARIOS)
    def test_invalid_scenarios_rejected(self, text, needle):
        with pytest.raises(ScenarioError) as ei:
            parse_scenario(text, "bad.yaml")
        assert needle.lower() in str(ei.value).lower()


class TestMockPipelineWiring:
    """Pipeline check (NOT detection evidence): synthetic aggregates -> replay -> expected family."""

    def test_expected_families_through_replay(self, scope, kill, tmp_path):
        from src.agent.schemas import IncidentAggregate
        from src.ir.replay import ReplayEngine
        from src.ir.runtime import IRRuntime

        rt = IRRuntime({}, database_url=f"sqlite:///{(tmp_path / 'ir.db').as_posix()}")
        try:
            eng = ReplayEngine(rt.service, sleep=lambda s: None)
            for sid in ("syn_flood", "ntp_reflection_sim", "http_low_and_slow"):
                sc = load_scenarios()[sid]
                rep = MockRunner(scope, in_lab, kill, sleep=lambda s: None).run(sc)
                inc = eng.replay(IncidentAggregate.model_validate(to_aggregate(sc, rep, scope)))["incident"]
                assert inc["attack_family"] == sc.expected.family, sid
        finally:
            rt.close()


BANNED_MODULES = {"scapy", "socket", "subprocess", "requests", "httpx", "urllib", "http", "asyncio", "ssl",
                  "pty", "ctypes", "multiprocessing"}
BANNED_CALLS = {"system", "popen", "spawnl", "spawnv", "execv", "execl", "sendto", "connect", "send"}


def test_lab_package_contains_no_traffic_code():
    """v4.6.0 ships no traffic generation: lab/ may not import networking or process libraries."""
    for path in sorted((REPO / "lab").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert a.name.split(".")[0] not in BANNED_MODULES, f"{path.name} imports {a.name}"
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in BANNED_MODULES, f"{path.name} imports {node.module}"
            elif isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                assert name not in BANNED_CALLS, f"{path.name} calls {name}()"
