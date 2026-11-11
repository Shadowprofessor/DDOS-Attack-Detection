# -*- coding: utf-8 -*-
"""v5.1.0 analyst model selection: Lightning primary, NEMOTRON_MODEL override, optional Ultra escalation."""
import pytest

from src.agent.llm_client import LIGHTNING_MODEL, ULTRA_MODEL, LLMConfig
from src.agent.schemas import IncidentAggregate
from src.agent.threat_analyst import ThreatAnalyst

SEV5 = IncidentAggregate(incident_id="m1", window_start=0, pps=2_000_000.0, protocol_mix={"tcp": 0.98},
                         tcp_flag_ratios={"syn": 0.95}, top_src_ips=[{"key": "10.0.0.9", "share": 0.2}], dst_ips=["10.0.0.4"])
SEV2 = IncidentAggregate(incident_id="m2", window_start=0, pps=5_000.0, protocol_mix={"tcp": 0.98},
                         tcp_flag_ratios={"syn": 0.95}, top_src_ips=[{"key": "10.0.0.9", "share": 0.2}], dst_ips=["10.0.0.4"])


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for v in ("DDOS_LLM_MODELS", "NEMOTRON_MODEL", "DDOS_LLM_ESCALATE_ULTRA", "DDOS_LLM_ESCALATION_MODEL"):
        monkeypatch.delenv(v, raising=False)


def test_default_primary_is_lightning():
    assert LIGHTNING_MODEL == "nvidia/nemotron-3.5-lightning-30b-a3b"
    cfg = LLMConfig.from_env({"models": ""})  # YAML default is now empty
    assert cfg.models == [LIGHTNING_MODEL] and cfg.escalate_severity5 is False


def test_nemotron_model_env_overrides_primary(monkeypatch):
    monkeypatch.setenv("NEMOTRON_MODEL", "nvidia/nemotron-3-super-120b-a12b")
    assert LLMConfig.from_env({"models": ""}).models == ["nvidia/nemotron-3-super-120b-a12b"]


def test_full_chain_override_still_supported(monkeypatch):
    monkeypatch.setenv("DDOS_LLM_MODELS", f"{LIGHTNING_MODEL},{ULTRA_MODEL}")
    assert LLMConfig.from_env({}).models == [LIGHTNING_MODEL, ULTRA_MODEL]


class _Client:
    def __init__(self, cfg):
        self.config = cfg
        self.available = False


def test_escalation_off_by_default_keeps_lightning_first():
    a = ThreatAnalyst(client=_Client(LLMConfig.from_env({"models": ""})))
    assert a.model_chain(SEV5) == [LIGHTNING_MODEL]


def test_escalation_on_puts_ultra_first_only_for_severity5(monkeypatch):
    monkeypatch.setenv("DDOS_LLM_ESCALATE_ULTRA", "true")
    a = ThreatAnalyst(client=_Client(LLMConfig.from_env({"models": ""})))
    assert a.model_chain(SEV5) == [ULTRA_MODEL, LIGHTNING_MODEL]
    assert a.model_chain(SEV2) == [LIGHTNING_MODEL]


def test_rule_fallback_without_key():
    a = ThreatAnalyst(client=_Client(LLMConfig.from_env({"models": ""})))
    r = a.analyze(SEV5)
    assert r.source == "rules" and r.degraded_reason == "no_api_key"


class _Resp:
    status_code = 200
    text = ""

    def __init__(self, data):
        self._d = data

    def json(self):
        return self._d


def _agent(monkeypatch, data, sent):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test-key-12345")
    import src.agent.nemotron_agent as na

    def fake_post(url, headers=None, data=None, timeout=None):
        import json as _j
        sent.append(_j.loads(data))
        return _Resp(response)

    response = data
    monkeypatch.setattr("requests.post", fake_post)  # the agent imports requests inside the call
    return na.NemotronAgent()


def test_legacy_agent_disables_thinking_and_survives_null_content(monkeypatch):
    sent = []
    agent = _agent(monkeypatch, {"choices": [{"message": {"content": None}, "finish_reason": "length"}]}, sent)
    parsed, raw = agent._call_nemotron_api("telemetry")
    assert parsed is None and "finish_reason=length" in raw          # clean degrade, no TypeError
    assert sent[0]["chat_template_kwargs"] == {"enable_thinking": False}
    assert sent[0]["model"] == LIGHTNING_MODEL
