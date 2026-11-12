# -*- coding: utf-8 -*-
"""v5.3.0 pre-fixes: the offline chat never invents a number; command names are checked."""
import ast
import inspect
import re

import src.agent.soc_chat_assistant as chat
from src.agent.command_check import annotate, check, repo_settings, sysctl_ok


def test_no_numeric_defaults_anywhere_in_the_chat_module():
    """`d.get(k, 4)` or `x or 0` would print a number nobody measured."""
    tree = ast.parse(inspect.getsource(chat))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "get" and len(node.args) == 2:
            d = node.args[1]
            assert not (isinstance(d, ast.Constant) and isinstance(d.value, (int, float)) and not isinstance(d.value, bool)), \
                f"numeric default in .get() at line {node.lineno}"
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            last = node.values[-1]
            assert not (isinstance(last, ast.Constant) and isinstance(last.value, (int, float)) and not isinstance(last.value, bool)), \
                f"'or <number>' default at line {node.lineno}"


def test_fallback_numbers_all_come_from_the_data_or_the_static_guidance():
    ctx = {"live_open_alerts": [{"dst": "10.99.0.10", "status": "CRITICAL", "vector": "Rate-Based SYN Flood"}],  # no pps
           "pending_actions_count": 1,
           "pending_actions": [{"action_id": "a1b2", "action_type": "BLOCK", "attacker_ip": "10.99.0.105",
                                "victim_ip": "10.99.0.10"}]}  # no confidence
    text = chat.SocChatAssistant()._fallback("block the syn flood", ctx, True, "no NVIDIA_API_KEY configured")
    assert "peak unknown" in text and "(confidence unknown)" in text
    allowed = set(re.findall(r"\d+", repr(ctx))) | set(re.findall(r"\d+", repr(chat.KB) + chat.NOTICE))
    invented = set(re.findall(r"\d+", text)) - allowed
    assert not invented, f"numbers not in the data or the guidance: {invented}"


def test_real_sysctl_keys_pass_and_invented_ones_are_flagged():
    assert sysctl_ok("net.ipv4.tcp_syncookies") and sysctl_ok("net.ipv4.conf.all.rp_filter")
    assert sysctl_ok("net.core.somaxconn") and sysctl_ok("net.netfilter.nf_conntrack_max")
    assert not sysctl_ok("net.ipv4.tcp_syn_retries2")  # the name Lightning invented in v5.2.0
    text, res = annotate("Run `sysctl -w net.ipv4.tcp_syncookies=1` and set net.ipv4.tcp_syn_retries2=3.")
    assert res == {"verified": ["net.ipv4.tcp_syncookies"], "unverified": ["net.ipv4.tcp_syn_retries2"]}
    assert "Unverified — check before running: `net.ipv4.tcp_syn_retries2`" in text


def test_repo_settings_and_script_flags_are_checked_against_the_code():
    assert "DDOS_LLM_ESCALATE_ULTRA" in repo_settings() and "NEMOTRON_MODEL" in repo_settings()
    res = check("export DDOS_LLM_ESCALATE_ULTRA=true DDOS_TURBO_MODE=1\n"
                "python scripts/live_bridge.py data/lab_runs/live1 --reset --turbo\n"
                "sudo python3 -m lab.traffic.orchestrate --out x --gap 15 --ovs-poll")
    assert "DDOS_LLM_ESCALATE_ULTRA" in res["verified"] and "DDOS_TURBO_MODE" in res["unverified"]
    assert "scripts/live_bridge.py --reset" in res["verified"] and "scripts/live_bridge.py --turbo" in res["unverified"]
    assert "-m lab.traffic.orchestrate --gap" in res["verified"] and "-m lab.traffic.orchestrate --ovs-poll" in res["verified"]
    assert check("python scripts/nope.py --x")["unverified"] == ["scripts/nope.py"]


def test_text_without_names_is_unchanged():
    assert annotate("Rate-limit at the edge.") == ("Rate-limit at the edge.", {"verified": [], "unverified": []})
