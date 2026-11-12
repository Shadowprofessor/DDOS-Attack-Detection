# -*- coding: utf-8 -*-
"""v5.3.0: labelled training catalogue vs the canonical (DEV / held-out) catalogue, and run seeds."""
import random

import pytest

from lab.library import CATALOGS, LABELS, ScenarioError, load_scenarios, parse_scenario
from lab.safety import load_scope

MAIN, TRAIN = load_scenarios(CATALOGS["main"]), load_scenarios(CATALOGS["train"])


def _cfg(s):
    p = s.profile
    return (p.protocol, p.rate_pps, p.sources, p.dst_port, p.packet_size, p.slow_connections)


def test_training_variants_never_equal_a_held_out_configuration():
    assert not {_cfg(s) for s in TRAIN.values()} & {_cfg(s) for s in MAIN.values()}
    assert not set(TRAIN) & set(MAIN)


def test_every_training_class_has_two_variants_and_the_ood_probe_is_not_trained_on():
    from collections import Counter

    counts = Counter(s.label for s in TRAIN.values())
    assert set(counts) == set(LABELS) and all(n >= 2 for n in counts.values())
    assert MAIN["novel_ood_mix"].label is None  # the zero-day probe stays unseen by training
    assert all(s.label for k, s in MAIN.items() if k != "novel_ood_mix")


def test_training_variants_respect_the_lab_caps():
    scope = load_scope()
    for s in TRAIN.values():
        assert s.profile.rate_pps <= scope.caps.max_pps and s.profile.duration_s <= scope.caps.max_duration_s


def test_labels_are_validated():
    base = ("id: x_test\nname: test scenario\nattack: true\nmitre: [T1498.001]\ndescription: a test scenario here\n"
            "profile: {protocol: udp, rate_pps: 10, duration_s: 5, sources: 1, source_role: attacker}\n"
            "expected: {incident: true, family: other, layers: [L1]}\n")
    assert parse_scenario(base + "label: UDP\n").label == "UDP"
    with pytest.raises(ScenarioError):
        parse_scenario(base + "label: Made-Up\n")
    with pytest.raises(ScenarioError):
        parse_scenario(base + "label: Benign\n")  # an attack cannot be labelled Benign


def test_seed_changes_the_random_stream():
    from lab.traffic.generator import build_packet

    def ports(seed):
        rng = random.Random(seed)
        return [build_packet("tcp_syn", "10.99.0.100", "10.99.0.10", 443, 60, rng).sport for _ in range(5)]

    assert ports(1001) == ports(1001) and ports(1001) != ports(4004)
