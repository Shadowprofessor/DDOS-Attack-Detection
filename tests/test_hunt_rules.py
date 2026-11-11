# -*- coding: utf-8 -*-
"""v4.7.0 hunt rules: every rule has positive and negative cases."""
from src.hunt.rules import FlowRecord, LowRateReflectionRule, SlowReadRule, run_hunts

V = "10.99.0.10"


def refl(n_src, pps_each, sport=123, window=60.0):
    return [FlowRecord(src=f"10.20.{i // 250}.{i % 250 + 1}", dst=V, sport=sport, dport=40000 + i, proto=17,
                       start=0.0, end=window - 1, packets=int(pps_each * window), bytes=468.0 * pps_each * window)
            for i in range(n_src)]


def slow_read(n_src, win=512, dur=60.0, bwd=50.0):
    return [FlowRecord(src=f"10.30.0.{i + 1}", dst=V, sport=50000 + i, dport=80, proto=6, start=0.0, end=dur,
                       packets=40, bytes=bwd * dur + 600, fwd_bytes=600, bwd_bytes=bwd * dur, init_fwd_win=win)
            for i in range(n_src)]


class TestH1LowRateReflection:
    def test_many_low_rate_reflectors_fire(self):
        out = LowRateReflectionRule().evaluate(refl(200, 5))  # 200 x 5 pps = 1000 pps, each under 20
        assert len(out) == 1 and out[0].victim == V and out[0].evidence["reflectors"] == 200

    def test_single_high_rate_reflector_is_left_to_L1(self):
        assert LowRateReflectionRule().evaluate(refl(1, 800)) == []

    def test_many_reflectors_but_low_total_is_normal_dns(self):
        assert LowRateReflectionRule().evaluate(refl(100, 0.5, sport=53)) == []  # 50 pps of DNS answers

    def test_non_reflector_ports_ignored(self):
        assert LowRateReflectionRule().evaluate(refl(200, 5, sport=40001)) == []

    def test_one_loud_source_among_many_breaks_the_low_rate_pattern(self):
        assert LowRateReflectionRule().evaluate(refl(100, 5) + refl(1, 500)) == []


class TestH2SlowRead:
    def test_distributed_slow_readers_fire(self):
        out = SlowReadRule().evaluate(slow_read(15))
        assert len(out) == 1 and out[0].evidence["sources"] == 15

    def test_normal_windows_do_not_fire(self):
        assert SlowReadRule().evaluate(slow_read(30, win=64240)) == []

    def test_short_or_fast_downloads_do_not_fire(self):
        assert SlowReadRule().evaluate(slow_read(30, dur=5.0)) == []
        assert SlowReadRule().evaluate(slow_read(30, bwd=50_000.0)) == []

    def test_few_sources_do_not_fire(self):
        assert SlowReadRule().evaluate(slow_read(5)) == []

    def test_unknown_window_never_fires(self):
        assert SlowReadRule().evaluate(slow_read(30, win=None)) == []  # type: ignore[arg-type]


def test_run_hunts_keys():
    out = run_hunts(refl(200, 5) + slow_read(15))
    assert {k: len(v) for k, v in out.items()} == {"H1_low_rate_distributed_reflection": 1, "H2_distributed_slow_read": 1}
