"""v6.0.0 (live6): the bridge waits for the platform instead of exiting when it is not up yet."""
import sys

import scripts.live_bridge as lb


def test_bridge_waits_for_platform(monkeypatch, tmp_path, capsys):
    calls = {"n": 0}

    class FakeHttp:
        def __init__(self, *a, **k):
            pass

        def get(self, path):
            calls["n"] += 1
            return (200, {"status": "ok"}) if calls["n"] >= 3 else (0, None)

        def post(self, path, body=None):
            return 200, {}

    class FakeBridge:
        def __init__(self, *a, **k):
            self.log_path, self.stats = tmp_path / "log", {}

        def run(self, duration_s=None):
            pass

        def close(self):
            pass

    monkeypatch.setattr(lb, "RequestsHttp", FakeHttp)
    monkeypatch.setattr(lb, "Bridge", FakeBridge)
    monkeypatch.setattr(lb.time, "sleep", lambda s: None)
    monkeypatch.setenv("DDOS_LIVE_KEY", "k")
    monkeypatch.setattr(sys, "argv", ["live_bridge.py", str(tmp_path / "run")])
    lb.main()
    assert calls["n"] == 3
    assert "waiting for the platform" in capsys.readouterr().out
