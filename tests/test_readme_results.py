"""v6.1.0: the README / REPORT results block must match the results files (no hand-typed numbers)."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _mod():
    spec = importlib.util.spec_from_file_location("readme_results", ROOT / "scripts" / "readme_results.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_readme_and_report_results_match_the_results_files():
    m = _mod()
    block, _ = m.build()
    for name in ("README.md", "REPORT.md"):
        text = (ROOT / name).read_text(encoding="utf-8").replace("\r\n", "\n")
        assert m.splice(text, block) == text, f"{name}: results drifted; run python scripts/readme_results.py"


def test_headline_numbers_come_from_data_and_keep_the_recorded_errors():
    _, h = _mod().build()
    assert h["heldout_detected"] == "10/10" and h["heldout_false_alarms"] == "0/2"
    assert "median" in h["live_mttd"] and h["mttc"] != "not reached"
    assert h["udp_misnamed"].split(" of ")[0] != "0"  # the recorded live UDP -> "SYN flood" error is reported


def test_every_exclusion_is_written_down_with_a_reason():
    import json

    ann = json.loads((ROOT / "docs/eval/live/annotations.json").read_text(encoding="utf-8"))
    for section in ("exclude_mttd", "exclude_mttc", "lost_runs"):
        for key, why in ann[section].items():
            assert len(why) > 20, key
