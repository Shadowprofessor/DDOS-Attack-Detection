"""v6.1.0: repo hygiene files exist, CITATION.cff is valid and tracks the latest release, LICENSE untouched."""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def test_hygiene_files_exist():
    for f in ("CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "CITATION.cff", "LICENSE",
              ".github/pull_request_template.md", ".github/ISSUE_TEMPLATE/bug_report.yml",
              ".github/ISSUE_TEMPLATE/detection_report.yml", ".github/ISSUE_TEMPLATE/config.yml"):
        assert (ROOT / f).is_file(), f


def test_citation_cff_is_valid_and_matches_the_latest_release():
    c = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    for k in ("cff-version", "message", "title", "authors", "version", "date-released", "license"):
        assert c.get(k), k
    assert c["authors"][0]["family-names"] == "Sharma" and c["authors"][0]["affiliation"] == "NIIT University"
    latest = re.search(r"^## \[(\d+\.\d+\.\d+)\] — (\d{4}-\d{2}-\d{2})", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
    assert (str(c["version"]), str(c["date-released"])) == (latest.group(1), latest.group(2))


def test_license_is_unchanged_mit():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("MIT License") and "Copyright (c) 2026 Sachit Sharma" in text
    assert yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))["license"] == "MIT"
