# -*- coding: utf-8 -*-
"""v5.0.0 citation checker logic (network mocked; the real check runs in CI)."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("check_citations", Path(__file__).resolve().parent.parent / "scripts" / "check_citations.py")
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)


def test_extract_urls_and_arxiv_and_skips_placeholders():
    text = ("See https://csrc.nist.gov/pubs/sp/800/61/r3/final. and arXiv:2301.01234v2, "
            "http://localhost:8000/app, https://example.com/x, https://<host>/y, http://192.0.2.1/ "
            "[link](https://attack.mitre.org/techniques/T1498/)")
    assert cc.extract(text) == ["https://csrc.nist.gov/pubs/sp/800/61/r3/final",
                                "https://attack.mitre.org/techniques/T1498/", "https://arxiv.org/abs/2301.01234"]


def test_verdicts():
    codes = {"https://a/ok": [200], "https://a/gone": [404], "https://a/bot": [403],
             "https://a/flaky": [503, 200], "https://a/down": [503, 503, 503]}
    calls = {k: iter(v) for k, v in codes.items()}
    res = cc.check(codes, fetch=lambda u: next(calls[u]), sleep=lambda s: None)
    assert res["https://a/ok"][0] == "OK" and res["https://a/gone"] == ("FAIL", "404")
    assert res["https://a/bot"][0] == "WARN" and res["https://a/flaky"][0] == "OK"
    assert res["https://a/down"] == ("FAIL", "503")


def test_connection_errors_fail():
    def boom(u):
        raise ConnectionError("dns")
    assert cc.check(["https://nope.invalid/"], fetch=boom, sleep=lambda s: None)["https://nope.invalid/"][0] == "FAIL"
