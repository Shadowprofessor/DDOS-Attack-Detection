# -*- coding: utf-8 -*-
"""
M0 observability tests: Prometheus /metrics endpoint + JSON log formatter.
"""
import json
import logging

from fastapi.testclient import TestClient

from src.api.scoring_service import app
from src.obs import metrics as obs_metrics
from src.obs.logging import JsonFormatter


def test_metrics_registry_counter_and_gauge_render():
    reg = obs_metrics.Registry()
    c = reg.counter("unit_test_total", "help")
    c.inc(endpoint="/x", status="200")
    c.inc(endpoint="/x", status="200")
    g = reg.gauge("unit_test_gauge", "help")
    g.set(3.0)
    out = reg.render()
    assert "# TYPE unit_test_total counter" in out
    assert 'unit_test_total{endpoint="/x",status="200"} 2.0' in out
    assert "unit_test_gauge 3.0" in out


def test_metrics_endpoint_scrapes(monkeypatch):
    with TestClient(app) as client:
        resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    assert "ddos_http_requests_total" in body
    assert "ddos_pending_actions" in body
    assert "# TYPE ddos_http_requests_total counter" in body


def test_metrics_route_label_bounds_cardinality():
    """1,000 requests to distinct unmatched paths must collapse to the single 'unmatched'
    endpoint label, not create ~1,000 per-path series."""
    import re

    with TestClient(app) as client:
        for i in range(1000):
            client.get(f"/no-such-path-{i}")
        body = client.get("/metrics").text

    endpoints = set(re.findall(r'ddos_http_requests_total\{[^}]*endpoint="([^"]*)"', body))
    # Random paths collapse to one 'unmatched' endpoint value...
    assert "unmatched" in endpoints
    # ...and none of them leak in as their own label.
    assert not any("no-such-path" in e for e in endpoints)
    # Total distinct endpoint labels stays tiny despite 1,000 distinct URLs.
    assert len(endpoints) < 50, f"cardinality explosion: {len(endpoints)} endpoint labels"


def test_json_formatter_emits_valid_json():
    rec = logging.LogRecord("t", logging.INFO, __file__, 1, "hello %s", ("world",), None)
    rec.incident_id = "inc-123"
    line = JsonFormatter().format(rec)
    obj = json.loads(line)
    assert obj["level"] == "INFO"
    assert obj["message"] == "hello world"
    assert obj["logger"] == "t"
    assert obj["incident_id"] == "inc-123"
    assert "ts" in obj
