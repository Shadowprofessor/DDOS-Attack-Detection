# -*- coding: utf-8 -*-
"""
Auth enforcement for the dashboard JSON/LLM endpoints (previously unauthenticated WIP):
/api/session-detection-summary, /api/campaigns, /api/chat.
"""
import pytest
from fastapi.testclient import TestClient

from src.api import scoring_service as api_module
from src.api.scoring_service import app

KEY = "scoring-key-test"


@pytest.fixture(autouse=True)
def with_key(monkeypatch):
    monkeypatch.setenv("DDOS_API_KEYS", KEY)
    orig = set(api_module.API_KEYS)
    api_module.API_KEYS.add(KEY)
    yield
    api_module.API_KEYS = orig


@pytest.mark.parametrize("method,path,payload", [
    ("get", "/api/session-detection-summary", None),
    ("get", "/api/campaigns", None),
    ("post", "/api/chat", {"message": "status?"}),
])
def test_endpoint_requires_api_key(method, path, payload):
    with TestClient(app) as client:
        # No key -> 401
        r = client.request(method, path, json=payload)
        assert r.status_code == 401, f"{path} should require auth, got {r.status_code}"
        # Valid key -> not 401 (200 or other non-auth status)
        r2 = client.request(method, path, json=payload, headers={"X-API-Key": KEY})
        assert r2.status_code != 401, f"{path} rejected a valid key: {r2.text[:120]}"
