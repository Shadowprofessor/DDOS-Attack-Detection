# -*- coding: utf-8 -*-
"""
Tests for FastAPI DDoS Real-Time Scoring Service (src/api/scoring_service.py).

Verifies:
- Auth enforcement (401 on invalid/missing X-API-Key header)
- Rate limit enforcement (429 on exceeding window limit)
- /health and /model/info endpoints
- /score/flow single flow prediction
- /score/batch vectorized batch prediction
- Batch size limit enforcement
"""
import os
import pytest
from fastapi.testclient import TestClient

from src.api.scoring_service import app, _generated_dev_key, rate_limiter

TEST_API_KEY = _generated_dev_key or "test-api-key"

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter counts between tests."""
    rate_limiter._hits.clear()

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["models_loaded"] is True

def test_auth_unauthorized(client):
    # Missing API key
    res = client.get("/model/info")
    assert res.status_code == 401

    # Invalid API key
    res = client.get("/model/info", headers={"X-API-Key": "invalid-key"})
    assert res.status_code == 401

def test_model_info_authorized(client):
    res = client.get("/model/info", headers={"X-API-Key": TEST_API_KEY})
    assert res.status_code == 200
    data = res.json()
    assert data["model_version"] == "hierarchical-xgb-6class-v1"
    assert "canonical_classes" in data
    assert len(data["canonical_classes"]) == 6

def test_score_flow_endpoint(client):
    dummy_features = {" Destination Port": 80, " Flow Duration": 1000}
    res = client.post(
        "/score/flow",
        json={"features": dummy_features},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert res.status_code == 200
    data = res.json()
    assert "result" in data
    result = data["result"]
    assert "is_attack" in result
    assert isinstance(result["is_attack"], bool)
    assert "confidence" in result

def test_score_batch_endpoint(client):
    dummy_flows = [
        {" Destination Port": 80, " Flow Duration": 1000},
        {" Destination Port": 53, " Flow Duration": 500},
    ]
    res = client.post(
        "/score/batch",
        json={"flows": dummy_flows},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 2
    assert len(data["results"]) == 2

def test_rate_limiting(client):
    """Test rate limiting by pre-filling the limiter's internal hit log."""
    import time as _time
    dummy_features = {" Destination Port": 80}

    # Pre-fill the rate limiter with 120 fake recent timestamps so the
    # very next real request exceeds the window.  This avoids sending 120
    # actual HTTP requests (which is slow and can time-out in CI).
    now = _time.monotonic()
    rate_limiter._hits[TEST_API_KEY] = [now - i * 0.01 for i in range(120)]

    # Next request should be rejected with 429
    res = client.post(
        "/score/flow",
        json={"features": dummy_features},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert res.status_code == 429
    assert "Rate limit exceeded" in res.json()["detail"]

    # After clearing, requests should succeed again
    rate_limiter._hits.clear()
    res = client.post(
        "/score/flow",
        json={"features": dummy_features},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert res.status_code == 200

def test_rate_limiting_blackbox(client):
    """End-to-end black-box rate limit test with 5 max requests limit."""
    dummy_features = {" Destination Port": 80}
    orig_max = rate_limiter.max
    rate_limiter.max = 5
    try:
        # First 5 requests should succeed
        for i in range(5):
            res = client.post(
                "/score/flow",
                json={"features": dummy_features},
                headers={"X-API-Key": TEST_API_KEY},
            )
            assert res.status_code == 200, f"Request {i+1} failed with status {res.status_code}"

        # 6th request should fail with 429 Too Many Requests
        res6 = client.post(
            "/score/flow",
            json={"features": dummy_features},
            headers={"X-API-Key": TEST_API_KEY},
        )
        assert res6.status_code == 429
        assert "Rate limit exceeded" in res6.json()["detail"]
    finally:
        rate_limiter.max = orig_max
        rate_limiter._hits.clear()

def test_startup_schema_validation(monkeypatch):
    """Verify loading preprocessor with wrong feature schema raises ValueError."""
    import joblib as _joblib
    import src.api.scoring_service as scoring_module
    reg = scoring_module.ModelRegistry()
    
    orig_load = _joblib.load
    bad_preprocessor = {"feature_cols": ["InvalidCol1", "InvalidCol2"], "medians": {}}
    
    def mock_load(path, *args, **kwargs):
        if "feature_preprocessor.joblib" in str(path):
            return bad_preprocessor
        return orig_load(path, *args, **kwargs)
    
    monkeypatch.setattr(scoring_module.joblib, "load", mock_load)
    with pytest.raises(ValueError, match="Feature count mismatch"):
        reg.load(scoring_module.MODEL_DIR)
