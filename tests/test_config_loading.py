# -*- coding: utf-8 -*-
"""
Tests for centralized environment configuration loader (src/config/loader.py).

Verifies:
- Standard environment templates (lab.yaml, on-prem.yaml, cloud.yaml) load cleanly
- Strict schema validation:
    - Missing config file raises FileNotFoundError
    - Malformed YAML raises ConfigError / ValueError
    - Missing required configuration keys raises ConfigError / ValueError with key name
- Lab environment starts cleanly with zero paid subscriptions (CLOUDFLARE_API_TOKEN unset)
- CLI --env argument extraction and stripping for Ryu and scoring service
- Dynamic environment variable interpolation (${VAR:-default})
"""
import os
import sys
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from src.config.loader import load_config, get_config_path, extract_env_flag, ConfigError
from src.mitigation.cloud_enforcers.cloudflare import CloudflareEnforcer
from src.api.scoring_service import app


def test_load_all_standard_environments():
    """Verify lab.yaml, on-prem.yaml, and cloud.yaml load and pass strict validation."""
    for env_name in ["lab", "on-prem", "cloud"]:
        cfg = load_config(env_name)
        assert cfg["environment"] == env_name
        assert "capture_backend" in cfg
        assert "models" in cfg
        assert "hierarchical" in cfg["models"]
        assert "ensemble" in cfg["models"]
        assert "scoring_service" in cfg
        assert "rate_limit" in cfg["scoring_service"]
        assert "auth" in cfg["scoring_service"]
        assert "llm" in cfg
        assert "cloud_providers" in cfg
        assert "cloudflare" in cfg["cloud_providers"]

    # Verify environment-specific backend configurations
    lab_cfg = load_config("lab")
    assert lab_cfg["capture_backend"]["type"] == "libpcap"

    onprem_cfg = load_config("on-prem")
    assert onprem_cfg["capture_backend"]["type"] == "ebpf"
    assert onprem_cfg["capture_backend"]["ebpf"]["fallback_to_skb"] is True
    assert onprem_cfg["capture_backend"]["ebpf"]["deployment_mode"] == "host_ingress"

    cloud_cfg = load_config("cloud")
    assert cloud_cfg["capture_backend"]["type"] == "cloud_flow_log"
    assert cloud_cfg["capture_backend"]["cloud_flow_log"]["provider"] == "aws"


def test_missing_config_file_raises():
    """Assert that requesting a non-existent environment or file path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_config("nonexistent_environment_test_999")

    with pytest.raises(FileNotFoundError):
        load_config("/tmp/definitely_not_existing_config.yaml")


def test_malformed_yaml_raises(tmp_path: Path):
    """Assert that a YAML file with syntax errors raises ConfigError / ValueError."""
    bad_yaml = tmp_path / "malformed.yaml"
    bad_yaml.write_text("environment: [unclosed list\nscoring_service: {", encoding="utf-8")

    with pytest.raises((ValueError, ConfigError)):
        load_config(str(bad_yaml))


def test_missing_required_key_raises(tmp_path: Path):
    """Assert that a configuration missing a required key raises ConfigError naming the key."""
    # Incomplete YAML missing 'capture_backend'
    incomplete_yaml = tmp_path / "incomplete.yaml"
    incomplete_yaml.write_text(
        """
environment: "incomplete_test"
models:
  hierarchical:
    model_dir: "src/models"
  ensemble:
    rf_path: "models/cicddos2019_rf.pkl"
    xgb_path: "models/cicddos2019_xgboost.pkl"
    sequence_classifier_path: "models/sequence_classifier_best.pt"
    ensemble_bundle_path: "models/ensemble_weights.joblib"
scoring_service:
  log_level: "info"
  rate_limit:
    window_seconds: 60
    max_requests: 120
    max_batch_size: 1000
  auth:
    api_keys: ""
    admin_keys: ""
llm:
  endpoint: "https://openrouter.ai/api/v1/chat/completions"
  model: "nvidia/nemotron-3-ultra-550b-a55b:free"
cloud_providers:
  cloudflare:
    api_token: ""
    account_id: ""
""",
        encoding="utf-8",
    )

    with pytest.raises((ValueError, ConfigError)) as exc_info:
        load_config(str(incomplete_yaml))
    assert "capture_backend" in str(exc_info.value)


def test_lab_environment_clean_start_without_cloudflare(monkeypatch):
    """Verify that lab config starts cleanly with no CLOUDFLARE_API_TOKEN set (mocked-only default)."""
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    monkeypatch.delenv("CLOUDFLARE_ACCOUNT_ID", raising=False)

    cfg = load_config("lab")
    cf_token = cfg["cloud_providers"]["cloudflare"]["api_token"]
    assert cf_token == "" or cf_token is None

    # CloudflareEnforcer should initialize cleanly without throwing an exception
    enforcer = CloudflareEnforcer(api_token=cf_token, account_id=cfg["cloud_providers"]["cloudflare"]["account_id"])
    assert enforcer.api_token is None or enforcer.api_token == ""

    # Ensure proposal works in proposal-only mode
    action_id = enforcer.propose_action(
        attacker_ip="192.168.1.100",
        victim_ip="10.0.0.1",
        reason="Test proposal under zero-paid subscription",
    )
    assert action_id is not None
    from src.mitigation.manager import get_manager
    action = get_manager().get_action(action_id)
    assert action is not None
    assert action["action_type"] == "cloudflare_scrub"
    assert action["status"] == "PENDING"

    # Verify scoring service health check passes
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


def test_env_flag_extraction_and_stripping():
    """Verify extract_env_flag handles both '--env val' and '--env=val' and strips them when requested."""
    # Test --env <val>
    argv1 = ["python", "run_ryu.py", "--env", "on-prem", "Codes/controller/controller.py"]
    val1 = extract_env_flag(argv1, remove=True)
    assert val1 == "on-prem"
    assert argv1 == ["python", "run_ryu.py", "Codes/controller/controller.py"]

    # Test --env=<val>
    argv2 = ["python", "run_ryu.py", "--env=cloud", "--verbose"]
    val2 = extract_env_flag(argv2, remove=True)
    assert val2 == "cloud"
    assert argv2 == ["python", "run_ryu.py", "--verbose"]

    # Test without removal
    argv3 = ["python", "--env", "lab"]
    val3 = extract_env_flag(argv3, remove=False)
    assert val3 == "lab"
    assert len(argv3) == 3

    # Test missing value
    with pytest.raises(ConfigError):
        extract_env_flag(["python", "--env"])


def test_environment_variable_interpolation(monkeypatch, tmp_path: Path):
    """Verify ${VAR:-default} and ${VAR} patterns are substituted correctly from os.environ."""
    monkeypatch.setenv("TEST_CUSTOM_LIMIT", "7777")
    monkeypatch.delenv("UNSET_TEST_VAR", raising=False)

    template = tmp_path / "interp.yaml"
    template.write_text(
        """
environment: "interpolation_test"
capture_backend:
  type: "libpcap"
models:
  hierarchical:
    model_dir: "src/models"
  ensemble:
    rf_path: "models/cicddos2019_rf.pkl"
    xgb_path: "models/cicddos2019_xgboost.pkl"
    sequence_classifier_path: "models/sequence_classifier_best.pt"
    ensemble_bundle_path: "models/ensemble_weights.joblib"
scoring_service:
  log_level: "info"
  rate_limit:
    window_seconds: 60
    max_requests: "${TEST_CUSTOM_LIMIT:-120}"
    max_batch_size: "${UNSET_TEST_VAR:-500}"
  auth:
    api_keys: ""
    admin_keys: ""
llm:
  endpoint: "https://openrouter.ai/api/v1/chat/completions"
  model: "nvidia/nemotron-3-ultra-550b-a55b:free"
cloud_providers:
  cloudflare:
    api_token: ""
    account_id: ""
""",
        encoding="utf-8",
    )

    cfg = load_config(str(template))
    assert cfg["scoring_service"]["rate_limit"]["max_requests"] == "7777"
    assert cfg["scoring_service"]["rate_limit"]["max_batch_size"] == "500"
