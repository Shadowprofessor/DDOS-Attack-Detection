# -*- coding: utf-8 -*-
"""
Tests for Deployment Packaging (Prompt 11).

Validates:
1. Environment configuration YAML files (development, staging, production)
2. Config loader interpolation and schema integrity
3. Docker Compose structure and validation
4. Helm chart manifests and zero-cloud-subscription defaults
5. Systemd unit files and security hardening directives
6. Graceful degradation without paid cloud subscriptions
"""
import os
import subprocess
from pathlib import Path
import pytest
import yaml

from src.config.loader import load_config, get_config_path
from src.mitigation.cloud_enforcers.cloudflare import CloudflareEnforcer
from src.mitigation.manager import get_manager

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_environment_configs_schema():
    """Verify that all environment configs are valid YAML and follow canonical schema."""
    config_dir = REPO_ROOT / "config" / "environments"
    expected_envs = ["development", "staging", "production"]

    for env in expected_envs:
        cfg_file = config_dir / f"{env}.yaml"
        assert cfg_file.is_file(), f"Missing config file for {env}"

        with open(cfg_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        assert data["environment"] == env
        assert "scoring_service" in data
        assert "controller" in data
        assert "reverse_proxy" in data
        assert "cloud_providers" in data

        # Condition 2: CLOUDFLARE_ZONE_ID dropped, auth keys are DDOS_API_KEYS / DDOS_ADMIN_KEYS
        assert "cloudflare" in data["cloud_providers"]
        assert "zone_id" not in data["cloud_providers"]["cloudflare"]
        assert "api_token" in data["cloud_providers"]["cloudflare"]
        assert "account_id" in data["cloud_providers"]["cloudflare"]

        auth = data["scoring_service"]["auth"]
        assert "DDOS_API_KEYS" in auth["api_keys"]
        assert "DDOS_ADMIN_KEYS" in auth["admin_keys"]


def test_config_loader_interpolation(monkeypatch):
    """Test that src/config/loader.py properly interpolates environment variables."""
    monkeypatch.setenv("DDOS_API_KEYS", "test_key_1,test_key_2")
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "acc_12345")

    cfg = load_config("development")
    assert cfg["environment"] == "development"
    assert cfg["scoring_service"]["auth"]["api_keys"] == "test_key_1,test_key_2"
    assert cfg["cloud_providers"]["cloudflare"]["account_id"] == "acc_12345"
    # Unset env should resolve to empty default
    assert cfg["cloud_providers"]["cloudflare"]["api_token"] == ""


def test_docker_compose_config_validation():
    """Validate docker-compose.yml structure and run 'docker compose config' if CLI is present."""
    compose_path = REPO_ROOT / "deploy" / "docker-compose.yml"
    assert compose_path.is_file(), "deploy/docker-compose.yml must exist"

    with open(compose_path, "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    services = compose_data.get("services", {})
    assert "scoring_service" in services
    assert "controller" in services
    assert "reverse_proxy" in services

    # Verify reverse proxy depends on scoring service
    assert "scoring_service" in services["reverse_proxy"]["depends_on"]

    # Verify scoring service health check is declared
    assert "healthcheck" in services["scoring_service"]

    # If docker compose CLI is installed, execute syntax verification
    try:
        proc = subprocess.run(
            ["docker", "compose", "-f", str(compose_path), "config"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        assert proc.returncode == 0, f"docker compose config failed: {proc.stderr}"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("docker compose CLI not found or timed out in environment")


def test_helm_chart_manifests():
    """Validate Helm chart metadata and defaults."""
    helm_dir = REPO_ROOT / "deploy" / "helm"
    chart_file = helm_dir / "Chart.yaml"
    values_file = helm_dir / "values.yaml"

    assert chart_file.is_file()
    assert values_file.is_file()

    with open(chart_file, "r", encoding="utf-8") as f:
        chart_data = yaml.safe_load(f)
    assert chart_data["name"] == "ddos-defense"
    assert chart_data["version"] == "3.0.0"

    with open(values_file, "r", encoding="utf-8") as f:
        values_data = yaml.safe_load(f)

    # Verify zero-paid-cloud subscription guarantee: default token is empty string
    assert values_data["secrets"]["cloudflare"]["apiToken"] == ""
    assert values_data["secrets"]["cloudflare"]["accountId"] == ""
    assert "zoneId" not in values_data["secrets"]["cloudflare"]

    # Verify template files exist
    templates_dir = helm_dir / "templates"
    for tmpl in [
        "_helpers.tpl",
        "secret.yaml",
        "configmap.yaml",
        "scoring-deployment.yaml",
        "scoring-service.yaml",
        "controller-deployment.yaml",
        "controller-service.yaml",
        "reverse-proxy-deployment.yaml",
        "reverse-proxy-service.yaml",
        "reverse-proxy-configmap.yaml",
    ]:
        assert (templates_dir / tmpl).is_file(), f"Missing template {tmpl}"


def test_systemd_unit_files():
    """Validate systemd service unit files and security hardening directives."""
    systemd_dir = REPO_ROOT / "deploy" / "systemd"
    scoring_svc = systemd_dir / "ddos-scoring.service"
    controller_svc = systemd_dir / "ddos-controller.service"
    env_example = systemd_dir / "ddos-defense.env.example"

    assert scoring_svc.is_file()
    assert controller_svc.is_file()
    assert env_example.is_file()

    scoring_text = scoring_svc.read_text(encoding="utf-8")
    assert "[Unit]" in scoring_text
    assert "[Service]" in scoring_text
    assert "[Install]" in scoring_text
    assert "NoNewPrivileges=true" in scoring_text
    assert "ProtectSystem=full" in scoring_text
    assert "ExecStart=" in scoring_text
    assert "EnvironmentFile=" in scoring_text

    controller_text = controller_svc.read_text(encoding="utf-8")
    assert "NoNewPrivileges=true" in controller_text
    assert "ExecStart=" in controller_text

    env_text = env_example.read_text(encoding="utf-8")
    assert "DDOS_API_KEYS=" in env_text
    assert "DDOS_ADMIN_KEYS=" in env_text
    assert "CLOUDFLARE_ZONE_ID" not in env_text


def test_graceful_degradation_without_cloud_credentials(monkeypatch):
    """
    Verify zero paid cloud subscription behavior:
    When CLOUDFLARE_API_TOKEN is unset, the enforcer operates in proposal mode,
    and attempting to execute returns a descriptive failure without raising an uncaught exception.
    """
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    monkeypatch.delenv("CLOUDFLARE_ACCOUNT_ID", raising=False)

    enforcer = CloudflareEnforcer(api_token="", account_id="")
    assert enforcer.api_token is None or enforcer.api_token == ""

    # Propose action
    action_id = enforcer.propose_action(
        attacker_ip="198.51.100.12",
        victim_ip="192.0.2.1",
        reason="Test flood with unconfigured cloud token",
    )
    assert action_id is not None

    mgr = get_manager()
    action = mgr.get_action(action_id)
    assert action is not None
    assert action["status"] == "PENDING"

    # Attempt to execute without credentials
    result = enforcer.execute(action)
    assert result["success"] is False
    assert "CLOUDFLARE_API_TOKEN not set" in result["executed"][0]["error"]
