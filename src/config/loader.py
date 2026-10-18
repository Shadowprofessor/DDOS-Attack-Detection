# -*- coding: utf-8 -*-
"""
Environment configuration loader with YAML and environment variable substitution.

Supports:
- Reading config/environments/*.yaml (development, staging, production)
- Interpolation of ${VAR:-default} and ${VAR} patterns from os.environ
- Fallback paths for containerized (/app/config) and bare-metal environments
"""
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional
import yaml

# Regex pattern for ${VAR:-default} or ${VAR}
ENV_PATTERN = re.compile(r"\$\{([A-Za-z0-9_]+)(?::-([^}]*))?\}")

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config" / "environments"


def _interpolate_value(val: Any) -> Any:
    """Recursively replace environment variable placeholders in config values."""
    if isinstance(val, str):
        def _replace(match: re.Match) -> str:
            var_name = match.group(1)
            default_val = match.group(2) if match.group(2) is not None else ""
            return os.environ.get(var_name, default_val)

        return ENV_PATTERN.sub(_replace, val)
    elif isinstance(val, dict):
        return {k: _interpolate_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_interpolate_value(item) for item in val]
    return val


def get_config_path(env_or_path: Optional[str] = None) -> Path:
    """
    Resolve the path to the environment configuration YAML file.
    """
    if env_or_path and (Path(env_or_path).is_file() or str(env_or_path).endswith((".yaml", ".yml"))):
        return Path(env_or_path).resolve()

    env_name = env_or_path or os.environ.get("DDOS_ENV", "development").lower()
    
    # Try local workspace directory
    candidate = DEFAULT_CONFIG_DIR / f"{env_name}.yaml"
    if candidate.is_file():
        return candidate

    # Try container default /app/config/environments
    container_candidate = Path("/app/config/environments") / f"{env_name}.yaml"
    if container_candidate.is_file():
        return container_candidate

    # Try /etc/ddos-defense/environments
    system_candidate = Path("/etc/ddos-defense/environments") / f"{env_name}.yaml"
    if system_candidate.is_file():
        return system_candidate

    raise FileNotFoundError(
        f"Environment configuration file not found for environment '{env_name}'. "
        f"Looked in: {candidate}, {container_candidate}, {system_candidate}"
    )


def load_config(env_or_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load and parse configuration YAML with environment variable substitution.
    """
    path = get_config_path(env_or_path)
    with open(path, "r", encoding="utf-8") as f:
        raw_data = yaml.safe_load(f) or {}

    return _interpolate_value(raw_data)


def get_environment_config(env_or_path: Optional[str] = None) -> Dict[str, Any]:
    """Alias for load_config."""
    return load_config(env_or_path)
