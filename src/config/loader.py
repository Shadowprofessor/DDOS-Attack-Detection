# -*- coding: utf-8 -*-
"""
Centralized environment configuration loader with YAML and environment variable substitution.

Supports:
- Reading config/environments/*.yaml (lab, on-prem, cloud, development, staging, production, or custom paths)
- Command-line `--env <name_or_path>` flag parsing and stripping
- Interpolation of ${VAR:-default} and ${VAR} patterns from os.environ
- Strict schema validation (missing files, malformed YAML, missing required keys)
- Zero-paid default tolerance (unconfigured cloudflare credentials start cleanly in proposal-only mode)
"""
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

# Regex pattern for ${VAR:-default} or ${VAR}
ENV_PATTERN = re.compile(r"\$\{([A-Za-z0-9_]+)(?::-([^}]*))?\}")

# Default config directory: <workspace_root>/config/environments
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_DIR = WORKSPACE_ROOT / "config" / "environments"


class ConfigError(ValueError):
    """Raised when configuration validation or file loading fails."""
    pass


def extract_env_flag(argv: Optional[List[str]] = None, remove: bool = False) -> Optional[str]:
    """
    Extract the value of the `--env` flag from an argument list.

    Args:
        argv: List of command-line arguments (defaults to sys.argv if None).
        remove: If True, mutates the list to remove the `--env` flag and its value.

    Returns:
        The string value of the environment argument, or None if not present.
    """
    target = sys.argv if argv is None else argv
    env_val: Optional[str] = None
    indices_to_remove: List[int] = []

    i = 0
    while i < len(target):
        arg = target[i]
        if arg == "--env":
            if i + 1 < len(target):
                env_val = target[i + 1]
                indices_to_remove.extend([i, i + 1])
                i += 2
                continue
            else:
                raise ConfigError("Flag '--env' requires a configuration name or file path argument.")
        elif arg.startswith("--env="):
            env_val = arg.split("=", 1)[1]
            indices_to_remove.append(i)
            i += 1
            continue
        i += 1

    if remove and indices_to_remove:
        for idx in sorted(indices_to_remove, reverse=True):
            del target[idx]

    return env_val


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

    Priority:
      1. Explicit `env_or_path` argument
      2. `--env` command-line flag
      3. `DDOS_ENV` environment variable
      4. Default to 'lab' (or 'development' if lab does not exist)
    """
    if not env_or_path:
        env_or_path = extract_env_flag(remove=False)
    if not env_or_path:
        env_or_path = os.environ.get("DDOS_ENV", "lab")

    raw_path = Path(env_or_path)
    if raw_path.is_file() or str(env_or_path).endswith((".yaml", ".yml")):
        if raw_path.is_file():
            return raw_path.resolve()
        raise FileNotFoundError(f"Configuration file not found at path: {raw_path}")

    env_name = str(env_or_path).lower().strip()

    # 1. Search in local workspace config/environments
    candidate = DEFAULT_CONFIG_DIR / f"{env_name}.yaml"
    if candidate.is_file():
        return candidate

    # 2. Container standard fallback
    container_candidate = Path("/app/config/environments") / f"{env_name}.yaml"
    if container_candidate.is_file():
        return container_candidate

    # 3. Bare-metal system standard fallback
    system_candidate = Path("/etc/ddos-defense/environments") / f"{env_name}.yaml"
    if system_candidate.is_file():
        return system_candidate

    raise FileNotFoundError(
        f"Environment configuration file not found for environment '{env_name}'. "
        f"Searched: {candidate}, {container_candidate}, {system_candidate}"
    )


# Required key definitions for strict schema validation
REQUIRED_KEYS: List[str] = [
    "environment",
    "capture_backend",
    "capture_backend.type",
    "models",
    "models.hierarchical",
    "models.hierarchical.model_dir",
    "models.ensemble",
    "models.ensemble.rf_path",
    "models.ensemble.xgb_path",
    "models.ensemble.sequence_classifier_path",
    "models.ensemble.ensemble_bundle_path",
    "scoring_service",
    "scoring_service.log_level",
    "scoring_service.rate_limit",
    "scoring_service.rate_limit.window_seconds",
    "scoring_service.rate_limit.max_requests",
    "scoring_service.rate_limit.max_batch_size",
    "scoring_service.auth",
    "scoring_service.auth.api_keys",
    "scoring_service.auth.admin_keys",
    "llm",
    "llm.endpoint",
    "llm.model",
    "cloud_providers",
    "cloud_providers.cloudflare",
]


def _validate_schema(cfg: Dict[str, Any]) -> None:
    """Validate that all required sections and keys exist in the configuration."""
    if not isinstance(cfg, dict):
        raise ConfigError("Configuration root must be a YAML dictionary/mapping.")

    for path in REQUIRED_KEYS:
        parts = path.split(".")
        curr: Any = cfg
        for part in parts:
            if not isinstance(curr, dict) or part not in curr:
                raise ConfigError(f"Missing required configuration key: '{path}'")
            curr = curr[part]


def load_config(env_or_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load, parse, interpolate, and validate an environment configuration file.

    Args:
        env_or_path: Environment name (e.g. 'lab', 'on-prem', 'cloud') or path to YAML file.

    Returns:
        Interpolated dictionary of configuration values.

    Raises:
        FileNotFoundError: If the configuration file cannot be found.
        ValueError (or ConfigError): If YAML is malformed or required keys are missing.
    """
    path = get_config_path(env_or_path)

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"Malformed YAML in configuration file '{path}': {e}") from e

    if raw_data is None:
        raw_data = {}

    interpolated = _interpolate_value(raw_data)
    _validate_schema(interpolated)
    return interpolated


_cached_config: Optional[Dict[str, Any]] = None


def get_config(env_or_path: Optional[str] = None, reload: bool = False) -> Dict[str, Any]:
    """Retrieve or cache the active environment configuration."""
    global _cached_config
    if _cached_config is None or reload:
        _cached_config = load_config(env_or_path)
    return _cached_config


def get_environment_config(env_or_path: Optional[str] = None) -> Dict[str, Any]:
    """Alias for load_config (Prompt 11 compatibility)."""
    return load_config(env_or_path)
