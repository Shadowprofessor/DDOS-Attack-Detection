# -*- coding: utf-8 -*-
"""
Central configuration package for DDoS Detection & Mitigation System.
"""
from src.config.loader import (
    load_config,
    get_config,
    get_environment_config,
    extract_env_flag,
    get_config_path,
    ConfigError,
)

__all__ = [
    "load_config",
    "get_config",
    "get_environment_config",
    "extract_env_flag",
    "get_config_path",
    "ConfigError",
]
