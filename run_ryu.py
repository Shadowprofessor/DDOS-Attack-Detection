#!/usr/bin/env python3
import sys
import collections
import collections.abc

# Fix Python 3.10+ compatibility for legacy Ryu/eventlet dependencies
collections.MutableMapping = collections.abc.MutableMapping
collections.Mapping = collections.abc.Mapping
collections.Callable = collections.abc.Callable

import eventlet.wsgi
if not hasattr(eventlet.wsgi, 'ALREADY_HANDLED'):
    eventlet.wsgi.ALREADY_HANDLED = object()

# Load unified environment configuration via --env flag or default
import logging
from src.config.loader import load_config, extract_env_flag

# Extract and strip --env from sys.argv so Ryu argument parser does not reject it
env_flag = extract_env_flag(sys.argv, remove=True)
config = load_config(env_flag)

# Configure logging level from config
_log_level_name = config.get("scoring_service", {}).get("log_level", "info").upper()
_log_level = getattr(logging, _log_level_name, logging.INFO)
logging.basicConfig(level=_log_level)

from ryu.cmd.manager import main

if __name__ == '__main__':
    sys.exit(main())
