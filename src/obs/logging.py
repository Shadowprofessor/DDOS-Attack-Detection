# -*- coding: utf-8 -*-
"""
Structured JSON logging (stdlib-only).

`configure_json_logging()` installs a formatter that emits one JSON object per
log line (ts, level, logger, message, plus any `extra=` fields). Opt-in via
`DDOS_JSON_LOGS=1` so local/test output stays human-readable by default; prod
configs can enable it. No external dependency (swappable for structlog later).
"""
import json
import logging
import os
from datetime import datetime, timezone

# Field names that live on every LogRecord and should not be duplicated as "extra".
_RESERVED = set(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
) | {"message", "asctime", "taskName"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Promote any structured extras attached via logger.*(..., extra={...}).
        for k, v in record.__dict__.items():
            if k in _RESERVED or k.startswith("_"):
                continue
            try:
                json.dumps(v)
                payload[k] = v
            except (TypeError, ValueError):
                payload[k] = str(v)
        return json.dumps(payload, default=str)


def configure_json_logging(level: int = logging.INFO) -> None:
    """Switch root logging to single-line JSON output."""
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        root.addHandler(logging.StreamHandler())
    for handler in root.handlers:
        handler.setFormatter(JsonFormatter())


def configure_from_env() -> bool:
    """Enable JSON logging if DDOS_JSON_LOGS is truthy. Returns whether it was enabled."""
    if os.environ.get("DDOS_JSON_LOGS", "").strip().lower() in ("1", "true", "yes", "on"):
        configure_json_logging()
        return True
    return False
