# -*- coding: utf-8 -*-
"""SQLite/SQLAlchemy persistence for incident response (Alembic-free: create_all + schema_version)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from src.ir.models import SCHEMA_VERSION, Base, SchemaVersion

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DATABASE_URL = "sqlite:///data/ir.db"


def resolve_database_url(url: Optional[str]) -> str:
    """Relative sqlite paths resolve against the repo root (like pending_actions.json)."""
    url = (url or DEFAULT_DATABASE_URL).strip()
    prefix = "sqlite:///"
    if url.startswith(prefix) and url != "sqlite:///:memory:":
        path = Path(url[len(prefix):])
        if not path.is_absolute():
            path = REPO_ROOT / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return prefix + path.as_posix()
    return url


class IRDatabase:
    def __init__(self, url: Optional[str] = None):
        self.url = resolve_database_url(url)
        connect_args = {"check_same_thread": False} if self.url.startswith("sqlite") else {}
        self.engine = create_engine(self.url, connect_args=connect_args, future=True)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)
        self.init()

    def init(self) -> None:
        Base.metadata.create_all(self.engine)
        with self.session() as s:
            row = s.scalar(select(SchemaVersion).limit(1))
            if row is None:
                s.add(SchemaVersion(id=1, version=SCHEMA_VERSION))
                s.commit()
            elif row.version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"IR database schema v{row.version} is newer than this code (v{SCHEMA_VERSION}).")

    def session(self) -> Session:
        return self._sessions()

    def dispose(self) -> None:
        self.engine.dispose()


def database_url_from_config(config: Optional[dict] = None) -> str:
    env = os.environ.get("DDOS_IR_DATABASE_URL")
    if env:
        return env
    return str(((config or {}).get("ir") or {}).get("database_url") or DEFAULT_DATABASE_URL)
