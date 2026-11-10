# -*- coding: utf-8 -*-
"""SQLAlchemy 2.x ORM models for the incident-response store.

Timestamps are UNIX epoch floats so every component can share one injectable clock.
"""
from __future__ import annotations

from typing import Any, List, Optional

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

SCHEMA_VERSION = 1


class Base(DeclarativeBase):
    pass


class SchemaVersion(Base):
    __tablename__ = "schema_version"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(Integer)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # INC-YYYYMMDD-xxxx
    title: Mapped[str] = mapped_column(String(200))
    attack_family: Mapped[str] = mapped_column(String(64), default="other")
    severity: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    created_at: Mapped[float] = mapped_column(Float)
    detected_at: Mapped[float] = mapped_column(Float)
    contained_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    closed_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source_alert_ids: Mapped[List[str]] = mapped_column(JSON, default=list)
    aggregate_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    analysis_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    cert_in_deadline: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cert_in_reported_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cert_in_warnings: Mapped[List[str]] = mapped_column(JSON, default=list)  # e.g. ["1h", "15m", "breach"]
    containment_justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_replay: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    events: Mapped[List["IncidentEvent"]] = relationship(
        back_populates="incident", order_by="IncidentEvent.seq", cascade="all, delete-orphan")
    actions: Mapped[List["IncidentAction"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan")
    playbook_runs: Mapped[List["PlaybookRun"]] = relationship(
        back_populates="incident", order_by="PlaybookRun.id", cascade="all, delete-orphan")


class IncidentEvent(Base):
    """Append-only timeline entry. `hash` = sha256(canonical(event fields) + prev_hash)."""

    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[float] = mapped_column(Float)
    actor: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(32))
    detail: Mapped[Any] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))

    incident: Mapped[Incident] = relationship(back_populates="events")


class IncidentAction(Base):
    """Link from an incident to a PendingActionManager action, plus its rollback schedule."""

    __tablename__ = "actions"

    action_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    linked_at: Mapped[float] = mapped_column(Float)
    linked_by: Mapped[str] = mapped_column(String(64))
    # linked -> scheduled -> rolled_back | permanent | failed
    rollback_state: Mapped[str] = mapped_column(String(16), default="linked", index=True)
    ttl_s: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # per-action override
    approved_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    rollback_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    rolled_back_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    permanent_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    incident: Mapped[Incident] = relationship(back_populates="actions")


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    playbook_id: Mapped[str] = mapped_column(String(64))
    step: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    actor: Mapped[str] = mapped_column(String(64))
    ts: Mapped[float] = mapped_column(Float)
    result: Mapped[Any] = mapped_column(JSON, default=dict)

    incident: Mapped[Incident] = relationship(back_populates="playbook_runs")
