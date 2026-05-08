"""
Database models and helpers for the UMA-Agent resource server.

Exports used by resource_server/app.py:
  AuditEvent             — tamper-evident audit log row
  DelegationChainRecord  — persisted delegation chain claim
  DatabaseManager        — session factory
  GENESIS_HASH           — seed hash for the audit hash chain
  get_latest_event_hash  — returns hash of most recent event
  verify_audit_chain     — recomputes full hash chain, reports broken links
  compute_event_hash     — HMAC-SHA256 over prev_hash || canonical payload
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import Column, DateTime, Integer, JSON, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

logger = logging.getLogger(__name__)

Base = declarative_base()

GENESIS_HASH: str = "0" * 64


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def compute_event_hash(prev_hash: str, payload: Dict[str, Any], secret: str) -> str:
    msg = prev_hash + json.dumps(payload, sort_keys=True, default=str)
    return _hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def get_latest_event_hash(session: Session) -> str:
    row = (
        session.query(AuditEvent)
        .order_by(AuditEvent.timestamp.desc())
        .first()
    )
    return (row.event_hash or GENESIS_HASH) if row else GENESIS_HASH


def verify_audit_chain(session: Session, secret: str) -> Dict[str, Any]:
    events = (
        session.query(AuditEvent)
        .order_by(AuditEvent.timestamp.asc())
        .all()
    )
    broken: List[Dict[str, Any]] = []
    prev_hash = GENESIS_HASH
    for ev in events:
        payload = {
            "agent_id": ev.agent_id,
            "action":   ev.action,
            "result":   ev.result,
            "resource": ev.resource,
            "scope":    ev.scope,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
        }
        expected = compute_event_hash(prev_hash, payload, secret)
        stored = ev.event_hash or ""
        if not _hmac.compare_digest(expected, stored):
            broken.append({
                "event_id": ev.id,
                "expected": expected,
                "stored":   stored,
            })
        prev_hash = stored or expected
    return {
        "total_events": len(events),
        "chain_intact": len(broken) == 0,
        "broken_links": broken,
    }


# ---------------------------------------------------------------------------
# SQLAlchemy models
# ---------------------------------------------------------------------------

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id                  = Column(String(64),  primary_key=True)
    event_type          = Column(String(32),  nullable=False)
    agent_id            = Column(String(128), nullable=True)
    action              = Column(String(256), nullable=True)
    result              = Column(String(32),  nullable=True)
    resource            = Column(String(128), nullable=True)
    scope               = Column(String(128), nullable=True)
    extra_data          = Column(JSON,        default=dict)
    delegation_chain_id = Column(String(64),  nullable=True)
    attack_class        = Column(String(32),  nullable=True)
    prev_event_id       = Column(String(64),  nullable=True)
    timestamp           = Column(DateTime,    default=datetime.utcnow)
    event_hash          = Column(String(64),  nullable=True)

    def compute_and_set_hash(self, prev_hash: str, secret: str) -> None:
        payload = {
            "agent_id": self.agent_id,
            "action":   self.action,
            "result":   self.result,
            "resource": self.resource,
            "scope":    self.scope,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
        self.event_hash = compute_event_hash(prev_hash, payload, secret)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id":            self.id,
            "event_type":          self.event_type,
            "agent_id":            self.agent_id,
            "action":              self.action,
            "result":              self.result,
            "resource":            self.resource,
            "scope":               self.scope,
            "extra_data":          self.extra_data,
            "delegation_chain_id": self.delegation_chain_id,
            "attack_class":        self.attack_class,
            "prev_event_id":       self.prev_event_id,
            "timestamp":           self.timestamp.isoformat() if self.timestamp else None,
            "event_hash":          self.event_hash,
        }


class DelegationChainRecord(Base):
    __tablename__ = "delegation_chain_records"

    chain_id       = Column(String(64),  primary_key=True)
    root_agent     = Column(String(128), nullable=False)
    members        = Column(JSON,        nullable=False)
    granted_scopes = Column(JSON,        nullable=False)
    depth          = Column(Integer,     nullable=False)
    max_depth      = Column(Integer,     nullable=False)
    chain_hash     = Column(String(64),  nullable=True)
    created_at     = Column(DateTime,    default=datetime.utcnow)
    last_used_at   = Column(DateTime,    nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id":       self.chain_id,
            "root_agent":     self.root_agent,
            "members":        self.members,
            "granted_scopes": self.granted_scopes,
            "depth":          self.depth,
            "max_depth":      self.max_depth,
            "chain_hash":     self.chain_hash,
            "created_at":     self.created_at.isoformat() if self.created_at else None,
            "last_used_at":   self.last_used_at.isoformat() if self.last_used_at else None,
        }


# ---------------------------------------------------------------------------
# DatabaseManager
# ---------------------------------------------------------------------------

def _build_url() -> str:
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    db   = os.getenv("POSTGRES_DB",   "keycloak")
    user = os.getenv("POSTGRES_USER", "keycloak")
    pw   = os.getenv("POSTGRES_PASSWORD", "keycloak_password")
    return f"postgresql://{user}:{pw}@{host}:{port}/{db}"


class DatabaseManager:
    def __init__(self, database_url: Optional[str] = None) -> None:
        url = database_url or _build_url()
        self._engine  = create_engine(url, pool_pre_ping=True)
        self._Session = sessionmaker(bind=self._engine)

    def create_tables(self) -> None:
        Base.metadata.create_all(self._engine)

    def get_session(self) -> Session:
        return self._Session()
