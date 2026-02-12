"""
Database Models and Session Management for UMA-Agent

Provides SQLAlchemy models for:
- Audit events (compliance logging)
- Delegations (agent task delegation)
- Agent states (persistent agent data)
- UMA tokens (RPT and permission ticket storage)
"""

from sqlalchemy import create_engine, Column, String, DateTime, JSON, Integer, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
from typing import Optional, List, Dict, Any
import os
import logging

logger = logging.getLogger(__name__)

Base = declarative_base()

# ============================================================================
# Database Models
# ============================================================================

class AuditEvent(Base):
    """Audit log entry for compliance and tracking"""
    __tablename__ = 'audit_events'

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    event_type = Column(String(50), nullable=False)  # delegation_requested, resource_accessed, etc.
    agent_id = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)
    result = Column(String(20), nullable=False)  # success, failure, pending
    resource = Column(String(100))
    scope = Column(String(50))
    target_agent_id = Column(String(100))  # For delegation events
    extra_data = Column(JSON)  # Additional event-specific data

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'agent_id': self.agent_id,
            'action': self.action,
            'result': self.result,
            'resource': self.resource,
            'scope': self.scope,
            'target_agent_id': self.target_agent_id,
            'extra_data': self.extra_data
        }


class Delegation(Base):
    """Agent delegation record"""
    __tablename__ = 'delegations'

    request_id = Column(String, primary_key=True)
    source_agent_id = Column(String(100), nullable=False)
    target_agent_id = Column(String(100), nullable=False)
    task_description = Column(Text, nullable=False)
    status = Column(String(20), nullable=False)  # pending, approved, rejected, completed
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    approved_at = Column(DateTime)
    completed_at = Column(DateTime)
    expires_at = Column(DateTime)
    scopes = Column(JSON)  # List of scopes delegated
    original_scopes = Column(JSON)  # Original scopes before reduction
    delegation_chain = Column(JSON)  # List of agent IDs in delegation chain
    permission_ticket = Column(String)  # UMA permission ticket
    rpt_token = Column(String)  # UMA RPT token
    result_data = Column(JSON)  # Task result data
    extra_data = Column(JSON)  # Additional delegation metadata

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'request_id': self.request_id,
            'source_agent_id': self.source_agent_id,
            'target_agent_id': self.target_agent_id,
            'task_description': self.task_description,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'scopes': self.scopes,
            'original_scopes': self.original_scopes,
            'delegation_chain': self.delegation_chain,
            'extra_data': self.extra_data
        }


class AgentState(Base):
    """Persistent agent state"""
    __tablename__ = 'agent_states'

    agent_id = Column(String(100), primary_key=True)
    agent_type = Column(String(50), nullable=False)
    agent_name = Column(String(200), nullable=False)
    description = Column(Text)
    capabilities = Column(JSON)  # List of capability strings
    scopes = Column(JSON)  # Current scopes
    delegation_chain = Column(JSON)  # Current delegation chain
    is_authenticated = Column(Boolean, default=False)
    last_authentication = Column(DateTime)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    custom_state = Column(JSON)  # Agent-specific state data
    extra_data = Column(JSON)  # Additional metadata

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'agent_id': self.agent_id,
            'agent_type': self.agent_type,
            'agent_name': self.agent_name,
            'description': self.description,
            'capabilities': self.capabilities,
            'scopes': self.scopes,
            'delegation_chain': self.delegation_chain,
            'is_authenticated': self.is_authenticated,
            'last_authentication': self.last_authentication.isoformat() if self.last_authentication else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'custom_state': self.custom_state,
            'extra_data': self.extra_data
        }


class UMAToken(Base):
    """UMA token storage (RPTs and permission tickets)"""
    __tablename__ = 'uma_tokens'

    id = Column(String, primary_key=True)
    agent_id = Column(String(100), nullable=False)
    token_type = Column(String(20), nullable=False)  # 'rpt' or 'permission_ticket'
    token_value = Column(Text, nullable=False)
    resource = Column(String(100))
    scopes = Column(JSON)  # List of scopes
    permissions = Column(JSON)  # Permission data from RPT
    issued_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    extra_data = Column(JSON)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'agent_id': self.agent_id,
            'token_type': self.token_type,
            'resource': self.resource,
            'scopes': self.scopes,
            'permissions': self.permissions,
            'issued_at': self.issued_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active
        }


# ============================================================================
# Database Session Management
# ============================================================================

class DatabaseManager:
    """Manages database connections and sessions"""

    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize database manager

        Args:
            database_url: SQLAlchemy database URL
                         Defaults to PostgreSQL using environment variables
        """
        if database_url is None:
            # Default to PostgreSQL from Docker Compose
            pg_host = os.getenv('POSTGRES_HOST', 'localhost')
            pg_port = os.getenv('POSTGRES_PORT', '5432')
            pg_db = os.getenv('POSTGRES_DB', 'keycloak')
            pg_user = os.getenv('POSTGRES_USER', 'keycloak')
            pg_pass = os.getenv('POSTGRES_PASSWORD', 'keycloak_password')

            database_url = f'postgresql://{pg_user}:{pg_pass}@{pg_host}:{pg_port}/{pg_db}'

        self.database_url = database_url
        self.engine = create_engine(database_url, echo=False)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

        logger.info(f"Database manager initialized")

    def create_tables(self):
        """Create all database tables"""
        Base.metadata.create_all(bind=self.engine)
        logger.info("Database tables created")

    def drop_tables(self):
        """Drop all database tables (use with caution!)"""
        Base.metadata.drop_all(bind=self.engine)
        logger.warning("All database tables dropped")

    def get_session(self) -> Session:
        """Get a new database session"""
        return self.SessionLocal()

    def close(self):
        """Close database connection"""
        self.engine.dispose()
        logger.info("Database connection closed")


# ============================================================================
# Global database instance
# ============================================================================

_db_manager: Optional[DatabaseManager] = None

def get_db_manager() -> DatabaseManager:
    """Get the global database manager instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
        _db_manager.create_tables()
    return _db_manager

def get_db_session() -> Session:
    """Get a new database session"""
    return get_db_manager().get_session()


# ============================================================================
# Helper Functions
# ============================================================================

def init_database(database_url: Optional[str] = None, create_tables: bool = True):
    """
    Initialize the database

    Args:
        database_url: Database connection URL
        create_tables: Whether to create tables on initialization
    """
    global _db_manager
    _db_manager = DatabaseManager(database_url)

    if create_tables:
        _db_manager.create_tables()

    logger.info("Database initialized successfully")


def reset_database():
    """Reset database (drop and recreate all tables)"""
    db = get_db_manager()
    db.drop_tables()
    db.create_tables()
    logger.warning("Database reset completed")
