"""
Comprehensive Workflow Logging System

Logs all workflow operations for:
- Testing and debugging
- Audit trails
- Performance monitoring
- User behavior analysis
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field, asdict
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class WorkflowEventType(str, Enum):
    """Types of workflow events to log"""
    # Agent lifecycle
    AGENT_CREATED = "agent_created"
    AGENT_AUTHENTICATED = "agent_authenticated"
    AGENT_SCOPE_GRANTED = "agent_scope_granted"
    AGENT_SCOPE_REVOKED = "agent_scope_revoked"

    # Delegation
    DELEGATION_REQUESTED = "delegation_requested"
    DELEGATION_APPROVED = "delegation_approved"
    DELEGATION_REJECTED = "delegation_rejected"
    DELEGATION_REVOKED = "delegation_revoked"

    # Messaging
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"
    MESSAGE_ACKNOWLEDGED = "message_acknowledged"

    # Task execution
    TASK_STARTED = "task_started"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"

    # Authorization
    AUTHORIZATION_CHECK = "authorization_check"
    AUTHORIZATION_ALLOWED = "authorization_allowed"
    AUTHORIZATION_DENIED = "authorization_denied"

    # System
    WORKFLOW_STARTED = "workflow_started"
    WORKFLOW_COMPLETED = "workflow_completed"
    WORKFLOW_FAILED = "workflow_failed"
    ERROR = "error"


class LogLevel(str, Enum):
    """Log levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class WorkflowLogEntry:
    """A single workflow log entry"""
    timestamp: datetime
    event_type: WorkflowEventType
    agent_id: Optional[str]
    agent_name: Optional[str]
    level: LogLevel
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None  # For tracking related events
    user_id: Optional[str] = None  # Real user (from Keycloak)
    session_id: Optional[str] = None  # Session/workflow ID

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["event_type"] = self.event_type.value
        data["level"] = self.level.value
        return data

    def to_json(self) -> str:
        """Convert to JSON"""
        return json.dumps(self.to_dict())


class WorkflowLogger:
    """
    Comprehensive workflow logging system.

    Logs all operations for:
    - Real-time monitoring
    - Testing and debugging
    - Audit trails
    - User behavior analysis
    """

    def __init__(
        self,
        log_dir: Optional[Path] = None,
        console_output: bool = True,
        file_output: bool = True
    ):
        """
        Initialize workflow logger.

        Args:
            log_dir: Directory to store log files
            console_output: Log to console
            file_output: Log to file
        """
        self.log_dir = log_dir or Path("/tmp/uma-agent-logs")
        self.console_output = console_output
        self.file_output = file_output

        # Create log directory if needed
        if self.file_output:
            self.log_dir.mkdir(parents=True, exist_ok=True)

        # In-memory log storage
        self._logs: List[WorkflowLogEntry] = []
        self._correlation_groups: Dict[str, List[WorkflowLogEntry]] = {}

        # Setup Python logging
        self._setup_logging()

    def _setup_logging(self):
        """Setup Python logging handlers"""
        # Create logger
        logger = logging.getLogger("uma-agent-workflow")
        logger.setLevel(logging.DEBUG)

        # Console handler
        if self.console_output:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            )
            logger.addHandler(console_handler)

        # File handler
        if self.file_output:
            log_file = self.log_dir / f"workflow-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            )
            logger.addHandler(file_handler)

    def log(
        self,
        event_type: WorkflowEventType,
        message: str,
        level: LogLevel = LogLevel.INFO,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> str:
        """
        Log a workflow event.

        Args:
            event_type: Type of event
            message: Human-readable message
            level: Log level
            agent_id: Agent performing action
            agent_name: Agent display name
            details: Additional details (dict)
            correlation_id: For grouping related events
            user_id: Real user from Keycloak
            session_id: Workflow/session ID

        Returns:
            Log entry ID
        """
        entry = WorkflowLogEntry(
            timestamp=datetime.now(),
            event_type=event_type,
            agent_id=agent_id,
            agent_name=agent_name,
            level=level,
            message=message,
            details=details or {},
            correlation_id=correlation_id,
            user_id=user_id,
            session_id=session_id
        )

        self._logs.append(entry)

        # Group by correlation ID
        if correlation_id:
            if correlation_id not in self._correlation_groups:
                self._correlation_groups[correlation_id] = []
            self._correlation_groups[correlation_id].append(entry)

        # Python logging
        log_func = {
            LogLevel.DEBUG: logger.debug,
            LogLevel.INFO: logger.info,
            LogLevel.WARNING: logger.warning,
            LogLevel.ERROR: logger.error,
            LogLevel.CRITICAL: logger.critical
        }[level]

        agent_str = f"[{agent_name or agent_id or 'SYSTEM'}]"
        log_func(f"{agent_str} {message}")

        return str(len(self._logs) - 1)

    # ========================================================================
    # Convenience logging methods
    # ========================================================================

    def log_agent_created(
        self,
        agent_id: str,
        agent_name: str,
        agent_type: str,
        user_id: Optional[str] = None
    ):
        """Log agent creation"""
        self.log(
            WorkflowEventType.AGENT_CREATED,
            f"Agent created: {agent_name} ({agent_type})",
            agent_id=agent_id,
            agent_name=agent_name,
            details={"agent_type": agent_type},
            user_id=user_id
        )

    def log_agent_authenticated(
        self,
        agent_id: str,
        agent_name: str,
        token_type: str = "Bearer",
        user_id: Optional[str] = None
    ):
        """Log agent authentication"""
        self.log(
            WorkflowEventType.AGENT_AUTHENTICATED,
            f"Agent authenticated with {token_type} token",
            agent_id=agent_id,
            agent_name=agent_name,
            details={"token_type": token_type},
            user_id=user_id
        )

    def log_scope_granted(
        self,
        agent_id: str,
        agent_name: str,
        scope: str,
        granted_by: str = "system",
        user_id: Optional[str] = None
    ):
        """Log scope grant"""
        self.log(
            WorkflowEventType.AGENT_SCOPE_GRANTED,
            f"Scope granted: {scope}",
            agent_id=agent_id,
            agent_name=agent_name,
            details={"scope": scope, "granted_by": granted_by},
            user_id=user_id
        )

    def log_delegation_requested(
        self,
        delegation_id: str,
        source_agent_id: str,
        source_agent_name: str,
        target_agent_id: str,
        target_agent_name: str,
        scopes: List[str],
        task_description: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """Log delegation request"""
        self.log(
            WorkflowEventType.DELEGATION_REQUESTED,
            f"Delegation request created: {source_agent_name} → {target_agent_name}",
            agent_id=source_agent_id,
            agent_name=source_agent_name,
            details={
                "delegation_id": delegation_id,
                "target_agent_id": target_agent_id,
                "target_agent_name": target_agent_name,
                "scopes": scopes,
                "task_description": task_description
            },
            correlation_id=delegation_id,
            user_id=user_id,
            session_id=session_id
        )

    def log_delegation_approved(
        self,
        delegation_id: str,
        source_agent_id: str,
        target_agent_id: str,
        target_agent_name: str,
        scopes: List[str],
        approved_by: str = "system",
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """Log delegation approval"""
        self.log(
            WorkflowEventType.DELEGATION_APPROVED,
            f"Delegation approved: {target_agent_name} received {len(scopes)} scope(s)",
            agent_id=source_agent_id,
            details={
                "delegation_id": delegation_id,
                "target_agent_id": target_agent_id,
                "scopes": scopes,
                "approved_by": approved_by
            },
            correlation_id=delegation_id,
            user_id=user_id,
            session_id=session_id
        )

    def log_message_sent(
        self,
        message_id: str,
        sender_id: str,
        sender_name: str,
        receiver_id: str,
        receiver_name: str,
        message_type: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """Log message sending"""
        self.log(
            WorkflowEventType.MESSAGE_SENT,
            f"Message sent: {sender_name} → {receiver_name}",
            agent_id=sender_id,
            agent_name=sender_name,
            details={
                "message_id": message_id,
                "receiver_id": receiver_id,
                "receiver_name": receiver_name,
                "message_type": message_type
            },
            correlation_id=message_id,
            user_id=user_id,
            session_id=session_id
        )

    def log_task_started(
        self,
        task_id: str,
        agent_id: str,
        agent_name: str,
        task_description: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """Log task start"""
        self.log(
            WorkflowEventType.TASK_STARTED,
            f"Task started: {task_description}",
            agent_id=agent_id,
            agent_name=agent_name,
            details={"task_description": task_description},
            correlation_id=task_id,
            user_id=user_id,
            session_id=session_id
        )

    def log_task_completed(
        self,
        task_id: str,
        agent_id: str,
        agent_name: str,
        task_description: str,
        result: Dict[str, Any],
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """Log task completion"""
        self.log(
            WorkflowEventType.TASK_COMPLETED,
            f"Task completed: {task_description}",
            agent_id=agent_id,
            agent_name=agent_name,
            details={"result": result},
            correlation_id=task_id,
            user_id=user_id,
            session_id=session_id
        )

    def log_authorization_check(
        self,
        agent_id: str,
        agent_name: str,
        action: str,
        allowed: bool,
        required_scopes: List[str],
        agent_scopes: List[str],
        user_id: Optional[str] = None
    ):
        """Log authorization check"""
        event_type = (
            WorkflowEventType.AUTHORIZATION_ALLOWED
            if allowed
            else WorkflowEventType.AUTHORIZATION_DENIED
        )

        self.log(
            event_type,
            f"Authorization check: {action} - {'ALLOWED' if allowed else 'DENIED'}",
            level=LogLevel.WARNING if not allowed else LogLevel.INFO,
            agent_id=agent_id,
            agent_name=agent_name,
            details={
                "action": action,
                "required_scopes": required_scopes,
                "agent_scopes": agent_scopes
            },
            user_id=user_id
        )

    def log_error(
        self,
        agent_id: Optional[str],
        agent_name: Optional[str],
        error_message: str,
        error_type: str,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None
    ):
        """Log error"""
        self.log(
            WorkflowEventType.ERROR,
            error_message,
            level=LogLevel.ERROR,
            agent_id=agent_id,
            agent_name=agent_name,
            details={
                "error_type": error_type,
                **(details or {})
            },
            user_id=user_id
        )

    # ========================================================================
    # Log Querying
    # ========================================================================

    def get_logs(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[WorkflowEventType] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        limit: int = 100
    ) -> List[WorkflowLogEntry]:
        """
        Query logs with optional filters.

        Args:
            agent_id: Filter by agent
            event_type: Filter by event type
            user_id: Filter by user
            session_id: Filter by session
            limit: Maximum results

        Returns:
            Matching log entries
        """
        logs = self._logs

        if agent_id:
            logs = [l for l in logs if l.agent_id == agent_id]

        if event_type:
            logs = [l for l in logs if l.event_type == event_type]

        if user_id:
            logs = [l for l in logs if l.user_id == user_id]

        if session_id:
            logs = [l for l in logs if l.session_id == session_id]

        return logs[-limit:]

    def get_logs_json(
        self,
        **kwargs
    ) -> str:
        """Get logs as JSON"""
        logs = self.get_logs(**kwargs)
        return json.dumps([l.to_dict() for l in logs], indent=2)

    def get_correlation_trail(self, correlation_id: str) -> List[WorkflowLogEntry]:
        """Get all logs related to a correlation ID"""
        return self._correlation_groups.get(correlation_id, [])

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Get summary of all activity in a session"""
        session_logs = self.get_logs(session_id=session_id)

        event_counts = {}
        for log in session_logs:
            event_counts[log.event_type.value] = event_counts.get(log.event_type.value, 0) + 1

        agents_involved = set()
        users_involved = set()
        for log in session_logs:
            if log.agent_id:
                agents_involved.add(log.agent_id)
            if log.user_id:
                users_involved.add(log.user_id)

        return {
            "session_id": session_id,
            "total_events": len(session_logs),
            "event_counts": event_counts,
            "agents_involved": list(agents_involved),
            "users_involved": list(users_involved),
            "start_time": session_logs[0].timestamp if session_logs else None,
            "end_time": session_logs[-1].timestamp if session_logs else None
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        return {
            "total_events": len(self._logs),
            "total_agents": len(set(l.agent_id for l in self._logs if l.agent_id)),
            "total_users": len(set(l.user_id for l in self._logs if l.user_id)),
            "total_sessions": len(set(l.session_id for l in self._logs if l.session_id)),
            "event_breakdown": self._get_event_breakdown(),
            "first_event": self._logs[0].timestamp if self._logs else None,
            "last_event": self._logs[-1].timestamp if self._logs else None
        }

    def _get_event_breakdown(self) -> Dict[str, int]:
        """Get breakdown of events by type"""
        breakdown = {}
        for log in self._logs:
            key = log.event_type.value
            breakdown[key] = breakdown.get(key, 0) + 1
        return breakdown

    def export_logs(self, filename: Optional[str] = None) -> Path:
        """
        Export all logs to JSON file.

        Args:
            filename: Output filename

        Returns:
            Path to exported file
        """
        if filename is None:
            filename = f"workflow-logs-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"

        filepath = self.log_dir / filename

        logs_data = {
            "timestamp": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "logs": [l.to_dict() for l in self._logs]
        }

        with open(filepath, 'w') as f:
            json.dump(logs_data, f, indent=2)

        logger.info(f"Exported {len(self._logs)} logs to {filepath}")
        return filepath

    def __repr__(self) -> str:
        """String representation"""
        return (
            f"WorkflowLogger("
            f"logs={len(self._logs)}, "
            f"dir={self.log_dir}"
            f")"
        )
