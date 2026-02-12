"""
Agent Audit Logging System - Complete audit trail for all agent actions

Provides:
- Event logging for all operations
- Delegation trail tracking
- Agent action history
- Audit log queries and exports
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import uuid
import logging

logger = logging.getLogger(__name__)


class AuditEventType(str, Enum):
    """Types of audit events"""
    AGENT_CREATED = "agent_created"
    AGENT_AUTHENTICATED = "agent_authenticated"
    AGENT_TOKEN_REFRESHED = "agent_token_refreshed"
    DELEGATION_REQUESTED = "delegation_requested"
    DELEGATION_APPROVED = "delegation_approved"
    DELEGATION_REJECTED = "delegation_rejected"
    DELEGATION_COMPLETED = "delegation_completed"
    DELEGATION_REVOKED = "delegation_revoked"
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"
    MESSAGE_ACKNOWLEDGED = "message_acknowledged"
    ACTION_EXECUTED = "action_executed"
    RESULT_VALIDATED = "result_validated"
    POLICY_CHECK = "policy_check"
    SCOPE_GRANTED = "scope_granted"
    SCOPE_REVOKED = "scope_revoked"
    ERROR = "error"


class AuditResult(str, Enum):
    """Result of an audited operation"""
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    CONDITIONAL = "conditional"


@dataclass
class AuditEvent:
    """An audit log event"""
    event_id: str = field(default_factory=lambda: f"event-{uuid.uuid4().hex[:8]}")
    event_type: AuditEventType = AuditEventType.POLICY_CHECK
    agent_id: str = ""
    agent_type: str = ""
    action: str = ""
    resource_accessed: Optional[str] = None
    result: AuditResult = AuditResult.SUCCESS
    delegation_chain: List[str] = field(default_factory=list)
    related_agent_id: Optional[str] = None
    scopes_involved: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

    def get_info(self) -> Dict[str, Any]:
        """Get event information"""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "action": self.action,
            "resource_accessed": self.resource_accessed,
            "result": self.result.value,
            "timestamp": self.timestamp.isoformat(),
            "delegation_chain": self.delegation_chain,
            "scopes_involved": self.scopes_involved,
            "related_agent_id": self.related_agent_id,
        }


class AuditLogger:
    """Manages audit logging for agent operations"""

    def __init__(self):
        """Initialize audit logger"""
        self._events: Dict[str, AuditEvent] = {}
        self._agent_events: Dict[str, List[str]] = {}  # agent_id -> event_ids
        self._delegation_trails: Dict[str, List[str]] = {}  # delegation_id -> event_ids

    # ========================================================================
    # Event Logging
    # ========================================================================

    def log_event(self, event: AuditEvent) -> str:
        """
        Log an audit event

        Args:
            event: Event to log

        Returns:
            Event ID
        """
        self._events[event.event_id] = event

        # Track by agent
        if event.agent_id not in self._agent_events:
            self._agent_events[event.agent_id] = []
        self._agent_events[event.agent_id].append(event.event_id)

        logger.info(
            f"Audit event: {event.event_type.value} "
            f"agent={event.agent_id} result={event.result.value}"
        )

        return event.event_id

    def log_agent_created(
        self,
        agent_id: str,
        agent_type: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Log agent creation"""
        event = AuditEvent(
            event_type=AuditEventType.AGENT_CREATED,
            agent_id=agent_id,
            agent_type=agent_type,
            action="create",
            result=AuditResult.SUCCESS,
            metadata=metadata or {},
        )
        return self.log_event(event)

    def log_authentication(
        self,
        agent_id: str,
        agent_type: str,
        success: bool,
        error_msg: Optional[str] = None,
    ) -> str:
        """Log agent authentication"""
        event = AuditEvent(
            event_type=AuditEventType.AGENT_AUTHENTICATED,
            agent_id=agent_id,
            agent_type=agent_type,
            action="authenticate",
            result=AuditResult.SUCCESS if success else AuditResult.FAILURE,
            error_message=error_msg,
        )
        return self.log_event(event)

    def log_delegation_requested(
        self,
        delegation_id: str,
        source_agent_id: str,
        target_agent_id: str,
        scopes: List[str],
        task_description: str,
    ) -> str:
        """Log delegation request"""
        event = AuditEvent(
            event_type=AuditEventType.DELEGATION_REQUESTED,
            agent_id=source_agent_id,
            action="request_delegation",
            result=AuditResult.SUCCESS,
            related_agent_id=target_agent_id,
            scopes_involved=scopes,
            metadata={"task_description": task_description},
        )
        event_id = self.log_event(event)

        # Track in delegation trail
        if delegation_id not in self._delegation_trails:
            self._delegation_trails[delegation_id] = []
        self._delegation_trails[delegation_id].append(event_id)

        return event_id

    def log_delegation_approved(
        self,
        delegation_id: str,
        source_agent_id: str,
        target_agent_id: str,
        scopes: List[str],
    ) -> str:
        """Log delegation approval"""
        event = AuditEvent(
            event_type=AuditEventType.DELEGATION_APPROVED,
            agent_id=source_agent_id,
            action="approve_delegation",
            result=AuditResult.SUCCESS,
            related_agent_id=target_agent_id,
            scopes_involved=scopes,
        )
        event_id = self.log_event(event)

        if delegation_id not in self._delegation_trails:
            self._delegation_trails[delegation_id] = []
        self._delegation_trails[delegation_id].append(event_id)

        return event_id

    def log_message_sent(
        self,
        message_id: str,
        sender_id: str,
        receiver_id: str,
        message_type: str,
    ) -> str:
        """Log message sending"""
        event = AuditEvent(
            event_type=AuditEventType.MESSAGE_SENT,
            agent_id=sender_id,
            action="send_message",
            result=AuditResult.SUCCESS,
            related_agent_id=receiver_id,
            metadata={"message_id": message_id, "message_type": message_type},
        )
        return self.log_event(event)

    def log_message_received(
        self,
        message_id: str,
        receiver_id: str,
        sender_id: str,
        message_type: str,
    ) -> str:
        """Log message receipt"""
        event = AuditEvent(
            event_type=AuditEventType.MESSAGE_RECEIVED,
            agent_id=receiver_id,
            action="receive_message",
            result=AuditResult.SUCCESS,
            related_agent_id=sender_id,
            metadata={"message_id": message_id, "message_type": message_type},
        )
        return self.log_event(event)

    def log_action_executed(
        self,
        agent_id: str,
        agent_type: str,
        action: str,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Log action execution"""
        event = AuditEvent(
            event_type=AuditEventType.ACTION_EXECUTED,
            agent_id=agent_id,
            agent_type=agent_type,
            action=action,
            result=AuditResult.SUCCESS if success else AuditResult.FAILURE,
            metadata=metadata or {},
        )
        return self.log_event(event)

    def log_result_validated(
        self,
        agent_id: str,
        result_id: str,
        is_valid: bool,
        validation_rules: List[str],
    ) -> str:
        """Log result validation"""
        event = AuditEvent(
            event_type=AuditEventType.RESULT_VALIDATED,
            agent_id=agent_id,
            action="validate_result",
            result=AuditResult.SUCCESS if is_valid else AuditResult.FAILURE,
            metadata={
                "result_id": result_id,
                "validation_rules": validation_rules,
            },
        )
        return self.log_event(event)

    def log_policy_check(
        self,
        agent_id: str,
        agent_type: str,
        action: str,
        decision: str,
        scopes: List[str],
    ) -> str:
        """Log policy check"""
        event = AuditEvent(
            event_type=AuditEventType.POLICY_CHECK,
            agent_id=agent_id,
            agent_type=agent_type,
            action=action,
            result=AuditResult[decision.upper()] if decision.upper() in AuditResult.__members__ else AuditResult.DENIED,
            scopes_involved=scopes,
        )
        return self.log_event(event)

    def log_scope_granted(
        self,
        agent_id: str,
        scope: str,
        granted_by: Optional[str] = None,
    ) -> str:
        """Log scope grant"""
        event = AuditEvent(
            event_type=AuditEventType.SCOPE_GRANTED,
            agent_id=agent_id,
            action=f"grant_scope:{scope}",
            result=AuditResult.SUCCESS,
            related_agent_id=granted_by,
            scopes_involved=[scope],
        )
        return self.log_event(event)

    def log_error(
        self,
        agent_id: str,
        error_type: str,
        error_message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Log error event"""
        event = AuditEvent(
            event_type=AuditEventType.ERROR,
            agent_id=agent_id,
            action=error_type,
            result=AuditResult.FAILURE,
            error_message=error_message,
            metadata=context or {},
        )
        return self.log_event(event)

    # ========================================================================
    # Queries
    # ========================================================================

    def get_event(self, event_id: str) -> Optional[AuditEvent]:
        """Get a specific event"""
        return self._events.get(event_id)

    def get_agent_history(
        self,
        agent_id: str,
        limit: Optional[int] = None,
        event_type: Optional[AuditEventType] = None,
    ) -> List[AuditEvent]:
        """
        Get audit history for an agent

        Args:
            agent_id: Agent ID
            limit: Maximum events to return
            event_type: Filter by event type

        Returns:
            List of audit events
        """
        event_ids = self._agent_events.get(agent_id, [])
        events = [self._events[eid] for eid in event_ids if eid in self._events]

        if event_type:
            events = [e for e in events if e.event_type == event_type]

        if limit:
            events = events[-limit:]

        return events

    def get_delegation_trail(self, delegation_id: str) -> List[AuditEvent]:
        """Get complete audit trail for a delegation"""
        event_ids = self._delegation_trails.get(delegation_id, [])
        return [self._events[eid] for eid in event_ids if eid in self._events]

    def query_events(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        result: Optional[AuditResult] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[AuditEvent]:
        """
        Query events with filters

        Args:
            agent_id: Filter by agent
            event_type: Filter by event type
            result: Filter by result
            start_time: Filter by start time
            end_time: Filter by end time

        Returns:
            Matching events
        """
        results = list(self._events.values())

        if agent_id:
            results = [e for e in results if e.agent_id == agent_id]

        if event_type:
            results = [e for e in results if e.event_type == event_type]

        if result:
            results = [e for e in results if e.result == result]

        if start_time:
            results = [e for e in results if e.timestamp >= start_time]

        if end_time:
            results = [e for e in results if e.timestamp <= end_time]

        return sorted(results, key=lambda e: e.timestamp)

    def get_failed_events(self, agent_id: Optional[str] = None) -> List[AuditEvent]:
        """Get all failed events"""
        return self.query_events(
            agent_id=agent_id,
            result=AuditResult.FAILURE,
        )

    def get_denied_events(self, agent_id: Optional[str] = None) -> List[AuditEvent]:
        """Get all denied events"""
        return self.query_events(
            agent_id=agent_id,
            result=AuditResult.DENIED,
        )

    # ========================================================================
    # Statistics
    # ========================================================================

    def get_agent_stats(self, agent_id: str) -> Dict[str, Any]:
        """Get statistics for an agent's activity"""
        events = self.get_agent_history(agent_id)

        if not events:
            return {
                "agent_id": agent_id,
                "total_events": 0,
                "successful_actions": 0,
                "failed_actions": 0,
                "denied_actions": 0,
            }

        successful = len([e for e in events if e.result == AuditResult.SUCCESS])
        failed = len([e for e in events if e.result == AuditResult.FAILURE])
        denied = len([e for e in events if e.result == AuditResult.DENIED])

        return {
            "agent_id": agent_id,
            "total_events": len(events),
            "successful_actions": successful,
            "failed_actions": failed,
            "denied_actions": denied,
            "first_event": events[0].timestamp.isoformat(),
            "last_event": events[-1].timestamp.isoformat(),
        }

    def get_summary(self) -> Dict[str, Any]:
        """Get overall audit log summary"""
        all_events = list(self._events.values())

        if not all_events:
            return {
                "total_events": 0,
                "total_agents": 0,
                "successful": 0,
                "failed": 0,
                "denied": 0,
            }

        successful = len([e for e in all_events if e.result == AuditResult.SUCCESS])
        failed = len([e for e in all_events if e.result == AuditResult.FAILURE])
        denied = len([e for e in all_events if e.result == AuditResult.DENIED])

        return {
            "total_events": len(all_events),
            "total_agents": len(self._agent_events),
            "successful": successful,
            "failed": failed,
            "denied": denied,
            "delegations_tracked": len(self._delegation_trails),
        }

    def export_logs(
        self,
        agent_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Export audit logs as dictionaries"""
        events = self.query_events(
            agent_id=agent_id,
            start_time=start_time,
            end_time=end_time,
        )

        return [e.get_info() for e in events]

    def __repr__(self) -> str:
        """String representation"""
        return f"AuditLogger(events={len(self._events)})"
