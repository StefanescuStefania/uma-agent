"""
Agent Delegation System - Enables agent-to-agent task delegation

Provides:
- Task delegation between agents
- Scope reduction on delegation
- Delegation chain tracking
- Permission validation
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import uuid

from .base import BaseAgent


class DelegationStatus(str, Enum):
    """Status of a delegation request"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    REVOKED = "revoked"


@dataclass
class DelegationRequest:
    """Request to delegate a task from one agent to another"""

    request_id: str = field(default_factory=lambda: f"deleg-{uuid.uuid4().hex[:8]}")
    source_agent_id: str = ""
    target_agent_id: str = ""
    task_description: str = ""
    required_scopes: List[str] = field(default_factory=list)
    task_data: Dict[str, Any] = field(default_factory=dict)
    status: DelegationStatus = DelegationStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    approved_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    reason_for_rejection: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if delegation request has expired"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def time_remaining(self) -> Optional[int]:
        """Get seconds until expiration"""
        if self.expires_at is None:
            return None
        delta = (self.expires_at - datetime.utcnow()).total_seconds()
        return max(0, int(delta))

    def get_info(self) -> Dict[str, Any]:
        """Get detailed delegation request information"""
        return {
            "request_id": self.request_id,
            "source_agent_id": self.source_agent_id,
            "target_agent_id": self.target_agent_id,
            "task_description": self.task_description,
            "required_scopes": self.required_scopes,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "is_expired": self.is_expired(),
            "time_remaining": self.time_remaining(),
        }


class DelegationManager:
    """
    Manages delegation requests between agents

    Tracks delegation chains, validates permissions, and manages
    the lifecycle of delegation requests.
    """

    def __init__(self, max_delegation_depth: int = 3):
        """
        Initialize delegation manager

        Args:
            max_delegation_depth: Maximum depth of delegation chains
        """
        self.max_delegation_depth = max_delegation_depth
        self._requests: Dict[str, DelegationRequest] = {}
        self._delegation_chains: Dict[str, List[str]] = {}  # task_id -> chain
        self._agent_delegations: Dict[str, List[str]] = {}  # agent_id -> request_ids

    # ========================================================================
    # Delegation Request Management
    # ========================================================================

    def create_delegation_request(
        self,
        source_agent: BaseAgent,
        target_agent: BaseAgent,
        task_description: str,
        required_scopes: List[str],
        task_data: Optional[Dict[str, Any]] = None,
        expires_in_hours: int = 24,
    ) -> Optional[DelegationRequest]:
        """
        Create a delegation request from one agent to another

        Args:
            source_agent: Agent making the delegation request
            target_agent: Agent being delegated to
            task_description: Description of the task
            required_scopes: Scopes required for the task
            task_data: Data for the task
            expires_in_hours: Hours until request expires

        Returns:
            The delegation request, or None if validation fails
        """
        # Validate source agent can delegate
        if not source_agent.can_delegate(self.max_delegation_depth):
            return None

        # Validate scopes can be reduced
        source_scopes = set(source_agent.get_scopes())
        required_scopes_set = set(required_scopes)
        if not required_scopes_set.issubset(source_scopes):
            return None

        # Create request
        request = DelegationRequest(
            source_agent_id=source_agent.agent_id,
            target_agent_id=target_agent.agent_id,
            task_description=task_description,
            required_scopes=required_scopes,
            task_data=task_data or {},
            expires_at=datetime.utcnow() + timedelta(hours=expires_in_hours),
        )

        # Store request
        self._requests[request.request_id] = request

        # Track for source agent
        if source_agent.agent_id not in self._agent_delegations:
            self._agent_delegations[source_agent.agent_id] = []
        self._agent_delegations[source_agent.agent_id].append(request.request_id)

        return request

    def get_delegation_request(self, request_id: str) -> Optional[DelegationRequest]:
        """Get a delegation request by ID"""
        return self._requests.get(request_id)

    def approve_delegation(
        self,
        request_id: str,
        target_agent: BaseAgent,
    ) -> bool:
        """
        Approve a delegation request

        Args:
            request_id: ID of the request to approve
            target_agent: The agent receiving the delegation

        Returns:
            True if successful, False otherwise
        """
        request = self._requests.get(request_id)
        if not request:
            return False

        if request.is_expired():
            return False

        if request.status != DelegationStatus.PENDING:
            return False

        # Update request
        request.status = DelegationStatus.APPROVED
        request.approved_at = datetime.utcnow()

        # Grant scopes to target agent
        for scope in request.required_scopes:
            target_agent.add_scope(scope)

        # Update delegation chain
        source_chain = self._delegation_chains.get(request.source_agent_id, [request.source_agent_id])
        new_chain = source_chain + [request.target_agent_id]
        task_id = request.request_id
        self._delegation_chains[task_id] = new_chain

        # Update target agent's delegation chain
        target_agent.set_delegation_chain(new_chain)

        return True

    def reject_delegation(
        self,
        request_id: str,
        reason: str = "Unknown",
    ) -> bool:
        """
        Reject a delegation request

        Args:
            request_id: ID of the request to reject
            reason: Reason for rejection

        Returns:
            True if successful, False otherwise
        """
        request = self._requests.get(request_id)
        if not request:
            return False

        if request.status != DelegationStatus.PENDING:
            return False

        request.status = DelegationStatus.REJECTED
        request.reason_for_rejection = reason

        return True

    def complete_delegation(
        self,
        request_id: str,
        result_data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Mark a delegation as completed

        Args:
            request_id: ID of the request to complete
            result_data: Result data from the delegated task

        Returns:
            True if successful, False otherwise
        """
        request = self._requests.get(request_id)
        if not request:
            return False

        if request.status != DelegationStatus.APPROVED:
            return False

        request.status = DelegationStatus.COMPLETED
        request.completed_at = datetime.utcnow()
        if result_data:
            request.metadata["result"] = result_data

        return True

    def revoke_delegation(self, request_id: str) -> bool:
        """
        Revoke an approved delegation

        Args:
            request_id: ID of the request to revoke

        Returns:
            True if successful, False otherwise
        """
        request = self._requests.get(request_id)
        if not request:
            return False

        if request.status not in [DelegationStatus.APPROVED, DelegationStatus.PENDING]:
            return False

        request.status = DelegationStatus.REVOKED

        return True

    # ========================================================================
    # Delegation Chain Management
    # ========================================================================

    def get_delegation_chain(self, task_id: str) -> List[str]:
        """Get the delegation chain for a task"""
        return self._delegation_chains.get(task_id, []).copy()

    def get_agent_delegations(self, agent_id: str) -> List[DelegationRequest]:
        """Get all delegation requests for an agent"""
        request_ids = self._agent_delegations.get(agent_id, [])
        return [
            self._requests[rid]
            for rid in request_ids
            if rid in self._requests
        ]

    def get_active_delegations(self, agent_id: str) -> List[DelegationRequest]:
        """Get all active delegations for an agent"""
        all_delegations = self.get_agent_delegations(agent_id)
        return [
            d for d in all_delegations
            if d.status == DelegationStatus.APPROVED and not d.is_expired()
        ]

    # ========================================================================
    # Scope Management
    # ========================================================================

    def reduce_scopes(
        self,
        source_scopes: List[str],
        required_scopes: List[str],
    ) -> List[str]:
        """
        Reduce scopes based on principle of least privilege

        Args:
            source_scopes: Scopes the source agent has
            required_scopes: Scopes needed for the task

        Returns:
            The reduced scope list (intersection of source and required)
        """
        source_set = set(source_scopes)
        required_set = set(required_scopes)
        reduced = list(source_set & required_set)
        return reduced

    # ========================================================================
    # Validation and Information
    # ========================================================================

    def can_delegate(
        self,
        source_agent: BaseAgent,
        target_agent: BaseAgent,
    ) -> bool:
        """
        Check if source agent can delegate to target agent

        Args:
            source_agent: Agent attempting to delegate
            target_agent: Target agent

        Returns:
            True if delegation is allowed, False otherwise
        """
        # Check source can delegate
        if not source_agent.can_delegate(self.max_delegation_depth):
            return False

        # Check target is not in source's delegation chain
        # (prevent circular delegations)
        if target_agent.agent_id in source_agent.get_delegation_chain():
            return False

        return True

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all delegations"""
        active = [d for d in self._requests.values() if d.status == DelegationStatus.APPROVED]
        pending = [d for d in self._requests.values() if d.status == DelegationStatus.PENDING]
        rejected = [d for d in self._requests.values() if d.status == DelegationStatus.REJECTED]
        completed = [d for d in self._requests.values() if d.status == DelegationStatus.COMPLETED]

        return {
            "total_requests": len(self._requests),
            "active_delegations": len(active),
            "pending_requests": len(pending),
            "rejected_requests": len(rejected),
            "completed_requests": len(completed),
            "max_delegation_depth": self.max_delegation_depth,
            "active_chains": len(self._delegation_chains),
        }

    def __repr__(self) -> str:
        """String representation"""
        return f"DelegationManager(requests={len(self._requests)})"
