"""
Keycloak-Backed Delegation Management

Uses Keycloak as the source of truth for:
- Delegation requests
- Delegation approvals
- Scope reduction and validation
- Delegation policies
- Audit trail

All delegation operations are validated against Keycloak.
"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from keycloak import KeycloakAdmin
import logging
import uuid

logger = logging.getLogger(__name__)


class DelegationStatus(str, Enum):
    """Status of a delegation request"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"
    COMPLETED = "completed"
    EXPIRED = "expired"


@dataclass
class KeycloakDelegationRequest:
    """A delegation request tracked in Keycloak"""
    request_id: str
    source_agent_id: str
    target_agent_id: str
    status: DelegationStatus
    required_scopes: List[str]
    granted_scopes: List[str]
    task_description: str
    created_at: datetime
    expires_at: datetime
    approved_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    rejection_reason: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if delegation request has expired"""
        return datetime.now() > self.expires_at

    def time_remaining_hours(self) -> float:
        """Get remaining time in hours"""
        if self.is_expired():
            return 0.0
        return (self.expires_at - datetime.now()).total_seconds() / 3600


class KeycloakDelegationManager:
    """
    Manages task delegation through Keycloak.

    Uses Keycloak as authoritative source for:
    - Delegation requests and approvals
    - Scope validation and reduction
    - Delegation audit trail
    """

    def __init__(
        self,
        keycloak_admin: KeycloakAdmin,
        keycloak_scope_manager,
        realm_name: str = "uma-agent-realm",
        max_delegation_depth: int = 3
    ):
        """
        Initialize Keycloak delegation manager.

        Args:
            keycloak_admin: Authenticated KeycloakAdmin instance
            keycloak_scope_manager: KeycloakScopeManager instance
            realm_name: Keycloak realm name
            max_delegation_depth: Maximum depth of delegation chains
        """
        self.keycloak_admin = keycloak_admin
        self.scope_manager = keycloak_scope_manager
        self.realm_name = realm_name
        self.max_delegation_depth = max_delegation_depth
        self.keycloak_admin.realm_name = realm_name

        # In-memory storage for demonstration
        # In production, store in Keycloak or database
        self._delegations: Dict[str, KeycloakDelegationRequest] = {}

    # ========================================================================
    # Delegation Request Creation
    # ========================================================================

    def create_delegation_request(
        self,
        source_agent_id: str,
        target_agent_id: str,
        task_description: str,
        required_scopes: List[str],
        expires_in_hours: int = 24
    ) -> Optional[KeycloakDelegationRequest]:
        """
        Create a delegation request validated against Keycloak.

        Validates:
        1. Source agent exists in Keycloak
        2. Target agent exists in Keycloak
        3. Source agent has all required scopes
        4. Scopes can be delegated

        Args:
            source_agent_id: Source agent ID
            target_agent_id: Target agent ID
            task_description: What task is being delegated
            required_scopes: Required scopes for the task
            expires_in_hours: When delegation expires

        Returns:
            DelegationRequest if successful, None otherwise
        """
        try:
            # Verify agents exist in Keycloak
            source_user_id = self.keycloak_admin.get_user_id(source_agent_id)
            if not source_user_id:
                logger.error(f"Source agent {source_agent_id} not found in Keycloak")
                return None

            target_user_id = self.keycloak_admin.get_user_id(target_agent_id)
            if not target_user_id:
                logger.error(f"Target agent {target_agent_id} not found in Keycloak")
                return None

            # Validate source agent has required scopes
            if not self.scope_manager.agent_has_scopes(source_agent_id, required_scopes):
                logger.error(
                    f"Agent {source_agent_id} missing required scopes: {required_scopes}"
                )
                return None

            # Calculate reduced scopes (principle of least privilege)
            reduced_scopes = self.scope_manager.reduce_scopes_for_delegation(
                source_agent_id,
                required_scopes
            )

            if not reduced_scopes:
                logger.error("Scope reduction resulted in empty scope set")
                return None

            # Create delegation request
            request_id = str(uuid.uuid4())[:8]
            now = datetime.now()
            expires_at = now + timedelta(hours=expires_in_hours)

            delegation = KeycloakDelegationRequest(
                request_id=request_id,
                source_agent_id=source_agent_id,
                target_agent_id=target_agent_id,
                status=DelegationStatus.PENDING,
                required_scopes=required_scopes,
                granted_scopes=reduced_scopes,
                task_description=task_description,
                created_at=now,
                expires_at=expires_at
            )

            # Store in Keycloak user attributes
            self._store_delegation_in_keycloak(delegation)

            # Store locally for quick access
            self._delegations[request_id] = delegation

            logger.info(
                f"Created delegation {request_id}: "
                f"{source_agent_id} → {target_agent_id} "
                f"scopes={reduced_scopes}"
            )

            return delegation

        except Exception as e:
            logger.error(f"Failed to create delegation request: {e}")
            return None

    # ========================================================================
    # Delegation Approval
    # ========================================================================

    def approve_delegation(
        self,
        request_id: str,
        approver_id: str = "system"
    ) -> bool:
        """
        Approve a delegation request.

        Updates Keycloak to:
        1. Mark delegation as approved
        2. Grant scopes to target agent
        3. Record audit trail

        Args:
            request_id: Delegation request ID
            approver_id: Who approved this delegation

        Returns:
            True if successful, False otherwise
        """
        try:
            if request_id not in self._delegations:
                logger.error(f"Delegation {request_id} not found")
                return False

            delegation = self._delegations[request_id]

            if delegation.is_expired():
                logger.error(f"Delegation {request_id} has expired")
                delegation.status = DelegationStatus.EXPIRED
                return False

            # Grant scopes to target agent via Keycloak
            for scope in delegation.granted_scopes:
                if not self.scope_manager.grant_scope_to_agent(
                    delegation.target_agent_id,
                    scope,
                    granted_by=approver_id
                ):
                    logger.error(
                        f"Failed to grant scope {scope} to target agent"
                    )
                    return False

            # Update delegation status
            delegation.status = DelegationStatus.APPROVED
            delegation.approved_at = datetime.now()
            delegation.approved_by = approver_id

            # Update in Keycloak
            self._update_delegation_in_keycloak(delegation)

            logger.info(
                f"Approved delegation {request_id}: "
                f"granted scopes {delegation.granted_scopes} "
                f"to {delegation.target_agent_id}"
            )

            return True

        except Exception as e:
            logger.error(f"Failed to approve delegation: {e}")
            return False

    # ========================================================================
    # Delegation Rejection
    # ========================================================================

    def reject_delegation(
        self,
        request_id: str,
        reason: str = "Not approved",
        rejected_by: str = "system"
    ) -> bool:
        """
        Reject a delegation request.

        Args:
            request_id: Delegation request ID
            reason: Reason for rejection
            rejected_by: Who rejected this delegation

        Returns:
            True if successful
        """
        try:
            if request_id not in self._delegations:
                logger.error(f"Delegation {request_id} not found")
                return False

            delegation = self._delegations[request_id]
            delegation.status = DelegationStatus.REJECTED
            delegation.rejection_reason = reason

            self._update_delegation_in_keycloak(delegation)

            logger.info(
                f"Rejected delegation {request_id}: {reason}"
            )

            return True

        except Exception as e:
            logger.error(f"Failed to reject delegation: {e}")
            return False

    # ========================================================================
    # Delegation Revocation
    # ========================================================================

    def revoke_delegation(
        self,
        request_id: str,
        revoked_by: str = "system"
    ) -> bool:
        """
        Revoke an approved delegation.

        Removes granted scopes from target agent.

        Args:
            request_id: Delegation request ID
            revoked_by: Who revoked this delegation

        Returns:
            True if successful
        """
        try:
            if request_id not in self._delegations:
                logger.error(f"Delegation {request_id} not found")
                return False

            delegation = self._delegations[request_id]

            if delegation.status != DelegationStatus.APPROVED:
                logger.error(f"Can only revoke approved delegations")
                return False

            # Revoke scopes from target agent
            for scope in delegation.granted_scopes:
                self.scope_manager.revoke_scope_from_agent(
                    delegation.target_agent_id,
                    scope,
                    revoked_by=revoked_by
                )

            # Update delegation status
            delegation.status = DelegationStatus.REVOKED

            self._update_delegation_in_keycloak(delegation)

            logger.info(f"Revoked delegation {request_id}")

            return True

        except Exception as e:
            logger.error(f"Failed to revoke delegation: {e}")
            return False

    # ========================================================================
    # Delegation Queries
    # ========================================================================

    def get_delegation(self, request_id: str) -> Optional[KeycloakDelegationRequest]:
        """Get a delegation request by ID"""
        return self._delegations.get(request_id)

    def get_delegations_from_agent(
        self,
        agent_id: str,
        status: Optional[DelegationStatus] = None
    ) -> List[KeycloakDelegationRequest]:
        """Get all delegations created by an agent"""
        delegations = [
            d for d in self._delegations.values()
            if d.source_agent_id == agent_id
        ]

        if status:
            delegations = [d for d in delegations if d.status == status]

        return delegations

    def get_delegations_to_agent(
        self,
        agent_id: str,
        status: Optional[DelegationStatus] = None
    ) -> List[KeycloakDelegationRequest]:
        """Get all delegations received by an agent"""
        delegations = [
            d for d in self._delegations.values()
            if d.target_agent_id == agent_id
        ]

        if status:
            delegations = [d for d in delegations if d.status == status]

        return delegations

    def get_pending_delegations(self) -> List[KeycloakDelegationRequest]:
        """Get all pending delegations"""
        return [
            d for d in self._delegations.values()
            if d.status == DelegationStatus.PENDING and not d.is_expired()
        ]

    def list_all_delegations(self) -> List[KeycloakDelegationRequest]:
        """List all delegations"""
        return list(self._delegations.values())

    # ========================================================================
    # Keycloak Integration
    # ========================================================================

    def _store_delegation_in_keycloak(
        self,
        delegation: KeycloakDelegationRequest
    ) -> bool:
        """Store delegation in Keycloak source agent's attributes"""
        try:
            source_user_id = self.keycloak_admin.get_user_id(
                delegation.source_agent_id
            )
            if not source_user_id:
                return False

            user_data = self.keycloak_admin.get_user(source_user_id)

            if "attributes" not in user_data:
                user_data["attributes"] = {}

            if "delegations" not in user_data["attributes"]:
                user_data["attributes"]["delegations"] = []

            delegation_data = {
                "request_id": delegation.request_id,
                "target_agent_id": delegation.target_agent_id,
                "status": delegation.status.value,
                "scopes": delegation.granted_scopes,
                "created_at": delegation.created_at.isoformat(),
                "expires_at": delegation.expires_at.isoformat()
            }

            user_data["attributes"]["delegations"].append(delegation_data)

            self.keycloak_admin.update_user(source_user_id, user_data)
            return True

        except Exception as e:
            logger.error(f"Failed to store delegation in Keycloak: {e}")
            return False

    def _update_delegation_in_keycloak(
        self,
        delegation: KeycloakDelegationRequest
    ) -> bool:
        """Update delegation status in Keycloak"""
        try:
            source_user_id = self.keycloak_admin.get_user_id(
                delegation.source_agent_id
            )
            if not source_user_id:
                return False

            user_data = self.keycloak_admin.get_user(source_user_id)

            # Find and update delegation
            delegations = user_data.get("attributes", {}).get("delegations", [])
            for deleg in delegations:
                if deleg["request_id"] == delegation.request_id:
                    deleg["status"] = delegation.status.value
                    deleg["approved_at"] = (
                        delegation.approved_at.isoformat()
                        if delegation.approved_at else None
                    )
                    break

            user_data["attributes"]["delegations"] = delegations
            self.keycloak_admin.update_user(source_user_id, user_data)
            return True

        except Exception as e:
            logger.error(f"Failed to update delegation in Keycloak: {e}")
            return False

    # ========================================================================
    # Delegation Statistics
    # ========================================================================

    def get_delegation_statistics(self) -> Dict[str, Any]:
        """Get statistics about delegations"""
        delegations = self._delegations.values()

        return {
            "total": len(delegations),
            "pending": len([d for d in delegations if d.status == DelegationStatus.PENDING]),
            "approved": len([d for d in delegations if d.status == DelegationStatus.APPROVED]),
            "rejected": len([d for d in delegations if d.status == DelegationStatus.REJECTED]),
            "revoked": len([d for d in delegations if d.status == DelegationStatus.REVOKED]),
            "completed": len([d for d in delegations if d.status == DelegationStatus.COMPLETED]),
            "expired": len([d for d in delegations if d.is_expired()])
        }

    def __repr__(self) -> str:
        """String representation"""
        return (
            f"KeycloakDelegationManager("
            f"realm={self.realm_name}, "
            f"delegations={len(self._delegations)}"
            f")"
        )
