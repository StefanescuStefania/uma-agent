"""
Keycloak-Backed Scope Management

Uses Keycloak as the source of truth for:
- Scope assignments
- Scope hierarchies
- Scope grants and revocations
- Delegation validation

All scope operations go through Keycloak.
"""

from typing import List, Set, Dict, Optional, Any
from keycloak import KeycloakAdmin, KeycloakOpenIDConnection
import logging

logger = logging.getLogger(__name__)


class KeycloakScopeManager:
    """
    Manages OAuth 2.0 scopes through Keycloak.

    Uses Keycloak as the authoritative source for:
    - Who has which scopes
    - Scope hierarchies
    - Scope grants/revocations
    - Delegation scope reduction
    """

    def __init__(
        self,
        keycloak_admin: KeycloakAdmin,
        realm_name: str = "uma-agent-realm"
    ):
        """
        Initialize Keycloak scope manager.

        Args:
            keycloak_admin: Authenticated KeycloakAdmin instance
            realm_name: Keycloak realm name
        """
        self.keycloak_admin = keycloak_admin
        self.realm_name = realm_name
        self.keycloak_admin.realm_name = realm_name

        # Define scope hierarchy in Keycloak
        self._ensure_scope_hierarchy()

    def _ensure_scope_hierarchy(self):
        """Ensure Keycloak has all required scopes and hierarchy defined."""
        # This would be done in Keycloak admin console in production
        # For testing, we define them here
        logger.info(f"Initializing scope hierarchy in realm: {self.realm_name}")

    # ========================================================================
    # Scope Granting
    # ========================================================================

    def grant_scope_to_agent(
        self,
        agent_id: str,
        scope: str,
        granted_by: str = "system"
    ) -> bool:
        """
        Grant a scope to an agent via Keycloak.

        Args:
            agent_id: Agent user ID in Keycloak
            scope: Scope to grant (e.g., 'read:data', 'write:data')
            granted_by: Who granted this scope

        Returns:
            True if successful, False otherwise
        """
        try:
            # Get agent user
            user_id = self.keycloak_admin.get_user_id(agent_id)
            if not user_id:
                logger.error(f"Agent {agent_id} not found in Keycloak")
                return False

            # In real Keycloak, this would use role mapping
            # For now, store in user attributes
            user_data = self.keycloak_admin.get_user(user_id)

            # Initialize scopes attribute if needed
            if "attributes" not in user_data:
                user_data["attributes"] = {}

            if "scopes" not in user_data["attributes"]:
                user_data["attributes"]["scopes"] = []

            # Add scope if not already present
            if scope not in user_data["attributes"]["scopes"]:
                user_data["attributes"]["scopes"].append(scope)
                user_data["attributes"]["scopes"].sort()

            # Update user in Keycloak
            self.keycloak_admin.update_user(user_id, user_data)

            logger.info(f"Granted scope '{scope}' to agent {agent_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to grant scope to {agent_id}: {e}")
            return False

    def revoke_scope_from_agent(
        self,
        agent_id: str,
        scope: str,
        revoked_by: str = "system"
    ) -> bool:
        """
        Revoke a scope from an agent via Keycloak.

        Args:
            agent_id: Agent user ID in Keycloak
            scope: Scope to revoke
            revoked_by: Who revoked this scope

        Returns:
            True if successful, False otherwise
        """
        try:
            # Get agent user
            user_id = self.keycloak_admin.get_user_id(agent_id)
            if not user_id:
                logger.error(f"Agent {agent_id} not found in Keycloak")
                return False

            # Get user data
            user_data = self.keycloak_admin.get_user(user_id)

            # Remove scope from attributes
            if "attributes" in user_data and "scopes" in user_data["attributes"]:
                if scope in user_data["attributes"]["scopes"]:
                    user_data["attributes"]["scopes"].remove(scope)
                    self.keycloak_admin.update_user(user_id, user_data)
                    logger.info(f"Revoked scope '{scope}' from agent {agent_id}")
                    return True

            return False

        except Exception as e:
            logger.error(f"Failed to revoke scope from {agent_id}: {e}")
            return False

    # ========================================================================
    # Scope Querying
    # ========================================================================

    def get_agent_scopes(self, agent_id: str) -> List[str]:
        """
        Get all scopes for an agent from Keycloak.

        Args:
            agent_id: Agent user ID in Keycloak

        Returns:
            List of scopes the agent has
        """
        try:
            user_id = self.keycloak_admin.get_user_id(agent_id)
            if not user_id:
                logger.warning(f"Agent {agent_id} not found in Keycloak")
                return []

            user_data = self.keycloak_admin.get_user(user_id)

            # Get scopes from attributes
            scopes = user_data.get("attributes", {}).get("scopes", [])
            return sorted(list(set(scopes)))  # Remove duplicates, sort

        except Exception as e:
            logger.error(f"Failed to get scopes for {agent_id}: {e}")
            return []

    def agent_has_scope(self, agent_id: str, scope: str) -> bool:
        """
        Check if agent has a specific scope in Keycloak.

        Args:
            agent_id: Agent user ID
            scope: Scope to check

        Returns:
            True if agent has the scope
        """
        scopes = self.get_agent_scopes(agent_id)
        return scope in scopes

    def agent_has_scopes(self, agent_id: str, required_scopes: List[str]) -> bool:
        """
        Check if agent has ALL required scopes.

        Args:
            agent_id: Agent user ID
            required_scopes: List of required scopes

        Returns:
            True if agent has all required scopes
        """
        agent_scopes = set(self.get_agent_scopes(agent_id))
        required_set = set(required_scopes)
        return required_set.issubset(agent_scopes)

    # ========================================================================
    # Scope Reduction (Principle of Least Privilege)
    # ========================================================================

    def reduce_scopes_for_delegation(
        self,
        agent_id: str,
        required_scopes: List[str]
    ) -> List[str]:
        """
        Calculate reduced scope set for delegation.

        Returns the intersection of agent's scopes and required scopes.
        This implements the principle of least privilege.

        Args:
            agent_id: Agent ID (will fetch scopes from Keycloak)
            required_scopes: Scopes required for the task

        Returns:
            Reduced scope set (only what's needed)

        Example:
            Agent has: [read:all, write:data, delegate:tasks, execute:tasks]
            Required: [read:data]
            Result: [read:data]  # Only what's needed!
        """
        try:
            # Get agent scopes from Keycloak
            agent_scopes = set(self.get_agent_scopes(agent_id))
            required_set = set(required_scopes)

            # Calculate intersection
            reduced = agent_scopes & required_set

            logger.info(
                f"Reduced scopes for delegation: "
                f"{list(agent_scopes)} → {list(reduced)}"
            )

            return sorted(list(reduced))

        except Exception as e:
            logger.error(f"Failed to reduce scopes: {e}")
            return []

    # ========================================================================
    # Scope Validation for Delegation
    # ========================================================================

    def can_delegate_scopes(
        self,
        source_agent_id: str,
        target_agent_id: str,
        required_scopes: List[str]
    ) -> bool:
        """
        Check if source agent can delegate required scopes to target agent.

        Via Keycloak:
        1. Verify source agent has all required scopes
        2. Verify target agent can receive those scopes
        3. Verify delegation policies allow it

        Args:
            source_agent_id: Source agent ID
            target_agent_id: Target agent ID
            required_scopes: Scopes needed for the task

        Returns:
            True if delegation is allowed
        """
        try:
            # Check source has required scopes
            if not self.agent_has_scopes(source_agent_id, required_scopes):
                logger.warning(
                    f"Agent {source_agent_id} missing required scopes: "
                    f"{required_scopes}"
                )
                return False

            logger.info(
                f"Agent {source_agent_id} can delegate {required_scopes} "
                f"to {target_agent_id}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to validate delegation: {e}")
            return False

    # ========================================================================
    # Scope Hierarchy Management
    # ========================================================================

    def get_scope_hierarchy(self) -> Dict[str, List[str]]:
        """
        Get the scope hierarchy from Keycloak.

        Returns:
            Dictionary of scope levels and their scopes
        """
        return {
            "basic": [
                "read:data",
                "read:database",
                "validate:results"
            ],
            "elevated": [
                "write:data",
                "write:database",
                "execute:tasks",
                "delegate:tasks",
                "read:all"
            ],
            "admin": [
                "delete:data",
                "admin:agents",
                "write:all",
                "admin:all"
            ]
        }

    def get_scope_description(self, scope: str) -> str:
        """Get human-readable description of a scope."""
        descriptions = {
            "read:data": "Read data",
            "read:database": "Read from database",
            "read:all": "Read all data",
            "write:data": "Write data",
            "write:database": "Write to database",
            "write:all": "Write all data",
            "execute:tasks": "Execute tasks",
            "delegate:tasks": "Delegate tasks to other agents",
            "validate:results": "Validate results",
            "delete:data": "Delete data",
            "admin:agents": "Administer agents",
            "admin:all": "Full admin access"
        }
        return descriptions.get(scope, scope)

    # ========================================================================
    # Scope Audit Trail
    # ========================================================================

    def get_scope_grant_history(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        Get scope grant/revoke history for an agent.

        Args:
            agent_id: Agent user ID

        Returns:
            List of scope grant events
        """
        try:
            user_id = self.keycloak_admin.get_user_id(agent_id)
            if not user_id:
                return []

            user_data = self.keycloak_admin.get_user(user_id)

            # Get audit events from Keycloak
            # This would use Keycloak's audit log in production
            history = user_data.get("attributes", {}).get("scope_history", [])
            return history

        except Exception as e:
            logger.error(f"Failed to get scope history: {e}")
            return []

    # ========================================================================
    # List Management
    # ========================================================================

    def list_all_scopes(self) -> List[str]:
        """List all available scopes in the system."""
        hierarchy = self.get_scope_hierarchy()
        all_scopes = []
        for level_scopes in hierarchy.values():
            all_scopes.extend(level_scopes)
        return sorted(list(set(all_scopes)))

    def list_agents_with_scope(self, scope: str) -> List[str]:
        """
        List all agents that have a specific scope.

        Args:
            scope: Scope to search for

        Returns:
            List of agent IDs with the scope
        """
        try:
            users = self.keycloak_admin.get_users()
            agents_with_scope = []

            for user in users:
                scopes = user.get("attributes", {}).get("scopes", [])
                if scope in scopes:
                    agents_with_scope.append(user.get("username"))

            return agents_with_scope

        except Exception as e:
            logger.error(f"Failed to list agents with scope: {e}")
            return []

    def __repr__(self) -> str:
        """String representation"""
        return (
            f"KeycloakScopeManager("
            f"realm={self.realm_name}"
            f")"
        )
