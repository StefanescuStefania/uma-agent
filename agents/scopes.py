"""
Scope Management System - OAuth 2.0 Scope handling for agents

Provides:
- Scope definitions
- Scope assignment and revocation
- Scope reduction for delegation
- Scope validation
"""

from enum import Enum
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


class StandardScope(str, Enum):
    """Standard OAuth 2.0 scopes for agents"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    DELEGATE = "delegate"
    EXECUTE = "execute"
    VALIDATE = "validate"
    ADMIN = "admin"


@dataclass
class Scope:
    """Represents an OAuth 2.0 scope"""
    name: str
    description: str = ""
    level: int = 0  # 0=basic, 1=elevated, 2=admin

    def __str__(self) -> str:
        return self.name

    def __eq__(self, other) -> bool:
        if isinstance(other, Scope):
            return self.name == other.name
        return self.name == str(other)

    def __hash__(self) -> int:
        return hash(self.name)


class ScopeManager:
    """Manages scopes for agents"""

    # Standard scopes
    STANDARD_SCOPES = {
        "read:data": Scope("read:data", "Read data access", level=0),
        "write:data": Scope("write:data", "Write data access", level=1),
        "delete:data": Scope("delete:data", "Delete data access", level=2),
        "read:database": Scope("read:database", "Database read access", level=0),
        "write:database": Scope("write:database", "Database write access", level=1),
        "execute:tasks": Scope("execute:tasks", "Execute tasks", level=1),
        "delegate:tasks": Scope("delegate:tasks", "Delegate tasks", level=1),
        "validate:results": Scope("validate:results", "Validate results", level=0),
        "admin:agents": Scope("admin:agents", "Agent administration", level=2),
        "read:all": Scope("read:all", "Read all resources", level=1),
        "write:all": Scope("write:all", "Write all resources", level=2),
        "admin:all": Scope("admin:all", "Full administration", level=2),
    }

    def __init__(self):
        """Initialize scope manager"""
        self._agent_scopes: Dict[str, Set[str]] = {}  # agent_id -> scope names
        self._scope_definitions: Dict[str, Scope] = self.STANDARD_SCOPES.copy()
        self._scope_grants: Dict[str, List[Dict[str, Any]]] = {}  # agent_id -> grant history

    # ========================================================================
    # Scope Definition
    # ========================================================================

    def register_scope(
        self,
        scope_name: str,
        description: str = "",
        level: int = 0,
    ) -> Scope:
        """Register a new scope"""
        if scope_name in self._scope_definitions:
            logger.warning(f"Scope {scope_name} already registered")
            return self._scope_definitions[scope_name]

        scope = Scope(scope_name, description, level)
        self._scope_definitions[scope_name] = scope
        logger.info(f"Registered scope: {scope_name}")
        return scope

    def get_scope(self, scope_name: str) -> Optional[Scope]:
        """Get scope definition"""
        return self._scope_definitions.get(scope_name)

    def list_scopes(self) -> List[Scope]:
        """List all defined scopes"""
        return list(self._scope_definitions.values())

    # ========================================================================
    # Agent Scope Assignment
    # ========================================================================

    def grant_scope(
        self,
        agent_id: str,
        scope_name: str,
        granted_by: Optional[str] = None,
    ) -> bool:
        """
        Grant a scope to an agent

        Args:
            agent_id: Agent ID
            scope_name: Scope name
            granted_by: ID of agent/admin granting scope

        Returns:
            True if granted successfully
        """
        if scope_name not in self._scope_definitions:
            logger.warning(f"Scope {scope_name} not defined")
            return False

        if agent_id not in self._agent_scopes:
            self._agent_scopes[agent_id] = set()

        if scope_name in self._agent_scopes[agent_id]:
            logger.warning(f"Agent {agent_id} already has scope {scope_name}")
            return True  # Already granted

        self._agent_scopes[agent_id].add(scope_name)

        # Log grant
        if agent_id not in self._scope_grants:
            self._scope_grants[agent_id] = []

        self._scope_grants[agent_id].append({
            "action": "grant",
            "scope": scope_name,
            "granted_by": granted_by,
        })

        logger.info(f"Granted scope {scope_name} to agent {agent_id}")
        return True

    def revoke_scope(
        self,
        agent_id: str,
        scope_name: str,
        revoked_by: Optional[str] = None,
    ) -> bool:
        """
        Revoke a scope from an agent

        Args:
            agent_id: Agent ID
            scope_name: Scope name
            revoked_by: ID of agent/admin revoking scope

        Returns:
            True if revoked successfully
        """
        if agent_id not in self._agent_scopes:
            logger.warning(f"Agent {agent_id} not found")
            return False

        if scope_name not in self._agent_scopes[agent_id]:
            logger.warning(f"Agent {agent_id} does not have scope {scope_name}")
            return False

        self._agent_scopes[agent_id].discard(scope_name)

        # Log revocation
        if agent_id not in self._scope_grants:
            self._scope_grants[agent_id] = []

        self._scope_grants[agent_id].append({
            "action": "revoke",
            "scope": scope_name,
            "revoked_by": revoked_by,
        })

        logger.info(f"Revoked scope {scope_name} from agent {agent_id}")
        return True

    def has_scope(self, agent_id: str, scope_name: str) -> bool:
        """Check if agent has a scope"""
        if agent_id not in self._agent_scopes:
            return False
        return scope_name in self._agent_scopes[agent_id]

    def get_agent_scopes(self, agent_id: str) -> List[str]:
        """Get all scopes for an agent"""
        return sorted(list(self._agent_scopes.get(agent_id, set())))

    def set_agent_scopes(self, agent_id: str, scopes: List[str]) -> bool:
        """Set all scopes for an agent (replaces existing)"""
        # Validate all scopes exist
        for scope in scopes:
            if scope not in self._scope_definitions:
                logger.warning(f"Invalid scope: {scope}")
                return False

        self._agent_scopes[agent_id] = set(scopes)
        logger.info(f"Set scopes for {agent_id}: {scopes}")
        return True

    # ========================================================================
    # Scope Reduction
    # ========================================================================

    def reduce_scopes(
        self,
        agent_id: str,
        required_scopes: List[str],
    ) -> List[str]:
        """
        Calculate reduced scope set for delegation

        Implements principle of least privilege:
        Delegated scopes = intersection of (agent scopes, required scopes)

        Args:
            agent_id: Agent ID
            required_scopes: Scopes being delegated

        Returns:
            Reduced scope set
        """
        agent_scopes = self._agent_scopes.get(agent_id, set())
        required_set = set(required_scopes)

        # Intersection: agent must have all requested scopes
        reduced = agent_scopes & required_set

        logger.info(
            f"Reduced scopes for delegation from {agent_id}: "
            f"{agent_scopes} & {required_set} = {reduced}"
        )

        return sorted(list(reduced))

    def can_delegate_scope(
        self,
        agent_id: str,
        scope_name: str,
    ) -> bool:
        """Check if agent can delegate a scope"""
        return self.has_scope(agent_id, scope_name)

    def can_delegate_scopes(
        self,
        agent_id: str,
        required_scopes: List[str],
    ) -> bool:
        """Check if agent can delegate all required scopes"""
        agent_scopes = set(self.get_agent_scopes(agent_id))
        required_set = set(required_scopes)
        return required_set.issubset(agent_scopes)

    # ========================================================================
    # Scope Hierarchy & Validation
    # ========================================================================

    def get_scope_level(self, scope_name: str) -> int:
        """Get privilege level of a scope"""
        scope = self.get_scope(scope_name)
        return scope.level if scope else -1

    def get_max_scope_level(self, agent_id: str) -> int:
        """Get maximum privilege level of agent's scopes"""
        scopes = self.get_agent_scopes(agent_id)
        if not scopes:
            return -1

        return max(self.get_scope_level(s) for s in scopes)

    def is_admin_scope(self, scope_name: str) -> bool:
        """Check if scope is an admin scope"""
        scope = self.get_scope(scope_name)
        return scope.level == 2 if scope else False

    def validate_scopes(self, scope_list: List[str]) -> bool:
        """Validate that all scopes are defined"""
        for scope in scope_list:
            if scope not in self._scope_definitions:
                logger.warning(f"Invalid scope: {scope}")
                return False
        return True

    # ========================================================================
    # Scope Queries
    # ========================================================================

    def get_agents_with_scope(self, scope_name: str) -> List[str]:
        """Get all agents that have a scope"""
        return [
            agent_id for agent_id, scopes in self._agent_scopes.items()
            if scope_name in scopes
        ]

    def get_agents_with_admin_scopes(self) -> List[str]:
        """Get all agents with admin-level scopes"""
        admin_agents = []
        for agent_id, scopes in self._agent_scopes.items():
            if any(self.is_admin_scope(s) for s in scopes):
                admin_agents.append(agent_id)
        return admin_agents

    def get_scope_grant_history(self, agent_id: str) -> List[Dict[str, Any]]:
        """Get scope grant/revoke history for an agent"""
        return self._scope_grants.get(agent_id, [])

    # ========================================================================
    # Statistics & Reporting
    # ========================================================================

    def get_agent_scope_stats(self, agent_id: str) -> Dict[str, Any]:
        """Get scope statistics for an agent"""
        scopes = self.get_agent_scopes(agent_id)
        admin_scopes = [s for s in scopes if self.is_admin_scope(s)]
        elevated_scopes = [s for s in scopes if self.get_scope_level(s) == 1]
        basic_scopes = [s for s in scopes if self.get_scope_level(s) == 0]

        return {
            "agent_id": agent_id,
            "total_scopes": len(scopes),
            "admin_scopes": len(admin_scopes),
            "elevated_scopes": len(elevated_scopes),
            "basic_scopes": len(basic_scopes),
            "max_level": self.get_max_scope_level(agent_id),
            "scopes": scopes,
        }

    def get_summary(self) -> Dict[str, Any]:
        """Get scope manager summary"""
        all_scopes = []
        admin_agents = self.get_agents_with_admin_scopes()

        for agent_id, scopes in self._agent_scopes.items():
            all_scopes.extend(scopes)

        return {
            "total_agents": len(self._agent_scopes),
            "total_unique_scopes": len(set(all_scopes)),
            "defined_scopes": len(self._scope_definitions),
            "agents_with_admin_scopes": len(admin_agents),
            "total_scope_assignments": sum(len(s) for s in self._agent_scopes.values()),
        }

    def __repr__(self) -> str:
        """String representation"""
        return f"ScopeManager(agents={len(self._agent_scopes)}, scopes={len(self._scope_definitions)})"
