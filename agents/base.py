"""
Base Agent Class - Foundation for all UMA-Agent implementations

Provides:
- Agent identity and metadata
- Authentication token management
- Capability tracking
- Delegation request handling
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import uuid
import logging

# Import UMA client - will be set via dependency injection
try:
    from agents.uma_client import UMAClient, RPT, PermissionTicket
except ImportError:
    UMAClient = None
    RPT = None
    PermissionTicket = None

logger = logging.getLogger(__name__)


class AgentType(str, Enum):
    """Types of agents in the UMA system"""
    COORDINATOR = "coordinator"
    RESEARCHER = "researcher"
    EXECUTOR = "executor"
    VALIDATOR = "validator"
    CUSTOM = "custom"


class AgentCapability(str, Enum):
    """Capabilities that agents can have"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    DELEGATE = "delegate"
    VALIDATE = "validate"
    ORCHESTRATE = "orchestrate"
    ANALYZE = "analyze"
    EXECUTE = "execute"


@dataclass
class AgentToken:
    """Represents an agent's authentication token"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    issued_at: datetime = field(default_factory=datetime.utcnow)
    refresh_token: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if token has expired"""
        elapsed = (datetime.utcnow() - self.issued_at).total_seconds()
        return elapsed >= self.expires_in

    def time_remaining(self) -> int:
        """Get seconds remaining before expiration"""
        elapsed = (datetime.utcnow() - self.issued_at).total_seconds()
        return max(0, int(self.expires_in - elapsed))


@dataclass
class AgentMetadata:
    """Metadata about an agent"""
    agent_id: str
    agent_type: AgentType
    agent_name: str
    description: str
    capabilities: List[AgentCapability] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    version: str = "0.1.0"
    custom_metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAgent:
    """
    Base class for all UMA agents

    Attributes:
        agent_id: Unique identifier for this agent
        agent_type: Type of agent (coordinator, researcher, executor, etc.)
        capabilities: List of capabilities this agent has
        token: Current authentication token
        metadata: Agent metadata and information
    """

    def __init__(
        self,
        agent_id: Optional[str] = None,
        agent_type: AgentType = AgentType.CUSTOM,
        agent_name: str = "UnnamedAgent",
        description: str = "A UMA agent",
        capabilities: Optional[List[AgentCapability]] = None,
    ):
        """
        Initialize a new agent

        Args:
            agent_id: Unique identifier (auto-generated if not provided)
            agent_type: Type of agent
            agent_name: Human-readable name
            description: Agent description
            capabilities: List of capabilities
        """
        self.agent_id = agent_id or f"agent-{uuid.uuid4().hex[:8]}"
        self.agent_type = agent_type
        self.capabilities = capabilities or []
        self.token: Optional[AgentToken] = None

        # Create metadata
        self.metadata = AgentMetadata(
            agent_id=self.agent_id,
            agent_type=agent_type,
            agent_name=agent_name,
            description=description,
            capabilities=self.capabilities,
        )

        # Agent state
        self._delegation_chain: List[str] = [self.agent_id]
        self._scopes: List[str] = []
        self._is_authenticated = False
        self._custom_state: Dict[str, Any] = {}

        # UMA 2.0 Integration
        self._uma_client: Optional['UMAClient'] = None
        self._rpt: Optional['RPT'] = None
        self._resource_server_url: str = "http://localhost:5000"

    # ========================================================================
    # Token Management
    # ========================================================================

    def set_token(self, token: AgentToken) -> None:
        """Set the agent's authentication token"""
        self.token = token
        self._is_authenticated = True

    def get_token(self) -> Optional[AgentToken]:
        """Get the current token"""
        if self.token and self.token.is_expired():
            self._is_authenticated = False
            return None
        return self.token

    def has_valid_token(self) -> bool:
        """Check if agent has a valid token"""
        return self._is_authenticated and self.token is not None and not self.token.is_expired()

    def clear_token(self) -> None:
        """Clear the authentication token"""
        self.token = None
        self._is_authenticated = False

    # ========================================================================
    # Capability Management
    # ========================================================================

    def add_capability(self, capability: AgentCapability) -> None:
        """Add a capability to this agent"""
        if capability not in self.capabilities:
            self.capabilities.append(capability)
            self.metadata.capabilities = self.capabilities

    def remove_capability(self, capability: AgentCapability) -> None:
        """Remove a capability from this agent"""
        if capability in self.capabilities:
            self.capabilities.remove(capability)
            self.metadata.capabilities = self.capabilities

    def has_capability(self, capability: AgentCapability) -> bool:
        """Check if agent has a specific capability"""
        return capability in self.capabilities

    def get_capabilities(self) -> List[AgentCapability]:
        """Get all capabilities"""
        return self.capabilities.copy()

    # ========================================================================
    # Scope Management
    # ========================================================================

    def set_scopes(self, scopes: List[str]) -> None:
        """Set the scopes this agent has been granted"""
        self._scopes = scopes

    def add_scope(self, scope: str) -> None:
        """Add a scope"""
        if scope not in self._scopes:
            self._scopes.append(scope)

    def has_scope(self, scope: str) -> bool:
        """Check if agent has a scope"""
        return scope in self._scopes

    def get_scopes(self) -> List[str]:
        """Get all scopes"""
        return self._scopes.copy()

    # ========================================================================
    # Delegation Chain Management
    # ========================================================================

    def get_delegation_chain(self) -> List[str]:
        """Get the complete delegation chain"""
        return self._delegation_chain.copy()

    def get_delegation_depth(self) -> int:
        """Get how many steps deep in the delegation chain"""
        return len(self._delegation_chain)

    def can_delegate(self, max_depth: int = 3) -> bool:
        """Check if agent can still delegate"""
        return self.has_capability(AgentCapability.DELEGATE) and self.get_delegation_depth() < max_depth

    def create_delegation_chain(self, source_agent_id: str) -> List[str]:
        """
        Create a new delegation chain starting from this agent
        when delegating to another agent

        Args:
            source_agent_id: The agent we're delegating to

        Returns:
            The new delegation chain
        """
        if not self.can_delegate():
            raise ValueError(f"Agent {self.agent_id} cannot delegate")

        new_chain = self._delegation_chain + [source_agent_id]
        return new_chain

    def set_delegation_chain(self, chain: List[str]) -> None:
        """Set the delegation chain when delegating from another agent"""
        self._delegation_chain = chain.copy()

    # ========================================================================
    # Agent State Management
    # ========================================================================

    def set_state(self, key: str, value: Any) -> None:
        """Store custom state"""
        self._custom_state[key] = value

    def get_state(self, key: str, default: Any = None) -> Any:
        """Retrieve custom state"""
        return self._custom_state.get(key, default)

    def get_all_state(self) -> Dict[str, Any]:
        """Get all custom state"""
        return self._custom_state.copy()

    # ========================================================================
    # UMA 2.0 Integration
    # ========================================================================

    def set_uma_client(self, uma_client: 'UMAClient', resource_server_url: str = "http://localhost:5000") -> None:
        """
        Set the UMA client for this agent

        Args:
            uma_client: Configured UMA client instance
            resource_server_url: Base URL of the resource server
        """
        self._uma_client = uma_client
        self._resource_server_url = resource_server_url
        logger.info(f"UMA client configured for agent {self.agent_id}")

    def request_resource_access(
        self,
        resource: str,
        scope: str
    ) -> Optional['RPT']:
        """
        Request access to a protected resource via UMA 2.0

        This implements the complete UMA flow:
        1. Try to access resource → get permission ticket
        2. Exchange ticket for RPT using agent's token
        3. Store RPT for future use

        Args:
            resource: Resource name (e.g., 'documents', 'calendar')
            scope: Required scope (e.g., 'read', 'write')

        Returns:
            RPT if access granted, None if denied
        """
        if not self._uma_client:
            logger.error(f"Agent {self.agent_id}: UMA client not configured")
            return None

        if not self.has_valid_token():
            logger.error(f"Agent {self.agent_id}: No valid authentication token")
            return None

        try:
            # Step 1: Try to access resource (will get 401 with permission ticket)
            import requests

            url = f"{self._resource_server_url}/api/{resource}"
            response = requests.get(url)

            if response.status_code != 401:
                logger.error(f"Expected 401, got {response.status_code}")
                return None

            # Step 2: Extract permission ticket from WWW-Authenticate header
            import re
            www_auth = response.headers.get("WWW-Authenticate", "")
            ticket_match = re.search(r'ticket="([^"]+)"', www_auth)

            if not ticket_match:
                logger.error("No permission ticket in WWW-Authenticate header")
                return None

            ticket = ticket_match.group(1)
            logger.info(f"Agent {self.agent_id}: Got permission ticket for {resource}:{scope}")

            # Step 3: Exchange ticket for RPT
            rpt = self._uma_client.exchange_ticket_for_rpt(
                ticket=ticket,
                agent_access_token=self.token.access_token
            )

            if rpt:
                self._rpt = rpt
                logger.info(f"Agent {self.agent_id}: Obtained RPT for {resource}:{scope}")
                return rpt
            else:
                logger.warning(f"Agent {self.agent_id}: Failed to obtain RPT")
                return None

        except Exception as e:
            logger.error(f"Agent {self.agent_id}: Resource access request failed: {e}")
            return None

    def access_protected_resource(
        self,
        resource: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Access a protected resource using stored RPT

        Args:
            resource: Resource endpoint (e.g., 'documents', 'calendar')
            method: HTTP method (GET, POST, etc.)
            data: Request data for POST/PUT

        Returns:
            Resource data if successful, None if access denied
        """
        if not self._rpt:
            logger.error(f"Agent {self.agent_id}: No RPT available. Call request_resource_access() first")
            return None

        try:
            import requests

            url = f"{self._resource_server_url}/api/{resource}"
            headers = {"Authorization": f"Bearer {self._rpt.access_token}"}

            if method == "GET":
                response = requests.get(url, headers=headers)
            elif method == "POST":
                response = requests.post(url, headers=headers, json=data)
            else:
                raise ValueError(f"Unsupported method: {method}")

            if response.status_code == 200:
                logger.info(f"Agent {self.agent_id}: Successfully accessed {resource}")
                return response.json()
            else:
                logger.warning(f"Agent {self.agent_id}: Access denied to {resource}: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Agent {self.agent_id}: Failed to access resource: {e}")
            return None

    def get_rpt(self) -> Optional['RPT']:
        """Get the current RPT"""
        return self._rpt

    def has_rpt(self) -> bool:
        """Check if agent has an RPT"""
        return self._rpt is not None

    # ========================================================================
    # Agent Information
    # ========================================================================

    def get_info(self) -> Dict[str, Any]:
        """Get complete agent information"""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type.value,
            "agent_name": self.metadata.agent_name,
            "description": self.metadata.description,
            "capabilities": [c.value for c in self.capabilities],
            "scopes": self._scopes,
            "delegation_depth": self.get_delegation_depth(),
            "authenticated": self.has_valid_token(),
            "token_remaining": self.token.time_remaining() if self.token else None,
            "created_at": self.metadata.created_at.isoformat(),
        }

    def __repr__(self) -> str:
        """String representation"""
        return (
            f"BaseAgent("
            f"id={self.agent_id}, "
            f"type={self.agent_type.value}, "
            f"auth={self.has_valid_token()}"
            f")"
        )

    def __str__(self) -> str:
        """Friendly string representation"""
        status = "authenticated" if self.has_valid_token() else "not authenticated"
        return f"{self.metadata.agent_name} ({self.agent_type.value}) - {status}"
