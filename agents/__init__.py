"""
UMA-Agent: AI Agent Framework with OAuth 2.0 & UMA 2.0 Authorization

This package implements a complete agent framework with:
- Agent identity and registration
- Keycloak OAuth 2.0 authentication
- Agent-to-agent delegation
- Fine-grained authorization policies
- Complete audit logging
"""

from .base import BaseAgent, AgentType, AgentCapability, AgentToken, AgentMetadata
from .registry import AgentRegistry
from .keycloak_auth import KeycloakAgentAuth
from .delegation import DelegationManager, DelegationRequest, DelegationStatus
from .implementations import (
    CoordinatorAgent,
    ResearcherAgent,
    ExecutorAgent,
    ValidatorAgent,
)

__all__ = [
    # Base classes
    "BaseAgent",
    "AgentType",
    "AgentCapability",
    "AgentToken",
    "AgentMetadata",
    # Registry
    "AgentRegistry",
    # Authentication
    "KeycloakAgentAuth",
    # Delegation
    "DelegationManager",
    "DelegationRequest",
    "DelegationStatus",
    # Specific agents
    "CoordinatorAgent",
    "ResearcherAgent",
    "ExecutorAgent",
    "ValidatorAgent",
]

__version__ = "0.1.0"
