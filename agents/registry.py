"""
Agent Registry - Central registry for managing agents

Provides:
- Agent registration and lookup
- Agent discovery by type or capability
- Agent lifecycle management
"""

from typing import Dict, List, Optional
from .base import BaseAgent, AgentType, AgentCapability


class AgentRegistry:
    """
    Central registry for managing agents

    Maintains a dictionary of all registered agents and provides
    methods for registration, discovery, and management.
    """

    def __init__(self):
        """Initialize the agent registry"""
        self._agents: Dict[str, BaseAgent] = {}
        self._agents_by_type: Dict[AgentType, List[str]] = {
            agent_type: [] for agent_type in AgentType
        }

    # ========================================================================
    # Registration
    # ========================================================================

    def register(self, agent: BaseAgent) -> None:
        """
        Register an agent in the registry

        Args:
            agent: The agent to register

        Raises:
            ValueError: If agent with same ID already registered
        """
        if agent.agent_id in self._agents:
            raise ValueError(f"Agent {agent.agent_id} already registered")

        self._agents[agent.agent_id] = agent
        self._agents_by_type[agent.agent_type].append(agent.agent_id)

    def unregister(self, agent_id: str) -> bool:
        """
        Unregister an agent

        Args:
            agent_id: ID of agent to unregister

        Returns:
            True if agent was registered and removed, False otherwise
        """
        if agent_id not in self._agents:
            return False

        agent = self._agents.pop(agent_id)
        self._agents_by_type[agent.agent_type].remove(agent_id)
        return True

    # ========================================================================
    # Lookup
    # ========================================================================

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """
        Get an agent by ID

        Args:
            agent_id: ID of agent to retrieve

        Returns:
            The agent, or None if not found
        """
        return self._agents.get(agent_id)

    def get_agents_by_type(self, agent_type: AgentType) -> List[BaseAgent]:
        """
        Get all agents of a specific type

        Args:
            agent_type: Type of agents to retrieve

        Returns:
            List of agents of the specified type
        """
        agent_ids = self._agents_by_type.get(agent_type, [])
        return [self._agents[agent_id] for agent_id in agent_ids if agent_id in self._agents]

    def get_agents_with_capability(self, capability: AgentCapability) -> List[BaseAgent]:
        """
        Get all agents with a specific capability

        Args:
            capability: Capability to search for

        Returns:
            List of agents with the specified capability
        """
        return [agent for agent in self._agents.values() if agent.has_capability(capability)]

    def list_all_agents(self) -> List[BaseAgent]:
        """
        Get all registered agents

        Returns:
            List of all registered agents
        """
        return list(self._agents.values())

    # ========================================================================
    # Information
    # ========================================================================

    def get_agent_count(self) -> int:
        """Get total number of registered agents"""
        return len(self._agents)

    def get_agent_ids(self) -> List[str]:
        """Get all agent IDs"""
        return list(self._agents.keys())

    def agent_exists(self, agent_id: str) -> bool:
        """Check if an agent is registered"""
        return agent_id in self._agents

    def get_summary(self) -> Dict:
        """Get summary of all registered agents"""
        return {
            "total_agents": self.get_agent_count(),
            "agents_by_type": {
                agent_type.value: len(self.get_agents_by_type(agent_type))
                for agent_type in AgentType
            },
            "authenticated_agents": len([a for a in self._agents.values() if a.has_valid_token()]),
            "agents": {agent_id: agent.get_info() for agent_id, agent in self._agents.items()},
        }

    def __repr__(self) -> str:
        """String representation"""
        return f"AgentRegistry(agents={self.get_agent_count()})"

    def __len__(self) -> int:
        """Return number of registered agents"""
        return self.get_agent_count()
