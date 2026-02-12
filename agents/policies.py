"""
Agent Policy Engine - Authorization Policies for Agents

Provides:
- Policy definitions for agents
- Policy evaluation for authorization decisions
- Fine-grained access control
- Rate limiting and time-based restrictions
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta
import logging

logger = logging.getLogger(__name__)


class PolicyAction(str, Enum):
    """Actions that can be controlled by policies"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    DELEGATE = "delegate"
    EXECUTE = "execute"
    VALIDATE = "validate"
    ADMIN = "admin"


class PolicyDecision(str, Enum):
    """Policy evaluation decisions"""
    ALLOW = "allow"
    DENY = "deny"
    CONDITIONAL = "conditional"


@dataclass
class TimeWindow:
    """Time-based restriction for policies"""
    start_time: time = field(default_factory=lambda: time(0, 0))
    end_time: time = field(default_factory=lambda: time(23, 59))
    days_of_week: List[int] = field(default_factory=lambda: list(range(7)))  # 0=Monday, 6=Sunday

    def is_within_window(self) -> bool:
        """Check if current time is within the time window"""
        now = datetime.now()
        current_time = now.time()

        # Check day of week
        if now.weekday() not in self.days_of_week:
            return False

        # Check time of day
        if current_time < self.start_time or current_time > self.end_time:
            return False

        return True


@dataclass
class RateLimit:
    """Rate limiting configuration"""
    max_requests: int = 100
    time_window: timedelta = field(default_factory=lambda: timedelta(hours=1))
    current_count: int = field(default=0, init=False)
    window_start: datetime = field(default_factory=datetime.utcnow, init=False)

    def is_allowed(self) -> bool:
        """Check if request is allowed under rate limit"""
        now = datetime.utcnow()

        # Reset counter if time window has passed
        if now - self.window_start > self.time_window:
            self.current_count = 0
            self.window_start = now

        # Check if under limit
        if self.current_count >= self.max_requests:
            return False

        self.current_count += 1
        return True

    def remaining_requests(self) -> int:
        """Get remaining requests in current window"""
        now = datetime.utcnow()
        if now - self.window_start > self.time_window:
            return self.max_requests

        return max(0, self.max_requests - self.current_count)


@dataclass
class AgentPolicy:
    """Authorization policy for an agent"""
    agent_type: str
    allowed_actions: List[PolicyAction] = field(default_factory=list)
    required_scopes: Dict[str, List[str]] = field(default_factory=dict)  # action -> scopes
    max_delegation_depth: int = 3
    time_restrictions: Optional[TimeWindow] = None
    rate_limits: Optional[RateLimit] = None
    can_delegate_to_types: List[str] = field(default_factory=list)
    resource_access_patterns: Dict[str, str] = field(default_factory=dict)  # resource_type -> pattern

    def allows_action(self, action: PolicyAction) -> bool:
        """Check if policy allows an action"""
        return action in self.allowed_actions

    def required_scopes_for_action(self, action: PolicyAction) -> List[str]:
        """Get required scopes for an action"""
        return self.required_scopes.get(action.value, [])

    def get_info(self) -> Dict[str, Any]:
        """Get policy information"""
        return {
            "agent_type": self.agent_type,
            "allowed_actions": [a.value for a in self.allowed_actions],
            "max_delegation_depth": self.max_delegation_depth,
            "can_delegate_to_types": self.can_delegate_to_types,
            "rate_limits": {
                "max_requests": self.rate_limits.max_requests if self.rate_limits else None,
                "current_count": self.rate_limits.current_count if self.rate_limits else None,
                "remaining": self.rate_limits.remaining_requests() if self.rate_limits else None,
            } if self.rate_limits else None,
        }


class PolicyEvaluator:
    """Evaluates policies for authorization decisions"""

    def __init__(self):
        """Initialize policy evaluator"""
        self._policies: Dict[str, AgentPolicy] = {}
        self._access_history: Dict[str, List[Dict[str, Any]]] = {}

    def register_policy(self, policy: AgentPolicy) -> None:
        """Register a policy for an agent type"""
        self._policies[policy.agent_type] = policy
        logger.info(f"Registered policy for {policy.agent_type}")

    def get_policy(self, agent_type: str) -> Optional[AgentPolicy]:
        """Get policy for an agent type"""
        return self._policies.get(agent_type)

    # ========================================================================
    # Action Authorization
    # ========================================================================

    def can_agent_act(
        self,
        agent_id: str,
        agent_type: str,
        action: PolicyAction,
        agent_scopes: List[str],
    ) -> bool:
        """
        Check if an agent can perform an action

        Args:
            agent_id: Agent ID
            agent_type: Agent type
            action: Action to perform
            agent_scopes: Scopes agent currently has

        Returns:
            True if action is allowed, False otherwise
        """
        policy = self.get_policy(agent_type)
        if not policy:
            logger.warning(f"No policy found for agent type {agent_type}")
            return False

        # Check if action is allowed
        if not policy.allows_action(action):
            logger.warning(f"Action {action.value} not allowed for {agent_type}")
            return False

        # Check required scopes
        required_scopes = policy.required_scopes_for_action(action)
        agent_scopes_set = set(agent_scopes)
        if not set(required_scopes).issubset(agent_scopes_set):
            logger.warning(
                f"Agent {agent_id} missing scopes for {action.value}: "
                f"required {required_scopes}, has {agent_scopes}"
            )
            return False

        # Check time restrictions
        if policy.time_restrictions and not policy.time_restrictions.is_within_window():
            logger.warning(f"Action outside allowed time window for {agent_type}")
            return False

        # Check rate limits
        if policy.rate_limits and not policy.rate_limits.is_allowed():
            logger.warning(f"Rate limit exceeded for agent {agent_id}")
            return False

        # Log successful authorization
        self._log_access(agent_id, agent_type, action.value, "allowed")
        return True

    def can_delegate_to(
        self,
        source_agent_id: str,
        source_type: str,
        target_type: str,
        delegation_depth: int,
        required_scopes: List[str],
        source_scopes: List[str],
    ) -> bool:
        """
        Check if source agent can delegate to target agent

        Args:
            source_agent_id: Source agent ID
            source_type: Source agent type
            target_type: Target agent type
            delegation_depth: Current delegation depth
            required_scopes: Scopes being delegated
            source_scopes: Scopes source agent has

        Returns:
            True if delegation allowed, False otherwise
        """
        source_policy = self.get_policy(source_type)
        if not source_policy:
            logger.warning(f"No policy for source type {source_type}")
            return False

        # Check if delegation action is allowed
        if not source_policy.allows_action(PolicyAction.DELEGATE):
            logger.warning(f"Delegation not allowed for {source_type}")
            return False

        # Check max delegation depth
        if delegation_depth >= source_policy.max_delegation_depth:
            logger.warning(
                f"Delegation depth {delegation_depth} exceeds max "
                f"{source_policy.max_delegation_depth}"
            )
            return False

        # Check if can delegate to target type
        if (source_policy.can_delegate_to_types and
                target_type not in source_policy.can_delegate_to_types):
            logger.warning(f"Cannot delegate from {source_type} to {target_type}")
            return False

        # Check scope reduction (delegated scopes <= source scopes)
        source_scopes_set = set(source_scopes)
        required_scopes_set = set(required_scopes)
        if not required_scopes_set.issubset(source_scopes_set):
            logger.warning(
                f"Cannot delegate scopes {required_scopes} "
                f"not in source scopes {source_scopes}"
            )
            return False

        self._log_access(source_agent_id, source_type, "delegate", "allowed")
        return True

    def can_access_resource(
        self,
        agent_id: str,
        agent_type: str,
        resource_id: str,
        agent_scopes: List[str],
    ) -> bool:
        """
        Check if agent can access a resource

        Args:
            agent_id: Agent ID
            agent_type: Agent type
            resource_id: Resource ID
            agent_scopes: Scopes agent has

        Returns:
            True if access allowed, False otherwise
        """
        policy = self.get_policy(agent_type)
        if not policy:
            logger.warning(f"No policy for agent type {agent_type}")
            return False

        # Check if agent has read access
        if PolicyAction.READ not in policy.allowed_actions:
            logger.warning(f"Read not allowed for {agent_type}")
            return False

        # Check resource access patterns if defined
        if policy.resource_access_patterns:
            # This is simplified - in real system would do regex matching
            logger.info(f"Resource access patterns defined for {agent_type}")

        self._log_access(agent_id, agent_type, "access_resource", "allowed")
        return True

    # ========================================================================
    # Policy Evaluation
    # ========================================================================

    def evaluate_policy(
        self,
        agent_id: str,
        agent_type: str,
        context: Dict[str, Any],
    ) -> PolicyDecision:
        """
        Evaluate policy in a given context

        Args:
            agent_id: Agent ID
            agent_type: Agent type
            context: Context including action, scopes, etc.

        Returns:
            Policy decision (allow/deny/conditional)
        """
        policy = self.get_policy(agent_type)
        if not policy:
            logger.warning(f"No policy for {agent_type}")
            return PolicyDecision.DENY

        action = context.get("action")
        scopes = context.get("scopes", [])

        # Evaluate action
        if action and not policy.allows_action(action):
            return PolicyDecision.DENY

        # Evaluate scopes
        required = policy.required_scopes.get(action.value if action else "", [])
        if required and not set(required).issubset(set(scopes)):
            return PolicyDecision.DENY

        # Evaluate time restrictions
        if policy.time_restrictions and not policy.time_restrictions.is_within_window():
            return PolicyDecision.DENY

        # Evaluate rate limits
        if policy.rate_limits and not policy.rate_limits.is_allowed():
            return PolicyDecision.DENY

        return PolicyDecision.ALLOW

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def _log_access(
        self,
        agent_id: str,
        agent_type: str,
        action: str,
        decision: str,
    ) -> None:
        """Log policy evaluation"""
        if agent_id not in self._access_history:
            self._access_history[agent_id] = []

        self._access_history[agent_id].append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "decision": decision,
            "agent_type": agent_type,
        })

    def get_agent_policy_violations(self, agent_id: str) -> List[Dict[str, Any]]:
        """Get policy violations for an agent"""
        return [
            entry for entry in self._access_history.get(agent_id, [])
            if entry["decision"] == "denied"
        ]

    def get_summary(self) -> Dict[str, Any]:
        """Get policy engine summary"""
        total_checks = sum(len(h) for h in self._access_history.values())
        total_denials = sum(
            len([e for e in h if e["decision"] == "denied"])
            for h in self._access_history.values()
        )

        return {
            "registered_policies": len(self._policies),
            "total_access_checks": total_checks,
            "total_denials": total_denials,
            "agents_checked": len(self._access_history),
        }

    def __repr__(self) -> str:
        """String representation"""
        return f"PolicyEvaluator(policies={len(self._policies)})"
