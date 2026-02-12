"""
Example Policies - Pre-configured policies for different agent types

Provides example authorization policies for:
- Coordinator agents
- Researcher agents
- Executor agents
- Validator agents
"""

from datetime import time, timedelta
from .policies import (
    AgentPolicy, PolicyAction, TimeWindow, RateLimit, PolicyEvaluator
)


def create_coordinator_policy() -> AgentPolicy:
    """
    Coordinator Policy - Full control with delegation

    Can:
    - Read all data
    - Write reports
    - Execute tasks (with delegation)
    - Delegate to other agents
    - Validate results

    Restrictions:
    - Max delegation depth: 3
    - Rate limit: 1000 requests/hour
    - Available 24/7
    """
    policy = AgentPolicy(
        agent_type="coordinator",
        allowed_actions=[
            PolicyAction.READ,
            PolicyAction.WRITE,
            PolicyAction.EXECUTE,
            PolicyAction.DELEGATE,
            PolicyAction.VALIDATE,
        ],
        required_scopes={
            PolicyAction.READ.value: ["read:data", "read:database"],
            PolicyAction.WRITE.value: ["write:data"],
            PolicyAction.EXECUTE.value: ["execute:tasks"],
            PolicyAction.DELEGATE.value: ["delegate:tasks"],
            PolicyAction.VALIDATE.value: ["validate:results"],
        },
        max_delegation_depth=3,
        can_delegate_to_types=["researcher", "executor", "validator"],
        rate_limits=RateLimit(
            max_requests=1000,
            time_window=timedelta(hours=1)
        ),
        time_restrictions=TimeWindow(
            start_time=time(0, 0),
            end_time=time(23, 59),
            days_of_week=[0, 1, 2, 3, 4, 5, 6]  # All week
        ),
    )
    return policy


def create_researcher_policy() -> AgentPolicy:
    """
    Researcher Policy - Read-only with limited delegation

    Can:
    - Read all data
    - Analyze data (read operations)
    - Execute analysis
    - Limited delegation
    - Validate results

    Cannot:
    - Write data
    - Delete data
    - Admin operations

    Restrictions:
    - Max delegation depth: 1
    - Rate limit: 500 requests/hour
    - Available 24/7
    """
    policy = AgentPolicy(
        agent_type="researcher",
        allowed_actions=[
            PolicyAction.READ,
            PolicyAction.EXECUTE,
            PolicyAction.DELEGATE,
            PolicyAction.VALIDATE,
        ],
        required_scopes={
            PolicyAction.READ.value: ["read:data", "read:database"],
            PolicyAction.EXECUTE.value: ["execute:tasks"],
            PolicyAction.DELEGATE.value: ["delegate:tasks"],
            PolicyAction.VALIDATE.value: ["validate:results"],
        },
        max_delegation_depth=1,
        can_delegate_to_types=["executor"],
        rate_limits=RateLimit(
            max_requests=500,
            time_window=timedelta(hours=1)
        ),
        time_restrictions=TimeWindow(
            start_time=time(0, 0),
            end_time=time(23, 59),
            days_of_week=[0, 1, 2, 3, 4, 5, 6]
        ),
    )
    return policy


def create_executor_policy() -> AgentPolicy:
    """
    Executor Policy - Read-write, execution only

    Can:
    - Read data
    - Write data
    - Execute tasks
    - Validate results

    Cannot:
    - Delete data
    - Delegate tasks (no delegation)
    - Admin operations

    Restrictions:
    - Max delegation depth: 0 (no delegation)
    - Rate limit: 2000 requests/hour (heavy use)
    - Available 24/7
    """
    policy = AgentPolicy(
        agent_type="executor",
        allowed_actions=[
            PolicyAction.READ,
            PolicyAction.WRITE,
            PolicyAction.EXECUTE,
            PolicyAction.VALIDATE,
        ],
        required_scopes={
            PolicyAction.READ.value: ["read:data", "read:database"],
            PolicyAction.WRITE.value: ["write:data"],
            PolicyAction.EXECUTE.value: ["execute:tasks"],
            PolicyAction.VALIDATE.value: ["validate:results"],
        },
        max_delegation_depth=0,  # No delegation allowed
        can_delegate_to_types=[],
        rate_limits=RateLimit(
            max_requests=2000,
            time_window=timedelta(hours=1)
        ),
        time_restrictions=TimeWindow(
            start_time=time(0, 0),
            end_time=time(23, 59),
            days_of_week=[0, 1, 2, 3, 4, 5, 6]
        ),
    )
    return policy


def create_validator_policy() -> AgentPolicy:
    """
    Validator Policy - Read-only, validation only

    Can:
    - Read data
    - Validate results

    Cannot:
    - Write data
    - Delete data
    - Execute tasks
    - Delegate tasks
    - Admin operations

    Restrictions:
    - Max delegation depth: 0
    - Rate limit: 300 requests/hour
    - Business hours only (8am-6pm weekdays)
    """
    policy = AgentPolicy(
        agent_type="validator",
        allowed_actions=[
            PolicyAction.READ,
            PolicyAction.VALIDATE,
        ],
        required_scopes={
            PolicyAction.READ.value: ["read:data"],
            PolicyAction.VALIDATE.value: ["validate:results"],
        },
        max_delegation_depth=0,
        can_delegate_to_types=[],
        rate_limits=RateLimit(
            max_requests=300,
            time_window=timedelta(hours=1)
        ),
        time_restrictions=TimeWindow(
            start_time=time(8, 0),    # 8am
            end_time=time(18, 0),     # 6pm
            days_of_week=[0, 1, 2, 3, 4]  # Weekdays only
        ),
    )
    return policy


def create_admin_policy() -> AgentPolicy:
    """
    Admin Policy - Full access

    Can:
    - All actions
    - Full delegation
    - Admin operations

    Restrictions:
    - Max delegation depth: 5
    - Rate limit: 5000 requests/hour
    - Available 24/7
    """
    policy = AgentPolicy(
        agent_type="admin",
        allowed_actions=[
            PolicyAction.READ,
            PolicyAction.WRITE,
            PolicyAction.DELETE,
            PolicyAction.EXECUTE,
            PolicyAction.DELEGATE,
            PolicyAction.VALIDATE,
            PolicyAction.ADMIN,
        ],
        required_scopes={
            PolicyAction.READ.value: ["read:all"],
            PolicyAction.WRITE.value: ["write:all"],
            PolicyAction.DELETE.value: ["admin:all"],
            PolicyAction.EXECUTE.value: ["admin:all"],
            PolicyAction.DELEGATE.value: ["admin:all"],
            PolicyAction.VALIDATE.value: ["validate:results"],
            PolicyAction.ADMIN.value: ["admin:all"],
        },
        max_delegation_depth=5,
        can_delegate_to_types=["coordinator", "researcher", "executor", "validator", "admin"],
        rate_limits=RateLimit(
            max_requests=5000,
            time_window=timedelta(hours=1)
        ),
        time_restrictions=TimeWindow(
            start_time=time(0, 0),
            end_time=time(23, 59),
            days_of_week=[0, 1, 2, 3, 4, 5, 6]
        ),
    )
    return policy


def create_restricted_policy() -> AgentPolicy:
    """
    Restricted Policy - Minimal access, for testing/sandbox

    Can:
    - Read only
    - Validate only

    Cannot:
    - Write or modify anything
    - Execute tasks
    - Delegate
    - Admin operations

    Restrictions:
    - Max delegation depth: 0
    - Rate limit: 50 requests/hour (very restricted)
    - Limited time window
    """
    policy = AgentPolicy(
        agent_type="restricted",
        allowed_actions=[
            PolicyAction.READ,
            PolicyAction.VALIDATE,
        ],
        required_scopes={
            PolicyAction.READ.value: ["read:data"],
            PolicyAction.VALIDATE.value: ["validate:results"],
        },
        max_delegation_depth=0,
        can_delegate_to_types=[],
        rate_limits=RateLimit(
            max_requests=50,
            time_window=timedelta(hours=1)
        ),
        time_restrictions=TimeWindow(
            start_time=time(9, 0),
            end_time=time(17, 0),
            days_of_week=[0, 1, 2, 3, 4]  # Business hours weekdays
        ),
    )
    return policy


def setup_default_policies(evaluator: PolicyEvaluator) -> None:
    """
    Register all default policies with an evaluator

    Args:
        evaluator: PolicyEvaluator instance
    """
    policies = [
        create_coordinator_policy(),
        create_researcher_policy(),
        create_executor_policy(),
        create_validator_policy(),
        create_admin_policy(),
        create_restricted_policy(),
    ]

    for policy in policies:
        evaluator.register_policy(policy)


# Quick reference: Policy Comparison
"""
Policy Comparison Matrix:

                Coordinator  Researcher  Executor  Validator  Admin  Restricted
├─ Read          ✓           ✓          ✓         ✓         ✓      ✓
├─ Write         ✓           ✗          ✓         ✗         ✓      ✗
├─ Delete        ✗           ✗          ✗         ✗         ✓      ✗
├─ Execute       ✓           ✓          ✓         ✗         ✓      ✗
├─ Delegate      ✓           ✓          ✗         ✗         ✓      ✗
├─ Validate      ✓           ✓          ✓         ✓         ✓      ✓
├─ Admin         ✗           ✗          ✗         ✗         ✓      ✗
├─
├─ Max Depth     3           1          0         0         5      0
├─ Rate Limit    1000/h      500/h      2000/h    300/h     5000/h 50/h
├─ Time Window   24/7        24/7       24/7      9-5 M-F   24/7   9-5 M-F
└─ Can Delegate  All         Executor   None      None      All    None
"""
