"""
Week 3 Tests: Authorization, Audit Logging, and Scope Management

Comprehensive tests for:
- Policy engine (policies.py)
- Audit logging (audit.py)
- Scope management (scopes.py)
- Example policies
"""

import unittest
from datetime import datetime, timedelta, time

from agents.policies import (
    PolicyEvaluator, AgentPolicy, PolicyAction, PolicyDecision,
    TimeWindow, RateLimit
)
from agents.audit import (
    AuditLogger, AuditEvent, AuditEventType, AuditResult
)
from agents.scopes import ScopeManager, StandardScope, Scope
from agents.example_policies import (
    create_coordinator_policy, create_researcher_policy,
    create_executor_policy, create_validator_policy,
    create_admin_policy, setup_default_policies
)


# ============================================================================
# Policy Tests
# ============================================================================

class TestPolicyAction(unittest.TestCase):
    """Test PolicyAction enum"""

    def test_policy_actions(self):
        """Test that all policy actions are defined"""
        self.assertEqual(PolicyAction.READ.value, "read")
        self.assertEqual(PolicyAction.WRITE.value, "write")
        self.assertEqual(PolicyAction.DELETE.value, "delete")
        self.assertEqual(PolicyAction.DELEGATE.value, "delegate")
        self.assertEqual(PolicyAction.EXECUTE.value, "execute")


class TestTimeWindow(unittest.TestCase):
    """Test TimeWindow class"""

    def test_time_window_creation(self):
        """Test creating a time window"""
        window = TimeWindow(
            start_time=time(8, 0),
            end_time=time(17, 0),
            days_of_week=[0, 1, 2, 3, 4]
        )
        self.assertEqual(window.start_time, time(8, 0))
        self.assertEqual(window.end_time, time(17, 0))

    def test_time_window_24_7(self):
        """Test 24/7 time window"""
        window = TimeWindow()  # Default is 24/7
        self.assertTrue(window.is_within_window())


class TestRateLimit(unittest.TestCase):
    """Test RateLimit class"""

    def test_rate_limit_creation(self):
        """Test creating a rate limit"""
        limit = RateLimit(max_requests=100, time_window=timedelta(hours=1))
        self.assertEqual(limit.max_requests, 100)
        self.assertTrue(limit.is_allowed())

    def test_rate_limit_exceeded(self):
        """Test rate limit enforcement"""
        limit = RateLimit(max_requests=3, time_window=timedelta(hours=1))
        self.assertTrue(limit.is_allowed())
        self.assertTrue(limit.is_allowed())
        self.assertTrue(limit.is_allowed())
        self.assertFalse(limit.is_allowed())

    def test_rate_limit_remaining(self):
        """Test checking remaining requests"""
        limit = RateLimit(max_requests=5, time_window=timedelta(hours=1))
        limit.is_allowed()
        limit.is_allowed()
        self.assertEqual(limit.remaining_requests(), 3)


class TestAgentPolicy(unittest.TestCase):
    """Test AgentPolicy class"""

    def test_policy_creation(self):
        """Test creating an agent policy"""
        policy = AgentPolicy(
            agent_type="coordinator",
            allowed_actions=[PolicyAction.READ, PolicyAction.WRITE],
            max_delegation_depth=3
        )
        self.assertEqual(policy.agent_type, "coordinator")
        self.assertEqual(len(policy.allowed_actions), 2)

    def test_allows_action(self):
        """Test action allowance checking"""
        policy = AgentPolicy(
            agent_type="executor",
            allowed_actions=[PolicyAction.READ, PolicyAction.EXECUTE]
        )
        self.assertTrue(policy.allows_action(PolicyAction.READ))
        self.assertTrue(policy.allows_action(PolicyAction.EXECUTE))
        self.assertFalse(policy.allows_action(PolicyAction.DELETE))

    def test_required_scopes_for_action(self):
        """Test getting required scopes for action"""
        policy = AgentPolicy(
            agent_type="researcher",
            required_scopes={
                PolicyAction.READ.value: ["read:data", "read:database"],
                PolicyAction.EXECUTE.value: ["execute:tasks"],
            }
        )
        read_scopes = policy.required_scopes_for_action(PolicyAction.READ)
        self.assertIn("read:data", read_scopes)


class TestPolicyEvaluator(unittest.TestCase):
    """Test PolicyEvaluator class"""

    def setUp(self):
        """Set up evaluator with policies"""
        self.evaluator = PolicyEvaluator()
        self.coordinator_policy = create_coordinator_policy()
        self.executor_policy = create_executor_policy()
        self.evaluator.register_policy(self.coordinator_policy)
        self.evaluator.register_policy(self.executor_policy)

    def test_register_policy(self):
        """Test registering a policy"""
        evaluator = PolicyEvaluator()
        policy = AgentPolicy(agent_type="test")
        evaluator.register_policy(policy)
        self.assertIsNotNone(evaluator.get_policy("test"))

    def test_can_agent_act_allowed(self):
        """Test action allowed by policy"""
        result = self.evaluator.can_agent_act(
            agent_id="coord-001",
            agent_type="coordinator",
            action=PolicyAction.READ,
            agent_scopes=["read:data", "read:database"]
        )
        self.assertTrue(result)

    def test_can_agent_act_denied(self):
        """Test action denied by policy"""
        result = self.evaluator.can_agent_act(
            agent_id="executor-001",
            agent_type="executor",
            action=PolicyAction.DELETE,
            agent_scopes=["read:data"]
        )
        self.assertFalse(result)

    def test_can_agent_act_missing_scopes(self):
        """Test action denied due to missing scopes"""
        result = self.evaluator.can_agent_act(
            agent_id="coord-001",
            agent_type="coordinator",
            action=PolicyAction.WRITE,
            agent_scopes=["read:data"]  # Missing write:data
        )
        self.assertFalse(result)

    def test_can_delegate_allowed(self):
        """Test delegation allowed"""
        result = self.evaluator.can_delegate_to(
            source_agent_id="coord-001",
            source_type="coordinator",
            target_type="executor",
            delegation_depth=0,
            required_scopes=["read:data"],
            source_scopes=["read:data", "write:data"]
        )
        self.assertTrue(result)

    def test_can_delegate_depth_exceeded(self):
        """Test delegation denied due to depth limit"""
        result = self.evaluator.can_delegate_to(
            source_agent_id="coord-001",
            source_type="coordinator",
            target_type="executor",
            delegation_depth=3,  # At max depth
            required_scopes=["read:data"],
            source_scopes=["read:data", "write:data"]
        )
        self.assertFalse(result)

    def test_evaluate_policy(self):
        """Test policy evaluation"""
        decision = self.evaluator.evaluate_policy(
            agent_id="coord-001",
            agent_type="coordinator",
            context={
                "action": PolicyAction.READ,
                "scopes": ["read:data", "read:database"]
            }
        )
        self.assertEqual(decision, PolicyDecision.ALLOW)


# ============================================================================
# Audit Logging Tests
# ============================================================================

class TestAuditEvent(unittest.TestCase):
    """Test AuditEvent class"""

    def test_event_creation(self):
        """Test creating an audit event"""
        event = AuditEvent(
            event_type=AuditEventType.AGENT_CREATED,
            agent_id="agent-001",
            agent_type="coordinator",
            action="create",
            result=AuditResult.SUCCESS
        )
        self.assertEqual(event.event_type, AuditEventType.AGENT_CREATED)
        self.assertEqual(event.result, AuditResult.SUCCESS)

    def test_event_info(self):
        """Test getting event information"""
        event = AuditEvent(
            event_type=AuditEventType.ACTION_EXECUTED,
            agent_id="agent-001",
            action="test_action",
            result=AuditResult.SUCCESS
        )
        info = event.get_info()
        self.assertEqual(info["agent_id"], "agent-001")
        self.assertEqual(info["action"], "test_action")


class TestAuditLogger(unittest.TestCase):
    """Test AuditLogger class"""

    def setUp(self):
        """Set up audit logger"""
        self.logger = AuditLogger()

    def test_log_event(self):
        """Test logging an event"""
        event = AuditEvent(
            event_type=AuditEventType.AGENT_CREATED,
            agent_id="agent-001",
            agent_type="coordinator",
            result=AuditResult.SUCCESS
        )
        event_id = self.logger.log_event(event)
        self.assertIsNotNone(event_id)
        self.assertIsNotNone(self.logger.get_event(event_id))

    def test_log_agent_created(self):
        """Test logging agent creation"""
        event_id = self.logger.log_agent_created(
            agent_id="agent-001",
            agent_type="coordinator"
        )
        event = self.logger.get_event(event_id)
        self.assertEqual(event.event_type, AuditEventType.AGENT_CREATED)

    def test_log_delegation_approved(self):
        """Test logging delegation approval"""
        event_id = self.logger.log_delegation_approved(
            delegation_id="deleg-001",
            source_agent_id="agent-001",
            target_agent_id="agent-002",
            scopes=["read:data"]
        )
        self.assertIsNotNone(event_id)

    def test_get_agent_history(self):
        """Test retrieving agent history"""
        self.logger.log_agent_created("agent-001", "coordinator")
        self.logger.log_authentication("agent-001", "coordinator", success=True)
        self.logger.log_action_executed("agent-001", "coordinator", "test", success=True)

        history = self.logger.get_agent_history("agent-001")
        self.assertEqual(len(history), 3)

    def test_get_agent_history_filtered(self):
        """Test filtering agent history by event type"""
        self.logger.log_agent_created("agent-001", "coordinator")
        self.logger.log_authentication("agent-001", "coordinator", success=True)

        history = self.logger.get_agent_history(
            "agent-001",
            event_type=AuditEventType.AGENT_CREATED
        )
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].event_type, AuditEventType.AGENT_CREATED)

    def test_query_events(self):
        """Test querying events"""
        self.logger.log_agent_created("agent-001", "coordinator")
        self.logger.log_agent_created("agent-002", "executor")

        events = self.logger.query_events(agent_id="agent-001")
        self.assertEqual(len(events), 1)

    def test_get_failed_events(self):
        """Test retrieving failed events"""
        self.logger.log_action_executed("agent-001", "coordinator", "test1", success=True)
        self.logger.log_action_executed("agent-001", "coordinator", "test2", success=False)

        failed = self.logger.get_failed_events(agent_id="agent-001")
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].result, AuditResult.FAILURE)

    def test_get_agent_stats(self):
        """Test getting agent statistics"""
        self.logger.log_action_executed("agent-001", "coordinator", "action1", success=True)
        self.logger.log_action_executed("agent-001", "coordinator", "action2", success=True)
        self.logger.log_action_executed("agent-001", "coordinator", "action3", success=False)

        stats = self.logger.get_agent_stats("agent-001")
        self.assertEqual(stats["total_events"], 3)
        self.assertEqual(stats["successful_actions"], 2)
        self.assertEqual(stats["failed_actions"], 1)

    def test_audit_summary(self):
        """Test audit summary"""
        self.logger.log_agent_created("agent-001", "coordinator")
        self.logger.log_authentication("agent-001", "coordinator", success=True)

        summary = self.logger.get_summary()
        self.assertEqual(summary["total_events"], 2)
        self.assertEqual(summary["total_agents"], 1)
        self.assertEqual(summary["successful"], 2)


# ============================================================================
# Scope Management Tests
# ============================================================================

class TestScope(unittest.TestCase):
    """Test Scope class"""

    def test_scope_creation(self):
        """Test creating a scope"""
        scope = Scope("read:data", "Read access", level=0)
        self.assertEqual(scope.name, "read:data")
        self.assertEqual(scope.level, 0)

    def test_scope_equality(self):
        """Test scope equality"""
        scope1 = Scope("read:data")
        scope2 = Scope("read:data")
        self.assertEqual(scope1, scope2)


class TestScopeManager(unittest.TestCase):
    """Test ScopeManager class"""

    def setUp(self):
        """Set up scope manager"""
        self.manager = ScopeManager()

    def test_register_scope(self):
        """Test registering a scope"""
        scope = self.manager.register_scope("custom:action", "Custom action", level=1)
        self.assertEqual(scope.name, "custom:action")
        self.assertIsNotNone(self.manager.get_scope("custom:action"))

    def test_grant_scope(self):
        """Test granting a scope"""
        result = self.manager.grant_scope("agent-001", "read:data")
        self.assertTrue(result)
        self.assertTrue(self.manager.has_scope("agent-001", "read:data"))

    def test_revoke_scope(self):
        """Test revoking a scope"""
        self.manager.grant_scope("agent-001", "read:data")
        result = self.manager.revoke_scope("agent-001", "read:data")
        self.assertTrue(result)
        self.assertFalse(self.manager.has_scope("agent-001", "read:data"))

    def test_get_agent_scopes(self):
        """Test getting agent scopes"""
        self.manager.grant_scope("agent-001", "read:data")
        self.manager.grant_scope("agent-001", "write:data")

        scopes = self.manager.get_agent_scopes("agent-001")
        self.assertEqual(len(scopes), 2)
        self.assertIn("read:data", scopes)

    def test_set_agent_scopes(self):
        """Test setting agent scopes"""
        result = self.manager.set_agent_scopes(
            "agent-001",
            ["read:data", "write:data", "execute:tasks"]
        )
        self.assertTrue(result)
        scopes = self.manager.get_agent_scopes("agent-001")
        self.assertEqual(len(scopes), 3)

    def test_reduce_scopes(self):
        """Test scope reduction"""
        self.manager.set_agent_scopes(
            "agent-001",
            ["read:data", "write:data", "execute:tasks"]
        )

        reduced = self.manager.reduce_scopes(
            "agent-001",
            ["read:data", "execute:tasks"]  # Don't request write:data
        )

        self.assertEqual(len(reduced), 2)
        self.assertIn("read:data", reduced)
        self.assertIn("execute:tasks", reduced)
        self.assertNotIn("write:data", reduced)

    def test_can_delegate_scope(self):
        """Test checking if can delegate scope"""
        self.manager.grant_scope("agent-001", "read:data")

        result = self.manager.can_delegate_scope("agent-001", "read:data")
        self.assertTrue(result)

        result = self.manager.can_delegate_scope("agent-001", "write:data")
        self.assertFalse(result)

    def test_can_delegate_scopes(self):
        """Test checking if can delegate multiple scopes"""
        self.manager.set_agent_scopes("agent-001", ["read:data", "write:data"])

        result = self.manager.can_delegate_scopes(
            "agent-001",
            ["read:data", "write:data"]
        )
        self.assertTrue(result)

        result = self.manager.can_delegate_scopes(
            "agent-001",
            ["read:data", "execute:tasks"]  # Missing execute:tasks
        )
        self.assertFalse(result)

    def test_is_admin_scope(self):
        """Test checking if scope is admin"""
        self.assertTrue(self.manager.is_admin_scope("admin:all"))
        self.assertFalse(self.manager.is_admin_scope("read:data"))

    def test_get_agents_with_scope(self):
        """Test finding agents with scope"""
        self.manager.grant_scope("agent-001", "admin:all")
        self.manager.grant_scope("agent-002", "admin:all")
        self.manager.grant_scope("agent-003", "read:data")

        admins = self.manager.get_agents_with_scope("admin:all")
        self.assertEqual(len(admins), 2)

    def test_get_agents_with_admin_scopes(self):
        """Test finding agents with admin scopes"""
        self.manager.grant_scope("agent-001", "admin:all")
        self.manager.grant_scope("agent-002", "read:data")

        admins = self.manager.get_agents_with_admin_scopes()
        self.assertEqual(len(admins), 1)

    def test_scope_manager_summary(self):
        """Test scope manager summary"""
        self.manager.grant_scope("agent-001", "read:data")
        self.manager.grant_scope("agent-001", "write:data")
        self.manager.grant_scope("agent-002", "read:data")

        summary = self.manager.get_summary()
        self.assertEqual(summary["total_agents"], 2)
        self.assertGreater(summary["total_scope_assignments"], 0)


# ============================================================================
# Example Policies Tests
# ============================================================================

class TestExamplePolicies(unittest.TestCase):
    """Test example policy creation"""

    def test_coordinator_policy(self):
        """Test coordinator policy"""
        policy = create_coordinator_policy()
        self.assertEqual(policy.agent_type, "coordinator")
        self.assertIn(PolicyAction.DELEGATE, policy.allowed_actions)
        self.assertEqual(policy.max_delegation_depth, 3)

    def test_researcher_policy(self):
        """Test researcher policy"""
        policy = create_researcher_policy()
        self.assertEqual(policy.agent_type, "researcher")
        self.assertNotIn(PolicyAction.WRITE, policy.allowed_actions)
        self.assertEqual(policy.max_delegation_depth, 1)

    def test_executor_policy(self):
        """Test executor policy"""
        policy = create_executor_policy()
        self.assertEqual(policy.agent_type, "executor")
        self.assertNotIn(PolicyAction.DELEGATE, policy.allowed_actions)
        self.assertEqual(policy.max_delegation_depth, 0)

    def test_validator_policy(self):
        """Test validator policy"""
        policy = create_validator_policy()
        self.assertEqual(policy.agent_type, "validator")
        self.assertIn(PolicyAction.VALIDATE, policy.allowed_actions)
        self.assertNotIn(PolicyAction.WRITE, policy.allowed_actions)

    def test_setup_default_policies(self):
        """Test setting up default policies"""
        evaluator = PolicyEvaluator()
        setup_default_policies(evaluator)

        self.assertIsNotNone(evaluator.get_policy("coordinator"))
        self.assertIsNotNone(evaluator.get_policy("researcher"))
        self.assertIsNotNone(evaluator.get_policy("executor"))
        self.assertIsNotNone(evaluator.get_policy("validator"))
        self.assertIsNotNone(evaluator.get_policy("admin"))


if __name__ == "__main__":
    unittest.main()
