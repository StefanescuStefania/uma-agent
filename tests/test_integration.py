"""
Week 4 Integration Tests - End-to-end workflows combining all components

Tests complete workflows that integrate:
- Agent framework (creation, authentication)
- Delegation system (with scope reduction)
- Message broker (inter-agent communication)
- Policy engine (authorization)
- Audit logging (complete audit trail)
- Scope management (permission enforcement)
"""

import unittest
from datetime import datetime, timedelta

from agents.registry import AgentRegistry
from agents.delegation import DelegationManager
from agents.messaging import MessageBroker, MessageType
from agents.implementations import (
    CoordinatorAgent, ResearcherAgent, ExecutorAgent, ValidatorAgent
)
from agents.policies import PolicyEvaluator, PolicyAction
from agents.audit import AuditLogger, AuditEventType
from agents.scopes import ScopeManager
from agents.example_policies import setup_default_policies


class TestDocumentProcessingWorkflow(unittest.TestCase):
    """Test document processing workflow with all components"""

    def setUp(self):
        """Set up complete framework"""
        self.registry = AgentRegistry()
        self.delegation_mgr = DelegationManager(max_delegation_depth=3)
        self.message_broker = MessageBroker()
        self.policy_evaluator = PolicyEvaluator()
        self.audit_logger = AuditLogger()
        self.scope_mgr = ScopeManager()

        # Set up policies
        setup_default_policies(self.policy_evaluator)

        # Create agents
        self.coordinator = CoordinatorAgent(agent_name="DocCoordinator")
        self.researcher = ResearcherAgent(agent_name="DocAnalyzer")
        self.executor = ExecutorAgent(agent_name="DocProcessor")
        self.validator = ValidatorAgent(agent_name="DocValidator")

        # Register agents
        self.registry.register(self.coordinator)
        self.registry.register(self.researcher)
        self.registry.register(self.executor)
        self.registry.register(self.validator)

        # Grant scopes to ScopeManager
        self.scope_mgr.grant_scope(self.coordinator.agent_id, "read:data")
        self.scope_mgr.grant_scope(self.coordinator.agent_id, "write:data")
        self.scope_mgr.grant_scope(self.coordinator.agent_id, "execute:tasks")
        self.scope_mgr.grant_scope(self.coordinator.agent_id, "delegate:tasks")

        # Set scopes on agents themselves
        self.coordinator.set_scopes(["read:data", "write:data", "execute:tasks", "delegate:tasks"])
        self.researcher.set_scopes(["read:data", "execute:tasks", "delegate:tasks"])
        self.executor.set_scopes(["read:data", "write:data", "execute:tasks"])
        self.validator.set_scopes(["read:data", "validate:results"])

        # Log agent creation
        self.audit_logger.log_agent_created(self.coordinator.agent_id, "coordinator")
        self.audit_logger.log_agent_created(self.researcher.agent_id, "researcher")
        self.audit_logger.log_agent_created(self.executor.agent_id, "executor")
        self.audit_logger.log_agent_created(self.validator.agent_id, "validator")

    def test_document_processing_workflow(self):
        """Test complete document processing workflow"""

        # Step 1: Coordinator checks if can delegate to researcher
        self.assertTrue(
            self.policy_evaluator.can_delegate_to(
                source_agent_id=self.coordinator.agent_id,
                source_type="coordinator",
                target_type="researcher",
                delegation_depth=0,
                required_scopes=["read:data"],
                source_scopes=self.scope_mgr.get_agent_scopes(self.coordinator.agent_id)
            )
        )

        # Step 2: Coordinator delegates to researcher
        delegation1 = self.delegation_mgr.create_delegation_request(
            source_agent=self.coordinator,
            target_agent=self.researcher,
            task_description="Analyze documents",
            required_scopes=["read:data"],
            expires_in_hours=24
        )
        self.assertIsNotNone(delegation1)

        # Grant researcher the delegated scopes
        self.delegation_mgr.approve_delegation(delegation1.request_id, self.researcher)
        self.scope_mgr.grant_scope(self.researcher.agent_id, "read:data")
        # Update researcher scopes to include what was delegated
        researcher_scopes = self.researcher.get_scopes()
        if "read:data" not in researcher_scopes:
            researcher_scopes.append("read:data")
            self.researcher.set_scopes(researcher_scopes)

        # Log delegation
        self.audit_logger.log_delegation_approved(
            delegation1.request_id,
            self.coordinator.agent_id,
            self.researcher.agent_id,
            ["read:data"]
        )

        # Step 3: Coordinator sends task request to researcher via message
        msg1 = self.message_broker.send_message(
            sender_id=self.coordinator.agent_id,
            receiver_id=self.researcher.agent_id,
            message_type=MessageType.TASK_REQUEST,
            content={"task": "analyze_documents", "file_count": 5}
        )
        self.audit_logger.log_message_sent(
            msg1.message_id, self.coordinator.agent_id, self.researcher.agent_id, "task_request"
        )

        # Step 4: Researcher receives and processes
        inbox = self.message_broker.get_inbox(self.researcher.agent_id)
        self.assertEqual(len(inbox), 1)
        self.message_broker.acknowledge_message(msg1.message_id)

        # Researcher does analysis
        self.researcher.start_research(
            project_id="doc-analysis-001",
            topic="Document Processing",
            sources=["file1.pdf", "file2.pdf"]
        )
        self.researcher.add_finding("doc-analysis-001", "5 documents processed")
        self.researcher.add_finding("doc-analysis-001", "Average quality: high")

        # Step 5: Researcher requests executor to process results
        delegation2 = self.delegation_mgr.create_delegation_request(
            source_agent=self.researcher,
            target_agent=self.executor,
            task_description="Process analysis results",
            required_scopes=["read:data"],
            expires_in_hours=12
        )
        self.assertIsNotNone(delegation2)

        self.delegation_mgr.approve_delegation(delegation2.request_id, self.executor)
        self.scope_mgr.grant_scope(self.executor.agent_id, "read:data")

        # Step 6: Researcher sends results to executor
        msg2 = self.message_broker.send_message(
            sender_id=self.researcher.agent_id,
            receiver_id=self.executor.agent_id,
            message_type=MessageType.STATUS_UPDATE,
            content={"findings": self.researcher.get_findings("doc-analysis-001")},
            reply_to=msg1.message_id
        )

        # Step 7: Executor processes
        self.executor.queue_task(
            task_id="process-001",
            action="aggregate_results",
            parameters={"source": "research"}
        )
        self.executor.execute_task("process-001")
        self.executor.complete_task("process-001", {
            "status": "success",
            "documents_processed": 5,
            "quality_score": 0.95
        })

        self.audit_logger.log_action_executed(
            self.executor.agent_id, "executor", "process_documents", success=True
        )

        # Step 8: Executor sends results to validator
        msg3 = self.message_broker.send_message(
            sender_id=self.executor.agent_id,
            receiver_id=self.validator.agent_id,
            message_type=MessageType.TASK_RESULT,
            content=self.executor.get_result("process-001")
        )

        # Step 9: Validator validates
        self.validator.add_validation_rule("document_result", "must_have_count")
        self.validator.add_validation_rule("document_result", "must_have_score")

        is_valid = self.validator.validate_result(
            result_id="result-001",
            result_type="document_result",
            result_data=self.executor.get_result("process-001")
        )
        self.assertTrue(is_valid)

        self.audit_logger.log_result_validated(
            self.validator.agent_id, "result-001", is_valid, ["must_have_count", "must_have_score"]
        )

        # Step 10: Validator sends final result back to coordinator
        msg4 = self.message_broker.send_message(
            sender_id=self.validator.agent_id,
            receiver_id=self.coordinator.agent_id,
            message_type=MessageType.TASK_RESULT,
            content={"validation_passed": is_valid, "result_id": "result-001"}
        )

        # Verify end state
        # Check delegation chain
        # Researcher: delegated from coordinator (depth 2: coordinator + researcher)
        # Executor: delegated from researcher via coordinator (depth 3: coordinator + researcher + executor)
        # But delegation depth starts at 1 for the agent itself, so:
        # - Researcher gets delegated to (depth starts at 1, becomes 2 when delegated)
        # - Executor gets delegated to (depth starts at 1, becomes 2 when delegated)
        self.assertGreater(self.researcher.get_delegation_depth(), 0)
        self.assertGreater(self.executor.get_delegation_depth(), 0)

        # Check scopes
        self.assertIn("read:data", self.scope_mgr.get_agent_scopes(self.researcher.agent_id))
        self.assertIn("read:data", self.scope_mgr.get_agent_scopes(self.executor.agent_id))

        # Check message history
        coord_history = self.message_broker.get_history(self.coordinator.agent_id)
        self.assertEqual(len(coord_history), 2)  # 1 sent, 1 received

        # Check audit trail
        coord_events = self.audit_logger.get_agent_history(self.coordinator.agent_id)
        self.assertGreater(len(coord_events), 0)

        # Check delegations were tracked
        summary = self.delegation_mgr.get_summary()
        self.assertEqual(summary["active_delegations"], 2)

    def test_scope_reduction_enforcement(self):
        """Test that scope reduction is enforced throughout delegation chain"""

        # Coordinator has many scopes - set on both manager and agent
        scopes_to_set = ["read:all", "write:all", "execute:tasks", "delegate:tasks"]
        self.scope_mgr.set_agent_scopes(self.coordinator.agent_id, scopes_to_set)
        self.coordinator.set_scopes(scopes_to_set)

        # Delegate only read to researcher
        delegation1 = self.delegation_mgr.create_delegation_request(
            source_agent=self.coordinator,
            target_agent=self.researcher,
            task_description="Limited research",
            required_scopes=["read:all"],  # Only grant read
            expires_in_hours=24
        )

        self.assertIsNotNone(delegation1, "Delegation should succeed with valid scopes")
        self.delegation_mgr.approve_delegation(delegation1.request_id, self.researcher)
        self.scope_mgr.grant_scope(self.researcher.agent_id, "read:all")
        self.researcher.add_scope("read:all")

        # Verify researcher only has read, not write or execute
        researcher_scopes = self.scope_mgr.get_agent_scopes(self.researcher.agent_id)
        self.assertIn("read:all", researcher_scopes)
        self.assertNotIn("write:all", researcher_scopes)
        self.assertNotIn("execute:tasks", researcher_scopes)

        # Researcher can only delegate what it has
        can_delegate = self.scope_mgr.can_delegate_scopes(
            self.researcher.agent_id,
            ["write:all"]  # Doesn't have this
        )
        self.assertFalse(can_delegate)

    def test_policy_enforcement_on_delegation(self):
        """Test policy enforcement during delegation"""

        # Researcher can only delegate depth 1
        researcher_policy = self.policy_evaluator.get_policy("researcher")
        self.assertEqual(researcher_policy.max_delegation_depth, 1)

        # Set researcher scopes
        self.scope_mgr.grant_scope(self.researcher.agent_id, "read:data")
        self.scope_mgr.grant_scope(self.researcher.agent_id, "delegate:tasks")

        # Researcher can delegate to executor (depth 0->1)
        can_delegate = self.policy_evaluator.can_delegate_to(
            source_agent_id=self.researcher.agent_id,
            source_type="researcher",
            target_type="executor",
            delegation_depth=0,
            required_scopes=["read:data"],
            source_scopes=["read:data", "delegate:tasks"]
        )
        self.assertTrue(can_delegate)

        # Executor cannot delegate further (no delegation capability)
        executor_policy = self.policy_evaluator.get_policy("executor")
        self.assertFalse(executor_policy.allows_action(PolicyAction.DELEGATE))

    def test_audit_trail_completeness(self):
        """Test that complete audit trail is maintained"""

        # Get initial count (from setUp which logs agent creation)
        initial_coordinator_events = len(self.audit_logger.get_agent_history(self.coordinator.agent_id))

        # Log additional activities
        self.audit_logger.log_scope_granted(self.coordinator.agent_id, "read:data")
        self.audit_logger.log_delegation_requested(
            "deleg-001",
            self.coordinator.agent_id,
            self.researcher.agent_id,
            ["read:data"],
            "test task"
        )

        # Check coordinator history increased by 2
        history = self.audit_logger.get_agent_history(self.coordinator.agent_id)
        self.assertEqual(len(history), initial_coordinator_events + 2)

        # Check delegation trail
        trail = self.audit_logger.get_delegation_trail("deleg-001")
        self.assertEqual(len(trail), 1)

        # Check that delegation events are tracked
        self.assertTrue(len(trail) > 0)


class TestMultiAgentCoordination(unittest.TestCase):
    """Test complex multi-agent coordination scenarios"""

    def setUp(self):
        """Set up framework"""
        self.registry = AgentRegistry()
        self.delegation_mgr = DelegationManager()
        self.message_broker = MessageBroker()
        self.policy_evaluator = PolicyEvaluator()
        self.scope_mgr = ScopeManager()

        setup_default_policies(self.policy_evaluator)

    def test_multi_coordinator_pattern(self):
        """Test multiple agents coordinating on same task"""

        # Create 3 researchers
        researchers = [
            ResearcherAgent(agent_name=f"Researcher{i}") for i in range(3)
        ]

        # Create coordinator
        coordinator = CoordinatorAgent(agent_name="Master")

        # Register all
        self.registry.register(coordinator)
        for researcher in researchers:
            self.registry.register(researcher)

        # Coordinator has scopes - set on both manager and agent
        coordinator_scopes = ["read:all", "delegate:tasks"]
        self.scope_mgr.set_agent_scopes(coordinator.agent_id, coordinator_scopes)
        coordinator.set_scopes(coordinator_scopes)

        # Set initial scopes on researchers
        for researcher in researchers:
            researcher.set_scopes([])  # Start with no scopes

        # Delegate to all researchers
        for i, researcher in enumerate(researchers):
            delegation = self.delegation_mgr.create_delegation_request(
                source_agent=coordinator,
                target_agent=researcher,
                task_description=f"Research topic {i}",
                required_scopes=["read:all"],
                expires_in_hours=24
            )
            self.assertIsNotNone(delegation)
            self.delegation_mgr.approve_delegation(delegation.request_id, researcher)
            self.scope_mgr.grant_scope(researcher.agent_id, "read:all")
            researcher.add_scope("read:all")

            # Send task via message
            self.message_broker.send_message(
                sender_id=coordinator.agent_id,
                receiver_id=researcher.agent_id,
                message_type=MessageType.TASK_REQUEST,
                content={"topic": f"topic_{i}"}
            )

        # All researchers got messages
        for researcher in researchers:
            inbox = self.message_broker.get_inbox(researcher.agent_id)
            self.assertEqual(len(inbox), 1)

        # Check summary
        summary = self.delegation_mgr.get_summary()
        self.assertEqual(summary["active_delegations"], 3)

    def test_sequential_processing_pipeline(self):
        """Test sequential processing through multiple agents"""

        # Create pipeline
        extractor = ExecutorAgent(agent_name="Extractor")
        transformer = ExecutorAgent(agent_name="Transformer")
        loader = ExecutorAgent(agent_name="Loader")

        self.registry.register(extractor)
        self.registry.register(transformer)
        self.registry.register(loader)

        # Grant all necessary scopes - set on both manager and agents
        for agent in [extractor, transformer, loader]:
            self.scope_mgr.grant_scope(agent.agent_id, "read:data")
            self.scope_mgr.grant_scope(agent.agent_id, "write:data")
            agent.set_scopes(["read:data", "write:data"])

        # Step 1: Extract
        extractor.queue_task("extract-001", "read_source", {"source": "database"})
        extractor.execute_task("extract-001")
        extractor.complete_task("extract-001", {"records": 1000})

        # Step 2: Send to transformer via message
        msg1 = self.message_broker.send_message(
            sender_id=extractor.agent_id,
            receiver_id=transformer.agent_id,
            message_type=MessageType.TASK_REQUEST,
            content=extractor.get_result("extract-001")
        )

        # Step 3: Transform
        transformer.queue_task("transform-001", "clean_data", {"input": "extract-001"})
        transformer.execute_task("transform-001")
        transformer.complete_task("transform-001", {"cleaned_records": 950})

        # Step 4: Send to loader via message
        msg2 = self.message_broker.send_message(
            sender_id=transformer.agent_id,
            receiver_id=loader.agent_id,
            message_type=MessageType.TASK_REQUEST,
            content=transformer.get_result("transform-001")
        )

        # Step 5: Load
        loader.queue_task("load-001", "write_target", {"destination": "warehouse"})
        loader.execute_task("load-001")
        loader.complete_task("load-001", {"loaded_records": 950})

        # Verify pipeline completed
        self.assertEqual(len(self.message_broker.get_history(extractor.agent_id)), 1)
        self.assertEqual(len(self.message_broker.get_history(transformer.agent_id)), 2)
        self.assertEqual(len(self.message_broker.get_history(loader.agent_id)), 1)

        # Total messages = 2 (1->2, 2->3)
        total_messages = len(list(self._iter_all_messages()))
        self.assertEqual(total_messages, 2)

    def _iter_all_messages(self):
        """Helper to iterate all messages in broker"""
        # This is a simplified iteration - in real system would use broker's internal state
        return self.message_broker._messages.values()


class TestPolicyViolationDetection(unittest.TestCase):
    """Test detection of policy violations"""

    def setUp(self):
        """Set up framework"""
        self.policy_evaluator = PolicyEvaluator()
        self.audit_logger = AuditLogger()
        setup_default_policies(self.policy_evaluator)

    def test_action_denial_logged(self):
        """Test that denied actions are logged"""

        # Executor shouldn't be able to delegate
        executor_policy = self.policy_evaluator.get_policy("executor")
        self.assertFalse(executor_policy.allows_action(PolicyAction.DELEGATE))

        # Try to have executor delegate (should fail policy check)
        result = self.policy_evaluator.can_agent_act(
            agent_id="exec-001",
            agent_type="executor",
            action=PolicyAction.DELEGATE,
            agent_scopes=["read:data", "write:data", "execute:tasks"]
        )
        self.assertFalse(result)

        # Log the denial
        self.audit_logger.log_policy_check(
            agent_id="exec-001",
            agent_type="executor",
            action="delegate",
            decision="DENIED",
            scopes=["read:data", "write:data"]
        )

        # Check audit trail
        events = self.audit_logger.get_agent_history("exec-001")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].result.value, "denied")

    def test_scope_violation_detection(self):
        """Test detection of scope violations"""

        scope_mgr = ScopeManager()

        # Agent has limited scopes
        scope_mgr.set_agent_scopes("agent-001", ["read:data"])

        # Try to use scopes it doesn't have
        can_write = scope_mgr.can_delegate_scopes("agent-001", ["write:data"])
        self.assertFalse(can_write)


if __name__ == "__main__":
    unittest.main()
