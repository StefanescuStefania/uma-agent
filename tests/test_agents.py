"""
Comprehensive Agent Framework Tests

Tests for:
- BaseAgent and agent lifecycle
- AgentRegistry
- Delegation system (DelegationManager, DelegationRequest)
- Agent implementations (Coordinator, Researcher, Executor, Validator)
- Messaging system (MessageBroker, Message)
"""

import unittest
from datetime import datetime, timedelta

from agents.base import (
    BaseAgent, AgentType, AgentCapability, AgentToken, AgentMetadata
)
from agents.registry import AgentRegistry
from agents.delegation import DelegationManager, DelegationRequest, DelegationStatus
from agents.implementations import (
    CoordinatorAgent, ResearcherAgent, ExecutorAgent, ValidatorAgent
)
from agents.messaging import MessageBroker, Message, MessageType, MessageStatus


# ============================================================================
# Test BaseAgent and AgentToken
# ============================================================================

class TestAgentToken(unittest.TestCase):
    """Test AgentToken class"""

    def test_token_creation(self):
        """Test creating an agent token"""
        token = AgentToken(
            access_token="test_token_123",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="refresh_123"
        )
        self.assertEqual(token.access_token, "test_token_123")
        self.assertEqual(token.token_type, "Bearer")
        self.assertEqual(token.expires_in, 3600)
        self.assertEqual(token.refresh_token, "refresh_123")

    def test_token_is_valid(self):
        """Test token validity checking"""
        # Valid token (not expired)
        token = AgentToken(
            access_token="test_token",
            expires_in=3600
        )
        self.assertFalse(token.is_expired())

    def test_token_expiration(self):
        """Test expired token detection"""
        # Expired token (0 seconds left)
        token = AgentToken(
            access_token="test_token",
            expires_in=0
        )
        self.assertTrue(token.is_expired())


class TestBaseAgent(unittest.TestCase):
    """Test BaseAgent class"""

    def setUp(self):
        """Set up test agent"""
        self.agent = BaseAgent(
            agent_id="agent-001",
            agent_type=AgentType.COORDINATOR,
            agent_name="TestAgent"
        )

    def test_agent_creation(self):
        """Test creating a base agent"""
        self.assertEqual(self.agent.agent_id, "agent-001")
        self.assertEqual(self.agent.agent_type, AgentType.COORDINATOR)
        self.assertEqual(self.agent.metadata.agent_name, "TestAgent")

    def test_token_management(self):
        """Test setting and getting tokens"""
        token = AgentToken(access_token="test_token_123")
        self.agent.set_token(token)
        self.assertEqual(self.agent.get_token(), token)
        self.assertTrue(self.agent.has_valid_token())

    def test_clear_token(self):
        """Test clearing agent token"""
        token = AgentToken(access_token="test_token")
        self.agent.set_token(token)
        self.assertTrue(self.agent.has_valid_token())
        self.agent.clear_token()
        self.assertIsNone(self.agent.get_token())

    def test_capability_management(self):
        """Test adding and checking capabilities"""
        self.assertFalse(self.agent.has_capability(AgentCapability.ANALYZE))
        self.agent.add_capability(AgentCapability.ANALYZE)
        self.assertTrue(self.agent.has_capability(AgentCapability.ANALYZE))

    def test_scope_management(self):
        """Test scope operations"""
        self.agent.add_scope("read:data")
        self.agent.add_scope("write:data")

        self.assertTrue(self.agent.has_scope("read:data"))
        self.assertTrue(self.agent.has_scope("write:data"))
        self.assertFalse(self.agent.has_scope("delete:data"))

        scopes = self.agent.get_scopes()
        self.assertIn("read:data", scopes)
        self.assertIn("write:data", scopes)

    def test_delegation_chain_management(self):
        """Test delegation chain operations"""
        # Initial chain includes the agent itself, so depth is 1
        self.assertEqual(self.agent.get_delegation_depth(), 1)

        chain = ["agent-001", "agent-002", "agent-003"]
        self.agent.set_delegation_chain(chain)
        self.assertEqual(self.agent.get_delegation_chain(), chain)
        self.assertEqual(self.agent.get_delegation_depth(), 3)

    def test_can_delegate(self):
        """Test delegation capability checking"""
        # Agent without DELEGATE capability cannot delegate
        self.assertFalse(self.agent.can_delegate(max_depth=3))

        # Add DELEGATE capability
        self.agent.add_capability(AgentCapability.DELEGATE)
        self.assertTrue(self.agent.can_delegate(max_depth=3))

        # Agent at max depth cannot delegate
        chain = ["a1", "a2", "a3", "a4"]  # depth 4
        self.agent.set_delegation_chain(chain)
        self.assertFalse(self.agent.can_delegate(max_depth=3))

    def test_state_management(self):
        """Test custom state storage"""
        self.agent.set_state("task_count", 5)
        self.agent.set_state("status", "active")

        self.assertEqual(self.agent.get_state("task_count"), 5)
        self.assertEqual(self.agent.get_state("status"), "active")
        self.assertIsNone(self.agent.get_state("nonexistent"))

    def test_agent_info(self):
        """Test getting agent information"""
        self.agent.add_capability(AgentCapability.READ)
        self.agent.add_scope("read:data")

        info = self.agent.get_info()
        self.assertEqual(info["agent_id"], "agent-001")
        self.assertEqual(info["agent_type"], "coordinator")
        self.assertIn("read", info["capabilities"])
        self.assertIn("read:data", info["scopes"])


# ============================================================================
# Test AgentRegistry
# ============================================================================

class TestAgentRegistry(unittest.TestCase):
    """Test AgentRegistry class"""

    def setUp(self):
        """Set up registry with test agents"""
        self.registry = AgentRegistry()
        self.coordinator = CoordinatorAgent()
        self.researcher = ResearcherAgent()
        self.executor = ExecutorAgent()

    def test_register_agent(self):
        """Test registering an agent"""
        self.registry.register(self.coordinator)
        self.assertEqual(len(self.registry.list_all_agents()), 1)

    def test_get_agent(self):
        """Test retrieving an agent by ID"""
        self.registry.register(self.coordinator)
        retrieved = self.registry.get_agent(self.coordinator.agent_id)
        self.assertEqual(retrieved, self.coordinator)

    def test_get_agent_not_found(self):
        """Test retrieving non-existent agent"""
        result = self.registry.get_agent("nonexistent-id")
        self.assertIsNone(result)

    def test_unregister_agent(self):
        """Test unregistering an agent"""
        self.registry.register(self.coordinator)
        self.assertTrue(self.registry.unregister(self.coordinator.agent_id))
        self.assertEqual(len(self.registry.list_all_agents()), 0)

    def test_get_agents_by_type(self):
        """Test filtering agents by type"""
        self.registry.register(self.coordinator)
        self.registry.register(self.researcher)
        self.registry.register(self.executor)

        coordinators = self.registry.get_agents_by_type(AgentType.COORDINATOR)
        researchers = self.registry.get_agents_by_type(AgentType.RESEARCHER)

        self.assertEqual(len(coordinators), 1)
        self.assertEqual(len(researchers), 1)

    def test_get_agents_with_capability(self):
        """Test filtering agents by capability"""
        self.coordinator.add_capability(AgentCapability.ORCHESTRATE)
        self.researcher.add_capability(AgentCapability.ANALYZE)

        self.registry.register(self.coordinator)
        self.registry.register(self.researcher)

        orchestrators = self.registry.get_agents_with_capability(AgentCapability.ORCHESTRATE)
        analyzers = self.registry.get_agents_with_capability(AgentCapability.ANALYZE)

        self.assertEqual(len(orchestrators), 1)
        self.assertEqual(len(analyzers), 1)

    def test_registry_summary(self):
        """Test getting registry summary statistics"""
        self.registry.register(self.coordinator)
        self.registry.register(self.researcher)

        summary = self.registry.get_summary()
        self.assertEqual(summary["total_agents"], 2)
        self.assertIn(AgentType.COORDINATOR.value, summary["agents_by_type"])


# ============================================================================
# Test DelegationRequest
# ============================================================================

class TestDelegationRequest(unittest.TestCase):
    """Test DelegationRequest class"""

    def test_request_creation(self):
        """Test creating a delegation request"""
        expires = datetime.utcnow() + timedelta(hours=24)
        request = DelegationRequest(
            source_agent_id="agent-001",
            target_agent_id="agent-002",
            task_description="Process data",
            required_scopes=["read:data", "write:data"],
            expires_at=expires
        )
        self.assertEqual(request.source_agent_id, "agent-001")
        self.assertEqual(request.target_agent_id, "agent-002")
        self.assertEqual(request.status, DelegationStatus.PENDING)

    def test_request_expiration(self):
        """Test checking request expiration"""
        # Not expired
        future_expires = datetime.utcnow() + timedelta(hours=1)
        request = DelegationRequest(expires_at=future_expires)
        self.assertFalse(request.is_expired())

        # Expired
        past_expires = datetime.utcnow() - timedelta(hours=1)
        request = DelegationRequest(expires_at=past_expires)
        self.assertTrue(request.is_expired())

    def test_time_remaining(self):
        """Test calculating time remaining"""
        future_expires = datetime.utcnow() + timedelta(hours=1)
        request = DelegationRequest(expires_at=future_expires)

        time_left = request.time_remaining()
        self.assertIsNotNone(time_left)
        self.assertGreater(time_left, 0)
        self.assertLess(time_left, 3600)  # Less than 1 hour in seconds

    def test_request_info(self):
        """Test getting request information"""
        request = DelegationRequest(
            source_agent_id="agent-001",
            target_agent_id="agent-002",
            task_description="Test task"
        )
        info = request.get_info()

        self.assertEqual(info["source_agent_id"], "agent-001")
        self.assertEqual(info["target_agent_id"], "agent-002")
        self.assertEqual(info["status"], "pending")


# ============================================================================
# Test DelegationManager
# ============================================================================

class TestDelegationManager(unittest.TestCase):
    """Test DelegationManager class"""

    def setUp(self):
        """Set up delegation manager with test agents"""
        self.manager = DelegationManager(max_delegation_depth=3)

        self.source_agent = CoordinatorAgent()
        self.source_agent.add_scope("read:data")
        self.source_agent.add_scope("write:data")
        self.source_agent.add_scope("execute:action")

        self.target_agent = ExecutorAgent()

    def test_create_delegation_request(self):
        """Test creating a delegation request"""
        request = self.manager.create_delegation_request(
            source_agent=self.source_agent,
            target_agent=self.target_agent,
            task_description="Execute data processing",
            required_scopes=["read:data", "execute:action"],
            expires_in_hours=24
        )

        self.assertIsNotNone(request)
        self.assertEqual(request.source_agent_id, self.source_agent.agent_id)
        self.assertEqual(request.target_agent_id, self.target_agent.agent_id)
        self.assertEqual(request.status, DelegationStatus.PENDING)

    def test_reject_scope_not_available(self):
        """Test rejecting delegation when scope not available"""
        request = self.manager.create_delegation_request(
            source_agent=self.source_agent,
            target_agent=self.target_agent,
            task_description="Delete data",
            required_scopes=["delete:data"],  # Source doesn't have this
            expires_in_hours=24
        )

        self.assertIsNone(request)

    def test_approve_delegation(self):
        """Test approving a delegation request"""
        request = self.manager.create_delegation_request(
            source_agent=self.source_agent,
            target_agent=self.target_agent,
            task_description="Execute action",
            required_scopes=["read:data", "execute:action"],
            expires_in_hours=24
        )

        result = self.manager.approve_delegation(request.request_id, self.target_agent)
        self.assertTrue(result)

        # Check target agent has scopes
        self.assertTrue(self.target_agent.has_scope("read:data"))
        self.assertTrue(self.target_agent.has_scope("execute:action"))

        # Check status
        approved_request = self.manager.get_delegation_request(request.request_id)
        self.assertEqual(approved_request.status, DelegationStatus.APPROVED)

    def test_reject_delegation(self):
        """Test rejecting a delegation request"""
        request = self.manager.create_delegation_request(
            source_agent=self.source_agent,
            target_agent=self.target_agent,
            task_description="Test task",
            required_scopes=["read:data"],
            expires_in_hours=24
        )

        result = self.manager.reject_delegation(request.request_id, "Agent not trusted")
        self.assertTrue(result)

        rejected = self.manager.get_delegation_request(request.request_id)
        self.assertEqual(rejected.status, DelegationStatus.REJECTED)
        self.assertEqual(rejected.reason_for_rejection, "Agent not trusted")

    def test_complete_delegation(self):
        """Test completing a delegation"""
        request = self.manager.create_delegation_request(
            source_agent=self.source_agent,
            target_agent=self.target_agent,
            task_description="Test task",
            required_scopes=["read:data"],
            expires_in_hours=24
        )

        # Approve first
        self.manager.approve_delegation(request.request_id, self.target_agent)

        # Then complete
        result = self.manager.complete_delegation(
            request.request_id,
            result_data={"status": "success", "items": 42}
        )
        self.assertTrue(result)

        completed = self.manager.get_delegation_request(request.request_id)
        self.assertEqual(completed.status, DelegationStatus.COMPLETED)

    def test_revoke_delegation(self):
        """Test revoking a delegation"""
        request = self.manager.create_delegation_request(
            source_agent=self.source_agent,
            target_agent=self.target_agent,
            task_description="Test task",
            required_scopes=["read:data"],
            expires_in_hours=24
        )

        # Approve first
        self.manager.approve_delegation(request.request_id, self.target_agent)

        # Then revoke
        result = self.manager.revoke_delegation(request.request_id)
        self.assertTrue(result)

        revoked = self.manager.get_delegation_request(request.request_id)
        self.assertEqual(revoked.status, DelegationStatus.REVOKED)

    def test_prevent_circular_delegation(self):
        """Test preventing circular delegations"""
        # Create a chain: source -> middle -> target
        middle_agent = ResearcherAgent()

        request1 = self.manager.create_delegation_request(
            source_agent=self.source_agent,
            target_agent=middle_agent,
            task_description="Task 1",
            required_scopes=["read:data"],
            expires_in_hours=24
        )

        self.manager.approve_delegation(request1.request_id, middle_agent)

        # Now try to have middle delegate back to source (circular)
        # This should fail because source is in middle's delegation chain
        can_delegate = self.manager.can_delegate(middle_agent, self.source_agent)
        self.assertFalse(can_delegate)

    def test_scope_reduction(self):
        """Test scope reduction principle"""
        source_scopes = ["read:data", "write:data", "delete:data", "execute:action"]
        required_scopes = ["read:data", "execute:action"]

        reduced = self.manager.reduce_scopes(source_scopes, required_scopes)

        self.assertEqual(len(reduced), 2)
        self.assertIn("read:data", reduced)
        self.assertIn("execute:action", reduced)
        self.assertNotIn("write:data", reduced)

    def test_get_delegation_chain(self):
        """Test retrieving delegation chain"""
        request = self.manager.create_delegation_request(
            source_agent=self.source_agent,
            target_agent=self.target_agent,
            task_description="Test task",
            required_scopes=["read:data"],
            expires_in_hours=24
        )

        self.manager.approve_delegation(request.request_id, self.target_agent)

        chain = self.manager.get_delegation_chain(request.request_id)
        self.assertIn(self.source_agent.agent_id, chain)
        self.assertIn(self.target_agent.agent_id, chain)


# ============================================================================
# Test Agent Implementations
# ============================================================================

class TestCoordinatorAgent(unittest.TestCase):
    """Test CoordinatorAgent class"""

    def setUp(self):
        """Set up coordinator agent"""
        self.coordinator = CoordinatorAgent()

    def test_create_task(self):
        """Test creating a task"""
        subtasks = [
            {"id": "sub1", "description": "Research"},
            {"id": "sub2", "description": "Analyze"},
        ]

        self.coordinator.create_task(
            task_id="task-001",
            description="Complex project",
            subtasks=subtasks
        )

        tasks = self.coordinator.get_delegated_tasks()
        self.assertIn("task-001", tasks)
        self.assertEqual(len(tasks["task-001"]["subtasks"]), 2)

    def test_store_and_retrieve_results(self):
        """Test storing and retrieving task results"""
        self.coordinator.create_task(
            task_id="task-001",
            description="Test task",
            subtasks=[{"id": "sub1"}]
        )

        self.coordinator.store_result("task-001", "sub1", {"data": "result"})
        results = self.coordinator.get_results("task-001")

        self.assertIn("sub1", results)
        self.assertEqual(results["sub1"]["data"], "result")

    def test_complete_task(self):
        """Test completing a task"""
        self.coordinator.create_task(
            task_id="task-001",
            description="Test task",
            subtasks=[]
        )

        result = self.coordinator.complete_task("task-001")
        self.assertTrue(result)

        tasks = self.coordinator.get_delegated_tasks()
        self.assertEqual(tasks["task-001"]["status"], "completed")


class TestResearcherAgent(unittest.TestCase):
    """Test ResearcherAgent class"""

    def setUp(self):
        """Set up researcher agent"""
        self.researcher = ResearcherAgent()

    def test_start_research(self):
        """Test starting a research project"""
        self.researcher.start_research(
            project_id="proj-001",
            topic="AI Agent Authorization",
            sources=["paper1", "paper2", "paper3"]
        )

        projects = self.researcher._research_projects
        self.assertIn("proj-001", projects)
        self.assertEqual(projects["proj-001"]["topic"], "AI Agent Authorization")

    def test_add_findings(self):
        """Test adding findings to research"""
        self.researcher.start_research(
            project_id="proj-001",
            topic="Test Topic",
            sources=[]
        )

        self.researcher.add_finding("proj-001", "Finding 1")
        self.researcher.add_finding("proj-001", "Finding 2")

        findings = self.researcher.get_findings("proj-001")
        self.assertEqual(len(findings), 2)
        self.assertIn("Finding 1", findings)

    def test_complete_research(self):
        """Test completing research"""
        self.researcher.start_research(
            project_id="proj-001",
            topic="Test",
            sources=[]
        )

        result = self.researcher.complete_research("proj-001")
        self.assertTrue(result)


class TestExecutorAgent(unittest.TestCase):
    """Test ExecutorAgent class"""

    def setUp(self):
        """Set up executor agent"""
        self.executor = ExecutorAgent()

    def test_queue_task(self):
        """Test queueing a task"""
        self.executor.queue_task(
            task_id="task-001",
            action="process_data",
            parameters={"file": "data.csv"}
        )

        queue = self.executor._task_queue
        self.assertIn("task-001", queue)
        self.assertEqual(queue["task-001"]["action"], "process_data")

    def test_execute_task(self):
        """Test executing a task"""
        self.executor.queue_task(
            task_id="task-001",
            action="process",
            parameters={}
        )

        result = self.executor.execute_task("task-001")
        self.assertTrue(result)

        queue = self.executor._task_queue
        self.assertEqual(queue["task-001"]["status"], "executing")

    def test_complete_task(self):
        """Test completing a task"""
        self.executor.queue_task(
            task_id="task-001",
            action="process",
            parameters={}
        )

        self.executor.execute_task("task-001")
        result = self.executor.complete_task("task-001", {"status": "success"})
        self.assertTrue(result)

        retrieved_result = self.executor.get_result("task-001")
        self.assertEqual(retrieved_result["status"], "success")


class TestValidatorAgent(unittest.TestCase):
    """Test ValidatorAgent class"""

    def setUp(self):
        """Set up validator agent"""
        self.validator = ValidatorAgent()

    def test_add_validation_rule(self):
        """Test adding validation rules"""
        self.validator.add_validation_rule("data_result", "must_be_non_empty")
        self.validator.add_validation_rule("data_result", "must_have_timestamp")

        rules = self.validator._validation_rules["data_result"]
        self.assertEqual(len(rules), 2)

    def test_validate_result(self):
        """Test validating a result"""
        self.validator.add_validation_rule("data_result", "must_be_non_empty")

        # Valid result
        is_valid = self.validator.validate_result(
            result_id="result-001",
            result_type="data_result",
            result_data={"items": [1, 2, 3]}
        )
        self.assertTrue(is_valid)

        # Invalid result (None)
        is_valid = self.validator.validate_result(
            result_id="result-002",
            result_type="data_result",
            result_data=None
        )
        self.assertFalse(is_valid)

    def test_get_validation_status(self):
        """Test retrieving validation status"""
        self.validator.validate_result(
            result_id="result-001",
            result_type="test_type",
            result_data={"value": 42}
        )

        status = self.validator.get_validation_status("result-001")
        self.assertIsNotNone(status)
        self.assertEqual(status["result_type"], "test_type")


# ============================================================================
# Test Messaging System
# ============================================================================

class TestMessage(unittest.TestCase):
    """Test Message class"""

    def test_message_creation(self):
        """Test creating a message"""
        message = Message(
            sender_id="agent-001",
            receiver_id="agent-002",
            message_type=MessageType.TASK_REQUEST,
            content={"task": "process_data"}
        )

        self.assertEqual(message.sender_id, "agent-001")
        self.assertEqual(message.receiver_id, "agent-002")
        self.assertEqual(message.message_type, MessageType.TASK_REQUEST)
        self.assertEqual(message.status, MessageStatus.SENT)

    def test_message_delivery(self):
        """Test marking message as delivered"""
        message = Message(
            sender_id="agent-001",
            receiver_id="agent-002",
            message_type=MessageType.INFO,
            content={}
        )

        self.assertEqual(message.status, MessageStatus.SENT)
        message.mark_delivered()
        self.assertEqual(message.status, MessageStatus.DELIVERED)
        self.assertIsNotNone(message.delivered_at)

    def test_message_acknowledgment(self):
        """Test acknowledging a message"""
        message = Message(
            sender_id="agent-001",
            receiver_id="agent-002",
            message_type=MessageType.TASK_REQUEST,
            content={}
        )

        message.mark_delivered()
        message.mark_acknowledged()
        self.assertEqual(message.status, MessageStatus.ACKNOWLEDGED)
        self.assertIsNotNone(message.acknowledged_at)

    def test_message_failure(self):
        """Test marking message as failed"""
        message = Message(
            sender_id="agent-001",
            receiver_id="agent-002",
            message_type=MessageType.ERROR,
            content={"error": "Failed"}
        )

        message.mark_failed()
        self.assertEqual(message.status, MessageStatus.FAILED)

    def test_message_reply_tracking(self):
        """Test tracking message replies"""
        original = Message(
            sender_id="agent-001",
            receiver_id="agent-002",
            message_type=MessageType.TASK_REQUEST,
            content={}
        )

        reply = Message(
            sender_id="agent-002",
            receiver_id="agent-001",
            message_type=MessageType.TASK_RESULT,
            content={"result": "done"},
            reply_to=original.message_id
        )

        self.assertEqual(reply.reply_to, original.message_id)

    def test_message_info(self):
        """Test getting message information"""
        message = Message(
            sender_id="agent-001",
            receiver_id="agent-002",
            message_type=MessageType.STATUS_UPDATE,
            content={"progress": 50}
        )

        info = message.get_info()
        self.assertEqual(info["sender_id"], "agent-001")
        self.assertEqual(info["message_type"], "status_update")
        self.assertEqual(info["status"], "sent")


class TestMessageBroker(unittest.TestCase):
    """Test MessageBroker class"""

    def setUp(self):
        """Set up message broker"""
        self.broker = MessageBroker()
        self.sender_id = "agent-001"
        self.receiver_id = "agent-002"

    def test_send_message(self):
        """Test sending a message"""
        message = self.broker.send_message(
            sender_id=self.sender_id,
            receiver_id=self.receiver_id,
            message_type=MessageType.TASK_REQUEST,
            content={"task": "process"}
        )

        self.assertIsNotNone(message)
        self.assertEqual(message.sender_id, self.sender_id)
        self.assertEqual(message.status, MessageStatus.DELIVERED)

    def test_get_message(self):
        """Test retrieving a message"""
        message = self.broker.send_message(
            sender_id=self.sender_id,
            receiver_id=self.receiver_id,
            message_type=MessageType.INFO,
            content={}
        )

        retrieved = self.broker.get_message(message.message_id)
        self.assertEqual(retrieved.message_id, message.message_id)

    def test_get_inbox(self):
        """Test getting inbox for agent"""
        self.broker.send_message(
            sender_id=self.sender_id,
            receiver_id=self.receiver_id,
            message_type=MessageType.TASK_REQUEST,
            content={}
        )
        self.broker.send_message(
            sender_id=self.sender_id,
            receiver_id=self.receiver_id,
            message_type=MessageType.INFO,
            content={}
        )

        inbox = self.broker.get_inbox(self.receiver_id)
        self.assertEqual(len(inbox), 2)

    def test_acknowledge_message(self):
        """Test acknowledging a message"""
        message = self.broker.send_message(
            sender_id=self.sender_id,
            receiver_id=self.receiver_id,
            message_type=MessageType.TASK_REQUEST,
            content={},
            requires_ack=True
        )

        result = self.broker.acknowledge_message(message.message_id)
        self.assertTrue(result)

        ack_msg = self.broker.get_message(message.message_id)
        self.assertEqual(ack_msg.status, MessageStatus.ACKNOWLEDGED)

    def test_clear_inbox(self):
        """Test clearing inbox"""
        self.broker.send_message(
            sender_id=self.sender_id,
            receiver_id=self.receiver_id,
            message_type=MessageType.TASK_REQUEST,
            content={}
        )
        self.broker.send_message(
            sender_id=self.sender_id,
            receiver_id=self.receiver_id,
            message_type=MessageType.INFO,
            content={}
        )

        count = self.broker.clear_inbox(self.receiver_id)
        self.assertEqual(count, 2)

        inbox = self.broker.get_inbox(self.receiver_id)
        self.assertEqual(len(inbox), 0)

    def test_get_history(self):
        """Test getting message history"""
        for i in range(5):
            self.broker.send_message(
                sender_id=self.sender_id,
                receiver_id=self.receiver_id,
                message_type=MessageType.INFO,
                content={"index": i}
            )

        history = self.broker.get_history(self.receiver_id)
        self.assertEqual(len(history), 5)

        # Test with limit
        limited = self.broker.get_history(self.receiver_id, limit=3)
        self.assertEqual(len(limited), 3)

    def test_get_conversation(self):
        """Test getting conversation between agents"""
        # agent-001 to agent-002
        self.broker.send_message(
            sender_id="agent-001",
            receiver_id="agent-002",
            message_type=MessageType.TASK_REQUEST,
            content={}
        )

        # agent-002 to agent-001 (reply)
        self.broker.send_message(
            sender_id="agent-002",
            receiver_id="agent-001",
            message_type=MessageType.TASK_RESULT,
            content={}
        )

        # Check conversation: agent-001 to agent-002 has one message
        conv_1_2 = self.broker.get_conversation("agent-001", "agent-002")
        self.assertEqual(len(conv_1_2), 1)
        self.assertEqual(conv_1_2[0].message_type, MessageType.TASK_REQUEST)

        # Check reverse conversation: agent-002 to agent-001 has one message
        conv_2_1 = self.broker.get_conversation("agent-002", "agent-001")
        self.assertEqual(len(conv_2_1), 1)
        self.assertEqual(conv_2_1[0].message_type, MessageType.TASK_RESULT)

    def test_get_inbox_count(self):
        """Test getting unread message count"""
        self.broker.send_message(
            sender_id=self.sender_id,
            receiver_id=self.receiver_id,
            message_type=MessageType.TASK_REQUEST,
            content={}
        )
        self.broker.send_message(
            sender_id=self.sender_id,
            receiver_id=self.receiver_id,
            message_type=MessageType.INFO,
            content={}
        )

        count = self.broker.get_inbox_count(self.receiver_id)
        self.assertEqual(count, 2)

    def test_get_agent_stats(self):
        """Test getting message statistics for an agent"""
        # Agent-001 sends messages
        self.broker.send_message(
            sender_id="agent-001",
            receiver_id="agent-002",
            message_type=MessageType.TASK_REQUEST,
            content={}
        )

        # Agent-001 receives messages
        self.broker.send_message(
            sender_id="agent-002",
            receiver_id="agent-001",
            message_type=MessageType.TASK_RESULT,
            content={}
        )

        stats = self.broker.get_agent_stats("agent-001")
        self.assertEqual(stats["sent_messages"], 1)
        self.assertEqual(stats["received_messages"], 1)
        self.assertEqual(stats["total_messages"], 2)

    def test_broker_summary(self):
        """Test getting broker summary"""
        self.broker.send_message(
            sender_id=self.sender_id,
            receiver_id=self.receiver_id,
            message_type=MessageType.TASK_REQUEST,
            content={}
        )

        summary = self.broker.get_summary()
        self.assertEqual(summary["total_messages"], 1)
        self.assertEqual(summary["active_agents"], 2)


# ============================================================================
# Integration Tests
# ============================================================================

class TestAgentIntegration(unittest.TestCase):
    """Integration tests for agent framework"""

    def test_full_delegation_workflow(self):
        """Test complete delegation workflow"""
        # Create agents
        coordinator = CoordinatorAgent()
        executor = ExecutorAgent()
        validator = ValidatorAgent()

        # Create manager and registry
        delegation_manager = DelegationManager()
        registry = AgentRegistry()

        # Register agents
        registry.register(coordinator)
        registry.register(executor)
        registry.register(validator)

        # Set up scopes
        coordinator.add_scope("read:data")
        coordinator.add_scope("write:data")

        # Create delegation
        delegation = delegation_manager.create_delegation_request(
            source_agent=coordinator,
            target_agent=executor,
            task_description="Process data files",
            required_scopes=["read:data"],
            expires_in_hours=24
        )

        self.assertIsNotNone(delegation)

        # Approve delegation
        delegation_manager.approve_delegation(delegation.request_id, executor)

        # Executor now has read:data scope
        self.assertTrue(executor.has_scope("read:data"))

        # Queue task on executor
        executor.queue_task(
            task_id="task-001",
            action="process_files",
            parameters={"path": "/data"}
        )

        executor.execute_task("task-001")
        executor.complete_task("task-001", {"processed": 42})

        # Validate result
        validator.add_validation_rule("task_result", "must_have_count")
        is_valid = validator.validate_result(
            result_id="result-001",
            result_type="task_result",
            result_data={"processed": 42}
        )
        self.assertTrue(is_valid)

    def test_multi_agent_communication(self):
        """Test communication between multiple agents"""
        broker = MessageBroker()

        # Create agent instances
        coordinator = CoordinatorAgent()
        researcher = ResearcherAgent()
        executor = ExecutorAgent()

        # Coordinator sends task request to researcher
        msg1 = broker.send_message(
            sender_id=coordinator.agent_id,
            receiver_id=researcher.agent_id,
            message_type=MessageType.TASK_REQUEST,
            content={"task": "research_topic", "topic": "AI"},
            requires_ack=True
        )

        # Researcher acknowledges
        broker.acknowledge_message(msg1.message_id)

        # Researcher sends findings back
        msg2 = broker.send_message(
            sender_id=researcher.agent_id,
            receiver_id=coordinator.agent_id,
            message_type=MessageType.TASK_RESULT,
            content={"findings": ["finding1", "finding2"]},
            reply_to=msg1.message_id
        )

        # Check coordinator's task request to researcher
        conversation_1 = broker.get_conversation(coordinator.agent_id, researcher.agent_id)
        self.assertEqual(len(conversation_1), 1)
        self.assertEqual(conversation_1[0].message_type, MessageType.TASK_REQUEST)

        # Check researcher's response to coordinator
        conversation_2 = broker.get_conversation(researcher.agent_id, coordinator.agent_id)
        self.assertEqual(len(conversation_2), 1)
        self.assertEqual(conversation_2[0].message_type, MessageType.TASK_RESULT)

        # Check coordinator's inbox
        coord_inbox = broker.get_inbox(coordinator.agent_id)
        self.assertEqual(len(coord_inbox), 1)
        self.assertEqual(coord_inbox[0].message_type, MessageType.TASK_RESULT)


if __name__ == "__main__":
    unittest.main()
