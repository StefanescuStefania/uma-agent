#!/usr/bin/env python3
"""
Complete Keycloak-Integrated Workflow Test

Tests the complete workflow with Keycloak as the authoritative source for:
- User authentication
- Scope management
- Delegation validation
- Authorization checks
- Audit logging

REQUIREMENTS:
- Keycloak server running on http://localhost:8080
- Test users created: python3 tests/setup_keycloak_test_users.py setup
"""

import sys
import os
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keycloak import KeycloakAdmin
from agents.keycloak_auth import KeycloakAgentAuth
from agents.keycloak_scopes import KeycloakScopeManager
from agents.keycloak_delegation import KeycloakDelegationManager, DelegationStatus
from agents.messaging import MessageBroker, MessageType
from agents.workflow_logger import WorkflowLogger, WorkflowEventType
from agents.implementations import CoordinatorAgent, ResearcherAgent, ExecutorAgent


class TestKeycloakCompleteWorkflow:
    """Test complete workflow with Keycloak integration"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures"""
        # Connect to Keycloak
        try:
            self.keycloak_admin = KeycloakAdmin(
                server_url="http://localhost:8080",
                client_id="admin-cli",
                client_secret=None,
                realm_name="master",
                user_realm_name="master",
                username="admin",
                password="admin",
                verify=False
            )
            self.keycloak_admin.realm_name = "uma-agent-realm"
        except Exception as e:
            pytest.skip(f"Keycloak not available: {e}")

        # Initialize components
        self.keycloak_auth = KeycloakAgentAuth(
            server_url="http://localhost:8080",
            realm_name="uma-agent-realm",
            admin_user="admin",
            admin_password="admin",
            client_id="uma-agent-client",
            client_secret="secret123"
        )

        self.scope_manager = KeycloakScopeManager(
            self.keycloak_admin,
            realm_name="uma-agent-realm"
        )

        self.delegation_manager = KeycloakDelegationManager(
            self.keycloak_admin,
            self.scope_manager,
            realm_name="uma-agent-realm",
            max_delegation_depth=3
        )

        self.message_broker = MessageBroker()
        self.logger = WorkflowLogger()

    def test_keycloak_connection(self):
        """Test Keycloak connection"""
        # Verify connection is working
        assert self.keycloak_admin is not None

        # List users to verify connectivity
        users = self.keycloak_admin.get_users()
        assert users is not None
        assert len(users) > 0

    def test_scope_management_via_keycloak(self):
        """Test scope management through Keycloak"""
        # Get a test user
        users = self.keycloak_admin.get_users()
        coordinator_user = None
        for user in users:
            if user.get("username") == "coordinator-user":
                coordinator_user = user
                break

        if coordinator_user is None:
            pytest.skip("coordinator-user not found in Keycloak")

        # Get scopes from Keycloak
        scopes = self.scope_manager.get_agent_scopes("coordinator-user")
        assert "read:data" in scopes
        assert "write:data" in scopes
        assert "delegate:tasks" in scopes

        # Verify agent has specific scope
        assert self.scope_manager.agent_has_scope("coordinator-user", "read:data")

        # Verify agent has all required scopes
        assert self.scope_manager.agent_has_scopes(
            "coordinator-user",
            ["read:data", "write:data"]
        )

    def test_scope_reduction_for_delegation(self):
        """Test scope reduction for delegation"""
        # Reduce scopes following principle of least privilege
        reduced = self.scope_manager.reduce_scopes_for_delegation(
            "coordinator-user",
            ["read:data"]
        )

        # Should only get what's needed
        assert "read:data" in reduced
        assert "write:data" not in reduced
        assert "delegate:tasks" not in reduced

    def test_delegation_creation_and_approval(self):
        """Test delegation through Keycloak"""
        # Create delegation request
        delegation = self.delegation_manager.create_delegation_request(
            source_agent_id="coordinator-user",
            target_agent_id="researcher-user",
            task_description="Test delegation task",
            required_scopes=["read:data"],
            expires_in_hours=24
        )

        assert delegation is not None
        assert delegation.status == DelegationStatus.PENDING
        assert "read:data" in delegation.granted_scopes

        # Approve delegation
        approved = self.delegation_manager.approve_delegation(
            delegation.request_id,
            approver_id="admin"
        )

        assert approved is True

        # Verify target agent now has delegated scope
        assert self.scope_manager.agent_has_scope(
            "researcher-user",
            "read:data"
        )

    def test_authorization_check_with_scopes(self):
        """Test authorization checks using Keycloak scopes"""
        # Coordinator should be able to delegate
        can_delegate = self.delegation_manager.scope_manager.agent_has_scopes(
            "coordinator-user",
            ["delegate:tasks"]
        )
        assert can_delegate is True

        # Executor should NOT have delegate:tasks
        can_delegate = self.delegation_manager.scope_manager.agent_has_scopes(
            "executor-user",
            ["delegate:tasks"]
        )
        assert can_delegate is False

    def test_message_passing_with_authenticated_agents(self):
        """Test messaging between authenticated agents"""
        # Send message
        msg = self.message_broker.send_message(
            sender_id="coordinator-user",
            receiver_id="researcher-user",
            message_type=MessageType.TASK_REQUEST,
            content={"task": "analyze_data"}
        )

        assert msg is not None
        assert msg.sender_id == "coordinator-user"
        assert msg.receiver_id == "researcher-user"

        # Check inbox
        inbox = self.message_broker.get_inbox("researcher-user")
        assert len(inbox) > 0

        # Log message
        self.logger.log_message_sent(
            msg.message_id,
            "coordinator-user",
            "Coordinator",
            "researcher-user",
            "Researcher",
            "task_request",
            user_id="test-user"
        )

    def test_complete_delegation_workflow(self):
        """Test complete delegation workflow with logging"""
        session_id = "test-session-001"

        # Log workflow start
        self.logger.log(
            WorkflowEventType.WORKFLOW_STARTED,
            "Starting complete workflow test",
            session_id=session_id,
            user_id="test-user"
        )

        # Step 1: Create delegation
        self.logger.log_delegation_requested(
            "deleg-001",
            "coordinator-user",
            "Coordinator",
            "researcher-user",
            "Researcher",
            ["read:data"],
            "Analyze research data",
            user_id="test-user",
            session_id=session_id
        )

        delegation = self.delegation_manager.create_delegation_request(
            source_agent_id="coordinator-user",
            target_agent_id="researcher-user",
            task_description="Analyze research data",
            required_scopes=["read:data"],
            expires_in_hours=24
        )

        assert delegation is not None

        # Step 2: Approve delegation
        approved = self.delegation_manager.approve_delegation(
            delegation.request_id
        )

        assert approved is True

        self.logger.log_delegation_approved(
            delegation.request_id,
            "coordinator-user",
            "researcher-user",
            "Researcher",
            ["read:data"],
            approved_by="admin",
            user_id="test-user",
            session_id=session_id
        )

        # Step 3: Send task
        msg = self.message_broker.send_message(
            sender_id="coordinator-user",
            receiver_id="researcher-user",
            message_type=MessageType.TASK_REQUEST,
            content={"task": "analyze", "dataset": "research_data"}
        )

        assert msg is not None

        self.logger.log_message_sent(
            msg.message_id,
            "coordinator-user",
            "Coordinator",
            "researcher-user",
            "Researcher",
            "task_request",
            user_id="test-user",
            session_id=session_id
        )

        # Step 4: Task execution
        self.logger.log_task_started(
            "task-001",
            "researcher-user",
            "Researcher",
            "Analyze research data",
            user_id="test-user",
            session_id=session_id
        )

        self.logger.log_task_completed(
            "task-001",
            "researcher-user",
            "Researcher",
            "Analyze research data",
            {"records_analyzed": 1000, "quality": 0.94},
            user_id="test-user",
            session_id=session_id
        )

        # Step 5: Log workflow completion
        self.logger.log(
            WorkflowEventType.WORKFLOW_COMPLETED,
            "Workflow completed successfully",
            session_id=session_id,
            user_id="test-user"
        )

        # Verify logs
        session_logs = self.logger.get_logs(session_id=session_id)
        assert len(session_logs) > 0

        # Get session summary
        summary = self.logger.get_session_summary(session_id)
        assert summary["session_id"] == session_id
        assert summary["total_events"] > 0

    def test_workflow_logging_and_export(self):
        """Test workflow logging and export capabilities"""
        # Create some test logs
        self.logger.log_agent_created(
            "agent-001",
            "Test Agent",
            "coordinator",
            user_id="test-user"
        )

        self.logger.log_scope_granted(
            "agent-001",
            "Test Agent",
            "read:data",
            user_id="test-user"
        )

        self.logger.log_authorization_check(
            "agent-001",
            "Test Agent",
            "read",
            allowed=True,
            required_scopes=["read:data"],
            agent_scopes=["read:data", "write:data"]
        )

        # Get statistics
        stats = self.logger.get_statistics()
        assert stats["total_events"] >= 3
        assert stats["total_agents"] >= 1

        # Export logs
        log_file = self.logger.export_logs()
        assert log_file.exists()

        # Verify log file contains data
        with open(log_file, 'r') as f:
            import json
            data = json.load(f)
            assert "logs" in data
            assert len(data["logs"]) > 0

    def test_delegation_statistics(self):
        """Test delegation statistics"""
        # Create a few delegations
        for i in range(3):
            delegation = self.delegation_manager.create_delegation_request(
                source_agent_id="coordinator-user",
                target_agent_id="researcher-user",
                task_description=f"Task {i}",
                required_scopes=["read:data"]
            )
            if delegation and i < 2:
                self.delegation_manager.approve_delegation(
                    delegation.request_id
                )

        # Get statistics
        stats = self.delegation_manager.get_delegation_statistics()
        assert stats["total"] >= 3
        assert stats["approved"] >= 2
        assert stats["pending"] >= 1


class TestKeycloakUserManagement:
    """Test user management via Keycloak"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup"""
        try:
            self.keycloak_admin = KeycloakAdmin(
                server_url="http://localhost:8080",
                client_id="admin-cli",
                client_secret=None,
                realm_name="master",
                user_realm_name="master",
                username="admin",
                password="admin",
                verify=False
            )
            self.keycloak_admin.realm_name = "uma-agent-realm"
        except Exception as e:
            pytest.skip(f"Keycloak not available: {e}")

        self.scope_manager = KeycloakScopeManager(
            self.keycloak_admin,
            realm_name="uma-agent-realm"
        )

    def test_list_test_users(self):
        """Test listing test users from Keycloak"""
        users = self.keycloak_admin.get_users()
        assert len(users) > 0

        # Find coordinator user
        coordinator = None
        for user in users:
            if user.get("username") == "coordinator-user":
                coordinator = user
                break

        assert coordinator is not None
        assert coordinator.get("email") == "coordinator@agents.local"

    def test_agents_with_specific_scope(self):
        """Test finding agents with specific scope"""
        agents = self.scope_manager.list_agents_with_scope("read:data")
        assert len(agents) > 0
        assert "coordinator-user" in agents

    def test_scope_hierarchy(self):
        """Test scope hierarchy"""
        hierarchy = self.scope_manager.get_scope_hierarchy()
        assert "basic" in hierarchy
        assert "elevated" in hierarchy
        assert "admin" in hierarchy

        assert "read:data" in hierarchy["basic"]
        assert "delegate:tasks" in hierarchy["elevated"]
        assert "admin:all" in hierarchy["admin"]


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "-s"])
