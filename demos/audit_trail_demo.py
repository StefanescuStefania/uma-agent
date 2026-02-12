#!/usr/bin/env python3
"""
Complete Audit Trail Demonstration

This demo shows:
1. Agent creation with database persistence
2. UMA resource access with audit logging
3. Agent delegation with scope reduction
4. Complete audit trail in database
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.base import BaseAgent, AgentType, AgentCapability, AgentToken
from agents.uma_client import UMAClient
from agents.database import get_db_session, AuditEvent, Delegation, AgentState, UMAToken
import requests
import uuid
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
KEYCLOAK_URL = "http://localhost:8080"
REALM = "test-realm"
RESOURCE_SERVER_URL = "http://localhost:5000"

def print_section(title: str):
    """Print a section header"""
    print(f"\n{'='*70}")
    print(f"{title}")
    print(f"{'='*70}\n")

def authenticate_agent() -> str:
    """Get client credentials token"""
    response = requests.post(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "resource-server",
            "client_secret": "uma-resource-server-secret"
        }
    )
    return response.json()["access_token"]

def create_audit_event(session, agent_id: str, event_type: str, action: str,
                       result: str, resource: str = None, scope: str = None,
                       extra_data: dict = None):
    """Create an audit event in the database"""
    event = AuditEvent(
        id=f"audit-{uuid.uuid4().hex[:8]}",
        event_type=event_type,
        agent_id=agent_id,
        action=action,
        result=result,
        resource=resource,
        scope=scope,
        extra_data=extra_data or {}
    )
    session.add(event)
    session.commit()
    print(f"  📝 Audit log: {event_type} - {action} - {result}")
    return event

def create_agent_state(session, agent: BaseAgent):
    """Persist agent state to database"""
    agent_state = AgentState(
        agent_id=agent.agent_id,
        agent_type=agent.agent_type.value,
        agent_name=agent.metadata.agent_name,
        description=agent.metadata.description,
        capabilities=[c.value for c in agent.capabilities],
        scopes=agent.get_scopes(),
        delegation_chain=agent.get_delegation_chain(),
        is_authenticated=agent.has_valid_token(),
        last_authentication=datetime.utcnow() if agent.has_valid_token() else None,
        custom_state=agent.get_all_state(),
        extra_data={}
    )
    session.add(agent_state)
    session.commit()
    print(f"  💾 Agent state saved: {agent.agent_id}")
    return agent_state

def create_delegation_record(session, source_agent: BaseAgent, target_agent_id: str,
                            task: str, scopes: list):
    """Create a delegation record"""
    delegation = Delegation(
        request_id=f"del-{uuid.uuid4().hex[:8]}",
        source_agent_id=source_agent.agent_id,
        target_agent_id=target_agent_id,
        task_description=task,
        status="approved",
        created_at=datetime.utcnow(),
        approved_at=datetime.utcnow(),
        scopes=scopes,
        original_scopes=source_agent.get_scopes(),
        delegation_chain=source_agent.get_delegation_chain() + [target_agent_id],
        extra_data={
            "source_type": source_agent.agent_type.value,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
    session.add(delegation)
    session.commit()
    print(f"  🔗 Delegation created: {source_agent.agent_id} → {target_agent_id}")
    return delegation

def main():
    """Run the complete audit trail demonstration"""

    print("""
╔══════════════════════════════════════════════════════════════════╗
║              COMPLETE AUDIT TRAIL DEMONSTRATION                  ║
╚══════════════════════════════════════════════════════════════════╝

This demo will:
  1. Create multiple agents and save their states
  2. Authenticate agents and log the events
  3. Access protected resources via UMA
  4. Create delegation chains
  5. Generate a complete audit trail
  6. Show you where to view all the logs
""")

    session = get_db_session()

    # ==================================================================
    # STEP 1: Create Coordinator Agent
    # ==================================================================
    print_section("Step 1: Create Coordinator Agent")

    coordinator = BaseAgent(
        agent_type=AgentType.COORDINATOR,
        agent_name="Coordinator Agent Alpha",
        description="Main coordinator agent that delegates tasks",
        capabilities=[AgentCapability.READ, AgentCapability.DELEGATE, AgentCapability.ORCHESTRATE]
    )

    coordinator.set_scopes(["read", "write", "delegate"])

    print(f"✓ Created: {coordinator.metadata.agent_name}")
    print(f"  ID: {coordinator.agent_id}")
    print(f"  Capabilities: {[c.value for c in coordinator.capabilities]}")
    print(f"  Scopes: {coordinator.get_scopes()}")

    # Save to database
    create_agent_state(session, coordinator)
    create_audit_event(session, coordinator.agent_id, "agent_created",
                      "create_coordinator", "success",
                      extra_data={"agent_type": coordinator.agent_type.value})

    # ==================================================================
    # STEP 2: Authenticate Coordinator
    # ==================================================================
    print_section("Step 2: Authenticate Coordinator Agent")

    token = authenticate_agent()
    coordinator.set_token(AgentToken(
        access_token=token,
        token_type="Bearer",
        expires_in=300
    ))

    print(f"✓ Coordinator authenticated")
    print(f"  Token valid: {coordinator.has_valid_token()}")

    # Log authentication
    create_audit_event(session, coordinator.agent_id, "authentication",
                      "authenticate_with_keycloak", "success",
                      extra_data={"method": "client_credentials"})

    # Update agent state
    session.query(AgentState).filter_by(agent_id=coordinator.agent_id).update({
        "is_authenticated": True,
        "last_authentication": datetime.utcnow()
    })
    session.commit()

    # ==================================================================
    # STEP 3: Configure UMA and Access Resource
    # ==================================================================
    print_section("Step 3: Access Protected Resource via UMA")

    uma_client = UMAClient(
        keycloak_url=KEYCLOAK_URL,
        realm=REALM,
        client_id="resource-server",
        client_secret="uma-resource-server-secret"
    )

    coordinator.set_uma_client(uma_client, RESOURCE_SERVER_URL)

    print("Requesting access to 'documents' resource...")

    # Request resource access
    rpt = coordinator.request_resource_access(resource="documents", scope="read")

    if rpt:
        print(f"✓ RPT obtained successfully")

        # Log UMA flow
        create_audit_event(session, coordinator.agent_id, "uma_authorization",
                          "request_rpt", "success",
                          resource="documents", scope="read",
                          extra_data={"rpt_expires_in": rpt.expires_in})

        # Save RPT to database
        uma_token = UMAToken(
            id=f"rpt-{uuid.uuid4().hex[:8]}",
            agent_id=coordinator.agent_id,
            token_type="rpt",
            token_value=rpt.access_token[:50] + "...",  # Truncated for security
            resource="documents",
            scopes=["read"],
            permissions=rpt.permissions or [],
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(seconds=rpt.expires_in),
            is_active=True
        )
        session.add(uma_token)
        session.commit()
        print(f"  💾 RPT saved to database")

        # Access the resource
        print("\nAccessing resource with RPT...")
        resource_data = coordinator.access_protected_resource(resource="documents")

        if resource_data:
            print(f"✓ Access granted!")
            create_audit_event(session, coordinator.agent_id, "resource_access",
                              "access_documents", "success",
                              resource="documents", scope="read",
                              extra_data={"document_count": len(resource_data.get("documents", []))})
        else:
            print(f"✗ Access denied")
            create_audit_event(session, coordinator.agent_id, "resource_access",
                              "access_documents", "failure",
                              resource="documents", scope="read")
    else:
        print(f"✗ Failed to obtain RPT")
        create_audit_event(session, coordinator.agent_id, "uma_authorization",
                          "request_rpt", "failure",
                          resource="documents", scope="read")

    # ==================================================================
    # STEP 4: Create Researcher Agent
    # ==================================================================
    print_section("Step 4: Create Researcher Agent")

    researcher = BaseAgent(
        agent_type=AgentType.RESEARCHER,
        agent_name="Researcher Agent Beta",
        description="Research agent that analyzes data",
        capabilities=[AgentCapability.READ, AgentCapability.ANALYZE]
    )

    # Set reduced scopes (scope reduction principle)
    researcher.set_scopes(["read"])
    researcher.set_delegation_chain(coordinator.get_delegation_chain() + [researcher.agent_id])

    print(f"✓ Created: {researcher.metadata.agent_name}")
    print(f"  ID: {researcher.agent_id}")
    print(f"  Scopes: {researcher.get_scopes()} (reduced from coordinator's scopes)")
    print(f"  Delegation depth: {researcher.get_delegation_depth()}")

    create_agent_state(session, researcher)
    create_audit_event(session, researcher.agent_id, "agent_created",
                      "create_researcher", "success",
                      extra_data={"delegated_from": coordinator.agent_id})

    # ==================================================================
    # STEP 5: Delegate Task to Researcher
    # ==================================================================
    print_section("Step 5: Delegate Task to Researcher")

    task = "Analyze documents and extract key findings"
    print(f"Task: {task}")
    print(f"Delegation chain: {' → '.join(researcher.get_delegation_chain())}")

    # Create delegation record
    delegation = create_delegation_record(
        session, coordinator, researcher.agent_id,
        task, researcher.get_scopes()
    )

    # Log delegation events for both agents
    create_audit_event(session, coordinator.agent_id, "delegation_requested",
                      "delegate_to_researcher", "success",
                      extra_data={
                          "target_agent": researcher.agent_id,
                          "task": task,
                          "scopes": researcher.get_scopes(),
                          "delegation_id": delegation.request_id
                      })

    create_audit_event(session, researcher.agent_id, "delegation_received",
                      "receive_delegation", "success",
                      extra_data={
                          "source_agent": coordinator.agent_id,
                          "task": task,
                          "delegation_id": delegation.request_id
                      })

    # ==================================================================
    # STEP 6: Create Executor Agent
    # ==================================================================
    print_section("Step 6: Create Executor Agent (Sub-delegation)")

    executor = BaseAgent(
        agent_type=AgentType.EXECUTOR,
        agent_name="Executor Agent Gamma",
        description="Executor agent that performs specific tasks",
        capabilities=[AgentCapability.READ, AgentCapability.EXECUTE]
    )

    # Further scope reduction
    executor.set_scopes(["read"])
    executor.set_delegation_chain(researcher.get_delegation_chain() + [executor.agent_id])

    print(f"✓ Created: {executor.metadata.agent_name}")
    print(f"  ID: {executor.agent_id}")
    print(f"  Delegation depth: {executor.get_delegation_depth()}")
    print(f"  Full chain: {' → '.join(executor.get_delegation_chain())}")

    create_agent_state(session, executor)
    create_audit_event(session, executor.agent_id, "agent_created",
                      "create_executor", "success",
                      extra_data={
                          "delegated_from": researcher.agent_id,
                          "delegation_depth": executor.get_delegation_depth()
                      })

    # Create sub-delegation
    sub_task = "Execute data extraction from documents"
    sub_delegation = create_delegation_record(
        session, researcher, executor.agent_id,
        sub_task, executor.get_scopes()
    )

    create_audit_event(session, researcher.agent_id, "delegation_requested",
                      "delegate_to_executor", "success",
                      extra_data={
                          "target_agent": executor.agent_id,
                          "task": sub_task,
                          "delegation_id": sub_delegation.request_id
                      })

    create_audit_event(session, executor.agent_id, "delegation_received",
                      "receive_delegation", "success",
                      extra_data={
                          "source_agent": researcher.agent_id,
                          "task": sub_task,
                          "delegation_id": sub_delegation.request_id
                      })

    # Mark delegation as completed
    session.query(Delegation).filter_by(request_id=sub_delegation.request_id).update({
        "status": "completed",
        "completed_at": datetime.utcnow(),
        "result_data": {"status": "success", "records_processed": 42}
    })
    session.commit()

    create_audit_event(session, executor.agent_id, "task_completed",
                      "complete_data_extraction", "success",
                      extra_data={
                          "delegation_id": sub_delegation.request_id,
                          "records_processed": 42
                      })

    # ==================================================================
    # STEP 7: Show Complete Audit Trail
    # ==================================================================
    print_section("Step 7: Complete Audit Trail Generated!")

    # Count events
    total_events = session.query(AuditEvent).count()
    total_delegations = session.query(Delegation).count()
    total_agents = session.query(AgentState).count()
    total_tokens = session.query(UMAToken).count()

    print(f"Database Summary:")
    print(f"  📝 Audit Events: {total_events}")
    print(f"  🔗 Delegations: {total_delegations}")
    print(f"  👤 Agent States: {total_agents}")
    print(f"  🎫 UMA Tokens: {total_tokens}")

    print(f"\n{'='*70}")
    print("HOW TO VIEW THE AUDIT TRAIL:")
    print(f"{'='*70}\n")

    print("1. Connect to PostgreSQL:")
    print("   docker exec -it uma-postgres psql -U keycloak")
    print()
    print("2. View all audit events:")
    print("   SELECT id, timestamp, event_type, agent_id, action, result, resource")
    print("   FROM audit_events")
    print("   ORDER BY timestamp DESC;")
    print()
    print("3. View delegations:")
    print("   SELECT request_id, source_agent_id, target_agent_id, task_description,")
    print("          status, delegation_chain")
    print("   FROM delegations")
    print("   ORDER BY created_at DESC;")
    print()
    print("4. View agent states:")
    print("   SELECT agent_id, agent_name, agent_type, capabilities, scopes,")
    print("          is_authenticated")
    print("   FROM agent_states;")
    print()
    print("5. View UMA tokens:")
    print("   SELECT id, agent_id, token_type, resource, scopes, is_active")
    print("   FROM uma_tokens;")
    print()

    print(f"{'='*70}")
    print("✓ COMPLETE AUDIT TRAIL DEMONSTRATION FINISHED!")
    print(f"{'='*70}\n")

    print("What was demonstrated:")
    print("  ✓ Agent creation with database persistence")
    print("  ✓ Agent authentication logging")
    print("  ✓ UMA resource access with audit trail")
    print("  ✓ Multi-level delegation (Coordinator → Researcher → Executor)")
    print("  ✓ Scope reduction at each delegation level")
    print("  ✓ Complete audit trail in PostgreSQL")
    print("  ✓ Delegation chain tracking")
    print("  ✓ Task completion logging")
    print()

    session.close()
    return 0

if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n✗ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
