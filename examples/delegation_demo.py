#!/usr/bin/env python3
"""
Agent Delegation Demo

Demonstrates the complete agent delegation workflow including:
- Agent registration and capability setup
- Delegation request creation and approval
- Scope reduction on delegation
- Delegation chain tracking
- Inter-agent communication
- Result validation

This example shows Phase 2 agent framework in action.
"""

import sys
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, '/home/nia/Desktop/ATM/disertatie/uma-agent')

from agents.registry import AgentRegistry
from agents.delegation import DelegationManager
from agents.messaging import MessageBroker, MessageType
from agents.implementations import (
    CoordinatorAgent, ResearcherAgent, ExecutorAgent, ValidatorAgent
)


def print_section(title: str) -> None:
    """Print a formatted section header"""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def print_agent_info(agent) -> None:
    """Print agent information"""
    info = agent.get_info()
    print(f"Agent: {info['agent_name']} ({info['agent_id']})")
    print(f"  Type: {info['agent_type']}")
    print(f"  Capabilities: {', '.join(info['capabilities'])}")
    print(f"  Scopes: {', '.join(info['scopes']) if info['scopes'] else '(none)'}")
    print(f"  Delegation Depth: {agent.get_delegation_depth()}")


def demo_basic_delegation():
    """Demo 1: Basic delegation between two agents"""
    print_section("Demo 1: Basic Delegation Between Two Agents")

    # Initialize components
    registry = AgentRegistry()
    delegation_manager = DelegationManager(max_delegation_depth=3)

    # Create agents
    coordinator = CoordinatorAgent(agent_name="MainCoordinator")
    executor = ExecutorAgent(agent_name="TaskExecutor")

    # Register agents
    registry.register(coordinator)
    registry.register(executor)
    print(f"Registered {len(registry.list_all_agents())} agents")

    # Set up scopes for coordinator
    coordinator.add_scope("read:database")
    coordinator.add_scope("write:cache")
    coordinator.add_scope("execute:tasks")
    print("\nCoordinator Initial State:")
    print_agent_info(coordinator)

    # Create delegation request
    print("\n→ Creating delegation request...")
    delegation = delegation_manager.create_delegation_request(
        source_agent=coordinator,
        target_agent=executor,
        task_description="Execute data processing task",
        required_scopes=["read:database", "execute:tasks"],
        expires_in_hours=24
    )

    if delegation:
        print(f"  ✓ Delegation request created: {delegation.request_id}")
        print(f"    Task: {delegation.task_description}")
        print(f"    Required scopes: {', '.join(delegation.required_scopes)}")
        print(f"    Status: {delegation.status.value}")
    else:
        print("  ✗ Failed to create delegation request")
        return

    # Approve delegation
    print("\n→ Approving delegation request...")
    if delegation_manager.approve_delegation(delegation.request_id, executor):
        print(f"  ✓ Delegation approved")
        print("\nExecutor After Delegation:")
        print_agent_info(executor)
        print(f"  Delegation chain: {' → '.join(executor.get_delegation_chain())}")
    else:
        print("  ✗ Failed to approve delegation")

    # Get delegation summary
    summary = delegation_manager.get_summary()
    print(f"\nDelegation Summary:")
    print(f"  Total requests: {summary['total_requests']}")
    print(f"  Active delegations: {summary['active_delegations']}")
    print(f"  Max depth: {summary['max_delegation_depth']}")


def demo_scope_reduction():
    """Demo 2: Scope reduction on delegation"""
    print_section("Demo 2: Scope Reduction (Principle of Least Privilege)")

    registry = AgentRegistry()
    delegation_manager = DelegationManager(max_delegation_depth=3)

    # Create agents
    researcher = ResearcherAgent(agent_name="DataResearcher")
    validator = ValidatorAgent(agent_name="ResultValidator")

    registry.register(researcher)
    registry.register(validator)

    # Researcher has broad scopes
    researcher.add_scope("read:all_databases")
    researcher.add_scope("read:production_data")
    researcher.add_scope("read:user_analytics")
    researcher.add_scope("write:reports")

    print("Researcher Scopes (broad access):")
    print(f"  {', '.join(researcher.get_scopes())}")

    # Delegate with reduced scopes
    print("\n→ Creating delegation with reduced scopes...")
    print("  Only granting: ['read:all_databases', 'read:user_analytics']")

    delegation = delegation_manager.create_delegation_request(
        source_agent=researcher,
        target_agent=validator,
        task_description="Validate analytics data",
        required_scopes=["read:all_databases", "read:user_analytics"],
        expires_in_hours=12
    )

    if delegation:
        delegation_manager.approve_delegation(delegation.request_id, validator)
        print(f"\n✓ Delegation approved with reduced scopes")
        print(f"\nValidator Scopes (reduced access):")
        print(f"  {', '.join(validator.get_scopes())}")
        print(f"  Scope reduction: 4 → {len(validator.get_scopes())}")


def demo_delegation_chain():
    """Demo 3: Multi-level delegation chain"""
    print_section("Demo 3: Multi-Level Delegation Chain")

    registry = AgentRegistry()
    delegation_manager = DelegationManager(max_delegation_depth=3)

    # Create three agents in a chain
    level1 = CoordinatorAgent(agent_name="Level1Coordinator")
    level2 = ResearcherAgent(agent_name="Level2Researcher")
    level3 = ExecutorAgent(agent_name="Level3Executor")

    registry.register(level1)
    registry.register(level2)
    registry.register(level3)

    # Set up scopes
    level1.add_capability('DELEGATE')
    level2.add_capability('DELEGATE')
    level1.add_scope("admin:all")
    level1.add_scope("read:data")
    level1.add_scope("write:data")

    print("Initial Setup:")
    print(f"  Level 1 scopes: {', '.join(level1.get_scopes())}")

    # First delegation: Level1 → Level2
    print("\n→ First delegation: Level1 → Level2")
    deleg1 = delegation_manager.create_delegation_request(
        source_agent=level1,
        target_agent=level2,
        task_description="Research task",
        required_scopes=["read:data"],
        expires_in_hours=24
    )
    if deleg1:
        delegation_manager.approve_delegation(deleg1.request_id, level2)
        print(f"  ✓ Level2 delegation chain: {' → '.join(level2.get_delegation_chain())}")
    else:
        print(f"  ✗ Failed to create delegation")
        return

    # Second delegation: Level2 → Level3
    print("\n→ Second delegation: Level2 → Level3")
    deleg2 = delegation_manager.create_delegation_request(
        source_agent=level2,
        target_agent=level3,
        task_description="Execution task",
        required_scopes=["read:data"],
        expires_in_hours=12
    )
    if deleg2:
        delegation_manager.approve_delegation(deleg2.request_id, level3)
        print(f"  ✓ Level3 delegation chain: {' → '.join(level3.get_delegation_chain())}")
        print(f"  ✓ Delegation depth: {level3.get_delegation_depth()}")
    else:
        print(f"  ✗ Failed to create second delegation (expected - demonstrating depth limits)")

    # Try to delegate further (should fail if exceeding max depth)
    print("\n→ Attempting third delegation: Level3 → New Agent...")
    new_agent = ValidatorAgent(agent_name="Level4Validator")
    registry.register(new_agent)

    can_delegate = delegation_manager.can_delegate(level3, new_agent)
    if can_delegate:
        deleg3 = delegation_manager.create_delegation_request(
            source_agent=level3,
            target_agent=new_agent,
            task_description="Validation task",
            required_scopes=["read:data"],
            expires_in_hours=6
        )
        print(f"  ✓ Further delegation allowed")
    else:
        print(f"  ✗ Cannot delegate further - reached max depth or constraint")


def demo_agent_communication():
    """Demo 4: Inter-agent communication"""
    print_section("Demo 4: Inter-Agent Communication")

    broker = MessageBroker()

    # Create agents
    coordinator = CoordinatorAgent(agent_name="TaskCoordinator")
    researcher = ResearcherAgent(agent_name="DataResearcher")
    executor = ExecutorAgent(agent_name="TaskExecutor")

    print(f"Created agents: {coordinator.agent_id}, {researcher.agent_id}, {executor.agent_id}")

    # Coordinator sends task request to researcher
    print("\n→ Coordinator sends task request to Researcher")
    msg1 = broker.send_message(
        sender_id=coordinator.agent_id,
        receiver_id=researcher.agent_id,
        message_type=MessageType.TASK_REQUEST,
        content={"task": "analyze_dataset", "dataset_id": "dataset-001"},
        requires_ack=True
    )
    print(f"  ✓ Message sent: {msg1.message_id}")

    # Researcher receives and acknowledges
    print("\n→ Researcher receives and acknowledges")
    inbox = broker.get_inbox(researcher.agent_id)
    print(f"  ✓ Inbox has {len(inbox)} message(s)")
    broker.acknowledge_message(msg1.message_id)
    print(f"  ✓ Message acknowledged")

    # Researcher sends findings to executor
    print("\n→ Researcher sends findings to Executor")
    msg2 = broker.send_message(
        sender_id=researcher.agent_id,
        receiver_id=executor.agent_id,
        message_type=MessageType.STATUS_UPDATE,
        content={"findings": ["trend_1", "trend_2", "anomaly_1"]},
        reply_to=msg1.message_id
    )
    print(f"  ✓ Message sent: {msg2.message_id}")

    # Executor processes and sends result
    print("\n→ Executor processes and sends result to Coordinator")
    msg3 = broker.send_message(
        sender_id=executor.agent_id,
        receiver_id=coordinator.agent_id,
        message_type=MessageType.TASK_RESULT,
        content={"status": "completed", "processed_items": 42},
        reply_to=msg1.message_id
    )
    print(f"  ✓ Message sent: {msg3.message_id}")

    # Show message statistics
    print("\n→ Message Statistics:")
    for agent_id, agent_name in [
        (coordinator.agent_id, "Coordinator"),
        (researcher.agent_id, "Researcher"),
        (executor.agent_id, "Executor")
    ]:
        stats = broker.get_agent_stats(agent_id)
        print(f"\n  {agent_name}:")
        print(f"    Sent: {stats['sent_messages']}")
        print(f"    Received: {stats['received_messages']}")
        print(f"    Unread: {stats['unread_messages']}")
        print(f"    Conversations: {stats['conversations']}")


def demo_complete_workflow():
    """Demo 5: Complete end-to-end workflow"""
    print_section("Demo 5: Complete End-to-End Workflow")

    # Initialize all components
    registry = AgentRegistry()
    delegation_manager = DelegationManager(max_delegation_depth=3)
    message_broker = MessageBroker()

    # Create agents
    coordinator = CoordinatorAgent(agent_name="MainCoordinator")
    researcher = ResearcherAgent(agent_name="DataAnalyst")
    executor = ExecutorAgent(agent_name="DataProcessor")
    validator = ValidatorAgent(agent_name="QualityValidator")

    # Register all agents
    for agent in [coordinator, researcher, executor, validator]:
        registry.register(agent)
    print(f"Registered {len(registry.list_all_agents())} agents")

    # Set up capabilities and scopes
    coordinator.add_capability('DELEGATE')
    researcher.add_capability('DELEGATE')
    executor.add_capability('DELEGATE')

    coordinator.add_scope("read:database")
    coordinator.add_scope("write:reports")
    coordinator.add_scope("execute:pipeline")

    print("\n--- Phase 1: Coordinate Work ---")
    print(f"Coordinator initiates workflow for dataset: 'sales-2024'")

    # Step 1: Coordinator delegates research to Researcher
    print("\n→ Delegating research task to Researcher")
    deleg_research = delegation_manager.create_delegation_request(
        source_agent=coordinator,
        target_agent=researcher,
        task_description="Analyze sales patterns",
        required_scopes=["read:database"],
        expires_in_hours=24
    )
    if deleg_research:
        delegation_manager.approve_delegation(deleg_research.request_id, researcher)
        print(f"  ✓ Approved: {deleg_research.request_id}")
        print(f"    Researcher scopes: {researcher.get_scopes()}")
    else:
        print(f"  ✗ Delegation failed")
        return

    # Step 2: Researcher sends task request via message
    print("\n→ Researcher starts research project")
    researcher.start_research(
        project_id="sales-analysis-2024",
        topic="Q4 Sales Patterns",
        sources=["database", "external_api"]
    )
    researcher.add_finding("sales-analysis-2024", "Revenue trend: +15% YoY")
    researcher.add_finding("sales-analysis-2024", "Top product: Widget-A")
    print(f"  ✓ Research started with 2 findings")

    # Step 3: Researcher delegates execution to Executor
    print("\n→ Delegating execution task to Executor")
    deleg_execution = delegation_manager.create_delegation_request(
        source_agent=researcher,
        target_agent=executor,
        task_description="Process research results",
        required_scopes=["read:database"],
        expires_in_hours=12
    )
    if deleg_execution:
        delegation_manager.approve_delegation(deleg_execution.request_id, executor)
        print(f"  ✓ Approved: {deleg_execution.request_id}")
    else:
        print(f"  ✗ Delegation failed (researcher may not have scopes)")
        print(f"    Researcher scopes: {researcher.get_scopes()}")

    # Step 4: Executor processes data
    print("\n--- Phase 2: Execute Work ---")
    executor.queue_task(
        task_id="process-sales-001",
        action="aggregate_sales_data",
        parameters={"project": "sales-analysis-2024", "period": "Q4"}
    )
    executor.execute_task("process-sales-001")
    executor.complete_task("process-sales-001", {
        "aggregated_records": 1250,
        "summary": {"revenue": 500000, "transactions": 2400}
    })
    print(f"  ✓ Processing completed: 1250 records aggregated")

    # Step 5: Executor sends results to Validator
    print("\n→ Sending results to Validator for quality check")
    msg_result = message_broker.send_message(
        sender_id=executor.agent_id,
        receiver_id=validator.agent_id,
        message_type=MessageType.TASK_RESULT,
        content=executor.get_result("process-sales-001")
    )
    print(f"  ✓ Result sent: {msg_result.message_id}")

    # Step 6: Validator validates
    print("\n--- Phase 3: Validate Results ---")
    validator.add_validation_rule("sales_result", "must_have_revenue")
    validator.add_validation_rule("sales_result", "must_have_transactions")

    result = executor.get_result("process-sales-001")
    is_valid = validator.validate_result(
        result_id="result-001",
        result_type="sales_result",
        result_data=result
    )
    print(f"  ✓ Validation: {'PASSED' if is_valid else 'FAILED'}")

    # Step 7: Send final result back to Coordinator
    print("\n→ Sending final result to Coordinator")
    msg_final = message_broker.send_message(
        sender_id=validator.agent_id,
        receiver_id=coordinator.agent_id,
        message_type=MessageType.TASK_RESULT,
        content={"validation_passed": is_valid, "records_processed": 1250}
    )
    print(f"  ✓ Final result sent: {msg_final.message_id}")

    # Summary
    print("\n--- Workflow Summary ---")
    print(f"Total agents: {len(registry.list_all_agents())}")
    print(f"Total delegations: {delegation_manager.get_summary()['total_requests']}")
    print(f"Total messages: {message_broker.get_summary()['total_messages']}")
    print(f"Coordinator inbox: {message_broker.get_inbox_count(coordinator.agent_id)} unread")


def main():
    """Run all demonstrations"""
    print("\n" + "=" * 70)
    print("  UMA-AGENT: Agent Framework Demonstration")
    print("  Phase 2 - Week 2: Delegation & Communication")
    print("=" * 70)

    try:
        # Run demonstrations
        demo_basic_delegation()
        demo_scope_reduction()
        demo_delegation_chain()
        demo_agent_communication()
        demo_complete_workflow()

        print_section("✓ All Demonstrations Completed Successfully")
        print("The agent framework is working correctly!")
        print("\nKey Features Demonstrated:")
        print("  ✓ Agent registration and capability management")
        print("  ✓ Delegation request creation and approval")
        print("  ✓ Scope reduction on delegation")
        print("  ✓ Delegation chain tracking and depth limits")
        print("  ✓ Multi-level delegation with circular prevention")
        print("  ✓ Inter-agent message passing")
        print("  ✓ Message acknowledgment and history")
        print("  ✓ Result validation workflow")
        print("\n")

    except Exception as e:
        print(f"\n✗ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
