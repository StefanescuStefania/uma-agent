#!/usr/bin/env python3
"""
Interactive Agent Framework Demo

Run this to get an interactive console where you can:
- Create agents
- Delegate tasks
- Send messages
- Validate results
- See everything in real-time

Usage:
    python3 examples/interactive_demo.py
"""

import sys
from datetime import datetime

sys.path.insert(0, '/home/nia/Desktop/ATM/disertatie/uma-agent')

from agents.registry import AgentRegistry
from agents.delegation import DelegationManager
from agents.messaging import MessageBroker, MessageType
from agents.implementations import (
    CoordinatorAgent, ResearcherAgent, ExecutorAgent, ValidatorAgent
)


class InteractiveDemo:
    """Interactive agent framework demonstration"""

    def __init__(self):
        self.registry = AgentRegistry()
        self.delegation_manager = DelegationManager(max_delegation_depth=3)
        self.message_broker = MessageBroker()
        self.agents = {}

    def show_menu(self):
        """Display main menu"""
        print("\n" + "=" * 70)
        print("  UMA-AGENT: Interactive Proof of Concept")
        print("=" * 70)
        print("\n1. Create Agent")
        print("2. List Agents")
        print("3. Create Delegation")
        print("4. Send Message")
        print("5. Check Inbox")
        print("6. View Agent Info")
        print("7. View Delegation Status")
        print("8. Execute Task")
        print("9. Validate Result")
        print("10. View Message History")
        print("0. Exit")
        print("\n" + "-" * 70)

    def create_agent(self):
        """Create a new agent interactively"""
        print("\n--- Create Agent ---")
        agent_name = input("Agent name: ").strip()

        print("\nAgent type:")
        print("1. Coordinator")
        print("2. Researcher")
        print("3. Executor")
        print("4. Validator")
        choice = input("Select (1-4): ").strip()

        agent_map = {
            "1": ("Coordinator", CoordinatorAgent),
            "2": ("Researcher", ResearcherAgent),
            "3": ("Executor", ExecutorAgent),
            "4": ("Validator", ValidatorAgent),
        }

        if choice not in agent_map:
            print("❌ Invalid choice")
            return

        type_name, agent_class = agent_map[choice]
        agent = agent_class(agent_name=agent_name)
        self.registry.register(agent)
        self.agents[agent.agent_id] = agent

        print(f"\n✓ Created {type_name}: {agent_name}")
        print(f"  ID: {agent.agent_id}")
        print(f"  Type: {type_name}")
        print(f"  Capabilities: {', '.join([c.value for c in agent.capabilities])}")

        # Add scopes
        add_scopes = input("\nAdd scopes? (comma-separated, e.g. 'read:data,write:cache'): ").strip()
        if add_scopes:
            for scope in add_scopes.split(","):
                agent.add_scope(scope.strip())
            print(f"✓ Scopes added: {agent.get_scopes()}")

    def list_agents(self):
        """List all agents"""
        print("\n--- Registered Agents ---")

        if not self.agents:
            print("No agents created yet")
            return

        for agent_id, agent in self.agents.items():
            info = agent.get_info()
            print(f"\n• {info['agent_name']} ({info['agent_type']})")
            print(f"  ID: {agent_id}")
            print(f"  Scopes: {', '.join(info['scopes']) if info['scopes'] else '(none)'}")
            print(f"  Capabilities: {', '.join(info['capabilities'])}")
            print(f"  Delegation Depth: {agent.get_delegation_depth()}")

    def create_delegation(self):
        """Create a delegation request"""
        print("\n--- Create Delegation ---")

        if len(self.agents) < 2:
            print("❌ Need at least 2 agents to delegate")
            return

        # Select source agent
        print("\nSource agent (who delegates):")
        source_agents = list(self.agents.items())
        for i, (agent_id, agent) in enumerate(source_agents, 1):
            print(f"{i}. {agent.metadata.agent_name} ({agent_id})")
        source_choice = int(input("Select (1-{}): ".format(len(source_agents)))) - 1
        source_agent = source_agents[source_choice][1]

        # Select target agent
        print("\nTarget agent (who receives delegation):")
        target_agents = [(aid, a) for aid, a in source_agents if aid != source_agent.agent_id]
        for i, (agent_id, agent) in enumerate(target_agents, 1):
            print(f"{i}. {agent.metadata.agent_name} ({agent_id})")
        target_choice = int(input("Select (1-{}): ".format(len(target_agents)))) - 1
        target_agent = target_agents[target_choice][1]

        # Get task description
        task_desc = input("\nTask description: ").strip()

        # Get required scopes
        print(f"\nSource agent scopes: {source_agent.get_scopes()}")
        required_scopes_input = input("Required scopes (comma-separated): ").strip()
        required_scopes = [s.strip() for s in required_scopes_input.split(",") if s.strip()]

        # Create delegation
        delegation = self.delegation_manager.create_delegation_request(
            source_agent=source_agent,
            target_agent=target_agent,
            task_description=task_desc,
            required_scopes=required_scopes,
            expires_in_hours=24
        )

        if not delegation:
            print("❌ Delegation failed - check scopes and capabilities")
            return

        print(f"\n✓ Delegation created: {delegation.request_id}")
        print(f"  Status: {delegation.status.value}")
        print(f"  Scopes: {delegation.required_scopes}")

        # Ask to approve
        approve = input("\nApprove now? (y/n): ").strip().lower()
        if approve == "y":
            if self.delegation_manager.approve_delegation(delegation.request_id, target_agent):
                print(f"✓ Delegation approved!")
                print(f"  {target_agent.metadata.agent_name} now has scopes: {target_agent.get_scopes()}")
            else:
                print("❌ Approval failed")

    def send_message(self):
        """Send a message between agents"""
        print("\n--- Send Message ---")

        if len(self.agents) < 2:
            print("❌ Need at least 2 agents")
            return

        # Select sender
        print("\nSender:")
        agents_list = list(self.agents.items())
        for i, (agent_id, agent) in enumerate(agents_list, 1):
            print(f"{i}. {agent.metadata.agent_name}")
        sender_choice = int(input("Select (1-{}): ".format(len(agents_list)))) - 1
        sender = agents_list[sender_choice][1]

        # Select receiver
        print("\nReceiver:")
        receivers = [(aid, a) for aid, a in agents_list if aid != sender.agent_id]
        for i, (agent_id, agent) in enumerate(receivers, 1):
            print(f"{i}. {agent.metadata.agent_name}")
        receiver_choice = int(input("Select (1-{}): ".format(len(receivers)))) - 1
        receiver = receivers[receiver_choice][1]

        # Message type
        print("\nMessage type:")
        print("1. Task Request")
        print("2. Task Result")
        print("3. Status Update")
        print("4. Error")
        print("5. Info")
        msg_type_choice = input("Select (1-5): ").strip()
        msg_types = {
            "1": MessageType.TASK_REQUEST,
            "2": MessageType.TASK_RESULT,
            "3": MessageType.STATUS_UPDATE,
            "4": MessageType.ERROR,
            "5": MessageType.INFO,
        }
        message_type = msg_types.get(msg_type_choice, MessageType.INFO)

        # Message content
        content_str = input("Message content (JSON or text): ").strip()
        try:
            import json
            content = json.loads(content_str)
        except:
            content = {"message": content_str}

        # Send message
        message = self.message_broker.send_message(
            sender_id=sender.agent_id,
            receiver_id=receiver.agent_id,
            message_type=message_type,
            content=content
        )

        print(f"\n✓ Message sent: {message.message_id}")
        print(f"  From: {sender.metadata.agent_name}")
        print(f"  To: {receiver.metadata.agent_name}")
        print(f"  Type: {message_type.value}")
        print(f"  Status: {message.status.value}")

    def check_inbox(self):
        """Check an agent's inbox"""
        print("\n--- Check Inbox ---")

        if not self.agents:
            print("❌ No agents created")
            return

        # Select agent
        print("Agent:")
        agents_list = list(self.agents.items())
        for i, (agent_id, agent) in enumerate(agents_list, 1):
            print(f"{i}. {agent.metadata.agent_name}")
        choice = int(input("Select (1-{}): ".format(len(agents_list)))) - 1
        agent = agents_list[choice][1]

        inbox = self.message_broker.get_inbox(agent.agent_id)

        print(f"\n--- Inbox for {agent.metadata.agent_name} ---")
        if not inbox:
            print("No unread messages")
            return

        for i, msg in enumerate(inbox, 1):
            print(f"\n{i}. Message {msg.message_id}")
            print(f"   From: {msg.sender_id}")
            print(f"   Type: {msg.message_type.value}")
            print(f"   Content: {msg.content}")
            print(f"   Status: {msg.status.value}")

            ack = input("   Acknowledge? (y/n): ").strip().lower()
            if ack == "y":
                self.message_broker.acknowledge_message(msg.message_id)
                print("   ✓ Acknowledged")

    def view_agent_info(self):
        """View detailed agent information"""
        print("\n--- Agent Information ---")

        if not self.agents:
            print("❌ No agents created")
            return

        # Select agent
        print("Agent:")
        agents_list = list(self.agents.items())
        for i, (agent_id, agent) in enumerate(agents_list, 1):
            print(f"{i}. {agent.metadata.agent_name}")
        choice = int(input("Select (1-{}): ".format(len(agents_list)))) - 1
        agent = agents_list[choice][1]

        info = agent.get_info()
        print(f"\n--- {info['agent_name']} ---")
        print(f"ID: {info['agent_id']}")
        print(f"Type: {info['agent_type']}")
        print(f"Description: {info['description']}")
        print(f"\nCapabilities:")
        for cap in info['capabilities']:
            print(f"  • {cap}")
        print(f"\nScopes:")
        for scope in info['scopes']:
            print(f"  • {scope}")
        print(f"\nDelegation Chain: {' → '.join(agent.get_delegation_chain())}")
        print(f"Delegation Depth: {agent.get_delegation_depth()}")

        # Show custom state if any
        all_state = agent.get_all_state()
        if all_state:
            print(f"\nCustom State:")
            for key, value in all_state.items():
                print(f"  {key}: {value}")

    def view_delegation_status(self):
        """View delegation status"""
        print("\n--- Delegation Status ---")

        summary = self.delegation_manager.get_summary()
        print(f"\nTotal Requests: {summary['total_requests']}")
        print(f"Active Delegations: {summary['active_delegations']}")
        print(f"Pending Requests: {summary['pending_requests']}")
        print(f"Rejected: {summary['rejected_requests']}")
        print(f"Completed: {summary['completed_requests']}")
        print(f"Max Delegation Depth: {summary['max_delegation_depth']}")

    def execute_task(self):
        """Execute a task on an executor agent"""
        print("\n--- Execute Task ---")

        # Find executor agents
        executors = [
            (aid, a) for aid, a in self.agents.items()
            if a.agent_type.value == "executor"
        ]

        if not executors:
            print("❌ No executor agents available")
            return

        print("Executor:")
        for i, (agent_id, agent) in enumerate(executors, 1):
            print(f"{i}. {agent.metadata.agent_name}")
        choice = int(input("Select (1-{}): ".format(len(executors)))) - 1
        executor = executors[choice][1]

        # Task details
        task_id = f"task-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        action = input("Action to execute: ").strip()
        params_str = input("Parameters (JSON): ").strip()

        try:
            import json
            params = json.loads(params_str) if params_str else {}
        except:
            params = {}

        # Queue and execute
        executor.queue_task(task_id, action, params)
        executor.execute_task(task_id)

        print(f"\n✓ Task started: {task_id}")
        print(f"  Action: {action}")
        print(f"  Status: executing")

        # Ask for result
        result_str = input("Task result (JSON): ").strip()
        try:
            import json
            result = json.loads(result_str)
        except:
            result = {"output": result_str}

        executor.complete_task(task_id, result)
        print(f"✓ Task completed!")
        print(f"  Result: {result}")

    def validate_result(self):
        """Validate a result with validator agent"""
        print("\n--- Validate Result ---")

        # Find validator agents
        validators = [
            (aid, a) for aid, a in self.agents.items()
            if a.agent_type.value == "validator"
        ]

        if not validators:
            print("❌ No validator agents available")
            return

        print("Validator:")
        for i, (agent_id, agent) in enumerate(validators, 1):
            print(f"{i}. {agent.metadata.agent_name}")
        choice = int(input("Select (1-{}): ".format(len(validators)))) - 1
        validator = validators[choice][1]

        # Validation details
        result_id = input("Result ID: ").strip()
        result_type = input("Result type: ").strip()
        result_data_str = input("Result data (JSON): ").strip()

        try:
            import json
            result_data = json.loads(result_data_str)
        except:
            result_data = {"data": result_data_str}

        # Validate
        is_valid = validator.validate_result(result_id, result_type, result_data)

        print(f"\n✓ Validation complete!")
        print(f"  Result: {'PASSED ✓' if is_valid else 'FAILED ✗'}")

        status = validator.get_validation_status(result_id)
        if status:
            print(f"  Type: {status['result_type']}")
            print(f"  Rules Checked: {status['rules_checked']}")

    def view_message_history(self):
        """View message history"""
        print("\n--- Message History ---")

        if not self.agents:
            print("❌ No agents created")
            return

        # Select agent
        print("Agent:")
        agents_list = list(self.agents.items())
        for i, (agent_id, agent) in enumerate(agents_list, 1):
            print(f"{i}. {agent.metadata.agent_name}")
        choice = int(input("Select (1-{}): ".format(len(agents_list)))) - 1
        agent = agents_list[choice][1]

        history = self.message_broker.get_history(agent.agent_id)

        print(f"\n--- Message History for {agent.metadata.agent_name} ---")
        if not history:
            print("No messages")
            return

        for i, msg in enumerate(history, 1):
            direction = "→" if msg.sender_id == agent.agent_id else "←"
            other_agent_id = msg.receiver_id if msg.sender_id == agent.agent_id else msg.sender_id
            print(f"\n{i}. {msg.message_id}")
            print(f"   {direction} {other_agent_id}")
            print(f"   Type: {msg.message_type.value}")
            print(f"   Status: {msg.status.value}")
            print(f"   Content: {msg.content}")

    def run(self):
        """Main interactive loop"""
        print("\n" + "=" * 70)
        print("  Welcome to UMA-AGENT Interactive Demo")
        print("  Proof of Concept: Agent Delegation & Communication")
        print("=" * 70)
        print("\nThis is an interactive console where you can:")
        print("  • Create agents (Coordinator, Researcher, Executor, Validator)")
        print("  • Set up scopes and capabilities")
        print("  • Create delegation requests")
        print("  • Send messages between agents")
        print("  • Check inboxes and message history")
        print("  • Execute tasks and validate results")
        print("\nLet's get started!\n")

        while True:
            self.show_menu()
            choice = input("Enter your choice (0-10): ").strip()

            if choice == "0":
                print("\n✓ Thanks for using UMA-AGENT!")
                break
            elif choice == "1":
                self.create_agent()
            elif choice == "2":
                self.list_agents()
            elif choice == "3":
                self.create_delegation()
            elif choice == "4":
                self.send_message()
            elif choice == "5":
                self.check_inbox()
            elif choice == "6":
                self.view_agent_info()
            elif choice == "7":
                self.view_delegation_status()
            elif choice == "8":
                self.execute_task()
            elif choice == "9":
                self.validate_result()
            elif choice == "10":
                self.view_message_history()
            else:
                print("❌ Invalid choice")


def main():
    """Run the interactive demo"""
    demo = InteractiveDemo()
    demo.run()


if __name__ == "__main__":
    main()
