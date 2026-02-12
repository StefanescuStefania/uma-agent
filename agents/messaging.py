"""
Agent Messaging System - Inter-agent communication

Provides:
- Message passing between agents
- Message acknowledgment
- Message history
- Message broker for coordination
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import uuid


class MessageType(str, Enum):
    """Types of messages agents can send"""
    TASK_REQUEST = "task_request"
    TASK_RESULT = "task_result"
    STATUS_UPDATE = "status_update"
    ACK = "acknowledgment"
    ERROR = "error"
    INFO = "info"


class MessageStatus(str, Enum):
    """Status of a message"""
    SENT = "sent"
    DELIVERED = "delivered"
    ACKNOWLEDGED = "acknowledged"
    FAILED = "failed"


@dataclass
class Message:
    """Message between agents"""

    message_id: str = field(default_factory=lambda: f"msg-{uuid.uuid4().hex[:8]}")
    sender_id: str = ""
    receiver_id: str = ""
    message_type: MessageType = MessageType.INFO
    content: Dict[str, Any] = field(default_factory=dict)
    status: MessageStatus = MessageStatus.SENT
    created_at: datetime = field(default_factory=datetime.utcnow)
    delivered_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    requires_ack: bool = False
    reply_to: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def mark_delivered(self) -> None:
        """Mark message as delivered"""
        self.status = MessageStatus.DELIVERED
        self.delivered_at = datetime.utcnow()

    def mark_acknowledged(self) -> None:
        """Mark message as acknowledged"""
        self.status = MessageStatus.ACKNOWLEDGED
        self.acknowledged_at = datetime.utcnow()

    def mark_failed(self) -> None:
        """Mark message as failed"""
        self.status = MessageStatus.FAILED

    def get_info(self) -> Dict[str, Any]:
        """Get message information"""
        return {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "message_type": self.message_type.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "delivered_at": self.delivered_at.isoformat() if self.delivered_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "requires_ack": self.requires_ack,
            "reply_to": self.reply_to,
        }


class MessageBroker:
    """
    Manages message passing between agents

    Stores messages, handles delivery, and maintains message history.
    """

    def __init__(self):
        """Initialize message broker"""
        self._messages: Dict[str, Message] = {}
        self._agent_inbox: Dict[str, List[str]] = {}  # agent_id -> message_ids
        self._agent_history: Dict[str, List[str]] = {}  # agent_id -> all message_ids
        self._conversations: Dict[str, List[str]] = {}  # conversation_id -> message_ids

    # ========================================================================
    # Message Operations
    # ========================================================================

    def send_message(
        self,
        sender_id: str,
        receiver_id: str,
        message_type: MessageType,
        content: Dict[str, Any],
        requires_ack: bool = False,
        reply_to: Optional[str] = None,
    ) -> Message:
        """
        Send a message from one agent to another

        Args:
            sender_id: ID of sending agent
            receiver_id: ID of receiving agent
            message_type: Type of message
            content: Message content
            requires_ack: Whether acknowledgment is required
            reply_to: ID of message this is replying to

        Returns:
            The created message
        """
        message = Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message_type=message_type,
            content=content,
            requires_ack=requires_ack,
            reply_to=reply_to,
        )

        # Store message
        self._messages[message.message_id] = message
        message.mark_delivered()

        # Add to receiver's inbox
        if receiver_id not in self._agent_inbox:
            self._agent_inbox[receiver_id] = []
        self._agent_inbox[receiver_id].append(message.message_id)

        # Add to history for both agents
        if sender_id not in self._agent_history:
            self._agent_history[sender_id] = []
        self._agent_history[sender_id].append(message.message_id)

        if receiver_id not in self._agent_history:
            self._agent_history[receiver_id] = []
        self._agent_history[receiver_id].append(message.message_id)

        # Create conversation
        conversation_id = f"conv-{sender_id}-{receiver_id}"
        if conversation_id not in self._conversations:
            self._conversations[conversation_id] = []
        self._conversations[conversation_id].append(message.message_id)

        return message

    def get_message(self, message_id: str) -> Optional[Message]:
        """Get a message by ID"""
        return self._messages.get(message_id)

    def acknowledge_message(self, message_id: str) -> bool:
        """
        Acknowledge a message

        Args:
            message_id: ID of message to acknowledge

        Returns:
            True if successful
        """
        message = self._messages.get(message_id)
        if not message:
            return False

        message.mark_acknowledged()
        return True

    # ========================================================================
    # Inbox Management
    # ========================================================================

    def get_inbox(self, agent_id: str) -> List[Message]:
        """
        Get unread messages in an agent's inbox

        Args:
            agent_id: ID of agent

        Returns:
            List of unread messages
        """
        message_ids = self._agent_inbox.get(agent_id, [])
        messages = []
        for msg_id in message_ids:
            if msg_id in self._messages:
                msg = self._messages[msg_id]
                if msg.status != MessageStatus.ACKNOWLEDGED:
                    messages.append(msg)
        return messages

    def clear_inbox(self, agent_id: str) -> int:
        """
        Mark all messages in inbox as acknowledged

        Args:
            agent_id: ID of agent

        Returns:
            Number of messages cleared
        """
        inbox = self.get_inbox(agent_id)
        for message in inbox:
            self.acknowledge_message(message.message_id)
        return len(inbox)

    def get_inbox_count(self, agent_id: str) -> int:
        """Get number of unread messages"""
        return len(self.get_inbox(agent_id))

    # ========================================================================
    # History Management
    # ========================================================================

    def get_history(self, agent_id: str, limit: Optional[int] = None) -> List[Message]:
        """
        Get message history for an agent

        Args:
            agent_id: ID of agent
            limit: Maximum number of messages to return

        Returns:
            List of messages
        """
        message_ids = self._agent_history.get(agent_id, [])
        messages = [self._messages[msg_id] for msg_id in message_ids if msg_id in self._messages]

        if limit:
            messages = messages[-limit:]

        return messages

    def get_conversation(
        self,
        agent1_id: str,
        agent2_id: str,
    ) -> List[Message]:
        """
        Get conversation history between two agents

        Args:
            agent1_id: ID of first agent
            agent2_id: ID of second agent

        Returns:
            List of messages in the conversation
        """
        conversation_id = f"conv-{agent1_id}-{agent2_id}"
        message_ids = self._conversations.get(conversation_id, [])

        # Try reversed order if not found
        if not message_ids:
            conversation_id = f"conv-{agent2_id}-{agent1_id}"
            message_ids = self._conversations.get(conversation_id, [])

        messages = [self._messages[msg_id] for msg_id in message_ids if msg_id in self._messages]
        return messages

    # ========================================================================
    # Statistics
    # ========================================================================

    def get_agent_stats(self, agent_id: str) -> Dict[str, Any]:
        """Get message statistics for an agent"""
        history = self.get_history(agent_id)
        inbox = self.get_inbox(agent_id)

        sent = [m for m in history if m.sender_id == agent_id]
        received = [m for m in history if m.receiver_id == agent_id]

        return {
            "agent_id": agent_id,
            "total_messages": len(history),
            "sent_messages": len(sent),
            "received_messages": len(received),
            "unread_messages": len(inbox),
            "conversations": len([c for c in self._conversations.keys() if agent_id in c]),
        }

    def get_summary(self) -> Dict[str, Any]:
        """Get overall message broker statistics"""
        return {
            "total_messages": len(self._messages),
            "active_agents": len(self._agent_history),
            "conversations": len(self._conversations),
            "undelivered_messages": len([m for m in self._messages.values() if m.status == MessageStatus.SENT]),
            "pending_ack": len([m for m in self._messages.values() if m.requires_ack and m.status != MessageStatus.ACKNOWLEDGED]),
        }

    def __repr__(self) -> str:
        """String representation"""
        return f"MessageBroker(messages={len(self._messages)}, agents={len(self._agent_history)})"
