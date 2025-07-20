import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

from loguru import logger

from src.models.base import AgentMessage, AgentRole
from src.services.logging_service import LoggingService


class BaseAgent(ABC):
    def __init__(self, role: AgentRole, session_id: str):
        self.role = role
        self.session_id = session_id
        self.logger = LoggingService()
        self.message_queue: List[AgentMessage] = []

    @abstractmethod
    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process incoming message and return response if needed"""

    async def send_message(self,
                          to_agent: AgentRole,
                          message_type: str,
                          content: Dict[str, Any]) -> AgentMessage:
        """Send message to another agent"""
        message = AgentMessage(
            session_id=self.session_id,
            from_agent=self.role,
            to_agent=to_agent,
            message_type=message_type,
            content=content,
        )

        await self.logger.log_agent_interaction(message)

        return message

    async def log_decision(self, decision: str, rationale: str, data: Dict[str, Any] = None):
        """Log agent decision with rationale"""
        log_entry = {
            "agent": self.role.value,
            "session_id": self.session_id,
            "decision": decision,
            "rationale": rationale,
            "data": data or {},
            "timestamp": datetime.now().isoformat(),
        }

        await self.logger.log_decision(log_entry)
        logger.info(f"[{self.role.value}] Decision: {decision} - {rationale}")

    def get_system_prompt(self) -> str:
        """Get system prompt for this agent"""
        return f"You are a {self.role.value} agent in a security analysis system."

