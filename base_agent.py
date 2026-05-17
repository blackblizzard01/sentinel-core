# agents/base_agent.py
# ============================================================
# SENTINEL AI — BASE AGENT
# Every agent in the system inherits from this class.
# This enforces a consistent interface, shared logging,
# ChromaDB access, and LLM client setup across all agents.
# ============================================================

import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from groq import AsyncGroq
from anthropic import AsyncAnthropic
from openai import AsyncOpenAI

from constants import AgentName, LLMModel, AGENT_MODELS

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Abstract base class for all Sentinel AI agents.
    All agents must implement the run() method.
    Provides shared LLM clients, logging, and utility methods.
    """

    def __init__(
        self,
        agent_name: str,
        client_id: str,
        scan_id: str,
    ) -> None:
        """
        Initialize the base agent.

        Args:
            agent_name: One of AgentName constants
            client_id: The authorized client's ID — used for all KB queries
            scan_id: The current scan session ID
        """
        self.agent_name  = agent_name
        self.client_id   = client_id
        self.scan_id     = scan_id
        self.model       = AGENT_MODELS.get(agent_name, LLMModel.LLAMA_70B)
        self.started_at  = datetime.utcnow()

        # ─── LLM Clients ────────────────────────────────────
        self.groq      = AsyncGroq(api_key=os.getenv("GROQ_API_KEY"))
        self.anthropic = AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.openai    = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

        logger.info(f"[{self.agent_name}] Initialized | scan={self.scan_id} | client={self.client_id}")

    @abstractmethod
    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        """
        Main entry point for every agent.
        Receives the LangGraph state, returns updated state.
        Every agent MUST implement this method.

        Args:
            state: LangGraph shared state dict

        Returns:
            Updated state dict
        """
        pass

    async def call_groq(
        self,
        prompt: str,
        system: str = "You are a helpful assistant.",
        temperature: float = 0.7,
    ) -> str:
        """
        Call Groq API with Llama 3.1 70B.
        Use for: high volume attack generation, recon tasks.

        Args:
            prompt: User message
            system: System prompt
            temperature: Sampling temperature

        Returns:
            Model response text
        """
        try:
            response = await self.groq.chat.completions.create(
                model=LLMModel.LLAMA_70B,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user",   "content": prompt},
                ],
                temperature=temperature,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"[{self.agent_name}] Groq API error: {e}")
            raise

    async def call_claude(
        self,
        prompt: str,
        system: str = "You are a helpful assistant.",
        max_tokens: int = 4096,
    ) -> str:
        """
        Call Anthropic Claude Sonnet.
        Use for: report generation, autopatch code generation.

        Args:
            prompt: User message
            system: System prompt
            max_tokens: Maximum response length

        Returns:
            Model response text
        """
        try:
            response = await self.anthropic.messages.create(
                model=LLMModel.CLAUDE_SONNET,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"[{self.agent_name}] Anthropic API error: {e}")
            raise

    async def call_openai(
        self,
        prompt: str,
        system: str = "You are a helpful assistant.",
        temperature: float = 0.9,
    ) -> str:
        """
        Call OpenAI GPT-4o mini.
        Use for: mutation generation (creative variation at low cost).

        Args:
            prompt: User message
            system: System prompt
            temperature: Sampling temperature (higher = more creative)

        Returns:
            Model response text
        """
        try:
            response = await self.openai.chat.completions.create(
                model=LLMModel.GPT4O_MINI,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user",   "content": prompt},
                ],
                temperature=temperature,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"[{self.agent_name}] OpenAI API error: {e}")
            raise

    def log_action(self, action: str, detail: str = "") -> None:
        """
        Standardized action logging for all agents.
        Use this instead of print() everywhere.

        Args:
            action: Short action description
            detail: Additional context
        """
        logger.info(f"[{self.agent_name}] {action} | {detail}")

    def log_error(self, error: str, exception: Exception | None = None) -> None:
        """
        Standardized error logging for all agents.

        Args:
            error: Error description
            exception: Optional exception object
        """
        logger.error(f"[{self.agent_name}] ERROR: {error}", exc_info=exception)
