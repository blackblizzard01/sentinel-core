import asyncio
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional

import groq
from groq import AsyncGroq
from google import genai
from google.genai import types
from openai import AsyncOpenAI
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# third-party imports block — add this line:
from dotenv import load_dotenv

from pathlib import Path
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")

from constants import AGENT_MODELS, LLMModel

from agents.api_key_manager import ApiKeyManager

try:
    from google.api_core.exceptions import ResourceExhausted
except ImportError:  # pragma: no cover
    ResourceExhausted = Exception  # type: ignore[misc, assignment]


class BaseAgent(ABC):
    """Abstract base class for all Sentinel AI agents. Provides shared LLM clients,
    structured logging, and retry-safe API call methods. All agent subclasses must inherit this."""

    def __init__(self, agent_name: str, client_id: str, scan_id: str) -> None:
        """Initialise agent identity, LLM clients, and logger."""
        self.agent_name = agent_name
        self.client_id = client_id
        self.scan_id = scan_id
        self.model: str = AGENT_MODELS.get(agent_name, LLMModel.LLAMA_70B)
        self.logger = logging.getLogger(f"sentinel.{agent_name}")

        groq_key = ApiKeyManager.acquire_key("groq")
        deepseek_key = ApiKeyManager.acquire_key("deepseek")
        gemini_key = ApiKeyManager.acquire_key("gemini")

        self.groq = AsyncGroq(api_key=groq_key)
        self.deepseek = AsyncOpenAI(
            api_key=deepseek_key,
            base_url="https://api.deepseek.com",
        )
        self.gemini = genai.Client(api_key=gemini_key)

        self.logger.info(
            "LLM clients ready — groq_keys=%s gemini_keys=%s deepseek_keys=%s",
            ApiKeyManager.key_count("groq"),
            ApiKeyManager.key_count("gemini"),
            ApiKeyManager.key_count("deepseek"),
        )

    def _rotate_groq_client(self) -> None:
        """Rebuild the Groq client with the next API key after rate limiting."""
        self.groq = AsyncGroq(api_key=ApiKeyManager.rotate("groq"))

    def _rotate_gemini_client(self) -> None:
        """Reconfigure Gemini with the next API key after rate limiting."""
        self.gemini = genai.Client(api_key=ApiKeyManager.rotate("gemini"))

    def _rotate_deepseek_client(self) -> None:
        """Rebuild the DeepSeek client with the next API key after rate limiting."""
        self.deepseek = AsyncOpenAI(
            api_key=ApiKeyManager.rotate("deepseek"),
            base_url="https://api.deepseek.com",
        )

    def _groq_before_retry(self, retry_state: object) -> None:
        """Rotate Groq key and log before a tenacity retry sleep."""
        self._rotate_groq_client()
        self._retry_warning("call_groq", retry_state)

    def _gemini_before_retry(self, retry_state: object) -> None:
        """Rotate Gemini key and log before a tenacity retry sleep."""
        self._rotate_gemini_client()
        self._retry_warning("call_gemini", retry_state)

    def _deepseek_before_retry(self, retry_state: object) -> None:
        """Rotate DeepSeek key and log before a tenacity retry sleep."""
        self._rotate_deepseek_client()
        self._retry_warning("call_deepseek", retry_state)

    def _retry_warning(self, method_name: str, retry_state: object) -> None:
        """Log a WARNING before a tenacity retry sleep."""
        attempt = getattr(retry_state, "attempt_number", "?")
        self.logger.warning(f"{method_name} rate limited, retry attempt {attempt}")

    async def call_groq(
        self,
        prompt: str,
        system: str = "You are a security testing assistant.",
        temperature: float = 0.7,
    ) -> str:
        """Call Groq Llama 70B with retry on rate-limit. Returns response string."""

        @retry(
            retry=retry_if_exception_type(groq.RateLimitError),
            wait=wait_exponential(multiplier=1, min=2, max=30),
            stop=stop_after_attempt(3),
            before_sleep=self._groq_before_retry,
            reraise=True,
        )
        async def _call() -> str:
            response = await self.groq.chat.completions.create(
                model=LLMModel.LLAMA_70B,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                temperature=temperature,
            )
            content = response.choices[0].message.content
            return content if content is not None else ""

        try:
            return await _call()
        except groq.RateLimitError:
            raise
        except Exception as e:
            self.log_error("call_groq failed", e)
            raise

    async def call_gemini(
        self,
        prompt: str,
        system: str = "You are a security testing assistant.",
        max_tokens: int = 2048,
    ) -> str:
        """Call Google Gemini flash with retry on rate-limit. Returns response string."""

        @retry(
            retry=retry_if_exception_type((ResourceExhausted,)),
            wait=wait_exponential(multiplier=1, min=2, max=30),
            stop=stop_after_attempt(3),
            before_sleep=self._gemini_before_retry,
            reraise=True,
        )
        async def _call() -> str:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.gemini.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system,
                        max_output_tokens=max_tokens,
                    ),
                ),
            )
            text = response.text
            return text if text is not None else ""

        try:
            return await _call()
        except Exception as e:
            self.log_error("call_gemini failed", e)
            raise

    async def call_deepseek(
        self,
        prompt: str,
        system: str = "You are a security testing assistant.",
        temperature: float = 0.7,
    ) -> str:
        """Call DeepSeek via OpenAI-compatible async client with retry. Returns response string."""

        @retry(
            retry=retry_if_exception_type(Exception),
            wait=wait_exponential(multiplier=1, min=2, max=30),
            stop=stop_after_attempt(3),
            before_sleep=self._deepseek_before_retry,
            reraise=True,
        )
        async def _call() -> str:
            response = await self.deepseek.chat.completions.create(
                model=LLMModel.DEEPSEEK,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                temperature=temperature,
            )
            content = response.choices[0].message.content
            return content if content is not None else ""

        try:
            return await _call()
        except Exception as e:
            self.log_error("call_deepseek failed", e)
            raise

    def log_action(self, action: str, detail: str) -> None:
        """Log a structured INFO entry with agent context."""
        entry = {
            "agent": self.agent_name,
            "client_id": self.client_id,
            "scan_id": self.scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "detail": detail,
        }
        self.logger.info(json.dumps(entry))

    def log_error(self, error: str, exception: Optional[Exception] = None) -> None:
        """Log a structured ERROR entry with agent context and optional exception info."""
        entry = {
            "agent": self.agent_name,
            "client_id": self.client_id,
            "scan_id": self.scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": error,
            "exception": str(exception) if exception else None,
        }
        self.logger.error(json.dumps(entry), exc_info=True)

    @abstractmethod
    async def run(self, state: dict) -> dict:
        """Every agent must implement run() — the LangGraph node entry point."""
        ...
