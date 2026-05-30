"""Base agent class providing shared LLM clients for Sentinel AI agents."""

import asyncio
import logging
import os
from typing import Optional

from dotenv import load_dotenv
from groq import AsyncGroq, RateLimitError as GroqRateLimitError
from anthropic import AsyncAnthropic
from openai import AsyncOpenAI

from constants import GROQ_KEYS, get_next_key

load_dotenv()

logger = logging.getLogger(__name__)


class BaseAgent:
    """Base class for all Sentinel AI agents with shared async LLM clients."""

    def __init__(
        self,
        agent_name: str,
        client_id: str,
        scan_id: str,
        attempt: int = 0,
    ) -> None:
        """
        Initialize BaseAgent with LLM clients and identity fields.

        Args:
            agent_name: One of AgentName constants
            client_id: The authorized client being scanned
            scan_id: The current scan session ID
            attempt: Key rotation attempt index for get_next_key()
        """
        self.agent_name: str = agent_name
        self.client_id: str = client_id
        self.scan_id: str = scan_id
        self.attempt: int = attempt
        self.logger = logging.getLogger(agent_name)

        self.groq: AsyncGroq = AsyncGroq(api_key=get_next_key(GROQ_KEYS, attempt))
        _anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        self.anthropic: Optional[AsyncAnthropic] = (
            AsyncAnthropic(api_key=_anthropic_key) if _anthropic_key else None
        )
        # NOTE: None during development. Reserved for investor demo only.
        # Agents must check: if not self.anthropic: use call_gemini() instead.

        _openai_key = os.getenv("OPENAI_API_KEY")
        self.openai: Optional[AsyncOpenAI] = AsyncOpenAI(api_key=_openai_key) if _openai_key else None
        # NOTE: None during development. Backup only — not used in any active agent.

        self._gemini_keys: list[str] = [
            v
            for k, v in sorted(os.environ.items())
            if k.startswith("GEMINI_API_KEY_")
            and v
            and not v.startswith("paste_")
            and v.startswith("AIzaSy")
        ]
        self._gemini_index: int = 0
        # NOTE: GEMINI_API_KEY_4 (AQ.Ab8Rn... prefix) will be auto-excluded
        # by the AIzaSy format check. Team member 4 must regenerate their key
        # at aistudio.google.com.

        self._deepseek_keys: list[str] = [
            v
            for k, v in sorted(os.environ.items())
            if k.startswith("DEEPSEEK_API_KEY_") and v and not v.startswith("paste_")
        ]
        self._deepseek_index: int = 0

        self.logger.info("%s initialized for client %s", agent_name, client_id)

    async def call_groq(
        self,
        prompt: str,
        system: str,
        model: str,
        temperature: float = 0.7,
    ) -> str:
        """
        Call Groq LLM with exponential backoff on rate limits (max 3 attempts).
        Returns the response text string.
        """
        last_exc: Exception = RuntimeError("call_groq: no attempts made")
        for attempt in range(3):
            try:
                response = await self.groq.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=temperature,
                )
                content: Optional[str] = response.choices[0].message.content
                return content or ""
            except GroqRateLimitError as exc:
                last_exc = exc
                wait: float = 2 ** attempt  # 1s, 2s, 4s
                self.logger.warning(
                    "[%s] Groq rate limit (attempt %d/3) — retrying in %.0fs",
                    self.agent_name,
                    attempt + 1,
                    wait,
                )
                await asyncio.sleep(wait)
            except Exception as exc:
                self.logger.error("[%s] Groq call failed: %s", self.agent_name, exc)
                raise
        self.logger.error("[%s] Groq rate limit exhausted after 3 attempts", self.agent_name)
        raise last_exc

    def log_action(self, action: str, detail: str) -> None:
        """Log an agent action at INFO level with agent name prefix."""
        self.logger.info("[%s] %s: %s", self.agent_name, action, detail)

    def log_error(self, error: str, exception: Optional[Exception] = None) -> None:
        """Log an agent error at ERROR level with agent name prefix."""
        self.logger.error("[%s] ERROR — %s: %s", self.agent_name, error, exception)

    async def call_gemini(
        self,
        prompt: str,
        system: str = "",
        model: str = "gemini-2.0-flash",
        max_tokens: int = 2048,
    ) -> str:
        """
        Call Google Gemini API with automatic key rotation.
        Primary LLM for ReportAgent (Week 5) and AutopatchAgent (Week 7).

        Args:
            prompt: User message content.
            system: System instruction string.
            model: Gemini model name. Default: gemini-2.0-flash.
            max_tokens: Maximum output tokens.

        Returns:
            Response text string.

        Raises:
            RuntimeError: If no valid GEMINI_API_KEY_N found in environment.
        """
        import google.generativeai as genai
        import asyncio

        if not self._gemini_keys:
            raise RuntimeError(
                "No valid GEMINI_API_KEY_N found. "
                "Keys must start with 'AIzaSy'. "
                "Check .env — GEMINI_API_KEY_4 appears malformed."
            )
        key = self._gemini_keys[self._gemini_index % len(self._gemini_keys)]
        self._gemini_index += 1
        genai.configure(api_key=key)
        model_client = genai.GenerativeModel(
            model_name=model,
            system_instruction=system if system else None,
        )
        response = await asyncio.to_thread(model_client.generate_content, prompt)
        self.log_action("call_gemini", f"model={model}")
        return response.text

    async def call_deepseek(
        self,
        prompt: str,
        system: str = "",
        model: str = "deepseek-coder",
        max_tokens: int = 2048,
    ) -> str:
        """
        Call DeepSeek API (OpenAI-compatible) with key rotation.
        Backup for AutopatchAgent code generation (Week 7).

        Args:
            prompt: User message content.
            system: System instruction string.
            model: DeepSeek model name. Default: deepseek-coder.
            max_tokens: Maximum output tokens.

        Returns:
            Response text string.

        Raises:
            RuntimeError: If no DEEPSEEK_API_KEY_N found in environment.
        """
        if not self._deepseek_keys:
            raise RuntimeError("No DEEPSEEK_API_KEY_N found in environment.")
        key = self._deepseek_keys[self._deepseek_index % len(self._deepseek_keys)]
        self._deepseek_index += 1
        from openai import AsyncOpenAI as _AsyncOpenAI

        client = _AsyncOpenAI(
            api_key=key,
            base_url="https://api.deepseek.com",
        )
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        response = await client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
        )
        self.log_action("call_deepseek", f"model={model}")
        return response.choices[0].message.content

    async def call_claude(
        self,
        prompt: str,
        system: str = "",
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
    ) -> str:
        """
        Call Anthropic Claude API.
        Primary LLM for ReportAgent (Week 5) and investor demo.
        Raises RuntimeError if ANTHROPIC_API_KEY is absent so callers can
        catch it and fall back to call_gemini() during development.

        Args:
            prompt: User message content.
            system: System instruction string.
            model: Claude model name. Default: claude-sonnet-4-20250514.
            max_tokens: Maximum output tokens.

        Returns:
            Response text string.

        Raises:
            RuntimeError: If ANTHROPIC_API_KEY is not set.
        """
        if not self.anthropic:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. "
                "Use call_gemini() instead during development. "
                "This key is reserved for the investor demo only."
            )
        response = await self.anthropic.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system if system else None,
            messages=[{"role": "user", "content": prompt}],
        )
        self.log_action("call_claude", f"model={model}")
        return response.content[0].text
