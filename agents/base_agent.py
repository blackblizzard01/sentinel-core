import logging
import os
import random

import google.genai as google_genai
from dotenv import load_dotenv
from groq import AsyncGroq
from openai import AsyncOpenAI

from constants import AgentName, LLMModel

load_dotenv()


class BaseAgent:
    """Base class providing shared LLM clients and logging for all Sentinel agents."""

    def __init__(self, agent_name: str, client_id: str, scan_id: str, model: str) -> None:
        """Initialize agent context and rotate API keys for Groq, Gemini, and DeepSeek."""
        self.agent_name = agent_name
        self.client_id = client_id
        self.scan_id = scan_id
        self.model = model
        self.logger = logging.getLogger(agent_name)

        groq_keys = [
            os.getenv(f"GROQ_API_KEY_{i}")
            for i in range(1, 6)
            if os.getenv(f"GROQ_API_KEY_{i}")
        ]
        assert groq_keys, "No GROQ API keys found"
        groq_key = random.choice(groq_keys)
        groq_index = groq_keys.index(groq_key)
        self.groq = AsyncGroq(api_key=groq_key)
        self.logger.debug("Using Groq key index %s", groq_index + 1)

        gemini_keys = [
            os.getenv(f"GEMINI_API_KEY_{i}")
            for i in range(1, 6)
            if os.getenv(f"GEMINI_API_KEY_{i}")
        ]
        assert gemini_keys, "No GEMINI API keys found"
        gemini_key = random.choice(gemini_keys)
        gemini_index = gemini_keys.index(gemini_key)
        self.gemini = google_genai.Client(api_key=gemini_key)
        self.logger.debug("Using Gemini key index %s", gemini_index + 1)

        deepseek_keys = [
            os.getenv(f"DEEPSEEK_API_KEY_{i}")
            for i in range(1, 6)
            if os.getenv(f"DEEPSEEK_API_KEY_{i}")
        ]
        assert deepseek_keys, "No DEEPSEEK API keys found"
        deepseek_key = random.choice(deepseek_keys)
        deepseek_index = deepseek_keys.index(deepseek_key)
        self.deepseek = AsyncOpenAI(
            api_key=deepseek_key,
            base_url="https://api.deepseek.com",
        )
        self.logger.debug("Using DeepSeek key index %s", deepseek_index + 1)

        self.logger.info(
            f"{agent_name} initialised | client={client_id} | scan={scan_id}"
        )

    async def call_groq(self, prompt: str, system: str, temperature: float) -> str:
        """Invoke the Groq chat completions API and return the assistant message."""
        try:
            response = await self.groq.chat.completions.create(
                model=self.model,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            )
            content = response.choices[0].message.content
            return content if content is not None else ""
        except Exception as exc:
            self.log_error("Groq call failed", exc)
            raise

    async def call_gemini(self, prompt: str, system: str, max_tokens: int) -> str:
        """Invoke the Gemini generate_content API and return the text response."""
        try:
            response = await self.gemini.aio.models.generate_content(
                model=LLMModel.GEMINI_FLASH,
                contents=prompt,
                config={
                    "system_instruction": system,
                    "max_output_tokens": max_tokens,
                },
            )
            text = response.text
            return text if text is not None else ""
        except Exception as exc:
            self.log_error("Gemini call failed", exc)
            raise

    async def call_deepseek(self, prompt: str, system: str, temperature: float) -> str:
        """Invoke the DeepSeek chat completions API and return the assistant message."""
        try:
            response = await self.deepseek.chat.completions.create(
                model=LLMModel.DEEPSEEK_CHAT,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            )
            content = response.choices[0].message.content
            return content if content is not None else ""
        except Exception as exc:
            self.log_error("DeepSeek call failed", exc)
            raise

    def log_action(self, action: str, detail: str) -> None:
        """Log a structured INFO message for agent actions."""
        self.logger.info(f"[{self.agent_name}][{self.scan_id}] {action}: {detail}")

    def log_error(self, error: str, exception: Exception) -> None:
        """Log a structured ERROR message with exception traceback."""
        self.logger.error(
            f"[{self.agent_name}][{self.scan_id}] ERROR — {error}: {exception}",
            exc_info=True,
        )
