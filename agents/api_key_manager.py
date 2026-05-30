"""Centralised round-robin API key rotation for GROQ, Gemini, and DeepSeek.

Supports numbered keys (GROQ_API_KEY_1 … _5) from .env as defined in constants.py,
with optional fallback to unnumbered vars (GROQ_API_KEY, GEMINI_API_KEY, etc.).
"""

import logging
import os
import threading
from typing import Literal

from constants import get_next_key

logger = logging.getLogger(__name__)

Provider = Literal["groq", "gemini", "deepseek"]

_SINGLE_ENV: dict[Provider, str] = {
    "groq": "GROQ_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
}

_KEY_SLOTS = 5


def _is_valid_key(key: str) -> bool:
    """Return True if the key looks like a real credential, not a placeholder."""
    return bool(key) and "paste" not in key.lower() and len(key) > 10


def _load_numbered_keys(prefix: str) -> list[str]:
    """Load GROQ_API_KEY_1 … _5 (or equivalent) from the current environment."""
    keys: list[str] = []
    for i in range(1, _KEY_SLOTS + 1):
        key = os.getenv(f"{prefix}_{i}")
        if key and _is_valid_key(key):
            keys.append(key)
    return keys


def resolve_key_pool(provider: Provider) -> list[str]:
    """Merge numbered keys from .env with an optional unnumbered env fallback."""
    prefix = _SINGLE_ENV[provider]
    keys = _load_numbered_keys(prefix)
    single = os.getenv(prefix)
    if single and _is_valid_key(single) and single not in keys:
        keys.insert(0, single)
    return keys


class ApiKeyManager:
    """Thread-safe round-robin selector for LLM provider API keys."""

    _lock = threading.Lock()
    _cursor: dict[Provider, int] = {"groq": 0, "gemini": 0, "deepseek": 0}

    @classmethod
    def available_keys(cls, provider: Provider) -> list[str]:
        """Return all valid keys configured for a provider."""
        return resolve_key_pool(provider)

    @classmethod
    def acquire_key(cls, provider: Provider) -> str:
        """Pick the next key in round-robin order (used at client init)."""
        with cls._lock:
            keys = resolve_key_pool(provider)
            if not keys:
                env_hint = _SINGLE_ENV[provider]
                raise ValueError(
                    f"No {provider.upper()} API keys found. "
                    f"Set {env_hint}_1 … {env_hint}_5 or {env_hint} in .env"
                )
            key = get_next_key(keys, cls._cursor[provider])
            slot = cls._cursor[provider] % len(keys)
            cls._cursor[provider] += 1
            logger.debug(
                "%s key acquired — slot %s/%s",
                provider,
                slot + 1,
                len(keys),
            )
            return key

    @classmethod
    def rotate(cls, provider: Provider) -> str:
        """Advance to the next key (typically after a rate-limit error)."""
        with cls._lock:
            keys = resolve_key_pool(provider)
            if not keys:
                raise ValueError(
                    f"No {provider.upper()} API keys available for rotation"
                )
            key = get_next_key(keys, cls._cursor[provider])
            slot = cls._cursor[provider] % len(keys)
            cls._cursor[provider] += 1
            logger.warning(
                "%s rate limit — rotating to key slot %s/%s",
                provider,
                slot + 1,
                len(keys),
            )
            return key

    @classmethod
    def key_count(cls, provider: Provider) -> int:
        """Return how many keys are configured for a provider."""
        return len(resolve_key_pool(provider))
