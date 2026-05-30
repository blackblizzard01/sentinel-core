import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agents.base_agent import BaseAgent
from constants import AgentName


class ConcreteAgent(BaseAgent):
    """Concrete subclass for testing BaseAgent (abstract run implementation)."""

    async def run(self, state: dict) -> dict:
        return state


def _patch_llm_clients() -> tuple:
    """Patch all LLM client constructors used in BaseAgent.__init__."""
    return (
        patch("agents.base_agent.ApiKeyManager.acquire_key", return_value="test-api-key"),
        patch("agents.base_agent.AsyncGroq"),
        patch("agents.base_agent.AsyncOpenAI"),
        patch("agents.base_agent.genai.configure"),
        patch("agents.base_agent.genai.GenerativeModel"),
    )


@pytest.mark.asyncio
async def test_call_groq_returns_non_empty_string() -> None:
    """Verify call_groq returns a non-empty string given a simple prompt."""
    key_patch, groq_patch, openai_patch, configure_patch, model_patch = _patch_llm_clients()
    with key_patch, groq_patch as mock_groq_cls, openai_patch, configure_patch, model_patch:
        mock_groq_instance = MagicMock()
        mock_groq_cls.return_value = mock_groq_instance
        mock_groq_instance.chat.completions.create = AsyncMock(
            return_value=MagicMock(
                choices=[MagicMock(message=MagicMock(content="test response"))]
            )
        )

        agent = ConcreteAgent(
            agent_name=AgentName.RECON,
            client_id="test-client",
            scan_id="test-scan",
        )
        result = await agent.call_groq("Say hello")

    assert isinstance(result, str)
    assert len(result) > 0


def test_log_action_calls_logger_info() -> None:
    """Verify log_action emits a structured INFO log entry."""
    key_patch, groq_patch, openai_patch, configure_patch, model_patch = _patch_llm_clients()
    with key_patch, groq_patch, openai_patch, configure_patch, model_patch:
        agent = ConcreteAgent(
            agent_name=AgentName.RECON,
            client_id="test-client",
            scan_id="test-scan",
        )
        with patch.object(agent.logger, "info") as mock_info:
            agent.log_action("test_action", "test_detail")

    mock_info.assert_called_once()
    logged = mock_info.call_args[0][0]
    assert "test_action" in logged


def test_log_error_calls_logger_error() -> None:
    """Verify log_error emits a structured ERROR log entry with exception info."""
    key_patch, groq_patch, openai_patch, configure_patch, model_patch = _patch_llm_clients()
    with key_patch, groq_patch, openai_patch, configure_patch, model_patch:
        agent = ConcreteAgent(
            agent_name=AgentName.RECON,
            client_id="test-client",
            scan_id="test-scan",
        )
        with patch.object(agent.logger, "error") as mock_error:
            agent.log_error("something broke", ValueError("oops"))

    mock_error.assert_called_once()
    assert mock_error.call_args[1].get("exc_info") is True
