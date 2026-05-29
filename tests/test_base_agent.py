"""Smoke tests for the Sentinel AI BaseAgent class."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agents.base_agent import BaseAgent
from constants import AgentName, LLMModel


@pytest.fixture
def mock_base_agent() -> BaseAgent:
    """Provide a BaseAgent instance with all external LLM clients mocked."""
    with patch("agents.base_agent.get_next_key", return_value="test-api-key"), patch(
        "agents.base_agent.AsyncGroq",
    ) as mock_groq_cls, patch(
        "agents.base_agent.AsyncAnthropic",
    ) as mock_anthropic_cls, patch(
        "agents.base_agent.AsyncOpenAI",
    ) as mock_openai_cls:
        mock_groq_cls.return_value = MagicMock()
        mock_anthropic_cls.return_value = MagicMock()
        mock_openai_cls.return_value = MagicMock()

        agent: BaseAgent = BaseAgent(
            agent_name=AgentName.RECON,
            client_id="test-client-001",
            scan_id="test-scan-001",
        )
        return agent


def test_base_agent_initializes(mock_base_agent: BaseAgent) -> None:
    """BaseAgent sets agent_name, client_id, scan_id on init."""
    assert mock_base_agent.agent_name == AgentName.RECON
    assert mock_base_agent.client_id == "test-client-001"
    assert mock_base_agent.scan_id == "test-scan-001"


def test_base_agent_has_all_clients(mock_base_agent: BaseAgent) -> None:
    """BaseAgent exposes groq, anthropic, and openai client attributes."""
    assert hasattr(mock_base_agent, "groq")
    assert hasattr(mock_base_agent, "anthropic")
    assert hasattr(mock_base_agent, "openai")


async def test_call_groq_returns_string(mock_base_agent: BaseAgent) -> None:
    """call_groq() returns the string content from the LLM response."""
    mock_response: MagicMock = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "mocked groq response"
    mock_base_agent.groq.chat.completions.create = AsyncMock(return_value=mock_response)

    result: str = await mock_base_agent.call_groq(
        prompt="test prompt",
        system="test system",
        model=LLMModel.LLAMA_70B,
    )

    assert result == "mocked groq response"


async def test_call_gemini_returns_string(mock_base_agent: BaseAgent) -> None:
    """call_gemini() returns response text from the Gemini client."""
    with patch.dict(
        os.environ,
        {"GEMINI_API_KEY_1": "AIzaSyTEST_KEY_1"},
        clear=False,
    ), patch(
        "google.generativeai.configure",
    ), patch(
        "google.generativeai.GenerativeModel",
    ) as mock_model_cls:
        mock_response: MagicMock = MagicMock()
        mock_response.text = "mocked gemini response"
        mock_model: MagicMock = MagicMock()
        mock_model.generate_content.return_value = mock_response
        mock_model_cls.return_value = mock_model

        mock_base_agent._gemini_keys = ["AIzaSyTEST_KEY_1"]
        mock_base_agent._gemini_index = 0

        result: str = await mock_base_agent.call_gemini(prompt="test prompt")

        assert result == "mocked gemini response"


def test_log_action_does_not_raise(mock_base_agent: BaseAgent) -> None:
    """log_action() logs without raising any exception."""
    mock_base_agent.log_action("test_action", "test detail")


def test_log_error_does_not_raise(mock_base_agent: BaseAgent) -> None:
    """log_error() logs error without raising any exception."""
    mock_base_agent.log_error("test error", Exception("boom"))
