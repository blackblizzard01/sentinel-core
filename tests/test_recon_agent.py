from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agents.recon_agent import COMPONENT_TYPE_EMBEDDING, ReconAgent
from constants import AttackDomain, ComponentType


@pytest.fixture
def recon_agent() -> ReconAgent:
    """Create a ReconAgent with LLM clients and KnowledgeBase mocked."""
    kb = MagicMock()
    mock_gemini_client = MagicMock()
    mock_gemini_response = MagicMock()
    mock_gemini_response.text = "mocked gemini response"
    mock_gemini_client.models.generate_content.return_value = mock_gemini_response
    with (
        patch("agents.base_agent.ApiKeyManager.acquire_key", return_value="test-api-key"),
        patch("agents.base_agent.AsyncGroq"),
        patch("agents.base_agent.AsyncOpenAI"),
        patch("agents.base_agent.genai.Client", return_value=mock_gemini_client),
    ):
        yield ReconAgent(
            client_id="test-client",
            scan_id="test-scan",
            kb=kb,
        )


@pytest.mark.asyncio
async def test_probe_endpoint_returns_correct_structure(recon_agent: ReconAgent) -> None:
    """Verify probe_endpoint returns a dict with all required keys."""
    agent = recon_agent

    mock_get_response = MagicMock()
    mock_get_response.status_code = 200
    mock_get_response.headers = {
        "server": "uvicorn",
        "content-type": "application/json",
    }
    mock_get_response.text = '{"status":"ok"}'

    mock_post_response = MagicMock()
    mock_post_response.status_code = 405
    mock_post_response.text = "Method Not Allowed"

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_get_response)
    mock_client.post = AsyncMock(return_value=mock_post_response)

    with patch("agents.recon_agent.httpx.AsyncClient") as mock_async_client:
        mock_async_client.return_value.__aenter__.return_value = mock_client
        mock_async_client.return_value.__aexit__.return_value = None

        result = await agent.probe_endpoint("http://target.local/health")

    required_keys = {
        "url",
        "get_status",
        "post_status",
        "headers",
        "content_type",
        "response_time_ms",
        "body_preview",
        "post_body_preview",
        "probed_at",
    }
    assert required_keys.issubset(result.keys())
    assert result["get_status"] == 200
    assert result["post_status"] == 405


@pytest.mark.asyncio
async def test_enumerate_routes_returns_live_urls(recon_agent: ReconAgent) -> None:
    """Verify enumerate_routes returns only URLs with non-(-1) status."""
    agent = recon_agent

    call_count = 0

    async def mock_probe(url: str) -> dict:
        nonlocal call_count
        call_count += 1
        status = 200 if call_count <= 3 else -1
        return {
            "url": url,
            "get_status": status,
            "post_status": -1,
            "headers": {},
            "content_type": "",
            "response_time_ms": 100.0,
            "body_preview": "",
            "post_body_preview": "",
            "probed_at": "",
        }

    agent.probe_endpoint = mock_probe  # type: ignore[method-assign]

    result = await agent.enumerate_routes("http://target.local")

    assert len(result) == 3
    assert all(url.startswith("http://target.local") for url in result)


def test_detect_framework_fastapi(recon_agent: ReconAgent) -> None:
    """Verify detect_framework returns 'fastapi' for uvicorn server header."""
    agent = recon_agent
    headers = {"server": "uvicorn", "content-type": "application/json"}
    body = ""
    assert agent.detect_framework(headers, body) == "fastapi"


def test_detect_framework_llm_endpoint(recon_agent: ReconAgent) -> None:
    """Verify detect_framework returns 'llm_endpoint' when openai token present."""
    agent = recon_agent
    headers = {"x-openai-processing-ms": "42"}
    body = '{"object": "chat.completion"}'
    assert agent.detect_framework(headers, body) == "llm_endpoint"


def test_detect_framework_unknown(recon_agent: ReconAgent) -> None:
    """Verify detect_framework returns 'unknown' when no signatures match."""
    agent = recon_agent
    headers = {"content-type": "text/html"}
    body = "<html><body>Hello</body></html>"
    assert agent.detect_framework(headers, body) == "unknown"


def test_assign_priority_high_score(recon_agent: ReconAgent) -> None:
    """Verify assign_priority returns 10 for an ideal LLM endpoint."""
    agent = recon_agent
    probe_result = {
        "get_status": 200,
        "post_status": 200,
        "response_time_ms": 120.0,
    }
    framework = "llm_endpoint"
    live_routes = ["/v1/chat/completions", "/health", "/embed"]
    assert agent.assign_priority(probe_result, framework, live_routes) == 10


@pytest.mark.asyncio
async def test_fingerprint_model_llm_response(recon_agent: ReconAgent) -> None:
    """Verify fingerprint_model classifies a short LLM text answer."""
    agent = recon_agent
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"text": "four"}
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("agents.recon_agent.httpx.AsyncClient") as mock_async_client:
        mock_async_client.return_value.__aenter__.return_value = mock_client
        mock_async_client.return_value.__aexit__.return_value = None
        result = await agent.fingerprint_model("http://target.local/chat")

    assert result == ComponentType.LLM_MODEL


@pytest.mark.asyncio
async def test_fingerprint_model_embedding_warning(
    recon_agent: ReconAgent, caplog: pytest.LogCaptureFixture
) -> None:
    """Verify embedding responses return embedding_model and log a warning."""
    agent = recon_agent
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"embedding": [0.1, 0.2]}
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("agents.recon_agent.httpx.AsyncClient") as mock_async_client:
        mock_async_client.return_value.__aenter__.return_value = mock_client
        mock_async_client.return_value.__aexit__.return_value = None
        result = await agent.fingerprint_model("http://target.local/embed")

    assert result == COMPONENT_TYPE_EMBEDDING


@pytest.mark.asyncio
async def test_build_component_map_validates_schema(recon_agent: ReconAgent) -> None:
    """Verify build_component_map returns validated component profiles."""
    agent = recon_agent
    manifest = {
        "components": [
            {
                "endpoint": "http://target.local",
                "type": ComponentType.LLM_MODEL,
                "framework": "fastapi",
            }
        ]
    }

    agent._summarize_probe = AsyncMock(  # type: ignore[method-assign]
        return_value=(True, "fastapi", 8)
    )

    result = await agent.build_component_map(manifest)

    assert len(result) == 1
    assert result[0]["component_id"] == "test-scan_0"
    assert result[0]["type"] == ComponentType.LLM_MODEL
    assert AttackDomain.PROMPT_INJECTION in result[0]["estimated_attack_domains"]


@pytest.mark.asyncio
async def test_run_updates_state_and_writes_chroma(recon_agent: ReconAgent) -> None:
    """Verify run() populates state components and attempts ChromaDB writes."""
    agent = recon_agent
    mock_component = {
        "component_id": "test-scan_0",
        "type": ComponentType.LLM_MODEL,
        "endpoint": "http://localhost:8001",
        "framework": "fastapi",
        "priority_score": 7,
        "estimated_attack_domains": [AttackDomain.PROMPT_INJECTION],
    }
    agent.build_component_map = AsyncMock(return_value=[mock_component])  # type: ignore[method-assign]

    mock_collection = MagicMock()
    agent.knowledge_base.chroma_client.get_collection.return_value = (
        mock_collection
    )

    state = {
        "client_id": "test-client",
        "scan_id": "test-scan",
        "manifest": {"components": [{"endpoint": "http://localhost:8001"}]},
        "components": [],
        "phase": "",
        "logs": [],
        "current_component_index": 0,
        "current_component": {},
        "current_domain_index": 0,
        "current_domain": "",
        "attack_results": [],
        "iteration": 0,
        "critical_halt": False,
        "approved_findings": [],
        "report_path": "",
        "report_json": {},
    }

    result = await agent.run(state)  # type: ignore[arg-type]

    assert len(result["components"]) == 1
    assert result["phase"] == "recon"
    assert any("ReconAgent complete" in entry for entry in result["logs"])
    mock_collection.add.assert_called_once()
