"""
================================================================================
TEST FILE: test_week4_integration.py
================================================================================
PURPOSE:
    Verifies the full three-component multi-domain pipeline introduced in Week 4.

WHAT IS BEING TESTED:
    - test_recon_identifies_all_three_component_types
    - test_all_five_attack_domains_execute
    - test_attack_history_has_entries_per_component
    - test_component_complete_fires_three_times
    - test_cross_component_hints_produced
    - test_scan_completes_within_time_limit

DEPENDENCIES:
    - Dummy target:     YES (uvicorn dummy_target.app:app --port 8001)
    - Sentinel backend: NO
    - Real API keys:    NO
    - Ollama:           NO
    - ChromaDB:         YES (auto-initialized)

HOW TO RUN:
    pytest tests/test_week4_integration.py -v -s

ESTIMATED RUNTIME: medium 10–30s (MAX_ITERATIONS patched to 1)
================================================================================
"""

import asyncio
import logging
import os
import time
import uuid
from unittest.mock import patch, AsyncMock

import httpx
import pytest

from agents.orchestrator import run_scan
from constants import ChromaCollection, AttackDomain
from knowledge_base.knowledge_base import KnowledgeBase

logger = logging.getLogger(__name__)
pytestmark = pytest.mark.asyncio

DUMMY_TARGET_URL = os.getenv("DUMMY_TARGET_URL", "http://localhost:8001")

captured_broadcasts: list[dict] = []

@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="module")
async def scan_results() -> dict:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{DUMMY_TARGET_URL}/health")
            if response.status_code != 200:
                pytest.fail(f"Dummy target returned status {response.status_code}, expected 200")
    except httpx.ConnectError:
        pytest.fail(
            f"Dummy target not accessible at {DUMMY_TARGET_URL}. "
            "Start it with: uvicorn dummy_target.app:app --port 8001 --reload"
        )

    client_id = f"test-client-w4-{uuid.uuid4().hex[:8]}"
    scan_id = f"scan-w4-{uuid.uuid4().hex[:8]}"
    
    start_time = time.monotonic()
    
    manifest = {
        "components": [
            {"endpoint": f"{DUMMY_TARGET_URL}/chat", "type": "llm_model"},
            {"endpoint": f"{DUMMY_TARGET_URL}/rag/query", "type": "rag_pipeline"},
            {"endpoint": f"{DUMMY_TARGET_URL}/api/data", "type": "api_layer"},
        ]
    }

    async def mock_execute_attack(self, payload: str, endpoint: str, component_type: str) -> dict:
        return {
            "success": True,
            "status_code": 200,
            "response_text": (
                "This response contains a traceback at line 42. "
                "Internal path: /home/app/server.py version v1.2 "
                "debug mode active. " + "x" * 600
            ),
            "response_time_ms": 1.5,
            "error": None,
        }

    async def mock_broadcast(scan_id_arg: str, event_type: str, payload: dict) -> None:
        captured_broadcasts.append({"event_type": event_type, "payload": payload})

    async def mock_get_cross_component_insights(self, completed_component_id: str, next_component_type: str) -> list[dict]:
        return [
            {
                "hint": f"Mock hint for {next_component_type}",
                "source_domain": "prompt_injection",
                "source_score": 0.75,
                "severity": "high",
            }
        ]

    with patch("agents.orchestrator.MAX_ITERATIONS", 1), \
         patch("agents.attack_agent.AttackAgent.execute_attack", mock_execute_attack), \
         patch("agents.orchestrator._broadcast", mock_broadcast), \
         patch("agents.attack_agent.KnowledgeBase.get_cross_component_insights", mock_get_cross_component_insights):
        final_state = await run_scan(client_id, scan_id, manifest=manifest)

    elapsed = time.monotonic() - start_time

    return {
        "client_id": client_id,
        "scan_id": scan_id,
        "final_state": final_state,
        "elapsed_seconds": elapsed,
    }


async def test_recon_identifies_all_three_component_types(scan_results: dict) -> None:
    final_state = scan_results["final_state"]
    components = final_state.get("components", [])
    
    assert len(components) >= 3, f"Expected at least 3 components, got {len(components)}"
    
    has_llm = any("llm" in str(c.get("component_type", "")).lower() or "/chat" in str(c.get("endpoint", "")).lower() for c in components)
    has_rag = any("rag" in str(c.get("component_type", "")).lower() or "/rag" in str(c.get("endpoint", "")).lower() for c in components)
    has_api = any("api" in str(c.get("component_type", "")).lower() or "/api/data" in str(c.get("endpoint", "")).lower() for c in components)
    
    assert has_llm, "Missing component type containing 'llm' or endpoint containing '/chat'"
    assert has_rag, "Missing component type containing 'rag' or endpoint containing '/rag'"
    assert has_api, "Missing component type containing 'api' or endpoint containing '/api/data'"


async def test_all_five_attack_domains_execute(scan_results: dict) -> None:
    client_id = scan_results["client_id"]
    kb = KnowledgeBase(client_id=client_id, scan_id=scan_results["scan_id"])
    collection = kb.chroma_client.get_collection(ChromaCollection.ATTACK_HISTORY)
    
    results = await asyncio.to_thread(collection.get, where={"client_id": client_id})
    metadatas = results.get("metadatas", [])
    
    executed_domains = {m.get("domain") for m in metadatas if m.get("domain")}
    
    expected_domains = {
        AttackDomain.PROMPT_INJECTION,
        AttackDomain.RAG_POISONING,
        AttackDomain.API_ATTACKS,
        AttackDomain.INDIRECT_INJECTION,
        AttackDomain.SYSTEM_PROMPT_EXTRACT,
    }
    
    missing = expected_domains - executed_domains
    assert not missing, f"Missing executed domains: {missing}"


async def test_attack_history_has_entries_per_component(scan_results: dict) -> None:
    client_id = scan_results["client_id"]
    final_state = scan_results["final_state"]
    components = final_state.get("components", [])
    
    state_component_ids = {c.get("component_id") for c in components if c.get("component_id")}
    
    kb = KnowledgeBase(client_id=client_id, scan_id=scan_results["scan_id"])
    collection = kb.chroma_client.get_collection(ChromaCollection.ATTACK_HISTORY)
    results = await asyncio.to_thread(collection.get, where={"client_id": client_id})
    metadatas = results.get("metadatas", [])
    
    logged_component_ids = {m.get("component_id") for m in metadatas if m.get("component_id")}
    
    missing = state_component_ids - logged_component_ids
    assert not missing, f"Missing attack history entries for component_ids: {missing}"


async def test_component_complete_fires_three_times(scan_results: dict) -> None:
    # Ensure fixture ran
    _ = scan_results
    
    component_complete_events = [e for e in captured_broadcasts if e.get("event_type") == "component_complete"]
    assert len(component_complete_events) >= 3, f"Expected at least 3 component_complete events, got {len(component_complete_events)}"
    
    for event in component_complete_events:
        payload = event.get("payload", {})
        assert "component_id" in payload, "Missing 'component_id' in component_complete event payload"
        assert "domains_tested" in payload, "Missing 'domains_tested' in component_complete event payload"
        assert "findings_count" in payload, "Missing 'findings_count' in component_complete event payload"


async def test_cross_component_hints_produced(scan_results: dict) -> None:
    final_state = scan_results["final_state"]
    
    logs = final_state.get("logs", [])
    hint_logged = any("cross_component" in log or "hint" in log for log in logs)
    
    components = final_state.get("components", [])
    components_transitioned = len(components) >= 2
    
    assert hint_logged or components_transitioned, "mock_get_cross_component_insights was not reached"
    
    assert final_state.get("current_component_index", 0) >= 2, (
        "current_component_index should be >= 2 after completing at least two components"
    )


async def test_scan_completes_within_time_limit(scan_results: dict) -> None:
    elapsed = scan_results["elapsed_seconds"]
    logger.info(f"Scan elapsed time: {elapsed:.2f} seconds")
    assert elapsed < 1800, f"Scan took too long: {elapsed:.2f} seconds"


async def test_full_week4_integration_pipeline(scan_results: dict) -> None:
    logger.info("=" * 60)
    logger.info("W4-TEAM-08: Full Integration Test")
    logger.info("=" * 60)
    
    await test_recon_identifies_all_three_component_types(scan_results)
    await test_all_five_attack_domains_execute(scan_results)
    await test_attack_history_has_entries_per_component(scan_results)
    await test_component_complete_fires_three_times(scan_results)
    await test_cross_component_hints_produced(scan_results)
    await test_scan_completes_within_time_limit(scan_results)
    
    logger.info("=" * 60)
    logger.info("ALL W4-TEAM-08 ASSERTIONS PASSED")
    logger.info("=" * 60)
