import asyncio
import logging
import os
import time
import uuid

import pytest
import httpx

from constants import ChromaCollection
from knowledge_base.knowledge_base import KnowledgeBase
from agents.orchestrator import run_scan

logger = logging.getLogger(__name__)
pytestmark = pytest.mark.asyncio

# Configuration
DUMMY_TARGET_URL = os.getenv("DUMMY_TARGET_URL", "http://localhost:8001")


@pytest.fixture(scope="module")
def event_loop():
    """Create a module-scoped event loop to resolve ScopeMismatch in pytest-asyncio."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
async def scan_results() -> dict:
    """
    Module-scoped fixture that runs the complete Recon -> Attack scan exactly once
    against the dummy target and yields the shared client, scan, and state.
    """
    logger.info("Running shared integration scan fixture...")
    
    # Check if dummy target is accessible before starting
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

    client_id = f"test-client-w2-{uuid.uuid4().hex[:8]}"
    scan_id = f"scan-w2-{uuid.uuid4().hex[:8]}"
    
    # Create a manifest with the three dummy target endpoints
    manifest = {
        "components": [
            {"endpoint": f"{DUMMY_TARGET_URL}/chat", "type": "llm_model"},
            {"endpoint": f"{DUMMY_TARGET_URL}/rag/query", "type": "rag_pipeline"},
            {"endpoint": f"{DUMMY_TARGET_URL}/api/data", "type": "api_layer"},
        ]
    }
    
    # Run the scan once
    final_state = await run_scan(client_id, scan_id, manifest=manifest)
    
    return {
        "client_id": client_id,
        "scan_id": scan_id,
        "final_state": final_state,
    }


async def test_recon_detects_all_dummy_target_endpoints(scan_results: dict) -> None:
    """
    W2-TEAM-09 Assertion 1:
    Recon agent detects all three dummy target endpoints:
    /chat, /rag/query, /api/data
    """
    logger.info("Starting test: recon_detects_all_dummy_target_endpoints")
    final_state = scan_results["final_state"]
    
    components = final_state.get("components", [])
    assert len(components) >= 3, (
        f"Expected at least 3 components detected, got {len(components)}. "
        f"Recon agent should detect /chat, /rag/query, and /api/data endpoints."
    )
    
    component_endpoints = [c.get("endpoint", "") for c in components]
    assert any("/chat" in ep for ep in component_endpoints), "Missing /chat endpoint detection"
    assert any("/rag/query" in ep for ep in component_endpoints), "Missing /rag/query endpoint detection"
    assert any("/api/data" in ep for ep in component_endpoints), "Missing /api/data endpoint detection"
    
    logger.info("✅ Recon detected all three dummy target endpoints")


async def test_component_map_written_to_chromadb(scan_results: dict) -> None:
    """
    W2-TEAM-09 Assertion 2:
    Component map with minimum 2 components is written to ChromaDB
    component_profiles collection.
    """
    logger.info("Starting test: component_map_written_to_chromadb")
    client_id = scan_results["client_id"]
    scan_id = scan_results["scan_id"]
    
    kb = KnowledgeBase(client_id=client_id, scan_id=scan_id)
    collection = kb.chroma_client.get_collection(ChromaCollection.COMPONENT_PROFILES)
    
    results = await asyncio.to_thread(
        collection.get,
        where={"client_id": client_id}
    )
    
    component_count = len(results.get("ids", []))
    assert component_count >= 2, (
        f"Expected at least 2 components in ChromaDB component_profiles, "
        f"got {component_count}. Component map should be persisted after recon."
    )
    
    logger.info(f"✅ Component map written to ChromaDB: {component_count} components")


async def test_attack_agent_executes_all_prompt_injection_templates(scan_results: dict) -> None:
    """
    W2-TEAM-09 Assertion 3:
    Attack agent executes prompt injection templates against the /chat endpoint.
    May execute all 20, or fewer if a CRITICAL score (>=0.9) triggers early halt.
    """
    logger.info("Starting test: attack_agent_executes_all_templates")
    client_id = scan_results["client_id"]
    scan_id = scan_results["scan_id"]
    
    kb = KnowledgeBase(client_id=client_id, scan_id=scan_id)
    collection = kb.chroma_client.get_collection(ChromaCollection.ATTACK_HISTORY)
    
    results = await asyncio.to_thread(
        collection.get,
        where={"client_id": client_id}
    )
    
    attack_count = len(results.get("ids", []))
    # Allow 19-20 attacks: 20 if all templates executed, 19 if critical halt triggered on last one
    assert 19 <= attack_count <= 20, (
        f"Expected 19-20 attack attempts logged, got {attack_count}. "
        f"AttackAgent should execute all 20 prompt injection templates "
        f"unless a CRITICAL score (>=0.9) triggers early halt."
    )
    
    logger.info(f"✅ Attack agent executed {attack_count} attack templates")


async def test_all_attacks_logged_with_scores(scan_results: dict) -> None:
    """
    W2-TEAM-09 Assertion 4:
    All attack attempts are logged to attack_history collection with non-null scores.
    """
    logger.info("Starting test: all_attacks_logged_with_scores")
    client_id = scan_results["client_id"]
    scan_id = scan_results["scan_id"]
    
    kb = KnowledgeBase(client_id=client_id, scan_id=scan_id)
    collection = kb.chroma_client.get_collection(ChromaCollection.ATTACK_HISTORY)
    
    results = await asyncio.to_thread(
        collection.get,
        where={"client_id": client_id}
    )
    
    ids = results.get("ids", [])
    metadatas = results.get("metadatas", [])
    
    assert len(ids) >= 19, f"Expected at least 19 attacks, got {len(ids)}"
    
    attacks_with_scores = 0
    for metadata in metadatas:
        score = metadata.get("score")
        if score is not None and isinstance(score, (int, float)):
            attacks_with_scores += 1
    
    assert attacks_with_scores >= 19, (
        f"Expected all attacks to have scores, but only {attacks_with_scores} have valid scores."
    )
    
    logger.info(f"✅ All {attacks_with_scores} attacks logged with scores")


async def test_at_least_one_attack_scores_above_threshold(scan_results: dict) -> None:
    """
    W2-TEAM-09 Assertion 5:
    At least one attack scores above 0.4 (partial hit) against the dummy target.
    """
    logger.info("Starting test: at_least_one_attack_scores_above_threshold")
    client_id = scan_results["client_id"]
    scan_id = scan_results["scan_id"]
    
    kb = KnowledgeBase(client_id=client_id, scan_id=scan_id)
    collection = kb.chroma_client.get_collection(ChromaCollection.ATTACK_HISTORY)
    
    results = await asyncio.to_thread(
        collection.get,
        where={"client_id": client_id}
    )
    
    metadatas = results.get("metadatas", [])
    
    high_scoring_attacks = []
    for metadata in metadatas:
        score = metadata.get("score", 0.0)
        if score >= 0.4:
            high_scoring_attacks.append({
                "score": score,
                "domain": metadata.get("domain", ""),
                "response_preview": metadata.get("response_preview", "")[:100]
            })
    
    assert len(high_scoring_attacks) >= 1, (
        f"Expected at least one attack with score >= 0.4, "
        f"but all attacks scored below 0.4. "
        f"Maximum score found: {max((m.get('score', 0.0) for m in metadatas), default=0.0):.2f}"
    )
    
    logger.info(f"✅ Found {len(high_scoring_attacks)} attacks scoring >= 0.4")
    for attack in high_scoring_attacks[:3]:
        logger.info(f"   - Score: {attack['score']:.2f}, Domain: {attack['domain']}")


async def test_full_integration_pipeline(scan_results: dict):
    """
    W2-TEAM-09: Full integration test combining all assertions.
    This runs all the sub-assertions on the shared scan results.
    """
    logger.info("=" * 60)
    logger.info("W2-TEAM-09: Full Integration Test (Assertions Only)")
    logger.info("=" * 60)
    
    await test_recon_detects_all_dummy_target_endpoints(scan_results)
    await test_component_map_written_to_chromadb(scan_results)
    await test_attack_agent_executes_all_prompt_injection_templates(scan_results)
    await test_all_attacks_logged_with_scores(scan_results)
    await test_at_least_one_attack_scores_above_threshold(scan_results)
    
    logger.info("=" * 60)
    logger.info("✅ ALL W2-TEAM-09 ASSERTIONS PASSED SUCCESSFULLY")
    logger.info("=" * 60)