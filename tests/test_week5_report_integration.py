"""
PURPOSE: Full end-to-end integration test of the Week 5 report pipeline —
         verifies ReportAgent.run() produces a valid PDF, valid JSON
         export, and that orchestrator.report_node correctly populates
         ScanState.report_path.
WHAT IS BEING TESTED: aggregate_findings -> component findings ->
         executive summary -> timeline -> remediation roadmap -> PDF/JSON
         write, end to end, plus report_node wiring.
DEPENDENCIES: Dummy target running on port 8001, real ChromaDB
         (chroma_store/), Gemini calls mocked (no real API key needed).
HOW TO RUN: pytest tests\test_week5_report_integration.py -v -s
ESTIMATED RUNTIME: 10-30s
"""

import asyncio
import os
import uuid
from unittest.mock import patch, AsyncMock

import pytest
import httpx
import pytest_asyncio

@pytest.fixture(scope="module")
def event_loop():
    """Module-scoped event loop so seeded_scan_data (module-scoped)
    and the tests that depend on it share one loop."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

from agents.orchestrator import run_scan
from agents.report_agent import ReportAgent
from constants import ScanPhase, Severity

pytestmark = pytest.mark.asyncio

DUMMY_TARGET_URL = os.getenv("DUMMY_TARGET_URL", "http://localhost:8001")


async def mock_call_gemini(self, prompt: str, system: str = "") -> str:
    system_lower = system.lower()
    if "executive summary" in system_lower:
        return "Paragraph 1: Summary.\n\nParagraph 2: Details.\n\nParagraph 3: Conclusion."
    elif "technical findings section" in system_lower:
        return "- Domain: API Attacks\n  CVSS: 9.8\n  Payload: ' OR 1=1--\n"
    elif "remediation roadmap" in system_lower:
        return '[{"component": "backend", "domain": "api_attacks", "short_title": "Fix SQLi", "description": "Use parameterized queries.", "code_example": "cursor.execute()", "estimated_effort": "Medium"}]'
    return ""


@pytest_asyncio.fixture(scope="module")
async def seeded_scan_data() -> dict:
    """Run a minimal recon_node + attack_node cycle to seed test data into Chroma."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{DUMMY_TARGET_URL}/health")
            if response.status_code != 200:
                pytest.fail(f"Dummy target returned status {response.status_code}")
    except httpx.ConnectError:
        pytest.fail(f"Dummy target not accessible at {DUMMY_TARGET_URL}.")

    client_id = f"test-client-w5-{uuid.uuid4().hex[:8]}"
    scan_id = f"scan-w5-{uuid.uuid4().hex[:8]}"

    manifest = {
        "components": [
            {"endpoint": f"{DUMMY_TARGET_URL}/chat", "type": "llm_model"},
            {"endpoint": f"{DUMMY_TARGET_URL}/api/data", "type": "api_layer"},
        ]
    }

    async def mock_execute_attack(*args, **kwargs):
        return {
            "success": True,
            "status_code": 200,
            "response_text": "Mock vulnerable response traceback...",
            "response_time_ms": 1.5,
            "error": None,
        }
        
    async def mock_broadcast(*args, **kwargs):
        pass
        
    async def mock_get_cross_component_insights(*args, **kwargs):
        return []

    with patch("agents.orchestrator.MAX_ITERATIONS", 1), \
         patch("agents.attack_agent.AttackAgent.execute_attack", mock_execute_attack), \
         patch("agents.orchestrator._broadcast", mock_broadcast), \
         patch("agents.attack_agent.KnowledgeBase.get_cross_component_insights", mock_get_cross_component_insights), \
         patch("agents.report_agent.ReportAgent.call_gemini", mock_call_gemini):
         
        # Run scan fully to seed data in ChromaDB via the natural orchestrator path
        final_state = await run_scan(client_id, scan_id, manifest=manifest)

    return {
        "client_id": client_id,
        "scan_id": scan_id,
        "final_state": final_state,
    }


async def test_report_agent_run_produces_pdf_and_json(seeded_scan_data: dict) -> None:
    client_id = seeded_scan_data["client_id"]
    scan_id = seeded_scan_data["scan_id"]
    
    agent = ReportAgent(client_id=client_id, scan_id=scan_id)
    dummy_state = {
        "client_id": client_id,
        "scan_id": scan_id,
        "logs": [],
        "phase": ScanPhase.ATTACKING,
    }
    
    with patch("agents.report_agent.ReportAgent.call_gemini", mock_call_gemini):
        result = await agent.run(dummy_state)
    
    assert "report_path" in result
    assert result["report_path"].endswith(".pdf")
    assert os.path.exists(result["report_path"])
    assert os.path.getsize(result["report_path"]) > 0
    
    assert "report_json" in result
    json_data = result["report_json"]
    assert json_data.get("schema_version") == "1.0"
    
    components = json_data.get("components", [])
    valid_severities = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.NONE}
    
    for comp in components:
        for finding in comp.get("findings", []):
            assert isinstance(finding.get("score"), float)
            assert finding.get("severity") in valid_severities


async def test_report_node_populates_scan_state(seeded_scan_data: dict) -> None:
    client_id = seeded_scan_data["client_id"]
    scan_id = seeded_scan_data["scan_id"]
    
    dummy_state = {
        "client_id": client_id,
        "scan_id": scan_id,
        "logs": [],
        "phase": ScanPhase.ATTACKING,
    }
    
    from agents.orchestrator import report_node
    
    with patch("agents.report_agent.ReportAgent.call_gemini", mock_call_gemini), \
         patch("agents.orchestrator._broadcast", AsyncMock()):
        updated_state = await report_node(dummy_state)
    
    assert "report_path" in updated_state
    assert updated_state["report_path"] != ""
    assert updated_state["phase"] == ScanPhase.REPORTING
