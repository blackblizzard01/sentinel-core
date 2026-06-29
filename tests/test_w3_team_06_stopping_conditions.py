"""
================================================================================
TEST FILE: test_w3_team_06_stopping_conditions.py
================================================================================
PURPOSE:
    Verifies that orchestrator routing functions correctly handle stopping conditions.

WHAT IS BEING TESTED:
    - test_critical_halt_routes_to_report_node: Both routers short-circuit to report_node when critical_halt is True.
    - test_max_iterations_routes_to_attack_node: route_after_mutation returns attack_node at MAX_ITERATIONS.
    - test_no_improvement_routes_to_attack_node: route_after_mutation returns attack_node when avg score is 0.0 and iteration > 0.

DEPENDENCIES (what must be running/available):
    - Dummy target:     NO  (uvicorn dummy_target.app:app --port 8001)
    - Sentinel backend: NO  (uvicorn backend.main:app --port 8000)
    - Real API keys:    NO  (Groq / Gemini / DeepSeek in .env)
    - Ollama:           NO  (ollama serve + ollama pull mistral)
    - ChromaDB:         NO  (auto-initialized — no manual step needed)

HOW TO RUN:
    pytest tests/test_w3_team_06_stopping_conditions.py -v

ESTIMATED RUNTIME: fast <5s

NOTES:
    Three pure-sync tests — one per stopping condition — using mocked ScanState dicts. No real agents, no ChromaDB, no API calls.
================================================================================
"""

from unittest.mock import MagicMock, patch

# pyrefly: ignore [missing-import]
import pytest

from agents.orchestrator import route_after_attack, route_after_mutation
from constants import MAX_ITERATIONS


def _base_state(**overrides) -> dict:
    """Build a minimal ScanState-shaped dict with safe defaults."""
    base = {
        "client_id": "test-client-001",
        "scan_id": "test-scan-001",
        "current_component_index": 0,
        "current_component": {"component_id": "comp-1", "component_type": "llm_model"},
        "current_domain_index": 0,
        "current_domain": "prompt_injection",
        "attack_results": [],
        "iteration": 1,
        "phase": "attacking",
        "logs": [],
        "critical_halt": False,
        "components": [
            {
                "component_id": "comp-1",
                "component_type": "llm_model",
                "estimated_attack_domains": ["prompt_injection", "system_prompt_extraction"],
            }
        ],
        "manifest": {},
        "approved_findings": [],
        "report_path": "",
        "report_json": {},
        "out_of_components": False,
        "previous_batch_avg_score": 0.5,
    }
    base.update(overrides)
    return base


def test_critical_halt_routes_to_report_node() -> None:
    """Both routers short-circuit to report_node when critical_halt is True."""
    state = _base_state(
        critical_halt=True,
        iteration=1,
        previous_batch_avg_score=0.95,
    )

    assert route_after_attack(state) == "report_node"
    assert route_after_mutation(state) == "report_node"


def test_max_iterations_routes_to_attack_node() -> None:
    """route_after_mutation returns attack_node at MAX_ITERATIONS so attack_node advances the domain."""
    state = _base_state(
        critical_halt=False,
        out_of_components=False,
        iteration=MAX_ITERATIONS,
        previous_batch_avg_score=0.5,
    )

    assert route_after_mutation(state) == "attack_node"


def test_no_improvement_routes_to_attack_node() -> None:
    """route_after_mutation returns attack_node when avg score is 0.0 and iteration > 0."""
    state = _base_state(
        critical_halt=False,
        out_of_components=False,
        iteration=1,
        previous_batch_avg_score=0.0,
    )

    assert route_after_mutation(state) == "attack_node"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
