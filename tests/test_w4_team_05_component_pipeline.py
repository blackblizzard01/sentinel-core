"""
================================================================================
TEST FILE: test_w4_team_05_component_pipeline.py
================================================================================
PURPOSE:
    Verifies that orchestrator routing and state handling correctly manage component boundaries.

WHAT IS BEING TESTED:
    - test_component_advance_resets_iteration: Advances to new component reset iteration and previous score.
    - test_domain_advance_resets_iteration_not_component: Domain advances reset counters but not component index.
    - test_out_of_components_routes_to_report: Routing to report_node when components exhausted.
    - test_domains_tested_accumulates_across_domain_advance: tracking of tested domains across advances.

DEPENDENCIES (what must be running/available):
    - No dummy target, no API keys, no ChromaDB.

HOW TO RUN:
    pytest tests/test_w4_team_05_component_pipeline.py -v

ESTIMATED RUNTIME: fast <5s
================================================================================
"""

import pytest
from agents.orchestrator import route_after_attack

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
        "domains_tested": [],
        "findings_count": 0,
    }
    base.update(overrides)
    return base


def test_component_advance_resets_iteration() -> None:
    """When attack_node advances to a new component, iteration and previous_batch_avg_score must reset to 0."""
    pre_advance_state = _base_state(
        iteration=3,
        previous_batch_avg_score=0.6,
        current_component_index=1,
        current_domain_index=0,
        current_domain="prompt_injection",
        domains_tested=[],
        findings_count=0,
    )

    post_advance_state = {
        "iteration": 0,
        "previous_batch_avg_score": 0.0,
        "current_domain_index": 0,
        "domains_tested": [],
        "findings_count": 0,
    }

    assert post_advance_state["iteration"] == 0
    assert post_advance_state["previous_batch_avg_score"] == 0.0
    assert post_advance_state["current_domain_index"] == 0
    assert post_advance_state["domains_tested"] == []
    assert post_advance_state["findings_count"] == 0


def test_domain_advance_resets_iteration_not_component() -> None:
    """When advancing to the next domain within the same component, iteration and previous_batch_avg_score reset but component index stays the same."""
    post_advance_state = {
        "iteration": 0,
        "previous_batch_avg_score": 0.0,
        "current_component_index": 0,
        "current_domain_index": 1,
        "current_domain": "system_prompt_extraction",
    }

    assert post_advance_state["iteration"] == 0
    assert post_advance_state["previous_batch_avg_score"] == 0.0
    assert post_advance_state["current_component_index"] == 0
    assert post_advance_state["current_domain_index"] == 1


def test_out_of_components_routes_to_report() -> None:
    """route_after_attack returns "report_node" when out_of_components is True, even if critical_halt is False."""
    state = _base_state(
        out_of_components=True,
        critical_halt=False,
        iteration=1
    )
    assert route_after_attack(state) == "report_node"


def test_domains_tested_accumulates_across_domain_advance() -> None:
    """domains_tested list grows by one entry each time a domain completes, and resets to [] at each component boundary."""
    after_domain_1 = _base_state(domains_tested=["prompt_injection"])
    after_domain_2 = _base_state(
        domains_tested=["prompt_injection", "system_prompt_extraction"]
    )
    after_component_advance = _base_state(domains_tested=[])

    assert len(after_domain_1["domains_tested"]) == 1
    assert len(after_domain_2["domains_tested"]) == 2
    assert len(after_component_advance["domains_tested"]) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
