"""
PURPOSE: Verify ReportAgent.map_cvss_score produces CVSS 3.1 base scores
         within a reasonable tolerance of the formula's expected output
         across domain/component_type/score combinations.
WHAT IS BEING TESTED: map_cvss_score's Impact/Exploitability calculation,
         Scope-Changed multiplier application, and Roundup(x) behavior.
DEPENDENCIES: None (pure function, no ChromaDB, no LLM calls).
HOW TO RUN: pytest tests\\test_report_agent_cvss.py -v
ESTIMATED RUNTIME: <5s

NOTE: The five reference values below are computed from the same formula
implemented in map_cvss_score, so this is a REGRESSION test, not a
validation against real expert-scored CVEs. Before relying on the ">within
0.5" claim in the task spec, replace these five reference_score values
with actual expert-assigned CVSS scores for comparable findings.
"""

import pytest

from agents.report_agent import ReportAgent
from constants import AttackDomain, ComponentType


from unittest.mock import patch

@pytest.fixture
def agent() -> ReportAgent:
    with patch("agents.base_agent.ApiKeyManager.acquire_key", return_value="dummy-key"), \
         patch("agents.base_agent.AsyncGroq"), \
         patch("agents.base_agent.AsyncOpenAI"), \
         patch("agents.base_agent.genai.Client"):
        return ReportAgent(client_id="test-client", scan_id="test-scan")


@pytest.mark.parametrize(
    "sentinel_score,domain,component_type,reference_score",
    [
        (0.95, AttackDomain.PROMPT_INJECTION, ComponentType.LLM_MODEL, 9.8),
        (0.75, AttackDomain.SYSTEM_PROMPT_EXTRACT, ComponentType.LLM_MODEL, 8.8),
        (0.60, AttackDomain.API_ATTACKS, ComponentType.BACKEND, 9.1),
        (0.45, AttackDomain.INDIRECT_INJECTION, ComponentType.API, 5.5),
        (0.85, AttackDomain.RAG_POISONING, ComponentType.DATABASE, 10.0),
    ],
)
def test_cvss_base_score_within_tolerance(
    agent: ReportAgent,
    sentinel_score: float,
    domain: str,
    component_type: str,
    reference_score: float,
) -> None:
    result = agent.map_cvss_score(sentinel_score, domain, component_type)
    assert abs(result["base_score"] - reference_score) <= 0.5, (
        f"base_score={result['base_score']} vs reference={reference_score} "
        f"for domain={domain} component_type={component_type}"
    )


def test_cvss_vector_string_reflects_scope_changed(agent: ReportAgent) -> None:
    result = agent.map_cvss_score(0.8, AttackDomain.API_ATTACKS, ComponentType.BACKEND)
    assert "S:C" in result["vector_string"]


def test_cvss_vector_string_reflects_scope_unchanged(agent: ReportAgent) -> None:
    result = agent.map_cvss_score(0.8, AttackDomain.API_ATTACKS, ComponentType.API)
    assert "S:U" in result["vector_string"]


def test_cvss_unknown_mapping_raises_keyerror(agent: ReportAgent) -> None:
    with pytest.raises(KeyError):
        agent.map_cvss_score(0.5, "not_a_real_domain", ComponentType.API)
