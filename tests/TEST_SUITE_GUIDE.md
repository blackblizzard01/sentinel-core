## Test Suite Overview

| File Name | Purpose | Estimated Runtime | Needs Dummy Target | Needs Real API Keys |
|---|---|---|---|---|
| `test_w3_team_06_stopping_conditions.py` | Verifies orchestrator routing functions handle stopping conditions. | fast <5s | NO | NO |
| `test_kb_retrieval.py` | Verifies KnowledgeBase retrieves top attacks correctly with client isolation. | fast <5s | NO | NO |
| `test_knowledge_base_mutation.py` | Verifies KnowledgeBase correctly logs and retrieves mutation lineage records. | fast <5s | NO | NO |
| `test_attack_logging.py` | Verifies KnowledgeBase correctly logs attacks and enforces client isolation. | fast <5s | NO | NO |
| `test_base_agent.py` | Verifies BaseAgent correctly initializes LLM clients and emits structured logs. | fast <5s | NO | NO |
| `test_api_key_manager.py` | Verifies ApiKeyManager correctly loads, cycles, and rotates API keys. | fast <5s | NO | NO |
| `test_mutation_variants.py` | Verifies MutationAgent generates distinct variants with sufficient cosine distance. | fast <5s | NO | NO |
| `test_recon_agent.py` | Verifies ReconAgent correctly maps targets, detects frameworks, and prioritizes. | fast <5s | NO | NO |
| `test_week1_smoke.py` | Basic smoke tests verifying backend connectivity and ChromaDB. | medium 10–30s | YES | NO |
| `test_week2_integration.py` | Verifies full integration graph run against the dummy target. | medium 10–30s | YES | NO |
| `test_week3_benchmark.py` | Verifies 3-iteration score improvement, variant quality, and lineage. | medium 10–30s | YES | NO |
| `test_week4_integration.py` | Full 3-component multi-domain pipeline integration test | medium 10-30s | YES | NO |
| `test_report_agent_cvss.py` | Verifies map_cvss_score's Impact/Exploitability formula and vector string output against reference values (regression, not expert-validated — see test docstring). | fast <5s | NO | NO |
| `test_week5_report_integration.py` | Verifies full report pipeline end-to-end via report_node: aggregation, executive summary, per-component findings, timeline, remediation roadmap, PDF + JSON write. | medium 10-30s | YES | NO (Gemini mocked) |

## Redundancy Findings

- File A: `test_attack_logging.py` (`test_client_isolation`)
- File B: `test_kb_retrieval.py` (`test_get_top_attacks_client_isolation`)
- Overlap: Both tests verify that attacks logged under one client do not leak into queries for a different client. They both test the exact same ChromaDB client isolation mechanism.
- Recommendation: CONSOLIDATE

- File A: `test_week2_integration.py` (`test_at_least_one_attack_scores_above_threshold`)
- File B: `test_week3_benchmark.py` (`test_iteration1_avg_score_above_baseline`)
- Overlap: Both assert that the initial execution of the attack agent against the dummy target produces measurable attack scores above a baseline/threshold.
- Recommendation: KEEP BOTH (Week 2 tests the basic scoring mechanism and threshold triggering, while Week 3 specifically sets up the baseline for the iteration comparison logic).

## Recommended Run Order

1. Fast unit tests with no dependencies (run always, under 10s)
2. Tests needing ChromaDB only (no API keys, no dummy target)
3. Tests needing API keys (real LLM calls)
4. Integration tests needing dummy target
5. Benchmark tests (run only before weekly audit)

## Quick Reference Commands

```cmd
    :: Group 1 — Fast unit tests (no dependencies)
    python -m pytest tests\test_w3_team_06_stopping_conditions.py -v

    :: Group 1b — CVSS scoring regression test (no dependencies)
    python -m pytest tests\test_report_agent_cvss.py -v

    :: Group 2 — ChromaDB tests (no API keys needed)
    python -m pytest tests\test_kb_retrieval.py tests\test_knowledge_base_mutation.py tests\test_attack_logging.py -v

    :: Group 3 — Real API key tests (Groq/Gemini/DeepSeek required)
    python -m pytest tests\test_base_agent.py tests\test_api_key_manager.py tests\test_mutation_variants.py -v

    :: Group 4 — Integration (dummy target must be running on port 8001)
    python -m pytest tests\test_week1_smoke.py tests\test_week2_integration.py tests\test_recon_agent.py -v

    :: Group 5 — Benchmark (dummy target + full 3-iteration scan)
    python -m pytest tests\test_week3_benchmark.py -v -s

    :: Week 4 integration (dummy target required)
    python -m pytest tests\test_week4_integration.py -v -s

    :: Week 5 report integration (dummy target required, Gemini mocked)
    python -m pytest tests\test_week5_report_integration.py -v -s
```
