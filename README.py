────────────────────────────────────────────────
# SENTINEL AI — PROJECT STATE DOCUMENT
*Last updated: 2026-07-03 | Covers: Weeks 1–5 completed*
────────────────────────────────────────────────

## 1. WHAT THIS PROJECT IS
Sentinel AI is an autonomous AI infrastructure security testing platform designed for security engineers. It discovers, attacks, and provides patches for vulnerabilities in AI applications (LLMs, RAG pipelines, APIs). Unlike traditional static scanners, Sentinel uses a multi-agent system that intelligently mutates its own successful attacks to bypass security controls, enabling a fully automated, iterative penetration testing loop.

## 2. SYSTEM ARCHITECTURE
- **The 5-agent pipeline**: The system orchestrates five specialized agents. `ReconAgent` maps the target's attack surface; `AttackAgent` executes targeted payloads; `MutationAgent` creatively mutates successful payloads to evade filters; `ReportAgent` (skeleton) compiles findings into CVSS-scored reports; and `AutopatchAgent` (skeleton) generates remediation PRs.
- **LangGraph orchestration**: A state machine controls the pipeline using a shared `ScanState`. Conditional edges route execution between nodes (`recon_node`, `attack_node`, `mutation_node`, etc.) based on real-time factors like attack scores, iteration counts, and stopping conditions.
- **ChromaDB**: Serves as the persistent vector knowledge base. Data is split across five collections (`attack_history`, `successful_attacks`, `mutation_lineage`, `component_profiles`, `vulnerability_catalog`). Strict multitenancy is enforced by requiring a `client_id` filter on every query.
- **WebSocket layer**: A `ConnectionManager` inside the FastAPI backend broadcasts live JSON events (e.g., `agent_started`, `mutation_occurred`) to the frontend, isolating event streams per `scan_id`.
- **Dummy Target**: An intentionally vulnerable FastAPI application (victim) running independently. It is strictly a testing sandbox used to validate the orchestrator and agents, and is not part of the deployed product.

## 3. COMPONENT STATUS TABLE
| Component | File(s) | Status | What it does | Known gaps |
| --- | --- | --- | --- | --- |
| BaseAgent | `agents/base_agent.py` | ✅ Complete | Base class for LLM calling and API rotation | None |
| ApiKeyManager | `agents/api_key_manager.py` | ✅ Complete | Rotates through API keys from `.env` | None |
| ReconAgent | `agents/recon_agent.py` | ✅ Complete | Discovers attack surface / components | None |
| AttackAgent | `agents/attack_agent.py` | ✅ Complete | Generates and executes payloads | None |
| MutationAgent | `agents/mutation_agent.py` | ✅ Complete | Mutates successful attacks using DeepSeek | None |
| ReportAgent | `agents/report_agent.py` | ✅ Complete | Aggregates findings, maps CVSS scores, generates executive summary + per-component technical findings + remediation roadmap via Gemini, writes PDF (ReportLab) and JSON exports | WebSocket ScanCompleteEvent/report_path not yet covered by an automated test (manual-only); PDF section-content not asserted, only file existence |
| CVSS scoring | `agents/cvss_tables.py` | ✅ Complete | CVSS 3.1 approximation tables and Roundup(x) logic used by ReportAgent.map_cvss_score | Simplified model — fixed AC:L/PR:N/UI:N, sentinel_score maps directly to Impact rather than decomposed C/I/A |
| Report styling | `agents/report_styles.py` | ✅ Complete | PDF color/font constants (severity colors, section headers) | None |
| Custom exceptions | `agents/exceptions.py` | ✅ Complete | Houses ReportGenerationTimeout | First exceptions module in the project — no other custom exceptions defined yet |
| AutopatchAgent (skeleton) | N/A | ❌ Skeleton | Generates code remediations | Missing file and logic |
| Orchestrator | `agents/orchestrator.py` | ✅ Complete | Runs LangGraph state machine | None |
| KnowledgeBase | `knowledge_base/knowledge_base.py` | ✅ Complete | ChromaDB interface and semantic queries | None |
| ChromaClientSingleton | `knowledge_base/chroma_client.py` | ✅ Complete | Singleton wrapper for ChromaDB | None |
| FastAPI backend | `backend/main.py` | ✅ Complete | HTTP API and WebSocket event streaming | None |
| WebSocket ConnectionManager| `backend/main.py` | ✅ Complete | Manages WS connections and replay buffers | None |
| Dummy Target | `dummy_target/app.py` | ✅ Complete | Intentionally vulnerable test victim | None |
| ScanState | `agents/orchestrator.py` | ✅ Complete | TypedDict for LangGraph state passing | None |
| DomainLibrary | `domains/domain_library.py` | ✅ Complete | Attack template library with 52 templates across 4 domains | None |
| domains/templates/rag_poisoning.json | `domains/templates/rag_poisoning.json` | ✅ Complete | 15 RAG attack templates | None |
| domains/templates/api_attacks.json | `domains/templates/api_attacks.json` | ✅ Complete | 15 API attack templates | None |
| domains/templates/indirect_injection.json | `domains/templates/indirect_injection.json` | ✅ Complete | 12 injection templates | None |
| domains/templates/system_prompt_extraction.json | `domains/templates/system_prompt_extraction.json` | ✅ Complete | 10 SPE templates | None |
| Frontend (React) | `frontend/` | ⏳ Not started | User interface dashboard | Directory is empty |

## 4. ITERATION LOOP — HOW A SCAN ACTUALLY RUNS
1. **Init**: `run_scan()` initializes the `ScanState` and calls `app.ainvoke()`.
2. **Recon**: `recon_node` runs the `ReconAgent` to map components, sets `current_component` and `current_domain` in state, and routes to `attack_node`.
3. **Attack**: `attack_node` executes attack payloads. It logs scores and checks if `score >= CRITICAL_THRESHOLD` (setting `critical_halt`). It calculates `current_batch_avg` and detects if improvement stalled (when `iteration > 1`). It increments the `iteration` counter.
4. **Post-Attack Routing**: `route_after_attack` checks flags. If `critical_halt` or `out_of_components`, it routes to `report_node`. If `iteration == 0` (fresh domain), it routes back to `attack_node`. Otherwise, it routes to `mutation_node`.
5. **Mutation**: `mutation_node` fetches the top successful attacks from ChromaDB. `MutationAgent` generates up to 10 variants per attack. It logs them via `kb.log_mutation` and injects them into the state's `attack_results` with `score = 0.0`. It resets `iteration` to 0.
6. **Post-Mutation Routing**: `route_after_mutation` checks stopping conditions. If `iteration >= MAX_ITERATIONS` or `previous_batch_avg_score == 0.0` (no improvement), it routes to `attack_node` (which internally detects these limits, advances to the next domain/component, and resets the iteration). Otherwise, it routes to `attack_node` to execute the mutated variants.
7. **Reporting**: Once all components/domains are exhausted, `out_of_components` is set. The graph routes to `report_node`.
8. **Patching & End**: `report_node` routes to `autopatch_node`, which then routes to `END`, terminating the graph.

## 5. STOPPING CONDITIONS (implemented as of W3-TEAM-06)
- **Critical Halt**: Detected inside `attack_node` if any attack achieves a `score >= 0.9`. Sets `critical_halt = True` in state and broadcasts `WSEvent.CRITICAL_HALT`. Both `route_after_attack` and `route_after_mutation` check this flag first and immediately route to `report_node`.
- **Max Iterations**: Detected in `route_after_mutation`. If `iteration >= MAX_ITERATIONS`, it routes to `attack_node`. Inside `attack_node`, this condition forces the state to advance to the next domain or component, resetting `iteration` and `previous_batch_avg_score` to 0.
- **No Improvement**: Detected in `attack_node` when `iteration > 1`. If `current_batch_avg <= previous_batch_avg_score`, a `no_improvement = True` flag triggers the same domain/component advancement logic as Max Iterations. Additionally, `route_after_mutation` checks if `prev_avg == 0.0` and avoids pointless mutations.

## 6. CHROMADB COLLECTIONS REFERENCE
| Collection name | What is stored | Key metadata fields | Who writes | Who reads |
| --- | --- | --- | --- | --- |
| `attack_history` | All attack attempts | client_id, scan_id, component_id, domain, score, timestamp | `KnowledgeBase.log_attack` | (Future/Reporting) |
| `successful_attacks` | Attacks scoring >= 0.7 | client_id, scan_id, component_id, domain, score | `KnowledgeBase.log_attack`, `log_successful_attack` | `KnowledgeBase.get_top_attacks` |
| `mutation_lineage` | Mutated child payloads | client_id, parent_attack_id, strategy, child_score, generation | `KnowledgeBase.log_mutation` | `KnowledgeBase.get_lineage` |
| `component_profiles` | Discovered attack surfaces | client_id, component_id, component_type, endpoint, priority_score | `KnowledgeBase.log_component_profile` | (Future/Reporting) |
| `vulnerability_catalog`| Confirmed vulnerabilities | client_id, component_id, domain, severity, remediation | `KnowledgeBase.log_vulnerability` | `KnowledgeBase.get_vulnerability_catalog` |

## 7. WEBSOCKET EVENTS REFERENCE
| Event type | Triggered by | Key payload fields | When it fires |
| --- | --- | --- | --- |
| `agent_started` | Orchestrator (`recon_node`, `attack_node`, `mutation_node`) | agent_name, phase, component_id, domain | At the beginning of a node's execution |
| `attack_executed` | Orchestrator (`attack_node`) | component_id, domain, payload_preview, score | After a batch of attacks completes |
| `mutation_occurred` | Orchestrator (`mutation_node`) | parent_attack_id, child_attack_id, strategy, component_id | For every variant generated |
| `critical_halt` | Orchestrator (`attack_node`) | component_id, domain, score, reason | When an attack scores >= 0.9 |
| `scan_complete` | Orchestrator (`run_scan`) | total_vulnerabilities, critical_count, report_path | At the very end of the orchestration loop |
| `progress_update` | (Unused) | - | - |
| `vulnerability_found` | (Unused) | - | - |
| `component_complete`| (Unused) | - | - |

## 8. CONSTANTS QUICK REFERENCE
| Constant | Value | Effect |
| --- | --- | --- |
| `MAX_ITERATIONS` | 3 | Max mutation loops per domain before advancing |
| `SUCCESS_THRESHOLD` | 0.7 | Score above this = confirmed vulnerability |
| `PARTIAL_THRESHOLD` | 0.4 | Score above this = feed to mutation agent |
| `CRITICAL_THRESHOLD` | 0.9 | Score above this = immediate halt + alert |
| `MAX_ATTACKS_PER_DOMAIN` | 20 | Max attack attempts per domain per component |
| `TOP_K_RETRIEVAL` | 5 | Top-k similar attacks retrieved for mutation |
| `MAX_MUTATIONS_PER_ATTACK`| 5 | Variants generated per successful attack |
| `ATTACK_RATE_LIMIT` | 1.0 | Seconds between attack executions (DoS prevention) |

## 9. HOW TO RUN THE APPLICATION
### Prerequisites
Python 3.11, venv, `.env` populated, Ollama installed and running, ChromaDB (local persistent). No Docker needed for local dev.

### Step-by-step startup (Windows CMD)
Terminal 1 — Ollama (required for dummy target):
```cmd
ollama serve
ollama pull mistral
```

Terminal 2 — Dummy target (the scan victim):
```cmd
cd sentinel-core
venv\Scripts\activate
uvicorn dummy_target.app:app --port 8001
```

Terminal 3 — Sentinel backend:
```cmd
cd sentinel-core
venv\Scripts\activate
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Terminal 4 — Run a scan (Python script or pytest):
```cmd
python agents/orchestrator.py
```

### How to verify everything is working
- GET `http://localhost:8000/health` → `{"status": "ok"}`
- GET `http://localhost:8001/health` → `{"status": "ok", "service": "sentinel-dummy-target"}`
- WebSocket test: connect to `ws://localhost:8000/ws/scan/test-123`

## 10. TEST SUITE REFERENCE
| File | What it tests | Needs dummy target? | Needs API keys? | Run command |
| --- | --- | --- | --- | --- |
| `tests/test_week1_smoke.py` | Basic backend + target connectivity | Yes | No | `pytest tests/test_week1_smoke.py` |
| `tests/test_base_agent.py` | LLM client initialization and error handling | No | Yes (Mocked) | `pytest tests/test_base_agent.py` |
| `tests/test_api_key_manager.py` | Key pooling and rotation | No | No | `pytest tests/test_api_key_manager.py` |
| `tests/test_kb_retrieval.py` | Vector search isolation / ChromaDB | No | No | `pytest tests/test_kb_retrieval.py` |
| `tests/test_knowledge_base_mutation.py` | Mutation lineage tracking | No | No | `pytest tests/test_knowledge_base_mutation.py` |
| `tests/test_mutation_variants.py` | MutationAgent logic and DeepSeek calls | No | Yes (Mocked) | `pytest tests/test_mutation_variants.py` |
| `tests/test_attack_logging.py` | Attack history and threshold triggers | No | No | `pytest tests/test_attack_logging.py` |
| `tests/test_recon_agent.py` | Recon mapping and manifest generation | No (Mocked) | Yes (Mocked) | `pytest tests/test_recon_agent.py` |
| `tests/test_week2_integration.py` | Full graph integration (iteration=1) | Yes | Yes (Mocked) | `pytest tests/test_week2_integration.py` |
| `tests/test_w3_team_06_stopping_conditions.py` | Routing logic (halt, max loops) | No | No | `pytest tests/test_w3_team_06_stopping_conditions.py` |
| `tests/test_week3_benchmark.py` | 3-iteration score validation & WSEvents | Yes | No (Mocked) | `pytest tests/test_week3_benchmark.py` |
| `tests/test_week4_integration.py` | Full 3-component multi-domain pipeline integration test | Yes | No (Mocked) | `pytest tests/test_week4_integration.py -v -s` |
| `tests/test_report_agent_cvss.py` | CVSS base score formula regression + vector string correctness | No | No | `pytest tests/test_report_agent_cvss.py` |
| `tests/test_week5_report_integration.py` | Full report pipeline: aggregate_findings -> executive summary -> component findings -> timeline -> remediation -> PDF/JSON write, via report_node | Yes | No (Mocked) | `pytest tests/test_week5_report_integration.py -v -s` |

## 11. KNOWN GAPS AND DEFERRED ITEMS
### Real gaps (things that are missing or broken)
- `AutopatchAgent` has no implementation file — Week 6 task.
- ReportAgent's WebSocket ScanCompleteEvent (with report_path populated)
  fires correctly in run_scan() but has no automated test covering it —
  verified manually only. A FastAPI TestClient + WebSocket test is
  deferred to a future task.
- generate_pdf()'s "at least four sections present" requirement is
  verified manually (by opening the PDF), not asserted in
  test_week5_report_integration.py — that test only checks file
  existence and nonzero size.
- Executive summary readability by a non-technical reader is a manual
  human-review step, not automatable — must be re-checked whenever
  generate_executive_summary's prompt changes.

### Intentionally deferred (per build plan)
- ReportAgent: skeleton only — Week 5 task
- AutopatchAgent: skeleton only — Week 6 task
- Frontend: not started — Week 6 task

### Fixed during Week 5 (not a Week 5 task, but discovered and resolved)
- `ReconAgent` was writing component profiles directly via
  `self.knowledge_base.chroma_client` instead of through
  `KnowledgeBase.log_component_profile()`, violating the
  never-call-ChromaDB-directly rule. It also only wrote client_id,
  scan_id, and component_id to metadata — component_type, endpoint,
  framework, and priority_score were serialized into the documents
  field only, making them unqueryable. This silently broke
  get_component_profiles(), get_cross_component_insights(), and any
  other metadata-filtered query against component_profiles since
  ReconAgent was first written. Fixed in agents/recon_agent.py to call
  log_component_profile() properly. Any pre-existing chroma_store/
  data from before this fix has malformed component_profiles records
  and should be treated as unreliable for components discovered
  before the fix landed.

## 12. UPDATE LOG
| Date | What changed | Updated by |
| --- | --- | --- |
| 2026-06-29 | Initial document — Weeks 1–3 state | Cursor |
| 2026-06-29 | Week 4 complete: 52 domain templates, multi-component pipeline, cross-component KB feed, W4 integration tests passing | Cursor |
| 2026-07-03 | Week 5 complete: ReportAgent fully implemented (aggregate_findings, CVSS mapping, executive summary, per-component findings, attack timeline, remediation roadmap, PDF/JSON export), wired into report_node. Fixed a pre-existing ReconAgent bug bypassing KnowledgeBase for component profile writes. | Cursor |
────────────────────────────────────────────────
