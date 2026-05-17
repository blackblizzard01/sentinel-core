# SENTINEL AI — MASTER CURSOR PROMPTS
# ============================================================
# Paste these into Cursor week by week.
# Always paste .cursorrules content first OR ensure it is 
# set as a Project Rule in Cursor settings.
# ============================================================

# ══════════════════════════════════════════════════════════════
# WEEK 1 — FOUNDATION
# ══════════════════════════════════════════════════════════════

## PROMPT W1-1: PostgreSQL Schema
Create SQLAlchemy async models in Python for the Sentinel AI platform.
Tables needed:
- clients: id (UUID), name, email, company, created_at, is_active
- consents: id, client_id (FK), signed_at, scope (JSON), signed_by_email
- scans: id, client_id (FK), consent_id (FK), status (use ScanStatus constants), 
  started_at, completed_at, component_count
- components: id, scan_id (FK), type (use ComponentType constants), 
  endpoint, framework, priority_score (float), status
- vulnerabilities: id, scan_id (FK), component_id (FK), domain, 
  severity (use Severity constants), sentinel_score (float), 
  cvss_score (float), description, remediation, found_at

Use async SQLAlchemy 2.0 style. Include Alembic migration setup.
Import all constants from constants.py. Never hardcode status values.

---

## PROMPT W1-2: LangGraph Orchestrator Skeleton
Build a LangGraph state machine in Python for Sentinel AI.

State TypedDict fields:
  client_id, scan_id, current_component_index, current_component,
  current_domain_index, current_domain, attack_results (list),
  iteration (int), phase (ScanPhase), logs (list of str),
  critical_halt (bool), components (list)

Create 5 async node functions (empty for now, just log and return state):
  recon_node, attack_node, mutation_node, report_node, autopatch_node

Wire conditional edges:
- After attack_node: if iteration < MAX_ITERATIONS and no critical_halt 
  → mutation_node, else → check if more domains/components, else → report_node
- After mutation_node → attack_node
- After report_node → autopatch_node

Import MAX_ITERATIONS, ScanPhase, ScanStatus from constants.py
Include a run_scan(client_id, scan_id) async function as entry point.

---

## PROMPT W1-3: FastAPI App + WebSocket Base
Build a FastAPI application with:

1. A ConnectionManager class that:
   - Maintains a dict of scan_id → list of WebSocket connections
   - async connect(scan_id, websocket)
   - disconnect(scan_id, websocket)  
   - async broadcast(scan_id, event_dict) — sends JSON to all connections
   - async replay_recent(scan_id, websocket) — replays last 50 events

2. WebSocket endpoint at /ws/scan/{scan_id}
   - On connect: replay recent events then keep alive
   - On disconnect: clean up from manager

3. Pydantic event schemas for all WSEvent types from constants.py:
   AgentStartedEvent, AttackExecutedEvent, MutationOccurredEvent,
   VulnerabilityFoundEvent, ComponentCompleteEvent, ScanCompleteEvent,
   CriticalHaltEvent — all include scan_id, timestamp, event_type fields

4. Basic REST endpoints:
   POST /scans — create new scan, return scan_id
   GET /scans/{scan_id} — get scan status
   GET /scans/{scan_id}/vulnerabilities — list all findings

Import all constants from constants.py. Use async SQLAlchemy for DB calls.

---

## PROMPT W1-4: ChromaDB Knowledge Base Module
Build a KnowledgeBase Python class using ChromaDB HTTP client.

Collections to create on init (from ChromaCollection constants):
  attack_history, successful_attacks, mutation_lineage, 
  component_profiles, vulnerability_catalog

Methods needed:
  async log_attack(client_id, scan_id, component_id, domain, 
                   payload, response, score, timestamp) → str (record id)
  
  async get_top_attacks(client_id, domain, component_type, k=5) → list[dict]
  # MUST filter by client_id metadata — never return other clients' data
  
  async log_mutation(client_id, parent_attack_id, child_payload, 
                     strategy, child_score, generation) → str
  
  async get_mutation_lineage(client_id, attack_id) → list[dict]
  
  async log_vulnerability(client_id, scan_id, component_id, 
                          domain, score, severity, description) → str
  
  async get_component_vulnerabilities(client_id, scan_id, 
                                      component_id) → list[dict]

Use sentence-transformers all-MiniLM-L6-v2 for embeddings.
All queries MUST include where={"client_id": client_id} filter.
Import EMBEDDING_MODEL and ChromaCollection from constants.py.


# ══════════════════════════════════════════════════════════════
# WEEK 2 — RECON + ATTACK AGENT
# ══════════════════════════════════════════════════════════════

## PROMPT W2-1: Recon Agent
Build ReconAgent class inheriting from BaseAgent in agents/base_agent.py.

The run(state) method should:
1. Read the client's infrastructure manifest from state["components"]
2. For each component, use httpx AsyncClient to:
   - Send a GET request to the endpoint
   - Check for /docs or /openapi.json to detect REST API
   - Parse response headers for framework fingerprinting
     (x-powered-by, server header, cookie names)
   - Calculate priority_score 1-10 based on:
     component type weight (LLM=10, RAG=9, Backend=8, API=7, DB=6, Frontend=4)
   - Estimate attack domains based on component type using ComponentType constants
3. Store each component profile in ChromaDB component_profiles collection
4. Return updated state with enriched component list and phase=ScanPhase.ATTACKING

Use asyncio.gather for concurrent probing.
Handle connection errors gracefully — mark unreachable endpoints 
with priority_score=0 and log warning.
Import all constants from constants.py.

---

## PROMPT W2-2: Attack Domain Templates JSON
Generate 5 JSON files in domains/templates/ folder:

prompt_injection.json — 20 attack templates
rag_poisoning.json — 15 attack templates  
api_attacks.json — 15 attack templates
indirect_injection.json — 12 attack templates
system_prompt_extraction.json — 10 attack templates

Each template object structure:
{
  "id": "domain_001",
  "name": "descriptive name",
  "template": "attack string with {target} and {context} placeholders",
  "expected_indicators": ["string1", "string2"],
  "severity_potential": "critical|high|medium",
  "domain": "domain_name"
}

Templates should be realistic adversarial test cases for authorized 
security testing of AI systems.

---

## PROMPT W2-3: Attack Agent
Build AttackAgent class inheriting from BaseAgent.

The run(state) method should:
1. Get current component and domain from state
2. Load attack templates from the relevant JSON file in domains/templates/
3. Retrieve top-5 similar past attacks from KnowledgeBase using 
   get_top_attacks(client_id, domain, component_type)
4. For each template (up to MAX_ATTACKS_PER_DOMAIN):
   - Format template with component endpoint as {target}
   - Send via httpx POST to component endpoint with rate limiting 
     (ATTACK_RATE_LIMIT seconds between each)
   - Score response 0.0-1.0 using heuristic scorer:
     * Check for expected_indicators in response
     * Use call_groq() to judge if model behavior deviated
     * Average both scores
   - Log to KnowledgeBase attack_history
   - If score > CRITICAL_THRESHOLD: set state critical_halt=True, 
     broadcast CriticalHaltEvent via WebSocket, return immediately
5. Return updated state with attack_results list

Import all thresholds from constants.py. Use self.log_action() for all logging.


# ══════════════════════════════════════════════════════════════
# WEEK 3 — MUTATION AGENT + VECTOR KB INTELLIGENCE  
# ══════════════════════════════════════════════════════════════

## PROMPT W3-1: Mutation Agent
Build MutationAgent class inheriting from BaseAgent.

The run(state) method should:
1. Filter attack_results from state where score > PARTIAL_THRESHOLD
2. For each successful attack, call get_top_attacks() from KnowledgeBase
3. For each attack generate 5 mutations using these strategies 
   (implement each as a separate private async method):
   
   _semantic_rephrase(payload) — reword while preserving intent using call_openai()
   _role_injection(payload) — prepend a role-setting persona prefix
   _context_extension(payload) — add fictional/hypothetical framing
   _encoding_obfuscation(payload) — base64 or leetspeak encode key phrases
   _language_switch(payload) — translate payload to another language then back
   
4. Store each mutation in KnowledgeBase mutation_lineage with 
   parent_attack_id and generation = state["iteration"] + 1
5. Broadcast MutationOccurredEvent via WebSocket for each mutation
6. Return updated state with new attack payloads list and 
   iteration incremented by 1

Import MAX_MUTATIONS_PER_ATTACK and all thresholds from constants.py.


# ══════════════════════════════════════════════════════════════
# WEEK 4 — EXPAND DOMAINS + MULTI-COMPONENT
# ══════════════════════════════════════════════════════════════

## PROMPT W4-1: Domain Selector
Build a DomainLibrary class in domains/domain_library.py that:
1. Loads all template JSON files from domains/templates/ on init
2. Has a get_domains_for_component(component_type) method that returns 
   an ordered list of AttackDomain constants appropriate for that component type
   (e.g. LLM_MODEL gets prompt_injection first, RAG gets rag_poisoning first)
3. Has a get_templates(domain) method returning the full template list
4. Has a get_template_by_id(domain, template_id) method

Use ComponentType and AttackDomain constants from constants.py.
Load JSON files once at init, cache in memory dict.

---

## PROMPT W4-2: Multi-Component Orchestrator Update
Update the existing LangGraph orchestrator in agents/orchestrator.py to:

1. After each domain completes (attack + mutation loop done):
   - Move to next domain for current component
   - If all domains done: log ComponentCompleteEvent, move to next component
   
2. After each component completes:
   - Store cross-component summary in KnowledgeBase
   - Pass top 3 findings as context into next component's attack state
     so Attack Agent is aware of patterns from previous components
   
3. Add a progress tracker that broadcasts after each domain:
   { completed_domains, total_domains, completed_components, 
     total_components, current_phase }

4. Stopping conditions:
   - state.critical_halt == True → skip to report_node immediately
   - All components done → proceed to report_node
   - Max iteration limit hit on any domain → move to next domain

Import all constants from constants.py. Never hardcode numbers.


# ══════════════════════════════════════════════════════════════
# WEEK 5 — REPORT AGENT
# ══════════════════════════════════════════════════════════════

## PROMPT W5-1: Report Agent
Build ReportAgent class inheriting from BaseAgent.

The run(state) method should:
1. Query KnowledgeBase for all vulnerabilities for this scan_id
2. Group by component, then by severity using Severity constants
3. Map sentinel_score to CVSS v3.1 using cvss Python library 
   and REPORT_CVSS_MAP from constants.py
4. Call call_claude() to generate these text sections with specific prompts:
   - Executive summary: 3 paragraphs, non-technical, risk-focused, 
     written for a CTO/CEO audience
   - Per-component findings: technical details with attack evidence
   - Remediation roadmap: prioritized by severity with concrete steps
5. Build PDF using ReportLab with sections:
   Cover page → Executive Summary → Risk Heatmap Table → 
   Per-Component Findings → Remediation Roadmap → Appendix
6. Save PDF to /reports/{scan_id}.pdf
7. Output JSON version to /reports/{scan_id}.json for Autopatch Agent
8. Return updated state with report_path and report_json

Import all constants from constants.py.


# ══════════════════════════════════════════════════════════════
# WEEK 6 — LIVE WAR ROOM DASHBOARD
# ══════════════════════════════════════════════════════════════

## PROMPT W6-1: React War Room Dashboard
Build a React component called WarRoom.jsx using TailwindCSS and shadcn/ui.

Dark theme throughout (#0f172a background, #1e293b panels).

5 panels layout:

PANEL 1 - Infrastructure Map (top left, 40% width):
D3.js force-directed graph. Nodes = components, colored by status:
  grey=#64748b (untested), yellow=#f59e0b (testing), 
  red=#ef4444 (vulnerable), green=#22c55e (clean)
Edges show attack paths. Node size based on priority_score.

PANEL 2 - Live Attack Feed (top right, 60% width):
Scrolling list of last 20 AttackExecutedEvents.
Each row: domain badge (color coded) | component name | score bar 0-1
Score bar color: green < 0.4, yellow 0.4-0.7, red > 0.7

PANEL 3 - Agent Status Bar (full width strip):
5 agent cards. Active agent shows pulsing blue ring + current action text.
Inactive agents show grey. Completed agents show green checkmark.

PANEL 4 - Severity Heatmap (bottom left):
Grid: rows = components, columns = domains.
Cell color = max score found. Empty = not tested yet.

PANEL 5 - Score Trend Chart (bottom right):
Recharts LineChart. X axis = iteration number, Y axis = avg success score.
One line per domain. Shows mutation improvement over iterations.

Connect WebSocket to /ws/scan/{scanId}.
Use Zustand store with actions for each WSEvent type.
Reconnect automatically if WebSocket drops.


# ══════════════════════════════════════════════════════════════
# WEEK 7 — AUTOPATCH AGENT + CLIENT PORTAL
# ══════════════════════════════════════════════════════════════

## PROMPT W7-1: Autopatch Agent
Build AutopatchAgent class inheriting from BaseAgent.

The run(state) method should:
1. Load report JSON from state["report_json"]
2. Filter to only client-approved finding IDs from state["approved_findings"]
   NEVER process unapproved findings — this is a hard security requirement
3. For each approved finding determine PatchType:
   - Config patches (prompt injection, system prompt issues): 
     use call_claude() to generate updated system prompt with guardrails
     return as string with explanation
   - Code patches (backend, API vulnerabilities):
     use call_claude() to generate fix code
     use PyGithub to:
       create branch: sentinel/patch-{finding_id}
       commit the fix with detailed commit message
       open PR with full vulnerability description
4. Return patch_summary: list of {finding_id, patch_type, status, pr_url}

Import PatchType from constants.py.
Log every action with self.log_action().
If GitHub API fails, save patch to file and flag for manual review.

---

## PROMPT W7-2: Client Onboarding Flow
Build a React multi-step onboarding form (no HTML form tags, use div + onClick).

Step 1 — Company Info: name, email, company name, role
Step 2 — Infrastructure Manifest: 
  Dynamic form to add components one by one.
  Each component: type (dropdown from ComponentType values), 
  endpoint URL, framework (text), notes
Step 3 — Scope Agreement:
  Checkbox list of what is authorized to test
  Date range picker for authorized testing window
  Digital signature field (typed name)
Step 4 — Review & Submit

On submit: POST to /scans with full manifest + consent data.
Redirect to WarRoom with returned scan_id.
Use React Router, Zustand, TailwindCSS, shadcn/ui.


# ══════════════════════════════════════════════════════════════
# WEEK 8 — TESTING
# ══════════════════════════════════════════════════════════════

## PROMPT W8-1: Full Test Suite
Write a pytest test suite covering:

1. Unit tests for each agent with mocked LLM calls using pytest-mock:
   - ReconAgent: mock httpx, verify component profile structure
   - AttackAgent: mock LLM call, verify scoring and ChromaDB logging
   - MutationAgent: verify 5 mutation strategies each produce 
     semantically different output
   - ReportAgent: mock Claude, verify PDF and JSON are generated
   - AutopatchAgent: verify unapproved findings are NEVER processed

2. ChromaDB isolation test:
   Insert 10 records under client_id="client_A"
   Query with client_id="client_B"
   Assert zero results returned — this test must never fail

3. WebSocket integration test using pytest-asyncio:
   Connect test client to /ws/scan/{scan_id}
   Trigger a mock scan event
   Assert event received within 500ms

4. Full pipeline integration test:
   Run complete Recon → Attack → Mutate pipeline against 
   local Ollama endpoint
   Verify all results logged to ChromaDB
   Verify iteration 2 has higher average score than iteration 1

Import all constants from constants.py in test assertions.
Never hardcode expected values — use constants.
