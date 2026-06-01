# SENTINEL AI — PROJECT BIBLE
# ============================================================
# VERSION: 1.0
# PURPOSE: Paste this entire document into a fresh Claude chat
# before asking for ANYTHING. This gives Claude full context
# to generate prompts consistent with the entire system.
# ============================================================

---

## SECTION 1 — WHAT WE ARE BUILDING

Sentinel AI is a multi-agent autonomous AI infrastructure security 
testing platform. Clients give us authorized, consent-based access 
to their full AI stack. Our system tests it component by component, 
learns from results, evolves attacks, generates vulnerability reports, 
and applies patches — all automated, all visible live on a war room 
dashboard.

This is AI penetration testing as a service. Like Burp Suite but 
for LLMs and AI infrastructure. Authorized. Automated. Full stack.

---

## SECTION 2 — THE FIVE AGENTS

Every agent is a Python class inheriting from BaseAgent 
in agents/base_agent.py. Every agent communicates through 
the LangGraph state object and ChromaDB. Never directly.

### Agent 1: ReconAgent
- File: agents/recon_agent.py
- Purpose: Maps the client's full AI attack surface
- Input: Client infrastructure manifest (list of endpoints)
- Actions: HTTP probe each endpoint, detect framework, 
  fingerprint model type, assign priority score 1-10
- Output: Structured component map stored in ChromaDB 
  component_profiles collection
- Model: Groq Llama 3.1 70B

### Agent 2: AttackAgent
- File: agents/attack_agent.py
- Purpose: Executes domain-specific attacks on each component
- Input: Component spec, attack domain, templates from DomainLibrary,
  past successful attacks retrieved from ChromaDB
- Actions: Load templates, execute attacks via httpx, score responses 
  0.0-1.0, log every attempt to ChromaDB attack_history
- Output: attack_results list in state, all attempts in ChromaDB
- Model: Groq Llama 3.1 70B
- Rate limit: ATTACK_RATE_LIMIT seconds between each attack

### Agent 3: MutationAgent
- File: agents/mutation_agent.py
- Purpose: Learns from successful attacks and evolves new variants
- Input: attack_results from state, top-k similar attacks from ChromaDB
- Mutation strategies: semantic_rephrase, role_injection, 
  context_extension, encoding_obfuscation, language_switch
- Output: New evolved attack payloads batch, mutation lineage in ChromaDB
- Model: DeepSeek

### Agent 4: ReportAgent
- File: agents/report_agent.py
- Purpose: Generates structured vulnerability report
- Input: All findings from ChromaDB vulnerability_catalog
- Output: PDF report + JSON report
- Report sections: Executive Summary, Risk Heatmap, 
  Per-Component Findings, Remediation Roadmap
- Model: Google Gemini

### Agent 5: AutopatchAgent
- File: agents/autopatch_agent.py
- Purpose: Applies remediation after client approval
- Input: Approved finding IDs + JSON report
- NEVER patches without approved_findings check
- Config patches: updated system prompts with guardrails
- Code patches: GitHub PR via PyGithub
- Model: Google Gemini

---

## SECTION 3 — THE ORCHESTRATOR

- File: agents/orchestrator.py
- Built with: LangGraph state machine
- Entry point: async run_scan(client_id, scan_id)

### State Object (TypedDict)
```
client_id: str
scan_id: str
current_component_index: int
current_component: dict
current_domain_index: int
current_domain: str
attack_results: list
iteration: int
phase: str          # use ScanPhase constants
logs: list[str]
critical_halt: bool
components: list
approved_findings: list
report_path: str
report_json: dict
```

### Flow
```
recon_node 
  → attack_node 
  → [if iteration < MAX_ITERATIONS and not critical_halt] mutation_node → attack_node
  → [if all iterations done] next domain
  → [if all domains done] next component
  → [if all components done] report_node
  → autopatch_node
```

### Stopping Conditions
- critical_halt == True → skip to report_node immediately
- All components tested → proceed to report_node
- Max iteration limit hit on domain → move to next domain

---

## SECTION 4 — SHARED VECTOR KNOWLEDGE BASE

- File: knowledge_base/knowledge_base.py
- Technology: ChromaDB (local via pip)
- Embeddings: sentence-transformers all-MiniLM-L6-v2 (local, free)

### Collections (from ChromaCollection constants)
```
attack_history        - every attack attempt ever made
successful_attacks    - attacks scoring above SUCCESS_THRESHOLD
mutation_lineage      - family tree of evolved attacks
component_profiles    - recon output per component
vulnerability_catalog - confirmed vulnerabilities with CVSS scores
```

### CRITICAL RULE
Every single ChromaDB query MUST include:
where={"client_id": client_id}
No exceptions. Client data must never leak across clients.

### Key Methods
```
log_attack(client_id, scan_id, component_id, domain, 
           payload, response, score, timestamp)
get_top_attacks(client_id, domain, component_type, k=5)
log_mutation(client_id, parent_attack_id, child_payload,
             strategy, child_score, generation)
log_vulnerability(client_id, scan_id, component_id,
                  domain, score, severity, description)
```

---

## SECTION 5 — ATTACK DOMAIN LIBRARY

- Files: domains/domain_library.py + domains/templates/*.json
- Class: DomainLibrary

### Domain Templates (JSON files in domains/templates/)
```
prompt_injection.json       - 20 templates
rag_poisoning.json          - 15 templates
api_attacks.json            - 15 templates
indirect_injection.json     - 12 templates
system_prompt_extraction.json - 10 templates
```

### Each Template Structure
```json
{
  "id": "domain_001",
  "name": "descriptive name",
  "template": "attack string with {target} and {context}",
  "expected_indicators": ["string1", "string2"],
  "severity_potential": "critical|high|medium",
  "domain": "domain_name"
}
```

### Domain to Component Mapping
```
LLM_MODEL  → prompt_injection, system_prompt_extraction
RAG        → rag_poisoning, indirect_injection
API        → api_attacks
BACKEND    → api_attacks, indirect_injection
FRONTEND   → indirect_injection
DATABASE   → api_attacks
```

---

## SECTION 6 — COMPLETE TECH STACK

### Backend
```
Language:      Python 3.11
Framework:     FastAPI (async)
Agents:        LangGraph (orchestration) + CrewAI (role abstraction)
Task Queue:    Celery + Redis (via Upstash, free tier)
Database:      PostgreSQL (via Supabase, free tier)
ORM:           SQLAlchemy 2.0 async + Alembic migrations
HTTP Client:   httpx (async)
Validation:    Pydantic v2
Auth:          JWT via python-jose + passlib
```

### LLM Models Per Agent
```
ReconAgent:     Groq — llama-3.1-70b-versatile
AttackAgent:    Groq — llama-3.1-70b-versatile
MutationAgent:  DeepSeek
ReportAgent:    Google Gemini
AutopatchAgent: Google Gemini
Local/Offline:  Ollama — mistral (runs on localhost)
```

### Vector & Embeddings
```
Vector DB:      ChromaDB (pip install chromadb, runs in-process)
Embeddings:     sentence-transformers all-MiniLM-L6-v2 (local, free)
```

### Frontend
```
Framework:   React 18 + Vite
Styling:     TailwindCSS
State:       Zustand
Charts:      Recharts
Graph:       D3.js force-directed layout
Components:  shadcn/ui
Real-time:   Native WebSocket API
Routing:     React Router v6
```

### Infrastructure
```
Backend host:   Railway (free tier for MVP)
Frontend host:  Vercel (free tier)
PostgreSQL:     Supabase (free tier)
Redis:          Upstash (free tier)
Secrets:        .env file (gitignored, .env.example as template)
                Numbered key slots: GROQ_API_KEY_1…_5, GEMINI_API_KEY_1…_5,
                DEEPSEEK_API_KEY_1…_N. Single unnumbered vars accepted as fallback.
CI/CD:          GitHub Actions
Monitoring:     Sentry (free tier)
```

---

## SECTION 7 — FOLDER STRUCTURE

```
sentinel-core/
├── backend/
│   ├── __init__.py
│   ├── main.py              # FastAPI app + WebSocket
│   ├── models.py            # SQLAlchemy DB models
│   ├── schemas/             # Pydantic schemas
│   │   └── events.py        # WebSocket event schemas
│   └── routers/
│       └── scans.py         # Scan endpoints
├── agents/
│   ├── __init__.py  
│   ├── api_key_manager.py   # Round-robin key rotation, thread-safe
│   ├── base_agent.py        # BaseAgent — all agents inherit this
│   ├── orchestrator.py      # LangGraph state machine
│   ├── recon_agent.py
│   ├── attack_agent.py
│   ├── mutation_agent.py
│   ├── report_agent.py
│   └── autopatch_agent.py
├── knowledge_base/
│   ├── __init__.py
│   ├── chroma_client.py     # ChromaDB singleton
│   └── knowledge_base.py    # KnowledgeBase class
├── domains/
│   ├── domain_library.py    # DomainLibrary class
│   └── templates/           # JSON attack template files
│       ├── prompt_injection.json
│       ├── rag_poisoning.json
│       ├── api_attacks.json
│       ├── indirect_injection.json
│       └── system_prompt_extraction.json
├── dummy_target/
│   └── app.py               # Vulnerable test app for development
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── WarRoom.jsx
│       │   ├── InfrastructureMap.jsx
│       │   ├── AttackFeed.jsx
│       │   ├── AgentStatusBar.jsx
│       │   ├── SeverityHeatmap.jsx
│       │   └── ScoreChart.jsx
│       ├── store/
│       │   └── scanStore.js
│       └── hooks/
│           └── useWebSocket.js
├── tests/
│   ├── __init__.py
│   ├── test_week1_smoke.py
│   └── test_base_agent.py
├── constants.py             # ALL shared constants
├── .cursorrules             # Cursor project rules
├── .env.example             # Environment variable template
├── .gitignore
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## SECTION 8 — CONSTANTS (ACTUAL VALUES)

These are the real values from constants.py.
Never hardcode these — always import from constants.py.

```python
MAX_ITERATIONS          = 3
SUCCESS_THRESHOLD       = 0.7
PARTIAL_THRESHOLD       = 0.4
CRITICAL_THRESHOLD      = 0.9
MAX_ATTACKS_PER_DOMAIN  = 20
ATTACK_RATE_LIMIT       = 1.0
MAX_MUTATIONS_PER_ATTACK = 5
TOP_K_RETRIEVAL         = 5
EMBEDDING_MODEL         = "all-MiniLM-L6-v2"

class ScanStatus:
    PENDING = "pending" | ACTIVE = "active" | PAUSED = "paused"
    COMPLETED = "completed" | HALTED = "halted" | FAILED = "failed"

class AgentName:
    RECON = "recon_agent" | ATTACK = "attack_agent"
    MUTATION = "mutation_agent" | REPORT = "report_agent"
    AUTOPATCH = "autopatch_agent"

class ScanPhase:
    RECON = "recon" | ATTACKING = "attacking" | MUTATING = "mutating"
    REPORTING = "reporting" | PATCHING = "patching" | DONE = "done"

class ComponentType:
    LLM_MODEL = "llm_model" | RAG = "rag_pipeline" | API = "api_layer"
    CODEBASE = "codebase" | DATABASE = "database"
    FRONTEND = "frontend" | BACKEND = "backend" | NETWORK = "network"

class AttackDomain:
    PROMPT_INJECTION = "prompt_injection"
    RAG_POISONING = "rag_poisoning"
    API_ATTACKS = "api_attacks"
    INDIRECT_INJECTION = "indirect_injection"
    SYSTEM_PROMPT_EXTRACT = "system_prompt_extraction"
    INTER_AGENT_TRUST = "inter_agent_trust"

class Severity:
    CRITICAL = "critical" | HIGH = "high"
    MEDIUM = "medium" | LOW = "low" | NONE = "none"

class ChromaCollection:
    ATTACK_HISTORY = "attack_history"
    SUCCESSFUL_ATTACKS = "successful_attacks"
    MUTATION_LINEAGE = "mutation_lineage"
    COMPONENT_PROFILES = "component_profiles"
    VULNERABILITY_CATALOG = "vulnerability_catalog"

class WSEvent:
    AGENT_STARTED = "agent_started"
    ATTACK_EXECUTED = "attack_executed"
    MUTATION_OCCURRED = "mutation_occurred"
    VULNERABILITY_FOUND = "vulnerability_found"
    COMPONENT_COMPLETE = "component_complete"
    SCAN_COMPLETE = "scan_complete"
    CRITICAL_HALT = "critical_halt"

class LLMModel:
    LLAMA_70B = "llama-3.1-70b-versatile"
    GEMINI = "gemini-2.0-flash"
    DEEPSEEK = "deepseek-chat"
    MISTRAL_LOCAL = "mistral"
```

---

## SECTION 9 — DATABASE SCHEMA

### Tables
```
clients        — id, name, email, company, created_at, is_active
consents       — id, client_id(FK), signed_at, scope(JSON), signed_by_email
scans          — id, client_id(FK), consent_id(FK), status, 
                 started_at, completed_at, component_count
components     — id, scan_id(FK), type, endpoint, framework, 
                 priority_score, status
vulnerabilities — id, scan_id(FK), component_id(FK), domain,
                  severity, sentinel_score, cvss_score, 
                  description, remediation, found_at
```

---

## SECTION 10 — WEBSOCKET EVENT SYSTEM

FastAPI server at: /ws/scan/{scan_id}
React client connects on dashboard load.
Backend broadcasts events as JSON in real time.
On reconnect: replay last 50 events.

### Event Schemas (Pydantic)
All events include: scan_id, timestamp, event_type

```
AgentStartedEvent       — agent_name, phase
AttackExecutedEvent     — component_id, domain, payload_preview, 
                          response_preview, score
MutationOccurredEvent   — parent_attack_id, child_attack_id, strategy
VulnerabilityFoundEvent — component_id, domain, severity, description
ComponentCompleteEvent  — component_id, domains_tested, findings_count
ScanCompleteEvent       — total_vulnerabilities, critical_count, 
                          high_count, report_path
CriticalHaltEvent       — component_id, domain, score, reason
```

---

## SECTION 11 — NAMING CONVENTIONS

NEVER deviate from these. Ever.

```
Agent classes:    PascalCase + Agent     ReconAgent, MutationAgent
All classes:      PascalCase             DomainLibrary, KnowledgeBase
Functions:        snake_case             execute_attack, log_result
Async functions:  snake_case             async def run_scan()
Variables:        snake_case             scan_id, client_id
Constants:        UPPER_SNAKE_CASE       MAX_ITERATIONS
Pydantic models:  PascalCase + Schema    AttackResultSchema
ChromaDB colls:   snake_case             attack_history
Env variables:    UPPER_SNAKE_CASE       GROQ_API_KEY
Python files:     snake_case.py          recon_agent.py
React components: PascalCase.jsx         WarRoom.jsx
```

---

## SECTION 12 — CODE RULES

Every single file generated must follow these:

```
1. Every function/class has a docstring
2. Every parameter has a type hint
3. Every function has a return type hint
4. All data structures between agents use Pydantic models
5. All I/O is async/await (HTTP, DB, LLM calls)
6. Never hardcode values — import from constants.py
7. Never hardcode API keys — use os.getenv()
8. All agent classes inherit from BaseAgent
9. All ChromaDB queries filter by client_id — NO EXCEPTIONS
10. Error handling uses try/except with specific exception types
11. Use logging module — never use print()
12. Imports order: stdlib → third party → local
13. Never call os.getenv() for API keys directly — always use ApiKeyManager.acquire_key()
```

---

## SECTION 13 — SECURITY RULES (NON-NEGOTIABLE)

```
1. Every scan requires a valid consent_id in PostgreSQL before starting
2. Scans cannot start unless status is ACTIVE in database
3. All ChromaDB queries include client_id filter
4. AutopatchAgent checks approved_findings list before EVERY patch
5. Client credentials stored encrypted, never plain text
6. No attack executes without valid scan_id and client_id
```

---

## SECTION 14 — BASE AGENT INTERFACE

All agents inherit BaseAgent which provides:

```python
# LLM clients available to every agent
self.groq      # AsyncGroq client
self.gemini    # Google Gemini client
self.deepseek  # DeepSeek client (via AsyncOpenAI-compatible interface)

# Methods available to every agent
async def call_groq(prompt, system, temperature) → str
async def call_gemini(prompt, system, max_tokens) → str
async def call_deepseek(prompt, system, temperature) → str
def log_action(action, detail) → None
def log_error(error, exception) → None

# Properties set on init
self.agent_name  # from AgentName constants
self.client_id   # the authorized client
self.scan_id     # current scan session
self.model       # from AGENT_MODELS dict in constants.py
```
# Key rotation (handled automatically — agents never call this directly)
ApiKeyManager (agents/api_key_manager.py)
  acquire_key(provider)  → str   # round-robin pick on agent init
  rotate(provider)       → str   # advance to next key on rate-limit retry

# Init behavior
- All three LLM clients initialized via ApiKeyManager.acquire_key()
- On RateLimitError: rotates key + rebuilds the affected client automatically
- Logs key pool sizes at startup: groq_keys=5 gemini_keys=5 deepseek_keys=5

# .env key format (required)
GROQ_API_KEY_1=gsk_...        # supports _1 through _N
GEMINI_API_KEY_1=AIza...
DEEPSEEK_API_KEY_1=sk-...
# Unnumbered fallbacks (GROQ_API_KEY=) accepted but not required

---


## HOW TO USE THIS BIBLE

You are the project guide for Sentinel AI.
The full architecture, stack, and conventions are above.

When I ask you for a Cursor prompt, generate it in 
this exact three part format:

---
PART 1 — PRE-CHECK
List everything that must be verified before running 
this prompt. Include exact terminal commands to verify.

PART 2 — CURSOR PROMPT
The complete, detailed prompt to paste into 
Cursor Composer (Ctrl+Shift+I).
Must include:
- Exact file paths for all generated files
- Explicit imports from constants.py
- Type hints on everything
- Docstrings on every class and function
- Specific method signatures
- Error handling requirements
- Logging requirements
Detailed enough that Cursor generates 100% complete 
working code with zero guesswork or missing pieces.

PART 3 — VALIDATION
Exact commands to run after Cursor generates the code.
Must confirm the code works before moving to next task.
---

My task is: [TEAMMATE WRITES THEIR TASK HERE]
