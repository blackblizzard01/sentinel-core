# constants.py
# ============================================================
# SENTINEL AI — SHARED CONSTANTS
# Every value used across more than one file lives here.
# NEVER hardcode these values anywhere else in the codebase.
# Import like: from constants import MAX_ITERATIONS
# ============================================================

# ─── SCAN SETTINGS ───────────────────────────────────────────
MAX_ITERATIONS          = 3       # Max mutation loops per domain
SUCCESS_THRESHOLD       = 0.7     # Score above this = confirmed vulnerability
PARTIAL_THRESHOLD       = 0.4     # Score above this = feed to mutation agent
CRITICAL_THRESHOLD      = 0.9     # Score above this = immediate halt + alert
MAX_ATTACKS_PER_DOMAIN  = 20      # Max attack attempts per domain per component
ATTACK_RATE_LIMIT       = 1.0     # Seconds between attack executions (DoS prevention)
MAX_MUTATIONS_PER_ATTACK = 5      # Variants generated per successful attack
TOP_K_RETRIEVAL         = 5       # Top-k similar attacks retrieved from Vector KB
WEBSOCKET_REPLAY_LIMIT  = 50      # Events replayed on dashboard reconnect

# ─── SCAN STATUS ─────────────────────────────────────────────
class ScanStatus:
    PENDING    = "pending"
    ACTIVE     = "active"
    PAUSED     = "paused"
    COMPLETED  = "completed"
    HALTED     = "halted"    # Critical vulnerability found
    FAILED     = "failed"

# ─── AGENT NAMES ─────────────────────────────────────────────
class AgentName:
    RECON      = "recon_agent"
    ATTACK     = "attack_agent"
    MUTATION   = "mutation_agent"
    REPORT     = "report_agent"
    AUTOPATCH  = "autopatch_agent"

# ─── SCAN PHASES ─────────────────────────────────────────────
class ScanPhase:
    RECON      = "recon"
    ATTACKING  = "attacking"
    MUTATING   = "mutating"
    REPORTING  = "reporting"
    PATCHING   = "patching"
    DONE       = "done"

# ─── COMPONENT TYPES ─────────────────────────────────────────
class ComponentType:
    LLM_MODEL  = "llm_model"
    RAG        = "rag_pipeline"
    API        = "api_layer"
    CODEBASE   = "codebase"
    DATABASE   = "database"
    FRONTEND   = "frontend"
    BACKEND    = "backend"
    NETWORK    = "network"

# ─── ATTACK DOMAINS ──────────────────────────────────────────
class AttackDomain:
    PROMPT_INJECTION       = "prompt_injection"
    RAG_POISONING          = "rag_poisoning"
    API_ATTACKS            = "api_attacks"
    INDIRECT_INJECTION     = "indirect_injection"
    SYSTEM_PROMPT_EXTRACT  = "system_prompt_extraction"
    INTER_AGENT_TRUST      = "inter_agent_trust"

DOMAIN_LIST = [
    AttackDomain.PROMPT_INJECTION,
    AttackDomain.RAG_POISONING,
    AttackDomain.API_ATTACKS,
    AttackDomain.INDIRECT_INJECTION,
    AttackDomain.SYSTEM_PROMPT_EXTRACT,
    AttackDomain.INTER_AGENT_TRUST,
]

# ─── SEVERITY LEVELS ─────────────────────────────────────────
class Severity:
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    NONE     = "none"

SCORE_TO_SEVERITY = {
    (0.9, 1.0):  Severity.CRITICAL,
    (0.7, 0.89): Severity.HIGH,
    (0.4, 0.69): Severity.MEDIUM,
    (0.1, 0.39): Severity.LOW,
    (0.0, 0.09): Severity.NONE,
}

# ─── CHROMADB COLLECTIONS ────────────────────────────────────
class ChromaCollection:
    ATTACK_HISTORY       = "attack_history"
    SUCCESSFUL_ATTACKS   = "successful_attacks"
    MUTATION_LINEAGE     = "mutation_lineage"
    COMPONENT_PROFILES   = "component_profiles"
    VULNERABILITY_CATALOG = "vulnerability_catalog"

CHROMA_COLLECTIONS = [
    ChromaCollection.ATTACK_HISTORY,
    ChromaCollection.SUCCESSFUL_ATTACKS,
    ChromaCollection.MUTATION_LINEAGE,
    ChromaCollection.COMPONENT_PROFILES,
    ChromaCollection.VULNERABILITY_CATALOG,
]

# ─── MODELS ──────────────────────────────────────────────────
class LLMModel:
    # Groq hosted
    LLAMA_70B        = "llama-3.1-70b-versatile"
    LLAMA_8B         = "llama-3.1-8b-instant"
    # Anthropic
    CLAUDE_SONNET    = "claude-sonnet-4-20250514"
    # OpenAI
    GPT4O_MINI       = "gpt-4o-mini"
    # Local via Ollama
    MISTRAL_LOCAL    = "mistral"

# Model assignment per agent — change here to change everywhere
AGENT_MODELS = {
    AgentName.RECON:     LLMModel.LLAMA_70B,
    AgentName.ATTACK:    LLMModel.LLAMA_70B,
    AgentName.MUTATION:  LLMModel.GPT4O_MINI,
    AgentName.REPORT:    LLMModel.CLAUDE_SONNET,
    AgentName.AUTOPATCH: LLMModel.CLAUDE_SONNET,
}

# ─── EMBEDDING MODEL ─────────────────────────────────────────
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# ─── WEBSOCKET EVENT TYPES ───────────────────────────────────
class WSEvent:
    AGENT_STARTED        = "agent_started"
    ATTACK_EXECUTED      = "attack_executed"
    MUTATION_OCCURRED    = "mutation_occurred"
    VULNERABILITY_FOUND  = "vulnerability_found"
    COMPONENT_COMPLETE   = "component_complete"
    SCAN_COMPLETE        = "scan_complete"
    CRITICAL_HALT        = "critical_halt"

# ─── PATCH TYPES ─────────────────────────────────────────────
class PatchType:
    CONFIG = "config_patch"   # Automated — system prompt guardrails
    CODE   = "code_patch"     # PR generated — human reviews before merge

# ─── REPORT SETTINGS ─────────────────────────────────────────
REPORT_CVSS_MAP = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH:     (7.0, 8.9),
    Severity.MEDIUM:   (4.0, 6.9),
    Severity.LOW:      (0.1, 3.9),
    Severity.NONE:     (0.0, 0.0),
}
