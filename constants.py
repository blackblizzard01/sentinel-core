# constants.py
# ============================================================
# SENTINEL AI — SHARED CONSTANTS
# Every value used across more than one file lives here.
# NEVER hardcode these values anywhere else in the codebase.
# Import like: from constants import MAX_ITERATIONS
# ============================================================

import os
from dotenv import load_dotenv

load_dotenv()

# ─── SCAN SETTINGS ───────────────────────────────────────────
MAX_ITERATIONS           = 3      # Max mutation loops per domain
SUCCESS_THRESHOLD        = 0.7    # Score above this = confirmed vulnerability
PARTIAL_THRESHOLD        = 0.4    # Score above this = feed to mutation agent
CRITICAL_THRESHOLD       = 0.9    # Score above this = immediate halt + alert
MAX_ATTACKS_PER_DOMAIN   = 20     # Max attack attempts per domain per component
ATTACK_RATE_LIMIT        = 1.0    # Seconds between attack executions (DoS prevention)
MAX_MUTATIONS_PER_ATTACK = 5      # Variants generated per successful attack
TOP_K_RETRIEVAL          = 5      # Top-k similar attacks retrieved from Vector KB
WEBSOCKET_REPLAY_LIMIT   = 50     # Events replayed on dashboard reconnect

# ─── SCAN STATUS ─────────────────────────────────────────────
class ScanStatus:
    PENDING   = "pending"
    ACTIVE    = "active"
    PAUSED    = "paused"
    COMPLETED = "completed"
    HALTED    = "halted"    # Critical vulnerability found — scan stopped
    FAILED    = "failed"

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
    LLM_MODEL = "llm_model"
    RAG       = "rag_pipeline"
    API       = "api_layer"
    CODEBASE  = "codebase"
    DATABASE  = "database"
    FRONTEND  = "frontend"
    BACKEND   = "backend"
    NETWORK   = "network"

# ─── ATTACK DOMAINS ──────────────────────────────────────────
class AttackDomain:
    PROMPT_INJECTION      = "prompt_injection"
    RAG_POISONING         = "rag_poisoning"
    API_ATTACKS           = "api_attacks"
    INDIRECT_INJECTION    = "indirect_injection"
    SYSTEM_PROMPT_EXTRACT = "system_prompt_extraction"
    INTER_AGENT_TRUST     = "inter_agent_trust"

DOMAIN_LIST = [
    AttackDomain.PROMPT_INJECTION,
    AttackDomain.RAG_POISONING,
    AttackDomain.API_ATTACKS,
    AttackDomain.INDIRECT_INJECTION,
    AttackDomain.SYSTEM_PROMPT_EXTRACT,
    AttackDomain.INTER_AGENT_TRUST,
]

# Domain to component type mapping
# Defines which domains apply to which component types
DOMAIN_COMPONENT_MAP = {
    ComponentType.LLM_MODEL: [
        AttackDomain.PROMPT_INJECTION,
        AttackDomain.SYSTEM_PROMPT_EXTRACT,
        AttackDomain.INTER_AGENT_TRUST,
    ],
    ComponentType.RAG: [
        AttackDomain.RAG_POISONING,
        AttackDomain.INDIRECT_INJECTION,
        AttackDomain.PROMPT_INJECTION,
    ],
    ComponentType.API: [
        AttackDomain.API_ATTACKS,
        AttackDomain.INDIRECT_INJECTION,
    ],
    ComponentType.BACKEND: [
        AttackDomain.API_ATTACKS,
        AttackDomain.INDIRECT_INJECTION,
        AttackDomain.INTER_AGENT_TRUST,
    ],
    ComponentType.FRONTEND: [
        AttackDomain.INDIRECT_INJECTION,
        AttackDomain.PROMPT_INJECTION,
    ],
    ComponentType.DATABASE: [
        AttackDomain.API_ATTACKS,
        AttackDomain.RAG_POISONING,
    ],
    ComponentType.CODEBASE: [
        AttackDomain.INDIRECT_INJECTION,
        AttackDomain.API_ATTACKS,
    ],
    ComponentType.NETWORK: [
        AttackDomain.API_ATTACKS,
    ],
}

# ─── SEVERITY LEVELS ─────────────────────────────────────────
class Severity:
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    NONE     = "none"

# Reference table for documentation purposes only.
# DO NOT use this dict directly for score lookups —
# use get_severity_from_score() below which handles
# floating point edge cases correctly.
SCORE_TO_SEVERITY = {
    (0.9, 1.0):  Severity.CRITICAL,
    (0.7, 0.89): Severity.HIGH,
    (0.4, 0.69): Severity.MEDIUM,
    (0.1, 0.39): Severity.LOW,
    (0.0, 0.09): Severity.NONE,
}

def get_severity_from_score(score: float) -> str:
    """
    Convert a float attack score to a Severity constant string.
    Uses threshold-based logic to avoid floating point gap issues.

    Args:
        score: Float between 0.0 and 1.0

    Returns:
        Severity constant string
    """
    if score >= CRITICAL_THRESHOLD:       # >= 0.9
        return Severity.CRITICAL
    elif score >= SUCCESS_THRESHOLD:      # >= 0.7
        return Severity.HIGH
    elif score >= PARTIAL_THRESHOLD:      # >= 0.4
        return Severity.MEDIUM
    elif score >= 0.1:
        return Severity.LOW
    else:
        return Severity.NONE

# ─── CHROMADB COLLECTIONS ────────────────────────────────────
class ChromaCollection:
    ATTACK_HISTORY        = "attack_history"
    SUCCESSFUL_ATTACKS    = "successful_attacks"
    MUTATION_LINEAGE      = "mutation_lineage"
    COMPONENT_PROFILES    = "component_profiles"
    VULNERABILITY_CATALOG = "vulnerability_catalog"

CHROMA_COLLECTIONS = [
    ChromaCollection.ATTACK_HISTORY,
    ChromaCollection.SUCCESSFUL_ATTACKS,
    ChromaCollection.MUTATION_LINEAGE,
    ChromaCollection.COMPONENT_PROFILES,
    ChromaCollection.VULNERABILITY_CATALOG,
]

# ─── LLM MODELS ──────────────────────────────────────────────
class LLMModel:
    # Groq hosted (free — console.groq.com)
    LLAMA_70B    = "llama-3.1-70b-versatile"   # Main attack + recon model
    LLAMA_8B     = "llama-3.1-8b-instant"       # Fast lightweight tasks
    QWEN_72B     = "qwen-2.5-72b-instruct"      # Mutation agent (replaces GPT-4o mini)

    # Google Gemini (free — aistudio.google.com)
    GEMINI_FLASH = "gemini-3.5-flash"       # Updated from 1.5-flash
    GEMINI_PRO   = "gemini-3.1-pro-preview" # Updated from 1.5-pro
    GEMINI       = GEMINI_FLASH            # Alias used by BaseAgent

    # DeepSeek (free credits — platform.deepseek.com)
    DEEPSEEK_CHAT = "deepseek-chat"            # MutationAgent (OpenAI-compatible API)
    DEEPSEEK        = "deepseek-chat"           # Backup for code generation

    # Anthropic (optional — save for final demo only)
    CLAUDE_SONNET = "claude-sonnet-4-20250514"

    # Local via Ollama (completely free, no API needed)
    MISTRAL_LOCAL = "mistral"

# ─── AGENT MODEL ASSIGNMENTS ─────────────────────────────────
# Change model per agent here — propagates everywhere automatically
AGENT_MODELS = {
    AgentName.RECON:      LLMModel.LLAMA_70B,    # Fast recon probing
    AgentName.ATTACK:     LLMModel.LLAMA_70B,    # High volume attack generation
    AgentName.MUTATION:   LLMModel.DEEPSEEK_CHAT, # Creative mutation via DeepSeek
    AgentName.REPORT:     LLMModel.GEMINI_FLASH, # Report generation (free)
    AgentName.AUTOPATCH:  LLMModel.GEMINI_FLASH, # Code patch generation (free)
}

# Fallback model if primary fails
AGENT_FALLBACK_MODELS = {
    AgentName.RECON:      LLMModel.LLAMA_8B,
    AgentName.ATTACK:     LLMModel.MISTRAL_LOCAL,
    AgentName.MUTATION:   LLMModel.MISTRAL_LOCAL,
    AgentName.REPORT:     LLMModel.DEEPSEEK,
    AgentName.AUTOPATCH:  LLMModel.DEEPSEEK,
}

# ─── API KEY ROTATION ────────────────────────────────────────
# Collect all filled-in keys per provider.
# Code rotates through them automatically when one hits rate limits.
# Each teammate adds their own key in .env under their numbered slot.

def _load_keys(prefix: str) -> list[str]:
    """Load all filled API keys for a given prefix from environment."""
    keys = []
    for i in range(1, 6):
        key = os.getenv(f"{prefix}_{i}")
        if key and "paste" not in key.lower() and len(key) > 10:
            keys.append(key)
    return keys

GROQ_KEYS    = _load_keys("GROQ_API_KEY")
GEMINI_KEYS  = _load_keys("GEMINI_API_KEY")
DEEPSEEK_KEYS = _load_keys("DEEPSEEK_API_KEY")

def get_next_key(keys: list[str], attempt: int) -> str:
    """
    Rotate through available API keys based on attempt count.
    Prevents single key from hitting rate limits.

    Args:
        keys: List of available API keys
        attempt: Current attempt number (used for rotation)

    Returns:
        Next API key to use
    """
    if not keys:
        raise ValueError("No API keys available. Check your .env file.")
    return keys[attempt % len(keys)]

# ─── EMBEDDING MODEL ─────────────────────────────────────────
EMBEDDING_MODEL      = "all-MiniLM-L6-v2"   # Local, free, runs on CPU
EMBEDDING_DIMENSIONS = 384                   # Dimensions for all-MiniLM-L6-v2

# ─── CHROMADB CONNECTION ─────────────────────────────────────
CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8001"))

# ─── WEBSOCKET EVENT TYPES ───────────────────────────────────
class WSEvent:
    AGENT_STARTED       = "agent_started"
    ATTACK_EXECUTED     = "attack_executed"
    MUTATION_OCCURRED   = "mutation_occurred"
    VULNERABILITY_FOUND = "vulnerability_found"
    COMPONENT_COMPLETE  = "component_complete"
    SCAN_COMPLETE       = "scan_complete"
    CRITICAL_HALT       = "critical_halt"
    PROGRESS_UPDATE     = "progress_update"

# ─── PATCH TYPES ─────────────────────────────────────────────
class PatchType:
    CONFIG = "config_patch"  # Automated — system prompt guardrails
    CODE   = "code_patch"    # PR generated — human reviews before merge

# ─── REPORT SETTINGS ─────────────────────────────────────────
REPORT_CVSS_MAP = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH:     (7.0, 8.9),
    Severity.MEDIUM:   (4.0, 6.9),
    Severity.LOW:      (0.1, 3.9),
    Severity.NONE:     (0.0, 0.0),
}

# ─── VALIDATION ──────────────────────────────────────────────
def validate_environment() -> dict[str, bool]:
    """
    Validate that all required environment variables are set.
    Call this on application startup in backend/main.py.

    Returns:
        Dict of variable name to whether it is set correctly
    """
    checks = {
        "GROQ_KEYS":     len(GROQ_KEYS) > 0,
        "GEMINI_KEYS":   len(GEMINI_KEYS) > 0,
        "DATABASE_URL":  bool(os.getenv("DATABASE_URL") and "paste" not in str(os.getenv("DATABASE_URL"))),
        "REDIS_URL":     bool(os.getenv("REDIS_URL") and "paste" not in str(os.getenv("REDIS_URL"))),
        "SECRET_KEY":    bool(os.getenv("JWT_SECRET") and len(str(os.getenv("JWT_SECRET"))) >= 16),
        "GITHUB_TOKEN":  bool(os.getenv("GITHUB_TOKEN") and "paste" not in str(os.getenv("GITHUB_TOKEN"))),
    }
    missing = [k for k, v in checks.items() if not v]
    if missing:
        import logging
        logging.warning(f"[Sentinel] Missing or invalid env vars: {missing}")
    return checks
