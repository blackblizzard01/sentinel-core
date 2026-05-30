# Sentinel AI — Dummy Target

## Purpose

This is a deliberately vulnerable FastAPI test target for Sentinel AI attack agents during local development. It exposes intentional weaknesses (prompt injection, RAG poisoning, API key bypass) so agents can be exercised safely against a known surface. Use it on your machine only — never deploy it to production.

## Prerequisites

- Python 3.11+
- Ollama installed and Mistral pulled

## Quick Start

### 1. Pull Mistral

```bash
ollama pull mistral
```

### 2. Start Ollama (keep this terminal open)

```bash
ollama serve
```

### 3. Start the dummy target (run from project root)

```bash
uvicorn dummy_target.app:app --host 0.0.0.0 --port 8001 --reload
```

### 4. Verify it's running

```bash
curl http://localhost:8001/health
```

## Endpoints

| Method | Path       | Auth          | Description                       |
|--------|------------|---------------|-----------------------------------|
| POST   | /chat      | None          | LLM chat — secret in system prompt|
| POST   | /rag/query | None          | Simulated RAG pipeline            |
| GET    | /api/data  | x-api-key hdr | Fake protected data API           |
| GET    | /health    | None          | Health check                      |

## Intentional Vulnerabilities

| Endpoint   | Vulnerability                                | Sentinel Domain              |
|------------|----------------------------------------------|------------------------------|
| /chat      | Secret phrase in system prompt               | system_prompt_extraction     |
| /chat      | No input sanitisation                        | prompt_injection             |
| /rag/query | Embedded injection string in doc_001         | rag_poisoning                |
| /rag/query | Retrieved content passed raw to LLM          | indirect_injection           |
| /api/data  | Hardcoded key + case-insensitive compare     | api_attacks                  |

## Interactive Docs

http://localhost:8001/docs
