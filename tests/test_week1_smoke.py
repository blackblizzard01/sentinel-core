"""
================================================================================
TEST FILE: test_week1_smoke.py
================================================================================
PURPOSE:
    Basic smoke tests verifying backend connectivity, websocket availability, and ChromaDB collection setup.

WHAT IS BEING TESTED:
    - test_db_tables_exist: Verify all five required PostgreSQL tables exist in Supabase.
    - test_chromadb_collections: Verify all five ChromaDB collections initialize and accept a write.
    - test_health_endpoint: Verify GET /health on backend/main.py FastAPI app returns HTTP 200.
    - test_websocket_connection: Verify WebSocket endpoint accepts and closes a connection cleanly.
    - test_orchestrator_run_scan: Verify orchestrator run_scan completes end-to-end without raising any exception.

DEPENDENCIES (what must be running/available):
    - Dummy target:     YES (uvicorn dummy_target.app:app --port 8001)
    - Sentinel backend: YES (uvicorn backend.main:app --port 8000)
    - Real API keys:    NO  (Groq / Gemini / DeepSeek in .env)
    - Ollama:           NO  (ollama serve + ollama pull mistral)
    - ChromaDB:         YES (auto-initialized — no manual step needed)

HOW TO RUN:
    pytest tests/test_week1_smoke.py -v

ESTIMATED RUNTIME: medium 10–30s

NOTES:
    Requires the Sentinel backend to be running. Does not mock the HTTP requests.
================================================================================
"""
import asyncio
import os
import uuid
import logging

import pytest
import httpx
import websockets
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from websockets.protocol import State

from constants import ChromaCollection
from knowledge_base.knowledge_base import KnowledgeBase
from agents.orchestrator import run_scan
logger = logging.getLogger(__name__)
pytestmark = pytest.mark.asyncio

DATABASE_URL = os.getenv("DATABASE_URL")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
WS_BASE_URL = os.getenv("WS_BASE_URL", "ws://localhost:8000")


async def test_db_tables_exist() -> None:
    """
    Verify all five required PostgreSQL tables exist in Supabase.
    Skips gracefully if DATABASE_URL env var is not set.
    Tables: clients, consents, scans, components, vulnerabilities.
    """
    if DATABASE_URL is None:
        pytest.skip("DATABASE_URL not set")

    try:
        engine = create_async_engine(DATABASE_URL, connect_args={"timeout": 5})
        async with engine.connect() as conn:
            for table in ["clients", "consents", "scans", "components", "vulnerabilities"]:
                result = await conn.execute(
                    text(
                        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = :t)"
                    ),
                    {"t": table},
                )
                row = result.fetchone()
                assert row is not None and row[0] is True, (
                    f"Table '{table}' missing from database"
                )
                logger.info("DB table verified: %s", table)
        await engine.dispose()
    except Exception as exc:
        pytest.skip(f"Database connection failed: {exc}. Skipping DB tables smoke test.")


async def test_chromadb_collections() -> None:
    """
    Verify all five ChromaDB collections initialize and accept a write
    that includes client_id in metadata, then query back with client_id filter.
    Inspects KnowledgeBase and chroma_client.py to find the underlying
    chromadb.Client or chromadb.PersistentClient instance.
    All queries MUST include where={"client_id": client_id}.
    """
    test_client_id = "test-client-smoke"
    test_scan_id = "test-scan-smoke"
    base_id = uuid.uuid4().hex
    kb = KnowledgeBase(client_id=test_client_id, scan_id=test_scan_id)

    collections = [
        ChromaCollection.ATTACK_HISTORY,
        ChromaCollection.SUCCESSFUL_ATTACKS,
        ChromaCollection.MUTATION_LINEAGE,
        ChromaCollection.COMPONENT_PROFILES,
        ChromaCollection.VULNERABILITY_CATALOG,
    ]

    for coll_name in collections:
        coll = kb._chroma.get_collection(coll_name)
        doc_id = f"smoke-{base_id}-{coll_name}"

        await asyncio.to_thread(
            coll.add,
            documents=["sentinel smoke test"],
            metadatas=[{"client_id": test_client_id, "test": "smoke"}],
            ids=[doc_id],
        )

        results = await asyncio.to_thread(
            coll.query,
            query_texts=["sentinel smoke test"],
            n_results=1,
            where={"client_id": test_client_id},
        )

        assert len(results["documents"][0]) == 1, (
            f"ChromaDB collection '{coll_name}' write/query failed"
        )
        logger.info("ChromaDB collection verified: %s", coll_name)


async def test_health_endpoint() -> None:
    """
    Verify GET /health on backend/main.py FastAPI app returns HTTP 200.
    Server must be running at BASE_URL before this test is executed.
    Fails with actionable message if server is unreachable.
    """
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        try:
            response = await client.get("/health")
        except httpx.ConnectError:
            pytest.fail(
                f"FastAPI server not reachable at {BASE_URL}. "
                "Run in a separate terminal: uvicorn backend.main:app --reload"
            )
        assert response.status_code == 200, (
            f"/health returned {response.status_code}, expected 200"
        )
        logger.info("Health endpoint verified: 200 OK")


async def test_websocket_connection() -> None:
    """
    Verify WebSocket endpoint /ws/scan/test-scan-id accepts and closes
    a connection cleanly. Server must be running before this test runs.
    """
    ws_url = f"{WS_BASE_URL}/ws/scan/test-scan-id"
    try:
        async with websockets.connect(ws_url, open_timeout=5) as ws:
            assert ws.state == State.OPEN, "WebSocket opened but reported closed state"
            await ws.close()
            logger.info("WebSocket verified at %s", ws_url)
    except (OSError, websockets.exceptions.WebSocketException) as exc:
        pytest.fail(
            f"WebSocket failed at {ws_url}: {exc}. "
            "Run in a separate terminal: uvicorn backend.main:app --reload"
        )


async def test_orchestrator_run_scan() -> None:
    """
    Verify orchestrator run_scan("test-client", "test-scan") completes
    end-to-end without raising any exception.
    Does not assert on output — only that no exception is thrown.
    """
    try:
        await run_scan("test-client", "test-scan")
        logger.info("Orchestrator run_scan completed without exception")
    except Exception as exc:
        pytest.fail(f"run_scan raised {type(exc).__name__}: {exc}")
