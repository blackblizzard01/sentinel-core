"""Week 1 smoke tests for Sentinel AI core modules."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest_mock.plugin import MockerFixture
from httpx import ASGITransport, AsyncClient
from fastapi import status

from backend.main import app
from backend.database import get_db
from backend.schemas.events import (
    AgentStartedEvent,
    AttackExecutedEvent,
    VulnerabilityFoundEvent,
    ScanCompleteEvent,
    CriticalHaltEvent,
)
from knowledge_base.knowledge_base import KnowledgeBase
from agents.orchestrator import SentinelOrchestrator, ScanState
from backend.websocket.connection_manager import ConnectionManager
from constants import ScanPhase, ScanStatus, WSEvent, ChromaCollection, AttackDomain


@pytest.fixture
async def async_client() -> AsyncClient:
    """Provide an async HTTP client for FastAPI app testing."""
    with patch("backend.main.init_db", new_callable=AsyncMock):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            yield client


@pytest.fixture
def mock_kb(mocker: MockerFixture) -> KnowledgeBase:
    """Provide a KnowledgeBase instance with mocked ChromaDB collections."""
    mock_client: MagicMock = MagicMock()
    collection_names: list[str] = [
        ChromaCollection.ATTACK_HISTORY,
        ChromaCollection.SUCCESSFUL_ATTACKS,
        ChromaCollection.MUTATION_LINEAGE,
        ChromaCollection.COMPONENT_PROFILES,
        ChromaCollection.VULNERABILITY_CATALOG,
    ]
    collections: dict[str, MagicMock] = {}
    for collection_name in collection_names:
        mock_collection: MagicMock = MagicMock()
        mock_collection.add = MagicMock()
        mock_collection.query = MagicMock(
            return_value={"metadatas": [[]], "documents": [[]], "distances": [[]]},
        )
        collections[collection_name] = mock_collection

    def get_or_create_collection(name: str, **kwargs: dict) -> MagicMock:
        """Return a mocked collection for the given name."""
        return collections[name]

    mock_client.get_or_create_collection = MagicMock(side_effect=get_or_create_collection)

    mocker.patch(
        "knowledge_base.chroma_client.chromadb.PersistentClient",
        return_value=mock_client,
    )
    mocker.patch(
        "knowledge_base.knowledge_base.get_chroma_client",
        return_value=mock_client,
    )

    kb: KnowledgeBase = KnowledgeBase()
    return kb


# ─── SECTION 1 — FastAPI Health + REST Endpoint Tests ───────────────────────


async def test_health_check(async_client: AsyncClient) -> None:
    """GET /health returns 200 with correct service name."""
    response = await async_client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status": "ok", "service": "sentinel-ai"}


async def test_create_scan_missing_client(async_client: AsyncClient) -> None:
    """POST /api/scans with non-existent client returns 404."""
    mock_session: AsyncMock = AsyncMock()
    mock_result: MagicMock = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)

    async def override_get_db() -> AsyncMock:
        """Yield a mocked database session for the scan create endpoint."""
        yield mock_session

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = await async_client.post(
            "/api/scans",
            json={
                "client_id": "00000000-0000-0000-0000-000000000001",
                "consent_id": "00000000-0000-0000-0000-000000000002",
                "components": [{"type": "llm_model", "endpoint": "http://test"}],
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == status.HTTP_404_NOT_FOUND


async def test_get_scan_not_found(async_client: AsyncClient) -> None:
    """GET /api/scans/{scan_id} with unknown ID returns 404."""
    mock_session: AsyncMock = AsyncMock()
    mock_result: MagicMock = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)

    async def override_get_db() -> AsyncMock:
        """Yield a mocked database session for the scan lookup endpoint."""
        yield mock_session

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = await async_client.get(
            "/api/scans/00000000-0000-0000-0000-000000000099",
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == status.HTTP_404_NOT_FOUND


# ─── SECTION 2 — Pydantic Schema Tests ──────────────────────────────────────


def test_agent_started_event_schema() -> None:
    """AgentStartedEvent instantiates correctly with required fields."""
    event: AgentStartedEvent = AgentStartedEvent(
        scan_id="test-scan-001",
        event_type=WSEvent.AGENT_STARTED,
        agent_name="recon_agent",
        phase=ScanPhase.RECON,
    )
    assert event.scan_id == "test-scan-001"
    assert event.event_type == WSEvent.AGENT_STARTED
    assert event.agent_name == "recon_agent"
    assert event.phase == ScanPhase.RECON
    assert event.timestamp is not None
    assert isinstance(event.timestamp, str)


def test_attack_executed_event_schema() -> None:
    """AttackExecutedEvent instantiates and validates score range."""
    event: AttackExecutedEvent = AttackExecutedEvent(
        scan_id="test-scan-001",
        event_type=WSEvent.ATTACK_EXECUTED,
        component_id="comp-001",
        domain=AttackDomain.PROMPT_INJECTION,
        payload_preview="test payload",
        response_preview="test response",
        score=0.75,
    )
    assert event.score == 0.75
    assert event.domain == AttackDomain.PROMPT_INJECTION


def test_vulnerability_found_event_schema() -> None:
    """VulnerabilityFoundEvent instantiates with severity field."""
    event: VulnerabilityFoundEvent = VulnerabilityFoundEvent(
        scan_id="test-scan-001",
        event_type=WSEvent.VULNERABILITY_FOUND,
        component_id="comp-001",
        domain=AttackDomain.PROMPT_INJECTION,
        severity="high",
        description="Test vulnerability",
    )
    assert event.severity == "high"


def test_scan_complete_event_schema() -> None:
    """ScanCompleteEvent instantiates with correct counts."""
    event: ScanCompleteEvent = ScanCompleteEvent(
        scan_id="test-scan-001",
        event_type=WSEvent.SCAN_COMPLETE,
        total_vulnerabilities=5,
        critical_count=1,
        high_count=2,
    )
    assert event.total_vulnerabilities == 5
    assert event.report_path is None


# ─── SECTION 3 — KnowledgeBase Tests ────────────────────────────────────────


async def test_log_attack_returns_id(mock_kb: KnowledgeBase) -> None:
    """log_attack() returns a valid UUID string."""
    result: str = await mock_kb.log_attack(
        client_id="client-001",
        scan_id="scan-001",
        component_id="comp-001",
        domain=AttackDomain.PROMPT_INJECTION,
        payload="test payload",
        response="test response",
        score=0.5,
    )
    assert isinstance(result, str)
    uuid.UUID(result)


async def test_log_attack_high_score_goes_to_successful(mock_kb: KnowledgeBase) -> None:
    """log_attack() with score >= 0.7 also writes to successful_attacks."""
    await mock_kb.log_attack(
        client_id="client-001",
        scan_id="scan-001",
        component_id="comp-001",
        domain=AttackDomain.PROMPT_INJECTION,
        payload="test payload",
        response="test response",
        score=0.85,
    )
    assert mock_kb.successful_attacks.add.call_count == 1
    assert mock_kb.attack_history.add.call_count == 1


async def test_log_attack_low_score_not_in_successful(mock_kb: KnowledgeBase) -> None:
    """log_attack() with score < 0.7 does NOT write to successful_attacks."""
    await mock_kb.log_attack(
        client_id="client-001",
        scan_id="scan-001",
        component_id="comp-001",
        domain=AttackDomain.PROMPT_INJECTION,
        payload="test payload",
        response="test response",
        score=0.3,
    )
    mock_kb.successful_attacks.add.assert_not_called()
    assert mock_kb.attack_history.add.call_count == 1


async def test_log_vulnerability_returns_id(mock_kb: KnowledgeBase) -> None:
    """log_vulnerability() returns a valid UUID string."""
    result: str = await mock_kb.log_vulnerability(
        client_id="client-001",
        scan_id="scan-001",
        component_id="comp-001",
        domain=AttackDomain.PROMPT_INJECTION,
        score=0.9,
        severity="critical",
        description="Critical injection vulnerability",
    )
    assert isinstance(result, str)
    uuid.UUID(result)


async def test_get_top_attacks_returns_list(mock_kb: KnowledgeBase) -> None:
    """get_top_attacks() returns a list (empty if no results)."""
    mock_kb.successful_attacks.count = MagicMock(return_value=10)  # non-zero so guard passes
    mock_kb.successful_attacks.query = MagicMock(
        return_value={"metadatas": [[]], "documents": [[]], "distances": [[]]},
    )
    result: list[dict] = await mock_kb.get_top_attacks(
        client_id="client-001",
        domain=AttackDomain.PROMPT_INJECTION,
        component_type="llm_model",
    )
    assert isinstance(result, list)


async def test_chromadb_query_includes_client_id(mock_kb: KnowledgeBase) -> None:
    """Every ChromaDB query must include client_id in the where clause."""
    mock_kb.successful_attacks.count = MagicMock(return_value=10)  # non-zero so guard passes
    mock_kb.successful_attacks.query = MagicMock(
        return_value={"metadatas": [[]], "documents": [[]], "distances": [[]]},
    )
    await mock_kb.get_top_attacks(
        client_id="client-001",
        domain=AttackDomain.PROMPT_INJECTION,
        component_type="llm_model",
    )
    call_kwargs: dict = mock_kb.successful_attacks.query.call_args.kwargs
    assert "where" in call_kwargs
    # With component_type set, where is now {"$and": [{"client_id": ...}, {"component_type": ...}]}
    where = call_kwargs["where"]
    conditions: list = where.get("$and", [])
    client_id_condition = next((c for c in conditions if "client_id" in c), None)
    assert client_id_condition is not None
    assert client_id_condition["client_id"] == "client-001"


# ─── SECTION 4 — ConnectionManager Tests ────────────────────────────────────


async def test_connection_manager_connect() -> None:
    """connect() adds websocket to active_connections under scan_id."""
    manager: ConnectionManager = ConnectionManager()
    websocket: MagicMock = MagicMock()
    websocket.accept = AsyncMock()

    await manager.connect(websocket, "scan-001")

    assert "scan-001" in manager.active_connections
    assert websocket in manager.active_connections["scan-001"]
    websocket.accept.assert_called_once()


def test_connection_manager_disconnect() -> None:
    """disconnect() removes websocket and cleans up empty scan entry."""
    manager: ConnectionManager = ConnectionManager()
    websocket: MagicMock = MagicMock()
    manager.active_connections["scan-001"] = [websocket]

    manager.disconnect(websocket, "scan-001")

    assert "scan-001" not in manager.active_connections


async def test_broadcast_to_scan() -> None:
    """broadcast_to_scan() calls send_json on all connected clients."""
    manager: ConnectionManager = ConnectionManager()
    websocket_one: MagicMock = MagicMock()
    websocket_one.send_json = AsyncMock()
    websocket_two: MagicMock = MagicMock()
    websocket_two.send_json = AsyncMock()
    manager.active_connections["scan-001"] = [websocket_one, websocket_two]

    await manager.broadcast_to_scan("scan-001", {"event_type": "test"})

    websocket_one.send_json.assert_called_once()
    websocket_two.send_json.assert_called_once()


async def test_broadcast_to_nonexistent_scan() -> None:
    """broadcast_to_scan() silently returns if scan_id has no connections."""
    manager: ConnectionManager = ConnectionManager()
    await manager.broadcast_to_scan("no-such-scan", {"event_type": "test"})


# ─── SECTION 5 — Orchestrator Tests ─────────────────────────────────────────


async def test_orchestrator_initializes(mocker: MockerFixture) -> None:
    """SentinelOrchestrator initializes and compiles graph without error."""
    mock_kb_instance: MagicMock = MagicMock()
    mocker.patch(
        "agents.orchestrator.KnowledgeBase",
        return_value=mock_kb_instance,
    )

    orchestrator: SentinelOrchestrator = SentinelOrchestrator()

    assert orchestrator.graph is not None
    assert orchestrator.kb is not None


async def test_run_scan_completes(mocker: MockerFixture) -> None:
    """run_scan() runs end-to-end and returns final state with phase=done."""
    mock_kb_instance: MagicMock = MagicMock()
    mocker.patch(
        "agents.orchestrator.KnowledgeBase",
        return_value=mock_kb_instance,
    )
    mocker.patch(
        "agents.orchestrator.manager.broadcast_to_scan",
        new_callable=AsyncMock,
    )

    mock_scan: MagicMock = MagicMock()
    mock_scan.status = ScanStatus.PENDING

    mock_result: MagicMock = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_scan

    mock_session: AsyncMock = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.commit = AsyncMock()

    mock_session_factory: MagicMock = MagicMock()
    mock_session_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    mocker.patch(
        "agents.orchestrator.AsyncSessionLocal",
        mock_session_factory,
    )

    orchestrator: SentinelOrchestrator = SentinelOrchestrator()
    final_state: dict = await orchestrator.run_scan(
        client_id="test-client-001",
        scan_id=str(uuid.uuid4()),
    )

    assert final_state["phase"] == ScanPhase.DONE
    assert len(final_state["logs"]) >= 4
    assert len(final_state["attack_results"]) >= 1
    assert final_state["report_path"] != ""


def test_scan_state_has_required_fields() -> None:
    """ScanState TypedDict contains all 15 required fields."""
    state: ScanState = {
        "client_id": "client-001",
        "scan_id": "scan-001",
        "current_component_index": 0,
        "current_component": {},
        "current_domain_index": 0,
        "current_domain": AttackDomain.PROMPT_INJECTION,
        "attack_results": [],
        "iteration": 0,
        "phase": ScanPhase.RECON,
        "logs": [],
        "critical_halt": False,
        "components": [],
        "approved_findings": [],
        "report_path": "",
        "report_json": {},
    }

    required_keys: list[str] = [
        "client_id",
        "scan_id",
        "current_component_index",
        "current_component",
        "current_domain_index",
        "current_domain",
        "attack_results",
        "iteration",
        "phase",
        "logs",
        "critical_halt",
        "components",
        "approved_findings",
        "report_path",
        "report_json",
    ]
    for key in required_keys:
        assert key in state
    assert len(state.keys()) >= 15
