"""REST API router for Sentinel AI scan operations."""

import asyncio
import logging
import uuid
from uuid import UUID
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi import status as http_status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from backend.database import get_db
from backend.models import Client, Consent, Scan, Component
from constants import ScanStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])

VALID_SCAN_STATUSES: list[str] = [
    ScanStatus.PENDING,
    ScanStatus.ACTIVE,
    ScanStatus.PAUSED,
    ScanStatus.COMPLETED,
    ScanStatus.HALTED,
    ScanStatus.FAILED,
]


class CreateScanRequest(BaseModel):
    """Request body for creating a new security scan."""

    client_id: str
    consent_id: str
    components: list[dict]


class ScanResponse(BaseModel):
    """Response payload returned after scan creation."""

    scan_id: str
    client_id: str
    status: str
    created_at: str


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    request: CreateScanRequest,
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    """
    Create a new scan. Validates client and consent exist in DB.
    Creates Scan record and all Component records.
    Returns the new scan_id.
    """
    try:
        client_uuid = uuid.UUID(request.client_id)
        consent_uuid = uuid.UUID(request.consent_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid client_id or consent_id format",
        ) from exc

    client_result = await db.execute(select(Client).where(Client.id == client_uuid))
    client: Optional[Client] = client_result.scalar_one_or_none()
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    consent_result = await db.execute(select(Consent).where(Consent.id == consent_uuid))
    consent: Optional[Consent] = consent_result.scalar_one_or_none()
    if consent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Consent not found")

    scan = Scan(
        client_id=client_uuid,
        consent_id=consent_uuid,
        status=ScanStatus.PENDING,
        component_count=len(request.components),
    )
    db.add(scan)
    await db.flush()

    for component_data in request.components:
        component = Component(
            scan_id=scan.id,
            type=component_data["type"],
            endpoint=component_data["endpoint"],
            status=ScanStatus.PENDING,
        )
        db.add(component)

    await db.commit()
    await db.refresh(scan)

    created_at: str = datetime.utcnow().isoformat()
    logger.info("Scan created", extra={"scan_id": str(scan.id)})

    return ScanResponse(
        scan_id=str(scan.id),
        client_id=str(scan.client_id),
        status=scan.status,
        created_at=created_at,
    )


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Retrieve scan status and metadata by scan_id."""
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan_id format",
        ) from exc

    result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
    scan: Optional[Scan] = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    return {
        "scan_id": str(scan.id),
        "client_id": str(scan.client_id),
        "consent_id": str(scan.consent_id),
        "status": scan.status,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "component_count": scan.component_count,
    }


@router.get("/{scan_id}/components")
async def get_scan_components(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Retrieve all components for a given scan."""
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan_id format",
        ) from exc

    result = await db.execute(select(Component).where(Component.scan_id == scan_uuid))
    components: list[Component] = list(result.scalars().all())

    return [
        {
            "component_id": str(component.id),
            "scan_id": str(component.scan_id),
            "type": component.type,
            "endpoint": component.endpoint,
            "framework": component.framework,
            "priority_score": component.priority_score,
            "status": component.status,
        }
        for component in components
    ]


@router.patch("/{scan_id}/status")
async def update_scan_status(
    scan_id: str,
    new_status: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update scan status. Validates status is a valid ScanStatus value."""
    if new_status not in VALID_SCAN_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan_id format",
        ) from exc

    result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
    scan: Optional[Scan] = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    scan.status = new_status
    await db.commit()
    await db.refresh(scan)

    return {
        "scan_id": str(scan.id),
        "client_id": str(scan.client_id),
        "consent_id": str(scan.consent_id),
        "status": scan.status,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "component_count": scan.component_count,
    }


@router.post(
    "/{scan_id}/start",
    status_code=http_status.HTTP_202_ACCEPTED,
    summary="Start orchestrated scan execution",
    description=(
        "Triggers the LangGraph orchestrator for an existing scan. "
        "Validates consent exists before starting (legal requirement). "
        "Runs via FastAPI BackgroundTasks for MVP — Celery migration in Week 8 hardening."
    ),
)
async def start_scan(
    scan_id: UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Scan start endpoint. Replaces test.py manual trigger.
    Called by frontend 'Start Scan' button and Postman during development.

    Args:
        scan_id: Valid UUID of an existing scan in PENDING status.
        background_tasks: FastAPI background task runner.
        db: Async database session.

    Returns:
        Accepted response with scan_id and status confirmation.

    Raises:
        404: Scan not found.
        409: Scan not in startable state (not PENDING).
        403: No valid consent record for this scan (legal gate).
    """
    from agents.orchestrator import SentinelOrchestrator  # local import � avoids circular at module load
    from backend.models import Scan, Consent
    from sqlalchemy import select
    from constants import ScanStatus

    # Load scan record
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found.",
        )

    # Validate scan is startable
    if scan.status != ScanStatus.PENDING:
        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT,
            detail=f"Scan {scan_id} has status '{scan.status}' — only PENDING scans can be started.",
        )

    # Legal gate: consent must exist (Roadmap Section 10, non-negotiable)
    if not scan.consent_id:
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Scan cannot start: no consent record attached. "
            "Obtain signed consent before initiating any testing.",
        )
    # TODO Week 7: Also validate consent.scope covers the components being tested
    # (Roadmap Section 4.2 — consent scope enforcement before Autopatch)

    consent_result = await db.execute(select(Consent).where(Consent.id == scan.consent_id))
    consent = consent_result.scalar_one_or_none()
    if not consent:
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Scan cannot start: no consent record attached. "
            "Obtain signed consent before initiating any testing.",
        )

    orchestrator = SentinelOrchestrator()
    background_tasks.add_task(
        orchestrator.run_scan,
        client_id=str(scan.client_id),
        scan_id=str(scan_id),
    )

    return {
        "message": "Scan accepted and queued for execution.",
        "scan_id": str(scan_id),
        "status": "accepted",
        "note": "BackgroundTasks runner active. Celery migration planned for Week 8.",
    }


@router.post(
    "/{scan_id}/run",
    status_code=http_status.HTTP_200_OK,
    summary="Trigger orchestrator for an existing scan (in-process)",
    description=(
        "Runs the LangGraph orchestrator inside the FastAPI event loop via "
        "asyncio.create_task(). The API returns immediately. Because the task "
        "runs in the same process, the WebSocket ConnectionManager singleton is "
        "the same instance the browser is already connected to — events are "
        "delivered live without any cross-process plumbing."
    ),
)
async def run_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Trigger the orchestrator for a given scan_id.

    Looks up the scan record to obtain client_id, then fires
    orchestrator.run_scan() as a background asyncio task so this
    endpoint returns immediately while the scan runs in the background.

    Args:
        scan_id: String UUID of an existing scan.
        db: Async database session (injected by FastAPI).

    Returns:
        {"status": "started", "scan_id": scan_id}

    Raises:
        400: scan_id is not a valid UUID.
        404: Scan record not found.
    """
    from agents.orchestrator import SentinelOrchestrator

    # Validate scan_id format
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan_id format — must be a valid UUID.",
        ) from exc

    # Load scan record to get client_id
    result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
    scan: Optional[Scan] = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found.",
        )

    client_id = str(scan.client_id)

    # Instantiate orchestrator inside the function so the WebSocket manager
    # singleton (imported at module level in orchestrator.py) is the same
    # instance already serving connected browser clients.
    orchestrator = SentinelOrchestrator()


    # Fire and forget — API returns immediately, scan runs in background.
    # asyncio.create_task keeps it in the same event loop, so WebSocket
    # broadcasts reach connected clients without any cross-process relay.
    asyncio.create_task(
        orchestrator.run_scan(client_id=client_id, scan_id=scan_id)
    )

    logger.info("Scan %s triggered via /run endpoint for client %s", scan_id, client_id)

    return {"status": "started", "scan_id": scan_id}

