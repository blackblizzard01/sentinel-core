import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
import json

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from constants import WSEvent, WEBSOCKET_REPLAY_LIMIT

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages all active WebSocket connections keyed by scan_id.

    Supports broadcast to all connections for a given scan.
    """

    def __init__(self) -> None:
        """Initialize connection tracking and per-scan event replay buffers."""
        self.active_connections: dict[str, list[WebSocket]] = {}
        self.event_log: dict[str, list[dict[str, Any]]] = {}
        logger.info("ConnectionManager initialized")

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        """Accepts a WebSocket connection and registers it under scan_id.

        Replays the last WEBSOCKET_REPLAY_LIMIT events to the newly connected client.
        """
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

        for event in self.event_log.get(scan_id, [])[-WEBSOCKET_REPLAY_LIMIT:]:
            await websocket.send_text(json.dumps(event))

        count = len(self.active_connections[scan_id])
        logger.info(f"Client connected to scan {scan_id}. Total connections: {count}")

    def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        """Removes a WebSocket from the active connections for scan_id."""
        if scan_id in self.active_connections:
            if websocket in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
        logger.info(f"Client disconnected from scan {scan_id}")

    async def broadcast(self, scan_id: str, event: dict[str, Any]) -> None:
        """Broadcasts a JSON event to all active connections for scan_id.

        Stores the event in event_log, capped at WEBSOCKET_REPLAY_LIMIT entries.
        """
        if scan_id not in self.event_log:
            self.event_log[scan_id] = []
        self.event_log[scan_id].append(event)
        self.event_log[scan_id] = self.event_log[scan_id][-WEBSOCKET_REPLAY_LIMIT:]

        for websocket in self.active_connections.get(scan_id, []):
            await websocket.send_text(json.dumps(event))

        logger.debug(
            f"Broadcast to scan {scan_id}: event_type={event.get('event_type')}"
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan handler. Runs startup and shutdown logic."""
    logger.info("Sentinel AI backend starting up")
    yield
    logger.info("Sentinel AI backend shutting down")


app = FastAPI(
    title="Sentinel AI",
    description="Autonomous AI infrastructure security testing platform",
    version="0.1.0",
    lifespan=lifespan,
)

manager = ConnectionManager()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint. Returns service status.

    Used by Railway and CI/CD to confirm the server is alive.
    """
    logger.debug("Health check requested")
    return {"status": "ok"}


@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan_endpoint(websocket: WebSocket, scan_id: str) -> None:
    """WebSocket endpoint for real-time scan event streaming.

    Connects the client, sends a connected confirmation event,
    then listens for incoming messages until disconnect.
    """
    await manager.connect(scan_id, websocket)
    await manager.broadcast(
        scan_id,
        {
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": WSEvent.AGENT_STARTED,
            "agent_name": "system",
            "phase": "connected",
        },
    )
    try:
        while True:
            data = await websocket.receive_text()
            logger.debug(f"Received from client on scan {scan_id}: {data}")
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)
        logger.info(f"WebSocket disconnected: scan_id={scan_id}")
    except Exception as exc:
        logger.error("WebSocket error on scan %s: %s", scan_id, exc)
        manager.disconnect(scan_id, websocket)
