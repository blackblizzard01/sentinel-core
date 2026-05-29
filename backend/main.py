"""FastAPI application entry point for Sentinel AI."""

import logging
import json
from typing import Optional
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.database import init_db
from backend.routers.scans import router as scans_router
from backend.websocket.connection_manager import manager
from constants import WSEvent

load_dotenv()

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Runs startup and shutdown logic for the FastAPI app."""
    await init_db()
    logger.info("Sentinel AI API started")
    yield
    logger.info("Sentinel AI API shutting down")


app = FastAPI(
    title="Sentinel AI API",
    description="Autonomous AI security testing platform API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router)


@app.get("/health")
async def health_check() -> dict:
    """Health check endpoint."""
    return {"status": "ok", "service": "sentinel-ai"}


@app.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    scan_id: str,
) -> None:
    """
    WebSocket endpoint for live scan event streaming.
    Clients connect here to receive real-time scan events.
    On connect: sends a connection_established confirmation message.
    On disconnect: cleans up gracefully.
    """
    await manager.connect(websocket, scan_id)
    await manager.send_personal_message(
        websocket,
        {
            "event_type": "connection_established",
            "scan_id": scan_id,
            "message": "Connected to scan feed",
        },
    )

    try:
        while True:
            received_text: str = await websocket.receive_text()
            logger.debug("WebSocket message received on scan %s: %s", scan_id, received_text)
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)
        logger.info("WebSocket disconnected")
    except Exception:
        manager.disconnect(websocket, scan_id)
        logger.exception("WebSocket error on scan %s", scan_id)
