"""WebSocket connection manager for Sentinel AI live scan event streaming."""

import logging
import json
from typing import Optional

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages all active WebSocket connections.
    Maintains a mapping of scan_id to list of connected clients.
    Handles connect, disconnect, and broadcast operations.
    """

    def __init__(self) -> None:
        """Initialize empty connection registry."""
        self.active_connections: dict[str, list[WebSocket]] = {}
        logger.info("ConnectionManager initialized")

    async def connect(self, websocket: WebSocket, scan_id: str) -> None:
        """Accept a new WebSocket connection and register it under scan_id."""
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)
        logger.info("Client connected to scan %s", scan_id)
        logger.debug(
            "Total connections for scan %s: %s",
            scan_id,
            len(self.active_connections[scan_id]),
        )

    def disconnect(self, websocket: WebSocket, scan_id: str) -> None:
        """Remove a WebSocket from the active connections for a scan."""
        if scan_id in self.active_connections:
            if websocket in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
        logger.info("Client disconnected from scan %s", scan_id)

    async def broadcast_to_scan(
        self,
        scan_id: str,
        message: dict,
    ) -> None:
        """
        Broadcast a JSON message to all clients connected to a scan.
        Silently disconnects any clients that have dropped.
        """
        if scan_id not in self.active_connections:
            logger.debug("No active connections for scan %s", scan_id)
            return

        for websocket in list(self.active_connections[scan_id]):
            try:
                await websocket.send_json(message)
            except Exception:
                self.disconnect(websocket, scan_id)
                logger.warning(
                    "Failed to broadcast to client on scan %s; disconnected",
                    scan_id,
                )

        logger.debug(
            "Broadcast to scan %s: %s",
            scan_id,
            message.get("event_type"),
        )

    async def send_personal_message(
        self,
        websocket: WebSocket,
        message: dict,
    ) -> None:
        """Send a JSON message to a single WebSocket client."""
        try:
            await websocket.send_json(message)
        except Exception:
            logger.exception("Failed to send personal WebSocket message")
            raise

    def get_connection_count(self, scan_id: str) -> int:
        """Return number of active connections for a scan_id."""
        return len(self.active_connections.get(scan_id, []))


manager = ConnectionManager()
