"""
chroma_client.py — ChromaDB client factory for Sentinel AI.

Environment variables:
    CHROMA_MODE  : 'local' (default) | 'remote'
    CHROMA_HOST  : hostname for remote Chroma (default: localhost)
    CHROMA_PORT  : port for remote Chroma (default: 8001)
    CHROMA_PATH  : local persistence path (default: ./chroma_data)

Do NOT cache the client at module level. Call get_chroma_client()
on demand so env vars are read at runtime, not at import time.
"""

import os
import logging

import chromadb
from chromadb import PersistentClient, HttpClient

logger = logging.getLogger(__name__)


def get_chroma_client() -> chromadb.ClientAPI:
    """
    Returns a ChromaDB client configured by CHROMA_MODE environment variable.

    Use CHROMA_MODE=remote for Docker/production (connects to docker-compose
    Chroma service on CHROMA_HOST:CHROMA_PORT).
    Use CHROMA_MODE=local (default) for local development with persistent storage.

    Returns:
        chromadb.ClientAPI: Configured ChromaDB client instance.
    """
    mode = os.getenv("CHROMA_MODE", "local")

    if mode == "remote":
        host = os.getenv("CHROMA_HOST", "localhost")
        port = int(os.getenv("CHROMA_PORT", "8001"))
        logger.info("ChromaDB: connecting to remote %s:%s", host, port)
        return HttpClient(host=host, port=port)
    else:
        path = os.getenv("CHROMA_PATH", "./chroma_data")
        logger.info("ChromaDB: using local PersistentClient at %s", path)
        return PersistentClient(path=path)
