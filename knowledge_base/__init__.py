"""Public exports for the Sentinel AI knowledge base package."""

from knowledge_base.knowledge_base import KnowledgeBase
from knowledge_base.chroma_client import get_chroma_client

__all__ = ["KnowledgeBase", "get_chroma_client"]
