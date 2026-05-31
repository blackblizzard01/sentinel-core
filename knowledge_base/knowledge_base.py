import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import chromadb

from constants import (
    ChromaCollection,
    SUCCESS_THRESHOLD,
    TOP_K_RETRIEVAL,
)
from knowledge_base.chroma_client import get_chroma_client

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """Shared vector knowledge base for all Sentinel AI agents.

    All methods enforce client_id isolation at the ChromaDB query level.
    """

    def __init__(self, client_id: str, scan_id: str) -> None:
        """Bind this knowledge base instance to a client and scan."""
        self.client_id = client_id
        self.scan_id = scan_id
        self._chroma = get_chroma_client()
        logger.info(
            "KnowledgeBase initialized — client=%s scan=%s", client_id, scan_id
        )

    @property
    def chroma_client(self):
        """Expose the ChromaDB singleton for collection access."""
        return self._chroma

    def _client_filter(self) -> dict[str, str]:
        """Return the mandatory client_id filter for ChromaDB query/get operations."""
        return {"client_id": self.client_id}

    async def log_attack(
        self,
        component_id: str,
        component_type: str,
        domain: str,
        payload: str,
        response: str,
        score: float,
        timestamp: str,
    ) -> None:
        """Logs a single attack attempt to attack_history.

        If score >= SUCCESS_THRESHOLD, also logs to successful_attacks.
        Returns the generated attack_id.
        """
        try:
            doc_text = payload[:500]
            response_preview = response[:300]
            doc_id = f"{self.scan_id}_{component_id}_{domain}_{timestamp}"
            doc_id = doc_id.replace(" ", "_")

            metadata: dict[str, Any] = {
                "client_id": self.client_id,
                "scan_id": self.scan_id,
                "component_id": component_id,
                "component_type": component_type,
                "domain": domain,
                "score": score,
                "timestamp": timestamp,
                "response_preview": response_preview,
            }

            attack_history = self._chroma.get_collection(ChromaCollection.ATTACK_HISTORY)
            attack_history.add(
                documents=[doc_text],
                metadatas=[metadata],
                ids=[doc_id],
            )
            logger.info(
                "Logged attack: id=%s score=%.2f domain=%s", doc_id, score, domain
            )

            if score >= SUCCESS_THRESHOLD:
                successful_attacks = self._chroma.get_collection(
                    ChromaCollection.SUCCESSFUL_ATTACKS
                )
                successful_attacks.add(
                    documents=[doc_text],
                    metadatas=[metadata],
                    ids=[doc_id],
                )
                logger.info(
                    "Logged successful attack: id=%s score=%.2f", doc_id, score
                )
        except Exception as e:
            logger.error("log_attack failed: %s", e)
            raise

    async def get_top_attacks(
        self,
        client_id: str,
        domain: str,
        component_type: str,
        k: int = 5,
    ) -> list[dict[str, Any]]:
        """Retrieves top-k semantically similar successful attacks for this client.

        Returns an empty list if no results exist.
        """
        try:
            collection = self._chroma.get_collection(ChromaCollection.ATTACK_HISTORY)
            query_text = f"{domain} {component_type}"
            results = collection.query(
                query_texts=[query_text],
                n_results=k,
                where={
                    "$and": [
                        {"client_id": client_id},
                        {"domain": domain},
                        {"component_type": component_type},
                    ]
                },
                include=["metadatas", "documents", "distances"],
            )

            if not results or not results.get("metadatas") or not results["metadatas"][0]:
                return []

            metadatas_list = results["metadatas"][0]
            documents_list = results["documents"][0]
            distances_list = results["distances"][0]

            mapped: list[dict[str, Any]] = []
            for i, meta in enumerate(metadatas_list):
                mapped.append(
                    {
                        "payload": documents_list[i],
                        "score": meta.get("score", 0.0),
                        "domain": meta.get("domain", ""),
                        "component_id": meta.get("component_id", ""),
                        "timestamp": meta.get("timestamp", ""),
                        "response_preview": meta.get("response_preview", ""),
                        "distance": distances_list[i],
                    }
                )

            mapped.sort(key=lambda x: x["score"], reverse=True)
            logger.info(
                "get_top_attacks returned %s results for domain=%s", len(mapped), domain
            )
            return mapped
        except Exception as e:
            logger.error("get_top_attacks failed: %s", e)
            return []

    async def log_mutation(
        self,
        parent_attack_id: str,
        child_payload: str,
        strategy: str,
        child_score: float,
        generation: int,
    ) -> str:
        """Logs a mutated attack variant and its lineage to mutation_lineage.

        Returns the generated mutation_id.
        """
        mutation_id = str(uuid.uuid4())
        collection = self._chroma.get_collection(ChromaCollection.MUTATION_LINEAGE)
        try:
            collection.add(
                documents=[child_payload],
                metadatas=[
                    {
                        "client_id": self.client_id,
                        "scan_id": self.scan_id,
                        "parent_attack_id": parent_attack_id,
                        "strategy": strategy,
                        "child_score": child_score,
                        "generation": generation,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                ids=[mutation_id],
            )
        except chromadb.errors.ChromaError as exc:
            logger.error("Failed to log mutation: %s", exc)
            raise
        logger.info(
            "Mutation logged: %s strategy=%s gen=%s", mutation_id, strategy, generation
        )
        return mutation_id

    async def log_vulnerability(
        self,
        component_id: str,
        domain: str,
        score: float,
        severity: str,
        description: str,
        remediation: str = "",
    ) -> str:
        """Logs a confirmed vulnerability to the vulnerability_catalog.

        Returns the generated vuln_id.
        """
        vuln_id = str(uuid.uuid4())
        collection = self._chroma.get_collection(ChromaCollection.VULNERABILITY_CATALOG)
        try:
            collection.add(
                documents=[description],
                metadatas=[
                    {
                        "client_id": self.client_id,
                        "scan_id": self.scan_id,
                        "component_id": component_id,
                        "domain": domain,
                        "score": score,
                        "severity": severity,
                        "remediation": remediation,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                ids=[vuln_id],
            )
        except chromadb.errors.ChromaError as exc:
            logger.error("Failed to log vulnerability: %s", exc)
            raise
        logger.warning(
            "Vulnerability logged: %s — %s on %s",
            severity.upper(),
            domain,
            component_id,
        )
        return vuln_id

    async def log_component_profile(
        self,
        component_id: str,
        component_type: str,
        endpoint: str,
        framework: str,
        priority_score: float,
        extra_metadata: Optional[dict[str, Any]] = None,
    ) -> str:
        """Logs a recon-discovered component profile to component_profiles.

        Returns the generated profile_id.
        """
        profile_id = str(uuid.uuid4())
        base_metadata: dict[str, Any] = {
            "client_id": self.client_id,
            "scan_id": self.scan_id,
            "component_id": component_id,
            "component_type": component_type,
            "endpoint": endpoint,
            "framework": framework,
            "priority_score": priority_score,
        }
        merged_metadata = {**(extra_metadata or {}), **base_metadata}
        collection = self._chroma.get_collection(ChromaCollection.COMPONENT_PROFILES)
        try:
            collection.add(
                documents=[f"{component_type} {endpoint} {framework}"],
                metadatas=[merged_metadata],
                ids=[profile_id],
            )
        except chromadb.errors.ChromaError as exc:
            logger.error("Failed to log component profile: %s", exc)
            raise
        logger.info(
            "Component profile logged: %s type=%s endpoint=%s",
            profile_id,
            component_type,
            endpoint,
        )
        return profile_id

    async def get_vulnerability_catalog(self) -> list[dict[str, Any]]:
        """Returns all vulnerabilities for this client from the catalog.

        Uses .get() not .query() — no semantic search needed here.
        """
        collection = self._chroma.get_collection(ChromaCollection.VULNERABILITY_CATALOG)
        try:
            results = collection.get(where=self._client_filter())
        except chromadb.errors.ChromaError as exc:
            logger.error("Failed to fetch vulnerability catalog: %s", exc)
            raise

        ids = results.get("ids") or []
        if not ids:
            return []

        documents = results.get("documents") or []
        metadatas = results.get("metadatas") or []
        mapped = [
            {
                "id": doc_id,
                "description": document,
                "severity": meta["severity"],
                "domain": meta["domain"],
                "component_id": meta["component_id"],
                "score": meta["score"],
                "remediation": meta["remediation"],
                "timestamp": meta["timestamp"],
            }
            for doc_id, document, meta in zip(ids, documents, metadatas)
        ]
        logger.info(
            "Vulnerability catalog fetched: %s entries for client=%s",
            len(mapped),
            self.client_id,
        )
        return mapped
