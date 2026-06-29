import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import chromadb

from constants import (
    ChromaCollection,
    SUCCESS_THRESHOLD,
    TOP_K_RETRIEVAL,
    Severity,
)
from knowledge_base.chroma_client import get_chroma_client

logger = logging.getLogger(__name__)

CROSS_COMPONENT_HINT_MAP = {
    ("system_prompt_extraction", "api_layer"): "System prompt leaked on LLM — probe API endpoints for hardcoded system prompt values in response headers or error bodies.",
    ("system_prompt_extraction", "rag_pipeline"): "System prompt leaked on LLM — test RAG retrieval for documents that reconstruct or mirror the system prompt.",
    ("prompt_injection", "rag_pipeline"): "Prompt injection succeeded on LLM — attempt indirect injection via RAG-retrieved documents to chain the exploit.",
    ("prompt_injection", "api_layer"): "Prompt injection succeeded on LLM — probe API input fields for unsanitized pass-through to downstream LLM calls.",
    ("rag_poisoning", "llm_model"): "RAG corpus poisoned — test if poisoned documents alter LLM responses in downstream inference calls.",
    ("indirect_injection", "api_layer"): "Indirect injection found in document layer — probe API endpoints that accept user-supplied document URLs or content.",
    ("api_attacks", "llm_model"): "API auth bypass found — test if the same endpoint passes unauthenticated prompts directly to the LLM.",
}


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
        """Expose the shared ChromaDB singleton for collection access."""
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

    async def log_successful_attack(
        self,
        component_id: str,
        component_type: str,
        domain: str,
        payload: str,
        response: str,
        score: float,
        timestamp: str,
    ) -> None:
        """Write a high-scoring attack directly to the successful_attacks collection.

        Skips and logs a warning if score is below SUCCESS_THRESHOLD.
        This is the public entry point for agents that want to record a
        confirmed successful attack without going through log_attack.
        """
        if score < SUCCESS_THRESHOLD:
            logger.warning(
                "Attack score %.2f below SUCCESS_THRESHOLD %.2f — skipping successful_attacks log",
                score,
                SUCCESS_THRESHOLD,
            )
            return

        doc_id = f"{self.scan_id}_{component_id}_{domain}_{timestamp}".replace(" ", "_")
        doc_text = payload[:500]
        response_preview = response[:300]

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

        try:
            collection = self._chroma.get_collection(ChromaCollection.SUCCESSFUL_ATTACKS)
            collection.add(
                documents=[doc_text],
                metadatas=[metadata],
                ids=[doc_id],
            )
            logger.info(
                "log_successful_attack: id=%s score=%.2f domain=%s component_type=%s",
                doc_id,
                score,
                domain,
                component_type,
            )
        except Exception as e:
            logger.error("log_successful_attack failed: %s", e)
            raise

    async def get_top_attacks(
        self,
        domain: str,
        component_type: str,
        k: int = TOP_K_RETRIEVAL,
    ) -> list[dict[str, Any]]:
        """Retrieve top-k semantically similar successful attacks for this client.

        Queries the successful_attacks collection (not attack_history) with
        mandatory client_id, domain, and component_type metadata filters.
        Returns results sorted by score descending. Returns empty list on
        no results or any ChromaDB error.
        """
        try:
            collection = self._chroma.get_collection(ChromaCollection.SUCCESSFUL_ATTACKS)
            query_text = f"{domain} {component_type}"

            # Guard: ChromaDB raises if n_results > collection size
            total = collection.count()
            if total == 0:
                return []
            n_results = min(k, total)

            results = collection.query(
                query_texts=[query_text],
                n_results=n_results,
                where={
                    "$and": [
                        {"client_id": {"$eq": self.client_id}},
                        {"domain": {"$eq": domain}},
                        {"component_type": {"$eq": component_type}},
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
                        "component_type": meta.get("component_type", ""),
                        "component_id": meta.get("component_id", ""),
                        "timestamp": meta.get("timestamp", ""),
                        "response_preview": meta.get("response_preview", ""),
                        "distance": distances_list[i],
                    }
                )

            mapped.sort(key=lambda x: x["score"], reverse=True)
            logger.info(
                "get_top_attacks returned %s results for domain=%s component_type=%s",
                len(mapped),
                domain,
                component_type,
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

    async def get_lineage(self, parent_attack_id: str) -> list[dict[str, Any]]:
        """Retrieve the full mutation lineage for a parent attack.

        Returns all mutation_lineage records scoped to this client and
        parent_attack_id, sorted by generation ascending. Uses collection.get()
        with metadata filters — not semantic search.
        """
        collection = self._chroma.get_collection(ChromaCollection.MUTATION_LINEAGE)
        try:
            use_python_parent_filter = False
            try:
                results = collection.get(
                    where={
                        "$and": [
                            {"client_id": {"$eq": self.client_id}},
                            {"parent_attack_id": {"$eq": parent_attack_id}},
                        ]
                    },
                    include=["metadatas", "documents"],
                )
            except chromadb.errors.ChromaError:
                use_python_parent_filter = True
                results = collection.get(
                    where={"client_id": {"$eq": self.client_id}},
                    include=["metadatas", "documents"],
                )

            ids = results.get("ids") or []
            if not ids:
                return []

            documents = results.get("documents") or []
            metadatas = results.get("metadatas") or []

            mapped: list[dict[str, Any]] = []
            for doc_id, document, meta in zip(ids, documents, metadatas):
                if (
                    use_python_parent_filter
                    and meta.get("parent_attack_id") != parent_attack_id
                ):
                    continue
                mapped.append(
                    {
                        "mutation_id": doc_id,
                        "child_payload": document,
                        "parent_attack_id": meta["parent_attack_id"],
                        "strategy": meta["strategy"],
                        "child_score": meta["child_score"],
                        "generation": meta["generation"],
                        "timestamp": meta["timestamp"],
                        "scan_id": meta["scan_id"],
                    }
                )

            mapped.sort(key=lambda x: int(x["generation"]))
            logger.info(
                "Lineage fetched: %s records for parent_attack_id=%s",
                len(mapped),
                parent_attack_id,
            )
            return mapped
        except chromadb.errors.ChromaError as exc:
            logger.error(
                "Failed to fetch lineage for parent_attack_id=%s: %s",
                parent_attack_id,
                exc,
            )
            raise

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

    async def get_cross_component_insights(
        self,
        completed_component_id: str,
        next_component_type: str,
    ) -> list[dict]:
        """
        Queries the vulnerability_catalog for high-severity findings from a
        completed component and returns attack strategy hints relevant to the
        next component type.

        Only findings with severity == Severity.HIGH or Severity.CRITICAL are
        considered. Returns an empty list on any ChromaDB error or if no
        qualifying findings exist.

        Args:
            completed_component_id: The component_id of the just-finished component.
            next_component_type: A ComponentType constant string for the upcoming
                component. Used to select relevant cross-component hint text.

        Returns:
            List of hint dicts, each with keys:
                "hint": str          — the strategy suggestion sentence
                "source_domain": str — the domain where the original vuln was found
                "source_score": float — the score of the original finding
                "severity": str      — Severity constant of the original finding
        """
        try:
            collection = self._chroma.get_collection(ChromaCollection.VULNERABILITY_CATALOG)
            results = collection.get(
                where={
                    "$and": [
                        {"client_id": {"$eq": self.client_id}},
                        {"component_id": {"$eq": completed_component_id}},
                    ]
                },
                include=["metadatas", "documents"]
            )
        except chromadb.errors.ChromaError as exc:
            logger.error("get_cross_component_insights failed: %s", exc)
            return []

        metadatas = results.get("metadatas") or []
        if not metadatas:
            return []

        hints = []
        for meta in metadatas:
            severity = meta.get("severity")
            if severity in (Severity.HIGH, Severity.CRITICAL):
                source_domain = meta.get("domain", "")
                score = float(meta.get("score", 0.0))
                
                key = (source_domain, next_component_type)
                if key in CROSS_COMPONENT_HINT_MAP:
                    hint = CROSS_COMPONENT_HINT_MAP[key]
                else:
                    hint = (
                        f"Prior finding on {completed_component_id} ({source_domain}, score "
                        f"{score:.2f}) — probe {next_component_type} for related weaknesses."
                    )
                
                hints.append({
                    "hint": hint,
                    "source_domain": source_domain,
                    "source_score": score,
                    "severity": severity,
                })

        logger.info(
            "get_cross_component_insights returned %d insights for completed_component_id=%s, next_component_type=%s",
            len(hints), completed_component_id, next_component_type
        )
        return hints
