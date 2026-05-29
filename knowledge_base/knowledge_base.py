"""Knowledge base interface wrapping ChromaDB collections for Sentinel AI agents."""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any, Optional

from dotenv import load_dotenv
import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

from constants import (
    ChromaCollection,
    EMBEDDING_MODEL,
    SUCCESS_THRESHOLD,
    TOP_K_RETRIEVAL,
)
from knowledge_base.chroma_client import get_chroma_client

load_dotenv()

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """
    Central knowledge base for all Sentinel AI agents.
    Wraps ChromaDB collections with client_id isolation enforced
    on every read and write operation.
    """

    def __init__(self) -> None:
        """
        Initialize ChromaDB client and all required collections.

        IMPORTANT: All collections use SentenceTransformerEmbeddingFunction
        with EMBEDDING_MODEL. Never create a collection without this function —
        dimension mismatch will break all semantic queries in Week 3+.
        """
        try:
            self.client: chromadb.Client = get_chroma_client()
            self._embedding_fn = SentenceTransformerEmbeddingFunction(
                model_name=EMBEDDING_MODEL
            )
            self.attack_history = self.client.get_or_create_collection(
                name=ChromaCollection.ATTACK_HISTORY,
                embedding_function=self._embedding_fn,
            )
            self.successful_attacks = self.client.get_or_create_collection(
                name=ChromaCollection.SUCCESSFUL_ATTACKS,
                embedding_function=self._embedding_fn,
            )
            self.mutation_lineage = self.client.get_or_create_collection(
                name=ChromaCollection.MUTATION_LINEAGE,
                embedding_function=self._embedding_fn,
            )
            self.component_profiles = self.client.get_or_create_collection(
                name=ChromaCollection.COMPONENT_PROFILES,
                embedding_function=self._embedding_fn,
            )
            self.vulnerability_catalog = self.client.get_or_create_collection(
                name=ChromaCollection.VULNERABILITY_CATALOG,
                embedding_function=self._embedding_fn,
            )
            logger.info("KnowledgeBase initialized with all collections")
        except Exception:
            logger.exception("Failed to initialize KnowledgeBase")
            raise

    async def log_attack(
        self,
        client_id: str,
        scan_id: str,
        component_id: str,
        domain: str,
        payload: str,
        response: str,
        score: float,
        timestamp: Optional[str] = None,
    ) -> str:
        """
        Log a single attack attempt to attack_history collection.
        Also logs to successful_attacks if score >= SUCCESS_THRESHOLD.
        Returns the generated attack_id.
        """
        try:
            attack_id: str = str(uuid.uuid4())
            attack_timestamp: str = timestamp or datetime.utcnow().isoformat()
            document: str = f"payload: {payload} | response: {response}"
            metadata: dict[str, Any] = {
                "client_id": client_id,
                "scan_id": scan_id,
                "component_id": component_id,
                "domain": domain,
                "score": score,
                "timestamp": attack_timestamp,
                "attack_id": attack_id,
            }

            await asyncio.to_thread(
                self.attack_history.add,
                documents=[document],
                metadatas=[metadata],
                ids=[attack_id],
            )

            if score >= SUCCESS_THRESHOLD:
                await asyncio.to_thread(
                    self.successful_attacks.add,
                    documents=[document],
                    metadatas=[metadata],
                    ids=[attack_id],
                )
                logger.info("Successful attack logged score=%s", score)

            logger.debug("Attack logged attack_id=%s", attack_id)
            return attack_id
        except Exception:
            logger.exception("Failed to log attack")
            raise

    async def get_top_attacks(
        self,
        client_id: str,
        domain: str,
        component_type: str,
        k: int = TOP_K_RETRIEVAL,
    ) -> list[dict]:
        """
        Retrieve top-k most relevant successful attacks for a given
        domain and component type. Used by AttackAgent before executing attacks.
        Returns list of metadata dicts.
        """
        try:
            results: dict[str, Any] = await asyncio.to_thread(
                self.successful_attacks.query,
                query_texts=[f"{domain} {component_type}"],
                n_results=k,
                where={"client_id": client_id},
                include=["metadatas", "documents", "distances"],
            )
            metadatas: list[list[dict]] | None = results.get("metadatas")
            if not metadatas or not metadatas[0]:
                return []
            return metadatas[0]
        except Exception:
            logger.exception("Failed to retrieve top attacks")
            raise

    async def log_mutation(
        self,
        client_id: str,
        scan_id: str,
        parent_attack_id: str,
        child_payload: str,
        strategy: str,
        child_score: float,
        generation: int,
    ) -> str:
        """
        Log a mutation event to mutation_lineage collection.
        Returns the generated mutation_id.
        """
        try:
            mutation_id: str = str(uuid.uuid4())
            timestamp: str = datetime.utcnow().isoformat()
            document: str = f"strategy: {strategy} | payload: {child_payload}"
            metadata: dict[str, Any] = {
                "client_id": client_id,
                "scan_id": scan_id,
                "parent_attack_id": parent_attack_id,
                "mutation_id": mutation_id,
                "strategy": strategy,
                "child_score": child_score,
                "generation": generation,
                "timestamp": timestamp,
            }

            await asyncio.to_thread(
                self.mutation_lineage.add,
                documents=[document],
                metadatas=[metadata],
                ids=[mutation_id],
            )
            logger.debug(
                "Mutation logged mutation_id=%s strategy=%s",
                mutation_id,
                strategy,
            )
            return mutation_id
        except Exception:
            logger.exception("Failed to log mutation")
            raise

    async def log_vulnerability(
        self,
        client_id: str,
        scan_id: str,
        component_id: str,
        domain: str,
        score: float,
        severity: str,
        description: str,
        remediation: Optional[str] = None,
    ) -> str:
        """
        Log a confirmed vulnerability to vulnerability_catalog collection.
        Returns the generated vulnerability_id.
        """
        try:
            vulnerability_id: str = str(uuid.uuid4())
            timestamp: str = datetime.utcnow().isoformat()
            document: str = f"severity: {severity} | domain: {domain} | {description}"
            metadata: dict[str, Any] = {
                "client_id": client_id,
                "scan_id": scan_id,
                "component_id": component_id,
                "domain": domain,
                "score": score,
                "severity": severity,
                "description": description,
                "remediation": remediation if remediation is not None else "",
                "timestamp": timestamp,
                "vulnerability_id": vulnerability_id,
            }

            await asyncio.to_thread(
                self.vulnerability_catalog.add,
                documents=[document],
                metadatas=[metadata],
                ids=[vulnerability_id],
            )
            logger.info(
                "Vulnerability logged severity=%s component_id=%s",
                severity,
                component_id,
            )
            return vulnerability_id
        except Exception:
            logger.exception("Failed to log vulnerability")
            raise

    async def log_component_profile(
        self,
        client_id: str,
        scan_id: str,
        component_id: str,
        component_type: str,
        endpoint: str,
        framework: Optional[str],
        priority_score: float,
        domains: list[str],
    ) -> str:
        """
        Log a component profile discovered by ReconAgent.
        Returns the generated profile_id.
        """
        try:
            profile_id: str = str(uuid.uuid4())
            timestamp: str = datetime.utcnow().isoformat()
            document: str = (
                f"type: {component_type} | endpoint: {endpoint} | framework: {framework}"
            )
            metadata: dict[str, Any] = {
                "client_id": client_id,
                "scan_id": scan_id,
                "component_id": component_id,
                "component_type": component_type,
                "endpoint": endpoint,
                "framework": framework if framework is not None else "",
                "priority_score": priority_score,
                "domains": str(domains),
                "timestamp": timestamp,
                "profile_id": profile_id,
            }

            await asyncio.to_thread(
                self.component_profiles.add,
                documents=[document],
                metadatas=[metadata],
                ids=[profile_id],
            )
            logger.debug("Component profile logged component_id=%s", component_id)
            return profile_id
        except Exception:
            logger.exception("Failed to log component profile")
            raise

    async def get_component_profiles(
        self,
        client_id: str,
        scan_id: str,
    ) -> list[dict]:
        """
        Retrieve all component profiles for a given scan.
        Used by Orchestrator to build the component list.
        Returns list of metadata dicts.
        """
        try:
            results: dict[str, Any] = await asyncio.to_thread(
                self.component_profiles.query,
                query_texts=[scan_id],
                n_results=100,
                where={"client_id": client_id},
                include=["metadatas"],
            )
            metadatas: list[list[dict]] | None = results.get("metadatas")
            if not metadatas or not metadatas[0]:
                return []
            return metadatas[0]
        except Exception:
            logger.exception("Failed to retrieve component profiles")
            raise

    async def get_vulnerabilities(
        self,
        client_id: str,
        scan_id: str,
    ) -> list[dict]:
        """
        Retrieve all vulnerabilities for a given scan.
        Used by ReportAgent to compile the final report.
        Returns list of metadata dicts.
        """
        try:
            results: dict[str, Any] = await asyncio.to_thread(
                self.vulnerability_catalog.query,
                query_texts=[scan_id],
                n_results=500,
                where={"client_id": client_id},
                include=["metadatas"],
            )
            metadatas: list[list[dict]] | None = results.get("metadatas")
            if not metadatas or not metadatas[0]:
                return []
            return metadatas[0]
        except Exception:
            logger.exception("Failed to retrieve vulnerabilities")
            raise
