import logging
from pathlib import Path

import chromadb
from chromadb.utils import embedding_functions

from constants import EMBEDDING_MODEL, ChromaCollection

logger = logging.getLogger(__name__)

_CHROMA_STORE_PATH = str(Path(__file__).resolve().parent.parent / "chroma_store")


class ChromaClientSingleton:
    """Singleton wrapper around the ChromaDB persistent client.

    Initializes all five canonical collections on first instantiation.
    """

    def __init__(self) -> None:
        """Create the persistent ChromaDB client and initialize all collections."""
        self._client = chromadb.PersistentClient(path=_CHROMA_STORE_PATH)
        self._embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=EMBEDDING_MODEL
        )
        self._collections: dict[str, chromadb.Collection] = {}
        self._initialize_collections()
        logger.info("ChromaDB client initialized")

    def _initialize_collections(self) -> None:
        """Creates all five ChromaDB collections if they do not already exist."""
        collection_names = [
            ChromaCollection.ATTACK_HISTORY,
            ChromaCollection.SUCCESSFUL_ATTACKS,
            ChromaCollection.MUTATION_LINEAGE,
            ChromaCollection.COMPONENT_PROFILES,
            ChromaCollection.VULNERABILITY_CATALOG,
        ]
        for name in collection_names:
            try:
                collection = self._client.get_or_create_collection(
                    name=name,
                    embedding_function=self._embedding_fn,
                )
            except chromadb.errors.ChromaError as exc:
                logger.error("Failed to initialize collection %s: %s", name, exc)
                raise
            self._collections[name] = collection
            logger.info(f"Collection ready: {name}")

    def get_collection(self, name: str) -> chromadb.Collection:
        """Returns the named collection. Raises ValueError for unknown names."""
        if name not in self._collections:
            raise ValueError(
                f"Unknown collection: {name}. Must be a ChromaCollection constant."
            )
        return self._collections[name]

    def get_or_create_collection(self, name: str) -> chromadb.Collection:
        """Return an existing collection (initialized at client startup)."""
        return self.get_collection(name)

    def reset_client_data(self, client_id: str) -> None:
        """Deletes all documents belonging to client_id across all five collections."""
        logger.warning(f"Resetting all ChromaDB data for client: {client_id}")
        for collection in self._collections.values():
            try:
                result = collection.get(where={"client_id": client_id})
                ids = result.get("ids") or []
                if ids:
                    collection.delete(ids=ids)
                    logger.info(
                        f"Deleted {len(ids)} documents from {collection.name}"
                    )
            except chromadb.errors.ChromaError as exc:
                logger.error(
                    "Failed to reset data in collection %s for client %s: %s",
                    collection.name,
                    client_id,
                    exc,
                )
                raise


_instance: ChromaClientSingleton | None = None


def get_chroma_client() -> ChromaClientSingleton:
    """Returns the module-level ChromaDB singleton, creating it on first call."""
    global _instance
    if _instance is None:
        _instance = ChromaClientSingleton()
        logger.info("ChromaDB singleton created")
    return _instance
