"""
RAG Engine — Retrieval-Augmented Generation
Loads security runbooks into a FAISS vector store and retrieves
relevant playbook context for each incoming alert.

Author: Sunny Bhardwaj
"""

import glob
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Lazy imports — only load heavy ML libs when needed
_embeddings = None
_vector_store = None
RUNBOOKS_DIR = Path(__file__).parent.parent.parent / "runbooks"
VECTOR_STORE_PATH = Path(__file__).parent.parent.parent / "vector_store"


def _get_embeddings():
    """Lazy-load sentence transformer embeddings."""
    global _embeddings
    if _embeddings is None:
        try:
            from langchain_community.embeddings import HuggingFaceEmbeddings
            _embeddings = HuggingFaceEmbeddings(
                model_name="all-MiniLM-L6-v2",
                model_kwargs={"device": "cpu"},
                encode_kwargs={"normalize_embeddings": True}
            )
            logger.info("Embeddings model loaded: all-MiniLM-L6-v2")
        except Exception as e:
            logger.error(f"Failed to load embeddings: {e}")
            raise
    return _embeddings


def build_vector_store(force_rebuild: bool = False) -> bool:
    """
    Build the FAISS vector store from runbooks.
    Skips rebuild if vector store already exists unless force_rebuild=True.
    """
    global _vector_store

    store_index = VECTOR_STORE_PATH / "index.faiss"

    if not force_rebuild and store_index.exists():
        logger.info("Vector store already exists — loading from disk")
        return load_vector_store()

    logger.info("Building vector store from runbooks...")

    try:
        from langchain_community.vectorstores import FAISS
        from langchain.text_splitter import MarkdownTextSplitter
        from langchain.docstore.document import Document

        runbook_files = glob.glob(str(RUNBOOKS_DIR / "*.md"))
        if not runbook_files:
            logger.warning(f"No runbooks found in {RUNBOOKS_DIR}")
            return False

        documents = []
        splitter = MarkdownTextSplitter(chunk_size=800, chunk_overlap=100)

        for filepath in runbook_files:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            chunks = splitter.split_text(content)
            filename = Path(filepath).stem

            for i, chunk in enumerate(chunks):
                documents.append(Document(
                    page_content=chunk,
                    metadata={
                        "source": filename,
                        "filepath": filepath,
                        "chunk": i
                    }
                ))

        logger.info(f"Loaded {len(runbook_files)} runbooks → {len(documents)} chunks")

        embeddings = _get_embeddings()
        _vector_store = FAISS.from_documents(documents, embeddings)

        # Persist to disk
        VECTOR_STORE_PATH.mkdir(parents=True, exist_ok=True)
        _vector_store.save_local(str(VECTOR_STORE_PATH))
        logger.info(f"Vector store saved to {VECTOR_STORE_PATH}")

        return True

    except Exception as e:
        logger.error(f"Failed to build vector store: {e}")
        return False


def load_vector_store() -> bool:
    """Load vector store from disk."""
    global _vector_store

    try:
        from langchain_community.vectorstores import FAISS

        embeddings = _get_embeddings()
        _vector_store = FAISS.load_local(
            str(VECTOR_STORE_PATH),
            embeddings,
            allow_dangerous_deserialization=True
        )
        logger.info("Vector store loaded from disk")
        return True

    except Exception as e:
        logger.error(f"Failed to load vector store: {e}")
        return False


def retrieve_runbook_context(alert: dict, top_k: int = 3) -> str:
    """
    Retrieve the most relevant runbook sections for a given alert.

    Args:
        alert: The security alert dict
        top_k: Number of chunks to retrieve

    Returns:
        Concatenated runbook context string
    """
    if _vector_store is None:
        logger.warning("Vector store not loaded — building now")
        build_vector_store()

    if _vector_store is None:
        return "No runbook context available."

    # Build a rich query from the alert
    query = (
        f"{alert.get('type', '')} "
        f"{alert.get('title', '')} "
        f"{alert.get('mitre_tactic', '')} "
        f"{alert.get('mitre_technique', '')} "
        f"{alert.get('resource_type', '')}"
    )

    try:
        docs = _vector_store.similarity_search(query, k=top_k)

        if not docs:
            return "No relevant runbook found for this alert type."

        context_parts = []
        seen_sources = set()

        for doc in docs:
            source = doc.metadata.get("source", "unknown")
            if source not in seen_sources:
                context_parts.append(f"### From runbook: {source}\n{doc.page_content}")
                seen_sources.add(source)

        return "\n\n".join(context_parts)

    except Exception as e:
        logger.error(f"RAG retrieval failed: {e}")
        return "Runbook retrieval failed — proceeding without context."


def is_ready() -> bool:
    """Check if the vector store is ready."""
    return _vector_store is not None
