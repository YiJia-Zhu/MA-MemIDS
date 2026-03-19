from __future__ import annotations

import os
from typing import Iterable, List

from .config import RuntimeConfig


class SentenceTransformerEmbedder:
    """SentenceTransformer-backed embedder with lazy model download/load."""

    def __init__(self, model_name: str | None = None):
        cfg = RuntimeConfig()
        self.model_name = (
            model_name
            or (os.getenv("MA_MEMIDS_EMBEDDING_MODEL") or "").strip()
            or cfg.embedding_model
        )
        self._dim: int | None = None
        self._model = None

    @property
    def dim(self) -> int:
        if self._dim is None:
            self._load_model()
        return int(self._dim or 0)

    def metadata(self) -> dict[str, object]:
        return {
            "provider": "sentence-transformers",
            "model_name": self.model_name,
            "dim": self.dim,
        }

    def _load_model(self):
        if self._model is not None:
            return self._model

        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - dependency installation issue
            raise RuntimeError(
                "sentence-transformers is required for embeddings. "
                "Install dependencies with `pip install -r requirements.txt`."
            ) from exc

        try:
            model = SentenceTransformer(self.model_name)
        except Exception as exc:  # pragma: no cover - environment/network specific
            raise RuntimeError(
                f"Failed to load embedding model '{self.model_name}'. "
                "SentenceTransformer should auto-download the model on first use if network access is available."
            ) from exc

        dim = model.get_sentence_embedding_dimension()
        if dim is None or int(dim) <= 0:
            raise RuntimeError(f"Embedding model '{self.model_name}' returned an invalid dimension: {dim}")

        self._model = model
        self._dim = int(dim)
        return self._model

    def embed_texts(self, texts: Iterable[str]) -> List[List[float]]:
        items = [str(text or "") for text in texts]
        if not items:
            return []

        blank_indexes = [idx for idx, text in enumerate(items) if not text.strip()]
        nonblank_items = [text for text in items if text.strip()]
        vectors: List[List[float]] = [[0.0] * self.dim for _ in items]
        if not nonblank_items:
            return vectors

        model = self._load_model()
        encoded = model.encode(
            nonblank_items,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        encoded_rows = encoded.tolist()

        encoded_iter = iter(encoded_rows)
        blank_set = set(blank_indexes)
        for idx in range(len(items)):
            if idx in blank_set:
                continue
            vectors[idx] = list(next(encoded_iter))
        return vectors

    def embed(self, text: str) -> List[float]:
        return self.embed_texts([text])[0]

    def serialize_note_fields(
        self,
        intent: str,
        keywords: Iterable[str],
        tactics: Iterable[str],
        knowledge_description: str,
        content: str,
    ) -> str:
        kw = ", ".join(keywords)
        tac = ", ".join(tactics)
        return (
            f"{intent} "
            f"[KW] {kw} "
            f"[TACT] {tac} "
            f"[CVE] {knowledge_description} "
            f"[RULE] {content}"
        )

    def embed_note(
        self,
        intent: str,
        keywords: Iterable[str],
        tactics: Iterable[str],
        knowledge_description: str,
        content: str,
    ) -> List[float]:
        serialized = self.serialize_note_fields(intent, keywords, tactics, knowledge_description, content)
        return self.embed(serialized)
