from __future__ import annotations

import os
from pathlib import Path
import logging
import threading
from typing import Any, ClassVar, Iterable, List

from .config import RuntimeConfig

LOGGER = logging.getLogger(__name__)


class SentenceTransformerEmbedder:
    """SentenceTransformer-backed embedder with lazy model download/load."""

    _MODEL_CACHE: ClassVar[dict[tuple[str, str], tuple[object, int, str]]] = {}
    _MODEL_LOCKS: ClassVar[dict[tuple[str, str], threading.Lock]] = {}
    _CACHE_GUARD: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, model_name: str | None = None):
        cfg = RuntimeConfig()
        self.requested_model_name = (
            model_name
            or (os.getenv("MA_MEMIDS_EMBEDDING_MODEL") or "").strip()
            or cfg.embedding_model
        )
        self.model_name, self.model_source = self._resolve_model_name(self.requested_model_name)
        self._dim: int | None = None
        self._model = None
        self.device = (os.getenv("MA_MEMIDS_EMBEDDING_DEVICE") or "").strip()

    @property
    def dim(self) -> int:
        if self._dim is None:
            self._load_model()
        return int(self._dim or 0)

    def metadata(self) -> dict[str, object]:
        return {
            "provider": "sentence-transformers",
            "model_name": self.requested_model_name,
            "resolved_model_name": self.model_name,
            "model_source": self.model_source,
            "device": self.device or "auto",
            "dim": self.dim,
        }

    def _resolve_model_name(self, requested_model_name: str) -> tuple[str, str]:
        requested = str(requested_model_name or "").strip()
        if not requested:
            raise RuntimeError("Embedding model name is empty")

        env_local_dir = (os.getenv("MA_MEMIDS_EMBEDDING_MODEL_DIR") or "").strip()
        if env_local_dir:
            env_path = Path(env_local_dir).expanduser()
            if env_path.exists():
                return str(env_path.resolve()), "env_local_dir"

        requested_path = Path(requested).expanduser()
        if requested_path.exists():
            return str(requested_path.resolve()), "explicit_path"

        model_leaf = requested.rstrip("/").split("/")[-1]
        repo_local = Path(__file__).resolve().parents[1] / "huggingface_models" / model_leaf
        if repo_local.exists():
            return str(repo_local.resolve()), "repo_local_dir"

        return requested, "hf_hub"

    def _load_model(self):
        if self._model is not None:
            return self._model

        cache_key = self._cache_key()
        cached = self._get_cached_model(cache_key)
        if cached is not None:
            self._apply_cached_model(cached)
            return self._model

        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - dependency installation issue
            raise RuntimeError(
                "sentence-transformers is required for embeddings. "
                "Install dependencies with `pip install -r requirements.txt`."
            ) from exc

        load_lock = self._get_model_lock(cache_key)
        with load_lock:
            cached = self._get_cached_model(cache_key)
            if cached is not None:
                self._apply_cached_model(cached)
                return self._model

            load_kwargs: dict[str, Any] = {
                "model_kwargs": {
                    # sentence-transformers 5.x + transformers 4.57 can hit a meta-tensor
                    # code path during concurrent/default loading; force normal materialization.
                    "low_cpu_mem_usage": False,
                }
            }
            if Path(self.model_name).exists():
                load_kwargs["local_files_only"] = True

            attempts: List[tuple[str, dict[str, object]]] = []
            if self.device:
                attempts.append((self.device, {**load_kwargs, "device": self.device}))
            else:
                attempts.append(("auto", dict(load_kwargs)))
                attempts.append(("cpu", {**load_kwargs, "device": "cpu"}))

            last_exc: Exception | None = None
            last_device = "auto"
            for device_name, kwargs in attempts:
                try:
                    model = SentenceTransformer(self.model_name, **kwargs)
                    resolved_device = self._resolve_loaded_device(model, device_name)
                    break
                except Exception as exc:  # pragma: no cover - environment/device specific
                    last_exc = exc
                    last_device = device_name
                    LOGGER.warning(
                        "Embedding model load failed for %s on device=%s (resolved=%s): %s",
                        self.requested_model_name,
                        device_name,
                        self.model_name,
                        exc,
                    )
            else:
                raise RuntimeError(
                    f"Failed to load embedding model '{self.requested_model_name}' "
                    f"(resolved='{self.model_name}', source={self.model_source}, last_device={last_device})."
                ) from last_exc

            dim = model.get_sentence_embedding_dimension()
            if dim is None or int(dim) <= 0:
                raise RuntimeError(f"Embedding model '{self.model_name}' returned an invalid dimension: {dim}")

            cached_model = (model, int(dim), resolved_device)
            self._set_cached_model(cache_key, cached_model)
            self._apply_cached_model(cached_model)
            return self._model

    def _cache_key(self) -> tuple[str, str]:
        return (self.model_name, self.device or "auto")

    @classmethod
    def _get_model_lock(cls, key: tuple[str, str]) -> threading.Lock:
        with cls._CACHE_GUARD:
            lock = cls._MODEL_LOCKS.get(key)
            if lock is None:
                lock = threading.Lock()
                cls._MODEL_LOCKS[key] = lock
            return lock

    @classmethod
    def _get_cached_model(cls, key: tuple[str, str]) -> tuple[object, int, str] | None:
        with cls._CACHE_GUARD:
            return cls._MODEL_CACHE.get(key)

    @classmethod
    def _set_cached_model(cls, key: tuple[str, str], value: tuple[object, int, str]) -> None:
        with cls._CACHE_GUARD:
            cls._MODEL_CACHE[key] = value

    def _apply_cached_model(self, cached: tuple[object, int, str]) -> None:
        model, dim, device = cached
        self._model = model
        self._dim = int(dim)
        self.device = device

    def _resolve_loaded_device(self, model: object, fallback: str) -> str:
        device = getattr(model, "device", None)
        if device is None:
            return fallback
        return str(device) or fallback

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
