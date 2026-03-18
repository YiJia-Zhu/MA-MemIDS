from __future__ import annotations

import hashlib
import math
from typing import Iterable, List

from .config import RuntimeConfig
from .utils import tokenize


class HashingEmbedder:
    """Deterministic embedding without external model dependency."""

    def __init__(self, dim: int | None = None):
        cfg = RuntimeConfig()
        self.dim = dim or cfg.embedding_dim

    def _hash(self, token: str) -> tuple[int, float]:
        digest = hashlib.sha256(token.encode("utf-8", errors="ignore")).digest()
        idx = int.from_bytes(digest[:4], "big") % self.dim
        sign = 1.0 if (digest[4] & 1) == 0 else -1.0
        return idx, sign

    def embed(self, text: str) -> List[float]:
        vec = [0.0] * self.dim
        for token in tokenize(text):
            idx, sign = self._hash(token)
            vec[idx] += sign

        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            return vec
        return [v / norm for v in vec]

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
