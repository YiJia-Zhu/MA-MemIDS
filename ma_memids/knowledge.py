from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

try:
    import numpy as np
except ImportError:  # pragma: no cover - optional dependency guard
    np = None

from .config import RuntimeConfig
from .embedding import SentenceTransformerEmbedder
from .models import EnrichedKnowledge, ExternalDoc, RetrievedItem
from .utils import dedupe_keep_order


LOGGER = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
WORD_RE = re.compile(r"[A-Za-z0-9]+")
BUILD_VERSION = 3
DEFAULT_RRF_K = 60
DEFAULT_COMPONENT_TOP_K = 5
EMBED_BATCH_SIZE = 128
SQLITE_TIMEOUT = 60.0
PROGRESS_FILE_BATCH = 100
PROGRESS_DOC_BATCH = 256
ProgressCallback = Callable[[Dict[str, object]], None]


@dataclass
class NormalizedDoc:
    doc_id: str
    title: str
    text: str
    metadata: Dict[str, object]
    aliases: List[str]

    def search_text(self) -> str:
        parts = [self.doc_id, self.title, self.text] + list(self.aliases)
        return _collapse_ws("\n".join(part for part in parts if str(part or "").strip()))


@dataclass
class SparseHit:
    rowid: int
    rank: int


@dataclass
class DenseHit:
    rowid: int
    rank: int
    score: float


@dataclass
class FusedHit:
    rowid: int
    score: float
    hit_type: str


@dataclass
class CacheSpec:
    cache_dir: Path
    db_path: Path
    dense_path: Path
    manifest_path: Path
    hnsw_path: Path


class KnowledgeSourceIndex:
    def __init__(
        self,
        *,
        source: str,
        embedder: SentenceTransformerEmbedder,
        cache_root: Path,
        top_k: int,
        sparse_k: int,
        dense_k: int,
        rrf_k: int,
    ):
        self.source = source
        self.embedder = embedder
        self.cache_root = cache_root
        self.top_k = top_k
        self.sparse_k = sparse_k
        self.dense_k = dense_k
        self.rrf_k = rrf_k

        self.doc_count = 0
        self.dim = 0
        self.backend = "none"
        self.input_path = ""
        self._conn: Optional[sqlite3.Connection] = None
        self._dense_matrix = None
        self._doc_cache: Dict[int, ExternalDoc] = {}
        self._hnsw_index = None
        self._hnsw_reason = "not_built"

    @classmethod
    def from_path(
        cls,
        *,
        source: str,
        path: str,
        embedder: SentenceTransformerEmbedder,
        cache_root: Path,
        top_k: int,
        sparse_k: int,
        dense_k: int,
        rrf_k: int,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> "KnowledgeSourceIndex":
        index = cls(
            source=source,
            embedder=embedder,
            cache_root=cache_root,
            top_k=top_k,
            sparse_k=sparse_k,
            dense_k=dense_k,
            rrf_k=rrf_k,
        )
        index._load_or_build_from_path(Path(path), progress_callback=progress_callback)
        return index

    @classmethod
    def from_docs(
        cls,
        *,
        source: str,
        docs: Sequence[ExternalDoc],
        embedder: SentenceTransformerEmbedder,
        cache_root: Path,
        top_k: int,
        sparse_k: int,
        dense_k: int,
        rrf_k: int,
    ) -> "KnowledgeSourceIndex":
        index = cls(
            source=source,
            embedder=embedder,
            cache_root=cache_root,
            top_k=top_k,
            sparse_k=sparse_k,
            dense_k=dense_k,
            rrf_k=rrf_k,
        )
        normalized = [
            NormalizedDoc(
                doc_id=doc.doc_id,
                title=doc.title,
                text=doc.text,
                metadata=dict(doc.metadata or {}),
                aliases=[doc.doc_id, _identifier_compact(doc.doc_id)],
            )
            for doc in docs
        ]
        cache_spec = index._cache_spec_for_label(f"builtin:{source}:{embedder.model_name}:{BUILD_VERSION}")
        manifest = {
            "version": BUILD_VERSION,
            "source": source,
            "input_path": f"builtin:{source}",
            "embedding_model": embedder.model_name,
            "embedding_dim": embedder.dim,
            "doc_count": len(normalized),
            "sparse_k": sparse_k,
            "dense_k": dense_k,
            "rrf_k": rrf_k,
            "builder": "builtin_docs",
        }
        current = index._read_manifest(cache_spec)
        if current is None or any(current.get(key) != value for key, value in manifest.items()):
            index._build_cache(cache_spec, normalized, manifest)
        index._open_cache(cache_spec)
        return index

    def stats(self) -> Dict[str, object]:
        return {
            "source": self.source,
            "input_path": self.input_path,
            "doc_count": self.doc_count,
            "embedding_dim": self.dim,
            "backend": self.backend,
            "sparse_k": self.sparse_k,
            "dense_k": self.dense_k,
            "top_k": self.top_k,
            "rrf_k": self.rrf_k,
            "hnsw_reason": self._hnsw_reason,
        }

    def retrieve(self, text: str) -> Tuple[List[RetrievedItem], Dict[str, object]]:
        if not text.strip() or self.doc_count <= 0:
            return [], {"source": self.source, "doc_count": self.doc_count, "sparse_hits": [], "dense_hits": [], "fused_hits": []}

        sparse_hits = self._sparse_search(text)
        dense_hits = self._dense_search(text)
        fused_hits = self._rrf_fuse(sparse_hits, dense_hits)

        items: List[RetrievedItem] = []
        for hit in fused_hits[: self.top_k]:
            doc = self._get_doc(hit.rowid)
            if doc is None:
                continue
            items.append(RetrievedItem(doc=doc, score=hit.score, hit_type=hit.hit_type))

        debug = {
            "source": self.source,
            "doc_count": self.doc_count,
            "sparse_hits": [
                {"doc_id": self._safe_doc_id(hit.rowid), "rank": hit.rank}
                for hit in sparse_hits
            ],
            "dense_hits": [
                {"doc_id": self._safe_doc_id(hit.rowid), "rank": hit.rank, "score": round(float(hit.score), 6)}
                for hit in dense_hits
            ],
            "fused_hits": [
                {"doc_id": self._safe_doc_id(hit.rowid), "rank": rank + 1, "score": round(float(hit.score), 6), "hit_type": hit.hit_type}
                for rank, hit in enumerate(fused_hits[: self.top_k])
            ],
        }
        return items, debug

    def _load_or_build_from_path(self, path: Path, progress_callback: Optional[ProgressCallback] = None) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Knowledge path not found: {path}")

        _emit_progress(progress_callback, event="source_start", source=self.source, path=str(path.resolve()))
        signature = self._input_signature(path)
        cache_spec = self._cache_spec_for_label(signature)
        manifest = self._read_manifest(cache_spec)

        expected = {
            "version": BUILD_VERSION,
            "source": self.source,
            "input_path": str(path.resolve()),
            "input_signature": signature,
            "embedding_model": self.embedder.model_name,
            "embedding_dim": self.embedder.dim,
            "sparse_k": self.sparse_k,
            "dense_k": self.dense_k,
            "rrf_k": self.rrf_k,
        }

        force_rebuild = (os.getenv("MA_MEMIDS_REBUILD_KNOWLEDGE_INDEX") or "").strip().lower() in {"1", "true", "yes", "on"}
        if force_rebuild or not manifest or any(manifest.get(key) != value for key, value in expected.items()):
            LOGGER.info("Building knowledge cache for %s from %s", self.source, path)
            _emit_progress(progress_callback, event="stage", source=self.source, stage="normalize", message="Normalizing source documents")
            normalized = list(self._iter_normalized_docs(path, progress_callback=progress_callback))
            _emit_progress(
                progress_callback,
                event="stage",
                source=self.source,
                stage="normalize",
                message=f"Normalized {len(normalized)} documents",
            )
            payload = dict(expected)
            payload["doc_count"] = len(normalized)
            payload["builder"] = self._detect_builder(path)
            self._build_cache(cache_spec, normalized, payload, progress_callback=progress_callback)
        else:
            LOGGER.info("Reusing cached knowledge index for %s from %s", self.source, path)
            _emit_progress(
                progress_callback,
                event="cache_reuse",
                source=self.source,
                path=str(path.resolve()),
                doc_count=int(manifest.get("doc_count") or 0),
            )

        self._open_cache(cache_spec)
        _emit_progress(
            progress_callback,
            event="source_done",
            source=self.source,
            path=self.input_path,
            doc_count=self.doc_count,
        )

    def _detect_builder(self, path: Path) -> str:
        if self.source == "attack" and _looks_like_attack_source(path):
            return "attack_stix"
        if self.source == "cve" and _looks_like_cve_source(path):
            return "cve_json"
        return "generic_json"

    def _build_cache(
        self,
        cache_spec: CacheSpec,
        docs: Sequence[NormalizedDoc],
        manifest: Dict[str, object],
        progress_callback: Optional[ProgressCallback] = None,
    ) -> None:
        tmp_suffix = f".{cache_spec.cache_dir.name}.tmp.{os.getpid()}.{os.urandom(4).hex()}"
        tmp_dir = cache_spec.cache_dir.parent / tmp_suffix
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir)
        tmp_dir.mkdir(parents=True, exist_ok=True)

        tmp_spec = CacheSpec(
            cache_dir=tmp_dir,
            db_path=tmp_dir / cache_spec.db_path.name,
            dense_path=tmp_dir / cache_spec.dense_path.name,
            manifest_path=tmp_dir / cache_spec.manifest_path.name,
            hnsw_path=tmp_dir / cache_spec.hnsw_path.name,
        )

        conn = sqlite3.connect(tmp_spec.db_path, timeout=SQLITE_TIMEOUT)
        try:
            self._init_sqlite_schema(conn)
            _emit_progress(progress_callback, event="stage", source=self.source, stage="sparse", message="Building SQLite / BM25 index")
            self._insert_docs(conn, docs, progress_callback=progress_callback, progress_stage="sparse")
            if len(docs) > 0:
                _emit_progress(progress_callback, event="stage", source=self.source, stage="dense", message="Building dense embedding cache")
                self._build_dense_matrix(conn, tmp_spec.dense_path, len(docs), progress_callback=progress_callback)
            else:
                tmp_spec.dense_path.write_bytes(b"")
            if np is not None and len(docs) > 0:
                _emit_progress(progress_callback, event="stage", source=self.source, stage="hnsw", message="Building HNSW index")
                self._try_build_hnsw(tmp_spec, len(docs), self.embedder.dim)
                _emit_progress(progress_callback, event="stage", source=self.source, stage="hnsw", message="HNSW index ready")
        finally:
            conn.close()

        manifest_out = dict(manifest)
        manifest_out["doc_count"] = len(docs)
        manifest_out["dense_dtype"] = "float32"
        manifest_out["hnsw_present"] = tmp_spec.hnsw_path.exists()
        tmp_spec.manifest_path.write_text(json.dumps(manifest_out, ensure_ascii=False, indent=2), encoding="utf-8")

        if cache_spec.cache_dir.exists():
            shutil.rmtree(cache_spec.cache_dir)
        tmp_dir.rename(cache_spec.cache_dir)

    def _try_build_hnsw(self, cache_spec: CacheSpec, doc_count: int, dim: int) -> None:
        if doc_count <= 0 or np is None:
            return
        try:
            import hnswlib  # type: ignore
        except Exception:
            return

        try:
            matrix = np.memmap(cache_spec.dense_path, dtype=np.float32, mode="r", shape=(doc_count, dim))
            index = hnswlib.Index(space="cosine", dim=dim)
            index.init_index(max_elements=max(1, doc_count), ef_construction=120, M=16)
            labels = np.arange(doc_count, dtype=np.int32)
            index.add_items(np.asarray(matrix, dtype=np.float32), labels)
            index.set_ef(max(64, self.dense_k))
            index.save_index(str(cache_spec.hnsw_path))
        except Exception as exc:  # pragma: no cover - optional acceleration path
            LOGGER.warning("Failed to build knowledge HNSW index for %s: %s", self.source, exc)
            try:
                if cache_spec.hnsw_path.exists():
                    cache_spec.hnsw_path.unlink()
            except OSError:
                pass

    def _open_cache(self, cache_spec: CacheSpec) -> None:
        manifest = self._read_manifest(cache_spec)
        if manifest is None:
            raise RuntimeError(f"Knowledge manifest missing for {self.source}: {cache_spec.manifest_path}")

        self.input_path = str(manifest.get("input_path") or "")
        self.doc_count = int(manifest.get("doc_count") or 0)
        self.dim = int(manifest.get("embedding_dim") or 0)
        self.backend = "hybrid_rrf"
        self._doc_cache = {}
        self._conn = sqlite3.connect(cache_spec.db_path, timeout=SQLITE_TIMEOUT)
        self._conn.row_factory = sqlite3.Row

        if np is None:
            raise RuntimeError("numpy is required for dense retrieval")
        if self.doc_count > 0 and self.dim > 0:
            self._dense_matrix = np.memmap(cache_spec.dense_path, dtype=np.float32, mode="r", shape=(self.doc_count, self.dim))
        else:
            self._dense_matrix = None
        self._hnsw_index = None
        self._hnsw_reason = "not_available"
        if self.doc_count <= 0 or self.dim <= 0:
            self._hnsw_reason = "no_docs"
        elif cache_spec.hnsw_path.exists():
            try:
                import hnswlib  # type: ignore

                self._hnsw_index = hnswlib.Index(space="cosine", dim=self.dim)
                self._hnsw_index.load_index(str(cache_spec.hnsw_path), max_elements=max(1, self.doc_count))
                self._hnsw_index.set_ef(max(64, self.dense_k))
                self._hnsw_reason = "ready"
            except Exception as exc:  # pragma: no cover - optional acceleration path
                self._hnsw_reason = f"load_failed:{type(exc).__name__}"
                LOGGER.warning("Failed to load knowledge HNSW index for %s: %s", self.source, exc)
        else:
            self._hnsw_reason = "exact_dense_scan"

    def _sparse_search(self, text: str) -> List[SparseHit]:
        if self._conn is None:
            return []
        terms = _query_terms(text)
        if not terms:
            return []
        query = " OR ".join(f'"{term}"' for term in terms)
        try:
            rows = self._conn.execute(
                "SELECT rowid, bm25(docs_fts) AS bm25_score "
                "FROM docs_fts WHERE docs_fts MATCH ? ORDER BY bm25_score LIMIT ?",
                (query, self.sparse_k),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            LOGGER.warning("Sparse retrieval failed for %s query=%r: %s", self.source, query, exc)
            return []

        return [SparseHit(rowid=int(row["rowid"]), rank=rank + 1) for rank, row in enumerate(rows)]

    def _dense_search(self, text: str) -> List[DenseHit]:
        if self.doc_count <= 0 or np is None or self._dense_matrix is None:
            return []

        query = np.asarray(self.embedder.embed(text), dtype=np.float32)
        if query.size == 0:
            return []

        if self._hnsw_index is not None:
            try:
                limit = min(self.dense_k, self.doc_count)
                labels, distances = self._hnsw_index.knn_query(np.asarray([query], dtype=np.float32), k=limit)
                hits: List[DenseHit] = []
                for rank, (label, distance) in enumerate(zip(labels[0], distances[0]), start=1):
                    score = 1.0 - float(distance)
                    if score <= 0.0:
                        continue
                    hits.append(DenseHit(rowid=int(label) + 1, rank=rank, score=score))
                return hits
            except Exception as exc:  # pragma: no cover - optional acceleration path
                self._hnsw_reason = f"query_failed:{type(exc).__name__}"
                LOGGER.warning("Dense HNSW query failed for %s: %s", self.source, exc)

        scores = self._dense_matrix @ query
        limit = min(self.dense_k, self.doc_count)
        if limit <= 0:
            return []
        idx = np.argpartition(scores, -limit)[-limit:]
        idx = idx[np.argsort(scores[idx])[::-1]]
        hits: List[DenseHit] = []
        for rank, pos in enumerate(idx, start=1):
            score = float(scores[pos])
            if score <= 0.0:
                continue
            hits.append(DenseHit(rowid=int(pos) + 1, rank=rank, score=score))
        return hits

    def _rrf_fuse(self, sparse_hits: Sequence[SparseHit], dense_hits: Sequence[DenseHit]) -> List[FusedHit]:
        fused: Dict[int, float] = {}
        hit_types: Dict[int, set[str]] = {}

        for hit in sparse_hits:
            fused[hit.rowid] = fused.get(hit.rowid, 0.0) + (1.0 / (self.rrf_k + hit.rank))
            hit_types.setdefault(hit.rowid, set()).add("sparse")

        for hit in dense_hits:
            fused[hit.rowid] = fused.get(hit.rowid, 0.0) + (1.0 / (self.rrf_k + hit.rank))
            hit_types.setdefault(hit.rowid, set()).add("dense")

        ranked = sorted(fused.items(), key=lambda item: (item[1], item[0]), reverse=True)
        out: List[FusedHit] = []
        for rowid, score in ranked:
            modes = sorted(hit_types.get(rowid, set()))
            hit_type = "rrf_" + "_".join(modes) if modes else "rrf"
            out.append(FusedHit(rowid=rowid, score=score, hit_type=hit_type))
        return out

    def _get_doc(self, rowid: int) -> Optional[ExternalDoc]:
        cached = self._doc_cache.get(rowid)
        if cached is not None:
            return cached
        if self._conn is None:
            return None
        row = self._conn.execute(
            "SELECT doc_id, title, text, metadata_json FROM docs WHERE rowid = ?",
            (rowid,),
        ).fetchone()
        if row is None:
            return None
        metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        doc = ExternalDoc(
            doc_id=str(row["doc_id"]),
            source=self.source,
            title=str(row["title"]),
            text=str(row["text"]),
            metadata=metadata if isinstance(metadata, dict) else {},
        )
        self._doc_cache[rowid] = doc
        return doc

    def _safe_doc_id(self, rowid: int) -> str:
        doc = self._get_doc(rowid)
        return doc.doc_id if doc is not None else f"rowid:{rowid}"

    def _init_sqlite_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            "CREATE TABLE docs ("
            "doc_id TEXT PRIMARY KEY, "
            "title TEXT NOT NULL, "
            "text TEXT NOT NULL, "
            "search_text TEXT NOT NULL, "
            "metadata_json TEXT NOT NULL"
            ")"
        )
        conn.execute(
            "CREATE VIRTUAL TABLE docs_fts USING fts5("
            "doc_id, title, search_text, tokenize='unicode61 remove_diacritics 2'"
            ")"
        )
        conn.execute("CREATE INDEX idx_docs_doc_id ON docs(doc_id)")

    def _insert_docs(
        self,
        conn: sqlite3.Connection,
        docs: Sequence[NormalizedDoc],
        progress_callback: Optional[ProgressCallback] = None,
        progress_stage: str = "sparse",
    ) -> None:
        _emit_progress(
            progress_callback,
            event="progress_start",
            source=self.source,
            stage=progress_stage,
            total=len(docs),
            unit="doc",
        )
        pending = 0
        for doc in docs:
            cursor = conn.execute(
                "INSERT INTO docs(doc_id, title, text, search_text, metadata_json) VALUES (?, ?, ?, ?, ?)",
                (
                    doc.doc_id,
                    doc.title,
                    doc.text,
                    doc.search_text(),
                    json.dumps(doc.metadata, ensure_ascii=False),
                ),
            )
            rowid = cursor.lastrowid
            conn.execute(
                "INSERT INTO docs_fts(rowid, doc_id, title, search_text) VALUES (?, ?, ?, ?)",
                (rowid, doc.doc_id, doc.title, doc.search_text()),
            )
            pending += 1
            if pending >= PROGRESS_DOC_BATCH:
                _emit_progress(
                    progress_callback,
                    event="progress_update",
                    source=self.source,
                    stage=progress_stage,
                    advance=pending,
                )
                pending = 0
        conn.commit()
        if pending > 0:
            _emit_progress(
                progress_callback,
                event="progress_update",
                source=self.source,
                stage=progress_stage,
                advance=pending,
            )
        _emit_progress(
            progress_callback,
            event="progress_end",
            source=self.source,
            stage=progress_stage,
            total=len(docs),
        )

    def _build_dense_matrix(
        self,
        conn: sqlite3.Connection,
        dense_path: Path,
        doc_count: int,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> None:
        if np is None:
            raise RuntimeError("numpy is required for dense retrieval")
        matrix = np.memmap(dense_path, dtype=np.float32, mode="w+", shape=(doc_count, self.embedder.dim))
        rows = conn.execute("SELECT rowid, title, text FROM docs ORDER BY rowid").fetchall()
        batch_texts: List[str] = []
        batch_rowids: List[int] = []
        _emit_progress(
            progress_callback,
            event="progress_start",
            source=self.source,
            stage="dense",
            total=doc_count,
            unit="doc",
        )

        def _flush() -> None:
            if not batch_texts:
                return
            vectors = self.embedder.embed_texts(batch_texts)
            arr = np.asarray(vectors, dtype=np.float32)
            for local_idx, rowid in enumerate(batch_rowids):
                matrix[rowid - 1] = arr[local_idx]
            _emit_progress(
                progress_callback,
                event="progress_update",
                source=self.source,
                stage="dense",
                advance=len(batch_rowids),
            )
            batch_texts.clear()
            batch_rowids.clear()

        for row in rows:
            batch_rowids.append(int(row[0]))
            batch_texts.append(f"{row[1]}\n{row[2]}")
            if len(batch_texts) >= EMBED_BATCH_SIZE:
                _flush()
        _flush()
        matrix.flush()
        _emit_progress(
            progress_callback,
            event="progress_end",
            source=self.source,
            stage="dense",
            total=doc_count,
        )

    def _cache_spec_for_label(self, label: str) -> CacheSpec:
        digest = hashlib.sha256(label.encode("utf-8", errors="ignore")).hexdigest()[:16]
        cache_dir = self.cache_root / self.source / digest
        return CacheSpec(
            cache_dir=cache_dir,
            db_path=cache_dir / "docs.sqlite3",
            dense_path=cache_dir / "dense.f32",
            manifest_path=cache_dir / "manifest.json",
            hnsw_path=cache_dir / "dense.hnsw.bin",
        )

    def _input_signature(self, path: Path) -> str:
        stat = path.stat()
        payload = {
            "path": str(path.resolve()),
            "is_dir": path.is_dir(),
            "mtime_ns": stat.st_mtime_ns,
            "size": stat.st_size,
            "builder": self._detect_builder(path),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def _read_manifest(self, cache_spec: CacheSpec) -> Optional[Dict[str, object]]:
        if not cache_spec.manifest_path.exists():
            return None
        try:
            raw = json.loads(cache_spec.manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        return raw if isinstance(raw, dict) else None

    def _iter_normalized_docs(self, path: Path, progress_callback: Optional[ProgressCallback] = None) -> Iterator[NormalizedDoc]:
        if self.source == "attack" and _looks_like_attack_source(path):
            yield from _iter_attack_docs(path, progress_callback=progress_callback, source=self.source)
            return
        if self.source == "cve" and _looks_like_cve_source(path):
            yield from _iter_cve_docs(path, progress_callback=progress_callback, source=self.source)
            return
        yield from _iter_generic_docs(path, progress_callback=progress_callback, source=self.source)


class DualPathRetriever:
    def __init__(
        self,
        embedder: SentenceTransformerEmbedder,
        cache_dir: Optional[str] = None,
        top_k: Optional[int] = None,
        sparse_k: Optional[int] = None,
        dense_k: Optional[int] = None,
        rrf_k: Optional[int] = None,
    ):
        cfg = RuntimeConfig()
        self.embedder = embedder
        self.top_k = top_k or cfg.knowledge_top_k
        self.sparse_k = sparse_k or getattr(cfg, "knowledge_sparse_k", DEFAULT_COMPONENT_TOP_K)
        self.dense_k = dense_k or getattr(cfg, "knowledge_dense_k", DEFAULT_COMPONENT_TOP_K)
        self.rrf_k = rrf_k or getattr(cfg, "knowledge_rrf_k", DEFAULT_RRF_K)
        self.cache_root = Path(
            cache_dir
            or (os.getenv("MA_MEMIDS_KNOWLEDGE_CACHE_DIR") or "").strip()
            or "./memory/knowledge_cache"
        )
        self.cache_root.mkdir(parents=True, exist_ok=True)

        self._indexes: Dict[str, KnowledgeSourceIndex] = {
            "cve": KnowledgeSourceIndex(
                source="cve",
                embedder=embedder,
                cache_root=self.cache_root,
                top_k=self.top_k,
                sparse_k=self.sparse_k,
                dense_k=self.dense_k,
                rrf_k=self.rrf_k,
            ),
            "attack": KnowledgeSourceIndex.from_docs(
                source="attack",
                docs=_default_attack_docs(),
                embedder=embedder,
                cache_root=self.cache_root,
                top_k=self.top_k,
                sparse_k=self.sparse_k,
                dense_k=self.dense_k,
                rrf_k=self.rrf_k,
            ),
            "cti": KnowledgeSourceIndex(
                source="cti",
                embedder=embedder,
                cache_root=self.cache_root,
                top_k=self.top_k,
                sparse_k=self.sparse_k,
                dense_k=self.dense_k,
                rrf_k=self.rrf_k,
            ),
        }

    def load_knowledge(
        self,
        cve_path: Optional[str] = None,
        attack_path: Optional[str] = None,
        cti_path: Optional[str] = None,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> None:
        if cve_path:
            self._indexes["cve"] = KnowledgeSourceIndex.from_path(
                source="cve",
                path=cve_path,
                embedder=self.embedder,
                cache_root=self.cache_root,
                top_k=self.top_k,
                sparse_k=self.sparse_k,
                dense_k=self.dense_k,
                rrf_k=self.rrf_k,
                progress_callback=progress_callback,
            )
        if attack_path:
            self._indexes["attack"] = KnowledgeSourceIndex.from_path(
                source="attack",
                path=attack_path,
                embedder=self.embedder,
                cache_root=self.cache_root,
                top_k=self.top_k,
                sparse_k=self.sparse_k,
                dense_k=self.dense_k,
                rrf_k=self.rrf_k,
                progress_callback=progress_callback,
            )
        if cti_path:
            self._indexes["cti"] = KnowledgeSourceIndex.from_path(
                source="cti",
                path=cti_path,
                embedder=self.embedder,
                cache_root=self.cache_root,
                top_k=self.top_k,
                sparse_k=self.sparse_k,
                dense_k=self.dense_k,
                rrf_k=self.rrf_k,
                progress_callback=progress_callback,
            )

    def retrieve(self, text: str) -> EnrichedKnowledge:
        explicit_cves = dedupe_keep_order(m.group(0).upper() for m in CVE_RE.finditer(text))
        explicit_techs = dedupe_keep_order(m.group(0).upper() for m in TECH_RE.finditer(text))

        cve_items, cve_debug = self._indexes["cve"].retrieve(text)
        attack_items, attack_debug = self._indexes["attack"].retrieve(text)
        cti_items, cti_debug = self._indexes["cti"].retrieve(text)

        all_cve_ids = set(explicit_cves)
        all_tech_ids = set(explicit_techs)
        for item in cve_items + cti_items:
            all_cve_ids.update(m.group(0).upper() for m in CVE_RE.finditer(f"{item.doc.doc_id} {item.doc.title} {item.doc.text}"))
        for item in attack_items + cti_items:
            all_tech_ids.update(m.group(0).upper() for m in TECH_RE.finditer(f"{item.doc.doc_id} {item.doc.title} {item.doc.text}"))

        return EnrichedKnowledge(
            cve_docs=cve_items,
            attack_docs=attack_items,
            cti_docs=cti_items,
            cve_ids=sorted(all_cve_ids),
            tech_ids=sorted(all_tech_ids),
            debug={
                "query_terms": _query_terms(text)[:30],
                "retrieval": {
                    "cve": cve_debug,
                    "attack": attack_debug,
                    "cti": cti_debug,
                },
                "rrf_k": self.rrf_k,
                "sparse_k": self.sparse_k,
                "dense_k": self.dense_k,
                "top_k": self.top_k,
            },
        )

    def stats(self) -> Dict[str, object]:
        return {
            "mode": "hybrid_rrf",
            "sparse": {"backend": "sqlite_fts5_bm25", "top_k": self.sparse_k},
            "dense": {"backend": "sentence-transformers", "top_k": self.dense_k, "embedding_model": self.embedder.model_name},
            "fusion": {"method": "rrf", "k": self.rrf_k, "top_k": self.top_k},
            "sources": {name: index.stats() for name, index in self._indexes.items()},
        }


def _default_attack_docs() -> List[ExternalDoc]:
    return [
        ExternalDoc(
            doc_id="T1190",
            source="attack",
            title="Exploit Public-Facing Application",
            text="Adversaries exploit vulnerabilities in public-facing web services to gain initial access.",
            metadata={"url": "https://attack.mitre.org/techniques/T1190/"},
        ),
        ExternalDoc(
            doc_id="T1059",
            source="attack",
            title="Command and Scripting Interpreter",
            text="Adversaries execute commands and scripts in command interpreters for execution.",
            metadata={"url": "https://attack.mitre.org/techniques/T1059/"},
        ),
        ExternalDoc(
            doc_id="T1027",
            source="attack",
            title="Obfuscated/Compressed Files and Information",
            text="Adversaries may obfuscate payloads to evade signature-based detections.",
            metadata={"url": "https://attack.mitre.org/techniques/T1027/"},
        ),
    ]


def _looks_like_attack_source(path: Path) -> bool:
    if path.is_file() and path.suffix.lower() == ".json":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return False
        return isinstance(raw, dict) and isinstance(raw.get("objects"), list)
    if path.is_dir():
        return any(child.name.endswith("-attack.json") for child in path.iterdir() if child.is_file())
    return False


def _looks_like_cve_source(path: Path) -> bool:
    if path.is_file() and path.suffix.lower() == ".json":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return False
        return isinstance(raw, dict) and isinstance(raw.get("cveMetadata"), dict)
    if path.is_dir():
        return any(path.rglob("CVE-*.json"))
    return False


def _iter_attack_docs(
    path: Path,
    progress_callback: Optional[ProgressCallback] = None,
    source: str = "attack",
) -> Iterator[NormalizedDoc]:
    files: List[Path]
    if path.is_dir():
        files = sorted([child for child in path.iterdir() if child.is_file() and child.name.endswith("-attack.json")])
    else:
        files = [path]

    _emit_progress(progress_callback, event="progress_start", source=source, stage="normalize", total=len(files), unit="file")
    merged: Dict[str, Dict[str, object]] = {}
    pending = 0
    for file_path in files:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
        for obj in raw.get("objects", []):
            if not isinstance(obj, dict):
                continue
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            technique_id = _extract_attack_external_id(obj)
            if not technique_id:
                continue

            description = _collapse_ws(str(obj.get("description") or ""))
            title = _collapse_ws(str(obj.get("name") or technique_id))
            tactics = [
                str(phase.get("phase_name") or "").strip()
                for phase in (obj.get("kill_chain_phases") or [])
                if isinstance(phase, dict) and str(phase.get("phase_name") or "").strip()
            ]
            platforms = [str(x).strip() for x in (obj.get("x_mitre_platforms") or []) if str(x).strip()]
            data_sources = [str(x).strip() for x in (obj.get("x_mitre_data_sources") or []) if str(x).strip()]
            aliases = [title, technique_id, _identifier_compact(technique_id)]
            aliases.extend(_extract_attack_aliases(obj))

            text = _join_sections(
                ("description", description),
                ("tactics", ", ".join(dedupe_keep_order(tactics))),
                ("platforms", ", ".join(dedupe_keep_order(platforms))),
                ("data_sources", ", ".join(dedupe_keep_order(data_sources))),
            )
            domain = file_path.stem.replace("-attack", "")
            metadata = {
                "stix_id": obj.get("id"),
                "domains": [domain],
                "tactics": dedupe_keep_order(tactics),
                "platforms": dedupe_keep_order(platforms),
                "data_sources": dedupe_keep_order(data_sources),
                "external_references": obj.get("external_references") or [],
            }

            prev = merged.get(technique_id)
            if prev is None:
                merged[technique_id] = {
                    "doc_id": technique_id,
                    "title": title,
                    "text_parts": [text],
                    "aliases": dedupe_keep_order([alias for alias in aliases if alias]),
                    "metadata": metadata,
                }
                continue

            prev["text_parts"] = dedupe_keep_order(list(prev.get("text_parts", [])) + [text])
            prev["aliases"] = dedupe_keep_order(list(prev.get("aliases", [])) + [alias for alias in aliases if alias])
            prev_meta = prev.get("metadata") if isinstance(prev.get("metadata"), dict) else {}
            prev_meta["domains"] = dedupe_keep_order(list(prev_meta.get("domains", [])) + [domain])
            prev_meta["tactics"] = dedupe_keep_order(list(prev_meta.get("tactics", [])) + dedupe_keep_order(tactics))
            prev_meta["platforms"] = dedupe_keep_order(list(prev_meta.get("platforms", [])) + dedupe_keep_order(platforms))
            prev_meta["data_sources"] = dedupe_keep_order(list(prev_meta.get("data_sources", [])) + dedupe_keep_order(data_sources))
            prev["metadata"] = prev_meta
        pending += 1
        if pending >= PROGRESS_FILE_BATCH:
            _emit_progress(progress_callback, event="progress_update", source=source, stage="normalize", advance=pending)
            pending = 0

    if pending > 0:
        _emit_progress(progress_callback, event="progress_update", source=source, stage="normalize", advance=pending)
    _emit_progress(progress_callback, event="progress_end", source=source, stage="normalize", total=len(files))

    for doc_id in sorted(merged):
        item = merged[doc_id]
        metadata = item["metadata"] if isinstance(item.get("metadata"), dict) else {}
        yield NormalizedDoc(
            doc_id=doc_id,
            title=str(item.get("title") or doc_id),
            text="\n".join(str(x) for x in item.get("text_parts", []) if str(x).strip()),
            metadata=metadata,
            aliases=list(item.get("aliases", [])),
        )


def _iter_cve_docs(
    path: Path,
    progress_callback: Optional[ProgressCallback] = None,
    source: str = "cve",
) -> Iterator[NormalizedDoc]:
    files: List[Path]
    if path.is_dir():
        files = list(path.rglob("CVE-*.json"))
    else:
        files = [path]

    total = len(files)
    _emit_progress(progress_callback, event="progress_start", source=source, stage="normalize", total=total, unit="file")
    pending = 0
    for file_path in files:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            pending += 1
            if pending >= PROGRESS_FILE_BATCH:
                _emit_progress(progress_callback, event="progress_update", source=source, stage="normalize", advance=pending)
                pending = 0
            continue
        metadata = raw.get("cveMetadata") if isinstance(raw.get("cveMetadata"), dict) else {}
        cna = {}
        containers = raw.get("containers")
        if isinstance(containers, dict):
            cna = containers.get("cna") if isinstance(containers.get("cna"), dict) else {}
        cve_id = str(metadata.get("cveId") or "").strip().upper()
        if not cve_id:
            continue
        state = str(metadata.get("state") or "").upper()
        if state == "REJECTED":
            continue

        title = _collapse_ws(str(cna.get("title") or cve_id))
        descriptions = [
            _collapse_ws(str(item.get("value") or ""))
            for item in (cna.get("descriptions") or [])
            if isinstance(item, dict) and str(item.get("value") or "").strip()
        ]
        affected = _format_cve_affected(cna.get("affected") or [])
        problem_types = _format_cve_problem_types(cna.get("problemTypes") or [])
        references = [
            str(item.get("url") or "").strip()
            for item in (cna.get("references") or [])
            if isinstance(item, dict) and str(item.get("url") or "").strip()
        ]

        text = _join_sections(
            ("description", "\n".join(dedupe_keep_order(descriptions))),
            ("affected", affected),
            ("problem_types", problem_types),
            ("references", ", ".join(dedupe_keep_order(references[:8]))),
        )

        aliases = [cve_id, _identifier_compact(cve_id)]
        metadata_out = {
            "state": state,
            "assigner": metadata.get("assignerOrgShortName") or metadata.get("assignerOrgId"),
            "date_published": metadata.get("datePublished"),
            "date_updated": metadata.get("dateUpdated"),
            "date_reserved": metadata.get("dateReserved"),
            "references": dedupe_keep_order(references[:16]),
        }
        pending += 1
        if pending >= PROGRESS_FILE_BATCH:
            _emit_progress(progress_callback, event="progress_update", source=source, stage="normalize", advance=pending)
            pending = 0
        yield NormalizedDoc(
            doc_id=cve_id,
            title=title,
            text=text,
            metadata=metadata_out,
            aliases=dedupe_keep_order([alias for alias in aliases if alias]),
        )
    if pending > 0:
        _emit_progress(progress_callback, event="progress_update", source=source, stage="normalize", advance=pending)
    _emit_progress(progress_callback, event="progress_end", source=source, stage="normalize", total=total)


def _iter_generic_docs(
    path: Path,
    progress_callback: Optional[ProgressCallback] = None,
    source: str = "generic",
) -> Iterator[NormalizedDoc]:
    files: List[Path] = []
    if path.is_dir():
        files = sorted([file_path for file_path in path.rglob("*") if file_path.is_file() and file_path.suffix.lower() in {".json", ".jsonl"}])
    else:
        files = [path]

    _emit_progress(progress_callback, event="progress_start", source=source, stage="normalize", total=len(files), unit="file")
    pending = 0
    for file_path in files:
        if file_path.suffix.lower() == ".jsonl":
            for line in file_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                doc = _generic_doc_from_raw(raw)
                if doc is not None:
                    yield doc
            pending += 1
            if pending >= PROGRESS_FILE_BATCH:
                _emit_progress(progress_callback, event="progress_update", source=source, stage="normalize", advance=pending)
                pending = 0
            continue

        raw_json = json.loads(file_path.read_text(encoding="utf-8"))
        items = raw_json.get("items", []) if isinstance(raw_json, dict) else raw_json
        if not isinstance(items, list):
            pending += 1
            if pending >= PROGRESS_FILE_BATCH:
                _emit_progress(progress_callback, event="progress_update", source=source, stage="normalize", advance=pending)
                pending = 0
            continue
        for raw in items:
            doc = _generic_doc_from_raw(raw)
            if doc is not None:
                yield doc
        pending += 1
        if pending >= PROGRESS_FILE_BATCH:
            _emit_progress(progress_callback, event="progress_update", source=source, stage="normalize", advance=pending)
            pending = 0
    if pending > 0:
        _emit_progress(progress_callback, event="progress_update", source=source, stage="normalize", advance=pending)
    _emit_progress(progress_callback, event="progress_end", source=source, stage="normalize", total=len(files))


def _generic_doc_from_raw(raw: object) -> Optional[NormalizedDoc]:
    if not isinstance(raw, dict):
        return None
    doc_id = str(raw.get("id") or raw.get("doc_id") or raw.get("cve") or raw.get("tech_id") or "").strip()
    if not doc_id:
        return None
    title = _collapse_ws(str(raw.get("title") or raw.get("name") or doc_id))
    text = _collapse_ws(str(raw.get("text") or raw.get("description") or raw.get("content") or ""))
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    aliases = [doc_id, _identifier_compact(doc_id), title]
    raw_aliases = raw.get("aliases") if isinstance(raw.get("aliases"), list) else []
    aliases.extend(str(x).strip() for x in raw_aliases if str(x).strip())
    return NormalizedDoc(
        doc_id=doc_id,
        title=title,
        text=text,
        metadata=metadata,
        aliases=dedupe_keep_order([alias for alias in aliases if alias]),
    )


def _extract_attack_external_id(obj: Dict[str, object]) -> str:
    for ref in obj.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        source_name = str(ref.get("source_name") or "").strip().lower()
        external_id = str(ref.get("external_id") or "").strip().upper()
        if source_name in {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"} and external_id:
            return external_id
    return ""


def _extract_attack_aliases(obj: Dict[str, object]) -> List[str]:
    aliases: List[str] = []
    for key in ("x_mitre_aliases", "aliases"):
        values = obj.get(key) or []
        if isinstance(values, list):
            aliases.extend(str(value).strip() for value in values if str(value).strip())
    return dedupe_keep_order(aliases)


def _format_cve_affected(items: object) -> str:
    if not isinstance(items, list):
        return ""
    chunks: List[str] = []
    for item in items[:20]:
        if not isinstance(item, dict):
            continue
        vendor = str(item.get("vendor") or "").strip()
        product = str(item.get("product") or "").strip()
        versions = []
        for version in item.get("versions") or []:
            if not isinstance(version, dict):
                continue
            version_text = str(version.get("version") or version.get("lessThan") or version.get("lessThanOrEqual") or "").strip()
            status = str(version.get("status") or "").strip()
            if version_text or status:
                versions.append(_collapse_ws(f"{status} {version_text}"))
        label = _collapse_ws(" ".join(part for part in [vendor, product] if part))
        if versions:
            label = _collapse_ws(f"{label}: {', '.join(dedupe_keep_order(versions[:6]))}")
        if label:
            chunks.append(label)
    return "; ".join(dedupe_keep_order(chunks))


def _format_cve_problem_types(items: object) -> str:
    if not isinstance(items, list):
        return ""
    out: List[str] = []
    for item in items[:10]:
        if not isinstance(item, dict):
            continue
        for desc in item.get("descriptions") or []:
            if not isinstance(desc, dict):
                continue
            value = _collapse_ws(str(desc.get("description") or ""))
            if value:
                out.append(value)
    return "; ".join(dedupe_keep_order(out))


def _collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def _join_sections(*sections: Tuple[str, str]) -> str:
    parts: List[str] = []
    for label, value in sections:
        cleaned = _collapse_ws(value)
        if cleaned:
            parts.append(f"[{label}] {cleaned}")
    return "\n".join(parts)


def _identifier_compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _query_terms(text: str) -> List[str]:
    tokens = [match.group(0).lower() for match in WORD_RE.finditer(text or "")]
    aliases: List[str] = []
    for match in CVE_RE.finditer(text or ""):
        aliases.append(match.group(0).lower())
        aliases.append(_identifier_compact(match.group(0)))
    for match in TECH_RE.finditer(text or ""):
        aliases.append(match.group(0).lower())
        aliases.append(_identifier_compact(match.group(0)))
    out = dedupe_keep_order(token for token in tokens + aliases if token and len(token) >= 2)
    return out[:32]


def _emit_progress(progress_callback: Optional[ProgressCallback], **payload: object) -> None:
    if progress_callback is not None:
        progress_callback(dict(payload))
