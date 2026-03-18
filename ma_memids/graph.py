from __future__ import annotations

from dataclasses import dataclass
import importlib
import logging
import os
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .config import SimilarityWeights, Thresholds
from .models import Link, Note, SimilarityResult
from .utils import cosine_sim, jaccard, set_subset

try:
    import numpy as np
except ImportError:  # pragma: no cover - optional acceleration
    np = None


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class PairFeatures:
    cosine: float
    keyword_jaccard: float
    tactic_jaccard: float
    cve_overlap: float
    keyword_containment: float
    keyword_subset: bool
    score: float


class NoteGraph:
    def __init__(self, weights: Optional[SimilarityWeights] = None, thresholds: Optional[Thresholds] = None):
        self.weights = weights or SimilarityWeights()
        self.thresholds = thresholds or Thresholds()
        self.notes: Dict[str, Note] = {}
        self._prefer_hnsw = (
            (os.getenv("MA_MEMIDS_ENABLE_HNSW") or "").strip().lower() in {"1", "true", "yes", "on"}
        )

        self._index_dirty = True
        self._ann_backend = "exact"
        self._hnsw_available = False
        self._hnsw_reason = "disabled"
        self._rule_note_ids: List[str] = []
        self._note_id_to_label: Dict[str, int] = {}
        self._label_to_note_id: Dict[int, str] = {}
        self._cve_to_rule_ids: Dict[str, Set[str]] = {}
        self._keyword_to_rule_ids: Dict[str, Set[str]] = {}
        self._hnsw_index = None

    def add_or_update(self, note: Note) -> None:
        self.notes[note.note_id] = note
        self._mark_indexes_dirty()
        self._rebuild_links_for(note.note_id)

    def add_or_update_many(self, notes: Iterable[Note]) -> None:
        changed = False
        for note in notes:
            self.notes[note.note_id] = note
            changed = True
        if not changed:
            return
        self._mark_indexes_dirty()
        self.rebuild_all_links()

    def get(self, note_id: str) -> Optional[Note]:
        return self.notes.get(note_id)

    def all_notes(self) -> List[Note]:
        return list(self.notes.values())

    def count(self) -> int:
        return len(self.notes)

    def rebuild_all_links(self) -> None:
        for note in self.notes.values():
            note.links = []

        self._mark_indexes_dirty()
        self._ensure_indexes()

        for note_id in self._rule_note_ids:
            note = self.notes[note_id]
            candidate_ids = self._candidate_ids_for_note(
                note,
                candidate_k=self.thresholds.graph_candidate_k,
                exclude_note_id=note_id,
            )
            for other_id in sorted(candidate_ids):
                if other_id <= note_id:
                    continue
                other = self.notes.get(other_id)
                if other is None:
                    continue
                link_candidates = self._compute_link_candidates(note, other)
                for ltype, weight in link_candidates:
                    self._upsert_link(note, other.note_id, ltype, weight)
                    self._upsert_link(other, note.note_id, ltype, weight)

    def retain_note_types(self, allowed_types: Set[str]) -> bool:
        allowed = {str(item).strip() for item in allowed_types if str(item).strip()}
        original_ids = set(self.notes.keys())
        before_links = {
            note_id: sorted((link.target_id, link.link_type, round(float(link.weight), 8)) for link in note.links)
            for note_id, note in self.notes.items()
            if note.note_type in allowed
        }
        self.notes = {
            note_id: note
            for note_id, note in self.notes.items()
            if note.note_type in allowed
        }
        self._mark_indexes_dirty()
        self.rebuild_all_links()
        after_links = {
            note_id: sorted((link.target_id, link.link_type, round(float(link.weight), 8)) for link in note.links)
            for note_id, note in self.notes.items()
        }
        changed = set(self.notes.keys()) != original_ids or before_links != after_links
        return changed

    def _rebuild_links_for(self, note_id: str) -> None:
        note = self.notes[note_id]

        note.links = []

        for other in self.notes.values():
            if other.note_id == note_id:
                continue
            other.links = [lk for lk in other.links if lk.target_id != note_id]

        for other in self.notes.values():
            if other.note_id == note_id:
                continue
            link_candidates = self._compute_link_candidates(note, other)
            for ltype, weight in link_candidates:
                self._upsert_link(note, other.note_id, ltype, weight)
                self._upsert_link(other, note.note_id, ltype, weight)

    def _compute_link_candidates(self, a: Note, b: Note) -> List[Tuple[str, float]]:
        features = self._pair_features(a, b)
        if not self._should_keep_pair(features):
            return []

        link_types: List[str] = []
        if features.cve_overlap > 0.0:
            link_types.append("exploit_chain")
        if features.keyword_subset:
            link_types.append("subsume")
        if features.tactic_jaccard > 0.0:
            link_types.append("tactic_group")
        if not link_types:
            link_types.append("semantic_similar")

        return [(link_type, features.score) for link_type in link_types]

    def _should_keep_pair(self, features: PairFeatures) -> bool:
        if features.cve_overlap > 0.0 or features.keyword_subset:
            return True
        return features.score >= self.thresholds.w

    def _upsert_link(self, src: Note, target_id: str, link_type: str, weight: float) -> None:
        for link in src.links:
            if link.target_id == target_id and link.link_type == link_type:
                if weight > link.weight:
                    link.weight = weight
                return
        src.links.append(Link(target_id=target_id, link_type=link_type, weight=weight))

    def _pair_features(self, a: Note, b: Note, cosine_override: Optional[float] = None) -> PairFeatures:
        cosine_value = cosine_override if cosine_override is not None else cosine_sim(a.embedding, b.embedding)
        keyword_jaccard = jaccard(a.keywords, b.keywords)
        tactic_jaccard = jaccard(a.tactics, b.tactics)
        cve_overlap = self._overlap_coefficient(a.external_knowledge.cve_ids, b.external_knowledge.cve_ids)
        keyword_containment = self._overlap_coefficient(a.keywords, b.keywords)
        keyword_subset = set_subset(a.keywords, b.keywords) or set_subset(b.keywords, a.keywords)
        score = (
            self.weights.alpha * cosine_value
            + self.weights.beta * keyword_jaccard
            + self.weights.gamma * tactic_jaccard
            + self.weights.delta * cve_overlap
            + self.weights.epsilon * keyword_containment
        )
        score = max(0.0, min(1.0, score))
        return PairFeatures(
            cosine=cosine_value,
            keyword_jaccard=keyword_jaccard,
            tactic_jaccard=tactic_jaccard,
            cve_overlap=cve_overlap,
            keyword_containment=keyword_containment,
            keyword_subset=keyword_subset,
            score=score,
        )

    def _overlap_coefficient(self, a: Iterable[str], b: Iterable[str]) -> float:
        sa = {str(item).strip() for item in a if str(item).strip()}
        sb = {str(item).strip() for item in b if str(item).strip()}
        if not sa or not sb:
            return 0.0
        return len(sa & sb) / max(1, min(len(sa), len(sb)))

    def compute_weight(self, a: Note, b: Note, cosine_override: Optional[float] = None) -> float:
        return self._pair_features(a, b, cosine_override=cosine_override).score

    def neighbors(self, note_id: str, link_type: Optional[str] = None) -> List[Link]:
        note = self.notes.get(note_id)
        if not note:
            return []
        if link_type is None:
            return list(note.links)
        return [link for link in note.links if link.link_type == link_type]

    def search_top_k(self, query_note: Note, ann_k: Optional[int] = None, top_n: Optional[int] = None) -> List[SimilarityResult]:
        ann_k = ann_k or self.thresholds.ann_k
        top_n = top_n or self.thresholds.rerank_n

        candidate_ids = self._candidate_ids_for_note(
            query_note,
            candidate_k=max(ann_k, top_n),
            exclude_note_id=query_note.note_id if query_note.note_id in self.notes else None,
        )
        reranked = self._score_candidates(query_note, candidate_ids)

        top5 = reranked[:5]
        expanded_ids: Set[str] = set(item.note_id for item in top5)
        for item in top5:
            for neigh in self.neighbors(item.note_id):
                if neigh.target_id in self.notes and self.notes[neigh.target_id].note_type == "rule":
                    expanded_ids.add(neigh.target_id)

        expanded_scores = self._score_candidates(query_note, expanded_ids)
        return expanded_scores[:top_n]

    def find_merge_candidates(self, note_id: str, threshold: Optional[float] = None) -> List[str]:
        threshold = threshold or self.thresholds.merge
        note = self.notes.get(note_id)
        if not note:
            return []

        candidate_ids = self._candidate_ids_for_note(
            note,
            candidate_k=self.thresholds.merge_candidate_k,
            exclude_note_id=note_id,
        )
        scored = self._score_candidates(note, candidate_ids)
        return [item.note_id for item in scored if item.score >= threshold]

    def index_stats(self) -> Dict[str, object]:
        self._ensure_indexes()
        return {
            "backend": self._ann_backend,
            "indexed_rules": len(self._rule_note_ids),
            "hnsw_requested": self._prefer_hnsw,
            "hnsw_available": self._hnsw_available,
            "hnsw_reason": self._hnsw_reason,
            "graph_candidate_k": self.thresholds.graph_candidate_k,
            "merge_candidate_k": self.thresholds.merge_candidate_k,
        }

    def _score_candidates(self, query_note: Note, candidate_ids: Iterable[str]) -> List[SimilarityResult]:
        reranked: List[SimilarityResult] = []
        for note_id in candidate_ids:
            target = self.notes.get(note_id)
            if target is None or target.note_type != "rule":
                continue
            score = self.compute_weight(query_note, target)
            reranked.append(SimilarityResult(note_id=note_id, score=score))
        reranked.sort(key=lambda item: item.score, reverse=True)
        return reranked

    def _candidate_ids_for_note(
        self,
        note: Note,
        candidate_k: int,
        exclude_note_id: Optional[str] = None,
    ) -> Set[str]:
        self._ensure_indexes()
        candidate_ids = set(self._ann_candidate_ids(note, candidate_k=candidate_k, exclude_note_id=exclude_note_id))
        candidate_ids.update(self._structural_candidate_ids(note, candidate_k=candidate_k))
        if exclude_note_id:
            candidate_ids.discard(exclude_note_id)
        return candidate_ids

    def _structural_candidate_ids(self, note: Note, candidate_k: int) -> Set[str]:
        out: Set[str] = set()
        cve_ids = set(note.external_knowledge.cve_ids)
        for cve_id in cve_ids:
            out.update(self._cve_to_rule_ids.get(str(cve_id).upper(), set()))

        bucket_cap = max(self.thresholds.keyword_bucket_cap, candidate_k * 2)
        keywords = {str(item).strip() for item in note.keywords if str(item).strip()}
        for keyword in keywords:
            bucket = self._keyword_to_rule_ids.get(keyword, set())
            if 0 < len(bucket) <= bucket_cap:
                out.update(bucket)
        return out

    def _ann_candidate_ids(self, note: Note, candidate_k: int, exclude_note_id: Optional[str] = None) -> List[str]:
        candidate_k = max(0, int(candidate_k))
        if candidate_k <= 0:
            return []
        self._ensure_indexes()
        if not self._rule_note_ids:
            return []

        if self._ann_backend == "hnsw" and self._hnsw_index is not None and np is not None:
            limit = min(len(self._rule_note_ids), candidate_k + (1 if exclude_note_id else 0))
            if limit <= 0:
                return []
            query = np.asarray([note.embedding], dtype=np.float32)
            labels, _ = self._hnsw_index.knn_query(query, k=limit)
            out: List[str] = []
            for label in labels[0]:
                note_id = self._label_to_note_id.get(int(label))
                if note_id is None or note_id == exclude_note_id:
                    continue
                out.append(note_id)
                if len(out) >= candidate_k:
                    break
            return out

        scores: List[Tuple[float, str]] = []
        for note_id in self._rule_note_ids:
            if note_id == exclude_note_id:
                continue
            target = self.notes[note_id]
            scores.append((cosine_sim(note.embedding, target.embedding), note_id))
        scores.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [note_id for _, note_id in scores[:candidate_k]]

    def _mark_indexes_dirty(self) -> None:
        self._index_dirty = True
        self._ann_backend = "exact"
        self._hnsw_available = False
        self._hnsw_reason = "disabled" if not self._prefer_hnsw else "not_initialized"
        self._hnsw_index = None
        self._rule_note_ids = []
        self._note_id_to_label = {}
        self._label_to_note_id = {}
        self._cve_to_rule_ids = {}
        self._keyword_to_rule_ids = {}

    def _ensure_indexes(self) -> None:
        if not self._index_dirty:
            return
        self._rebuild_indexes()

    def _rebuild_indexes(self) -> None:
        self._rule_note_ids = sorted(
            note_id
            for note_id, note in self.notes.items()
            if note.note_type == "rule"
        )
        self._cve_to_rule_ids = {}
        self._keyword_to_rule_ids = {}

        for note_id in self._rule_note_ids:
            note = self.notes[note_id]
            for cve_id in {str(item).upper().strip() for item in note.external_knowledge.cve_ids if str(item).strip()}:
                self._cve_to_rule_ids.setdefault(cve_id, set()).add(note_id)
            for keyword in {str(item).strip() for item in note.keywords if str(item).strip()}:
                self._keyword_to_rule_ids.setdefault(keyword, set()).add(note_id)

        self._ann_backend = "exact"
        self._hnsw_available = False
        self._hnsw_index = None
        self._note_id_to_label = {}
        self._label_to_note_id = {}

        if not self._rule_note_ids:
            self._hnsw_reason = "no_rule_notes"
            self._index_dirty = False
            return

        if not self._prefer_hnsw:
            self._hnsw_reason = "disabled_by_default"
            self._index_dirty = False
            return

        if np is None:
            self._hnsw_reason = "numpy_missing"
            self._index_dirty = False
            return

        hnswlib = self._load_hnswlib()
        if hnswlib is None:
            self._index_dirty = False
            return

        dim = len(self.notes[self._rule_note_ids[0]].embedding)
        if dim <= 0:
            self._hnsw_reason = "invalid_dimension"
            self._index_dirty = False
            return

        vectors: List[List[float]] = []
        for note_id in self._rule_note_ids:
            emb = self.notes[note_id].embedding
            if len(emb) != dim:
                self._hnsw_reason = "inconsistent_embedding_dimension"
                self._index_dirty = False
                return
            vectors.append(list(emb))

        labels = list(range(len(self._rule_note_ids)))
        self._note_id_to_label = {note_id: label for label, note_id in enumerate(self._rule_note_ids)}
        self._label_to_note_id = {label: note_id for note_id, label in self._note_id_to_label.items()}

        index = hnswlib.Index(space="cosine", dim=dim)
        index.init_index(
            max_elements=max(1, len(vectors)),
            ef_construction=self.thresholds.hnsw_ef_construction,
            M=self.thresholds.hnsw_m,
        )
        index.add_items(np.asarray(vectors, dtype=np.float32), np.asarray(labels, dtype=np.int32))
        index.set_ef(max(self.thresholds.hnsw_ef_search, self.thresholds.ann_k, self.thresholds.graph_candidate_k))

        self._hnsw_index = index
        self._ann_backend = "hnsw"
        self._hnsw_available = True
        self._hnsw_reason = "ready"
        self._index_dirty = False

    def _load_hnswlib(self):
        try:
            module = importlib.import_module("hnswlib")
        except Exception as exc:  # pragma: no cover - environment-specific optional dependency
            self._hnsw_reason = f"import_failed:{type(exc).__name__}"
            LOGGER.warning("HNSW disabled: failed to import hnswlib: %s", exc)
            return None
        return module

    def to_dict(self) -> Dict[str, object]:
        return {
            "notes": {nid: note.to_dict() for nid, note in self.notes.items()},
            "weights": {
                "alpha": self.weights.alpha,
                "beta": self.weights.beta,
                "gamma": self.weights.gamma,
                "delta": self.weights.delta,
                "epsilon": self.weights.epsilon,
            },
            "thresholds": {
                "high": self.thresholds.high,
                "med": self.thresholds.med,
                "sem": self.thresholds.sem,
                "w": self.thresholds.w,
                "merge": self.thresholds.merge,
                "pass_score": self.thresholds.pass_score,
                "fpr_redline": self.thresholds.fpr_redline,
                "ann_k": self.thresholds.ann_k,
                "rerank_n": self.thresholds.rerank_n,
                "max_regen": self.thresholds.max_regen,
                "graph_candidate_k": self.thresholds.graph_candidate_k,
                "merge_candidate_k": self.thresholds.merge_candidate_k,
                "keyword_bucket_cap": self.thresholds.keyword_bucket_cap,
                "hnsw_m": self.thresholds.hnsw_m,
                "hnsw_ef_construction": self.thresholds.hnsw_ef_construction,
                "hnsw_ef_search": self.thresholds.hnsw_ef_search,
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "NoteGraph":
        weights_raw = data.get("weights", {}) if isinstance(data.get("weights"), dict) else {}
        thresholds_raw = data.get("thresholds", {}) if isinstance(data.get("thresholds"), dict) else {}
        graph = cls(
            weights=SimilarityWeights(
                alpha=float(weights_raw.get("alpha", 0.5)),
                beta=float(weights_raw.get("beta", 0.1)),
                gamma=float(weights_raw.get("gamma", 0.2)),
                delta=float(weights_raw.get("delta", 0.15)),
                epsilon=float(weights_raw.get("epsilon", 0.05)),
            ),
            thresholds=Thresholds(
                high=float(thresholds_raw.get("high", 0.68)),
                med=float(thresholds_raw.get("med", 0.40)),
                sem=float(thresholds_raw.get("sem", 0.0)),
                w=float(thresholds_raw.get("w", 0.40)),
                merge=float(thresholds_raw.get("merge", 0.78)),
                pass_score=float(thresholds_raw.get("pass_score", 0.70)),
                fpr_redline=float(thresholds_raw.get("fpr_redline", 0.05)),
                ann_k=int(thresholds_raw.get("ann_k", 24)),
                rerank_n=int(thresholds_raw.get("rerank_n", 5)),
                max_regen=int(thresholds_raw.get("max_regen", 3)),
                graph_candidate_k=int(thresholds_raw.get("graph_candidate_k", 24)),
                merge_candidate_k=int(thresholds_raw.get("merge_candidate_k", 32)),
                keyword_bucket_cap=int(thresholds_raw.get("keyword_bucket_cap", 64)),
                hnsw_m=int(thresholds_raw.get("hnsw_m", 16)),
                hnsw_ef_construction=int(thresholds_raw.get("hnsw_ef_construction", 120)),
                hnsw_ef_search=int(thresholds_raw.get("hnsw_ef_search", 64)),
            ),
        )
        notes_raw = data.get("notes", {})
        if isinstance(notes_raw, dict):
            for note_id, raw in notes_raw.items():
                if isinstance(raw, dict):
                    graph.notes[note_id] = Note.from_dict(raw)
        graph._mark_indexes_dirty()
        return graph
