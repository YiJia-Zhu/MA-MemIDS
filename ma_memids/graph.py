from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set, Tuple

from .config import SimilarityWeights, Thresholds
from .models import Link, Note, SimilarityResult
from .utils import cosine_sim, jaccard, set_subset


class NoteGraph:
    def __init__(self, weights: Optional[SimilarityWeights] = None, thresholds: Optional[Thresholds] = None):
        self.weights = weights or SimilarityWeights()
        self.thresholds = thresholds or Thresholds()
        self.notes: Dict[str, Note] = {}

    def add_or_update(self, note: Note) -> None:
        self.notes[note.note_id] = note
        self._rebuild_links_for(note.note_id)

    def get(self, note_id: str) -> Optional[Note]:
        return self.notes.get(note_id)

    def all_notes(self) -> List[Note]:
        return list(self.notes.values())

    def count(self) -> int:
        return len(self.notes)

    def rebuild_all_links(self) -> None:
        notes = list(self.notes.values())
        for note in notes:
            note.links = []

        for idx, note in enumerate(notes):
            for other in notes[idx + 1 :]:
                link_candidates = self._compute_link_candidates(note, other)
                for ltype, weight in link_candidates:
                    self._upsert_link(note, other.note_id, ltype, weight)
                    self._upsert_link(other, note.note_id, ltype, weight)

    def retain_note_types(self, allowed_types: Set[str]) -> bool:
        allowed = {str(item).strip() for item in allowed_types if str(item).strip()}
        original_ids = set(self.notes.keys())
        self.notes = {
            note_id: note
            for note_id, note in self.notes.items()
            if note.note_type in allowed
        }
        changed = set(self.notes.keys()) != original_ids
        for note in self.notes.values():
            if any(link.target_id not in self.notes for link in note.links):
                changed = True
                break
        if changed:
            self.rebuild_all_links()
        return changed

    def _rebuild_links_for(self, note_id: str) -> None:
        note = self.notes[note_id]

        # Remove outbound links from target note.
        note.links = []

        # Remove inbound links pointing to target note.
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
        out: List[Tuple[str, float]] = []

        cve_a = set(a.external_knowledge.cve_ids)
        cve_b = set(b.external_knowledge.cve_ids)
        if cve_a & cve_b:
            out.append(("exploit_chain", 1.0))

        if a.protocol and b.protocol and a.protocol == b.protocol:
            out.append(("protocol_family", 0.8))

        if set_subset(a.keywords, b.keywords) or set_subset(b.keywords, a.keywords):
            out.append(("subsume", 0.9))

        cos = cosine_sim(a.embedding, b.embedding)
        if cos >= self.thresholds.sem:
            w = self.compute_weight(a, b, cosine_override=cos)
            if w >= self.thresholds.w:
                tactic_overlap = set(a.tactics) & set(b.tactics)
                out.append((("tactic_group" if tactic_overlap else "semantic_similar"), w))

        return out

    def _upsert_link(self, src: Note, target_id: str, link_type: str, weight: float) -> None:
        for link in src.links:
            if link.target_id == target_id and link.link_type == link_type:
                if weight > link.weight:
                    link.weight = weight
                return
        src.links.append(Link(target_id=target_id, link_type=link_type, weight=weight))

    def compute_weight(self, a: Note, b: Note, cosine_override: Optional[float] = None) -> float:
        cos = cosine_override if cosine_override is not None else cosine_sim(a.embedding, b.embedding)
        prim = jaccard(a.keywords, b.keywords)
        tact = jaccard(a.tactics, b.tactics)
        return self.weights.alpha * cos + self.weights.beta * prim + self.weights.gamma * tact

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

        candidates: List[Tuple[str, float]] = []
        for note in self.notes.values():
            if note.note_type != "rule":
                continue
            cos = cosine_sim(query_note.embedding, note.embedding)
            candidates.append((note.note_id, cos))
        candidates.sort(key=lambda item: item[1], reverse=True)
        coarse = candidates[:ann_k]

        reranked: List[SimilarityResult] = []
        for note_id, _ in coarse:
            target = self.notes[note_id]
            w = self.compute_weight(query_note, target)
            reranked.append(SimilarityResult(note_id=note_id, score=w))
        reranked.sort(key=lambda item: item.score, reverse=True)

        top5 = reranked[:5]
        expanded_ids: Set[str] = set(item.note_id for item in top5)
        for item in top5:
            for neigh in self.neighbors(item.note_id):
                if neigh.target_id in self.notes and self.notes[neigh.target_id].note_type == "rule":
                    expanded_ids.add(neigh.target_id)

        expanded_scores: List[SimilarityResult] = []
        for note_id in expanded_ids:
            target = self.notes[note_id]
            w = self.compute_weight(query_note, target)
            expanded_scores.append(SimilarityResult(note_id=note_id, score=w))
        expanded_scores.sort(key=lambda item: item.score, reverse=True)

        return expanded_scores[:top_n]

    def find_merge_candidates(self, note_id: str, threshold: Optional[float] = None) -> List[str]:
        threshold = threshold or self.thresholds.merge
        note = self.notes.get(note_id)
        if not note:
            return []
        out: List[str] = []
        for other in self.notes.values():
            if other.note_id == note_id or other.note_type != "rule":
                continue
            score = self.compute_weight(note, other)
            if score >= threshold:
                out.append(other.note_id)
        return out

    def to_dict(self) -> Dict[str, object]:
        return {
            "notes": {nid: note.to_dict() for nid, note in self.notes.items()},
            "weights": {
                "alpha": self.weights.alpha,
                "beta": self.weights.beta,
                "gamma": self.weights.gamma,
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
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "NoteGraph":
        weights_raw = data.get("weights", {}) if isinstance(data.get("weights"), dict) else {}
        thresholds_raw = data.get("thresholds", {}) if isinstance(data.get("thresholds"), dict) else {}
        graph = cls(
            weights=SimilarityWeights(
                alpha=float(weights_raw.get("alpha", 0.5)),
                beta=float(weights_raw.get("beta", 0.3)),
                gamma=float(weights_raw.get("gamma", 0.2)),
            ),
            thresholds=Thresholds(
                high=float(thresholds_raw.get("high", 0.80)),
                med=float(thresholds_raw.get("med", 0.60)),
                sem=float(thresholds_raw.get("sem", 0.75)),
                w=float(thresholds_raw.get("w", 0.60)),
                merge=float(thresholds_raw.get("merge", 0.90)),
                pass_score=float(thresholds_raw.get("pass_score", 0.70)),
                fpr_redline=float(thresholds_raw.get("fpr_redline", 0.05)),
                ann_k=int(thresholds_raw.get("ann_k", 20)),
                rerank_n=int(thresholds_raw.get("rerank_n", 5)),
                max_regen=int(thresholds_raw.get("max_regen", 3)),
            ),
        )
        notes_raw = data.get("notes", {})
        if isinstance(notes_raw, dict):
            for note_id, raw in notes_raw.items():
                if isinstance(raw, dict):
                    graph.notes[note_id] = Note.from_dict(raw)
        return graph
