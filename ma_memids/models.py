from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class ExternalDoc:
    doc_id: str
    source: str
    title: str
    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RetrievedItem:
    doc: ExternalDoc
    score: float
    hit_type: str


@dataclass
class EnrichedKnowledge:
    cve_docs: List[RetrievedItem] = field(default_factory=list)
    attack_docs: List[RetrievedItem] = field(default_factory=list)
    cti_docs: List[RetrievedItem] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    tech_ids: List[str] = field(default_factory=list)
    debug: Dict[str, Any] = field(default_factory=dict)

    def description_text(self) -> str:
        parts: List[str] = []
        for item in self.cve_docs + self.attack_docs + self.cti_docs:
            parts.append(item.doc.text)
        return "\n".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        def _items(items: List[RetrievedItem]) -> List[Dict[str, Any]]:
            return [
                {
                    "doc": asdict(item.doc),
                    "score": item.score,
                    "hit_type": item.hit_type,
                }
                for item in items
            ]

        return {
            "cve_docs": _items(self.cve_docs),
            "attack_docs": _items(self.attack_docs),
            "cti_docs": _items(self.cti_docs),
            "cve_ids": list(self.cve_ids),
            "tech_ids": list(self.tech_ids),
            "debug": dict(self.debug),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EnrichedKnowledge":
        def _load(items: List[Dict[str, Any]]) -> List[RetrievedItem]:
            out: List[RetrievedItem] = []
            for raw in items:
                out.append(
                    RetrievedItem(
                        doc=ExternalDoc(**raw["doc"]),
                        score=float(raw["score"]),
                        hit_type=raw["hit_type"],
                    )
                )
            return out

        return cls(
            cve_docs=_load(data.get("cve_docs", [])),
            attack_docs=_load(data.get("attack_docs", [])),
            cti_docs=_load(data.get("cti_docs", [])),
            cve_ids=list(data.get("cve_ids", [])),
            tech_ids=list(data.get("tech_ids", [])),
            debug=dict(data.get("debug", {})),
        )


@dataclass
class Link:
    target_id: str
    link_type: str
    weight: float


@dataclass
class Note:
    note_id: str
    note_type: str
    content: str
    intent: str
    keywords: List[str]
    tactics: List[str]
    embedding: List[float]
    external_knowledge: EnrichedKnowledge
    timestamp: str
    version: int = 1
    links: List[Link] = field(default_factory=list)
    protocol: Optional[str] = None
    sid: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "note_id": self.note_id,
            "note_type": self.note_type,
            "content": self.content,
            "intent": self.intent,
            "keywords": list(self.keywords),
            "tactics": list(self.tactics),
            "embedding": list(self.embedding),
            "external_knowledge": self.external_knowledge.to_dict(),
            "timestamp": self.timestamp,
            "version": self.version,
            "links": [asdict(link) for link in self.links],
            "protocol": self.protocol,
            "sid": self.sid,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Note":
        return cls(
            note_id=data["note_id"],
            note_type=data["note_type"],
            content=data["content"],
            intent=data["intent"],
            keywords=list(data.get("keywords", [])),
            tactics=list(data.get("tactics", [])),
            embedding=list(data.get("embedding", [])),
            external_knowledge=EnrichedKnowledge.from_dict(data.get("external_knowledge", {})),
            timestamp=data["timestamp"],
            version=int(data.get("version", 1)),
            links=[Link(**raw) for raw in data.get("links", [])],
            protocol=data.get("protocol"),
            sid=data.get("sid"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class SimilarityResult:
    note_id: str
    score: float


@dataclass
class ValidationResult:
    is_valid: bool
    format_check_passed: bool
    alerts_triggered: bool
    error_message: Optional[str] = None
    alert_details: Optional[List[Dict[str, Any]]] = None


@dataclass
class ValidationMetrics:
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    fpr: float
    f2: float
    p_fpr: float
    score: float


@dataclass
class SandboxResult:
    passed: bool
    syntax_ok: bool
    metrics: Optional[ValidationMetrics]
    reason: str


@dataclass
class FailureDiagnosis:
    failure_type: str
    suggestion: str


@dataclass
class LLMNoteExtraction:
    intent: str
    keywords: List[str]
    tactics: List[str]


@dataclass
class RuleProposal:
    rule_text: str
    mode: str
    base_note_id: Optional[str]
    max_similarity: float


@dataclass
class ProcessResult:
    success: bool
    mode: str
    rule_text: Optional[str]
    score: Optional[float]
    reason: str
    retries: int
    merge_candidates: List[str] = field(default_factory=list)
    linked_notes: List[str] = field(default_factory=list)
