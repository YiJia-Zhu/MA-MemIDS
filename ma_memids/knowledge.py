from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .config import RuntimeConfig
from .embedding import HashingEmbedder
from .models import EnrichedKnowledge, ExternalDoc, RetrievedItem
from .utils import cosine_sim, dedupe_keep_order, tokenize


CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


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


class KnowledgeStore:
    def __init__(self):
        self.docs: Dict[str, List[ExternalDoc]] = {"cve": [], "attack": _default_attack_docs(), "cti": []}

    def load_from_path(self, source: str, path: Optional[str]) -> None:
        if not path:
            return
        p = Path(path)
        if not p.exists():
            return

        loaded: List[ExternalDoc] = []
        if p.suffix.lower() == ".jsonl":
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                loaded.append(self._from_raw(raw, source))
        else:
            raw_data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(raw_data, dict):
                raw_data = raw_data.get("items", [])
            for raw in raw_data:
                loaded.append(self._from_raw(raw, source))

        self.docs[source] = loaded

    def _from_raw(self, raw: Dict[str, object], source: str) -> ExternalDoc:
        doc_id = str(raw.get("id") or raw.get("doc_id") or raw.get("cve") or raw.get("tech_id") or "unknown")
        title = str(raw.get("title") or raw.get("name") or doc_id)
        text = str(raw.get("text") or raw.get("description") or raw.get("content") or "")
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        return ExternalDoc(doc_id=doc_id, source=source, title=title, text=text, metadata=metadata)


class DualPathRetriever:
    def __init__(
        self,
        embedder: HashingEmbedder,
        store: Optional[KnowledgeStore] = None,
        top_k: Optional[int] = None,
    ):
        cfg = RuntimeConfig()
        self.embedder = embedder
        self.store = store or KnowledgeStore()
        self.top_k = top_k or cfg.knowledge_top_k
        self._index: Dict[str, List[List[float]]] = {}
        self._rebuild_index()

    def load_knowledge(self, cve_path: Optional[str] = None, attack_path: Optional[str] = None, cti_path: Optional[str] = None) -> None:
        self.store.load_from_path("cve", cve_path)
        self.store.load_from_path("attack", attack_path)
        self.store.load_from_path("cti", cti_path)
        self._rebuild_index()

    def _rebuild_index(self) -> None:
        self._index = {}
        for source, docs in self.store.docs.items():
            self._index[source] = [self.embedder.embed(doc.title + "\n" + doc.text) for doc in docs]

    def retrieve(self, text: str) -> EnrichedKnowledge:
        explicit_cves = dedupe_keep_order(m.group(0).upper() for m in CVE_RE.finditer(text))
        explicit_techs = dedupe_keep_order(m.group(0).upper() for m in TECH_RE.finditer(text))

        query_vec = self.embedder.embed(text)
        tokens = tokenize(text)

        cve_items = self._retrieve_source("cve", tokens, query_vec, explicit_cves)
        attack_items = self._retrieve_source("attack", tokens, query_vec, explicit_techs)
        cti_items = self._retrieve_source("cti", tokens, query_vec, explicit_cves + explicit_techs)

        all_cve_ids = set(explicit_cves)
        all_tech_ids = set(explicit_techs)
        for item in cve_items + cti_items:
            all_cve_ids.update(m.group(0).upper() for m in CVE_RE.finditer(item.doc.text + " " + item.doc.doc_id))
        for item in attack_items + cti_items:
            all_tech_ids.update(m.group(0).upper() for m in TECH_RE.finditer(item.doc.text + " " + item.doc.doc_id))

        return EnrichedKnowledge(
            cve_docs=cve_items,
            attack_docs=attack_items,
            cti_docs=cti_items,
            cve_ids=sorted(all_cve_ids),
            tech_ids=sorted(all_tech_ids),
            debug={"query_tokens": tokens[:30]},
        )

    def _retrieve_source(
        self,
        source: str,
        tokens: List[str],
        query_vec: List[float],
        explicit_ids: Iterable[str],
    ) -> List[RetrievedItem]:
        docs = self.store.docs.get(source, [])
        if not docs:
            return []
        sem = self._semantic_search(source, query_vec)
        kw = self._keyword_search(docs, tokens, explicit_ids)
        merged = self._merge_hits(kw, sem)
        merged.sort(key=lambda item: item.score, reverse=True)
        return merged[: self.top_k]

    def _keyword_search(
        self,
        docs: List[ExternalDoc],
        tokens: List[str],
        explicit_ids: Iterable[str],
    ) -> List[RetrievedItem]:
        explicit_upper = {x.upper() for x in explicit_ids}
        query_terms = set(tokens)
        hits: List[RetrievedItem] = []

        for doc in docs:
            corpus = f"{doc.doc_id} {doc.title} {doc.text}".lower()
            doc_tokens = set(tokenize(corpus))
            id_hit = any(exp_id in doc.doc_id.upper() or exp_id in doc.text.upper() for exp_id in explicit_upper)
            overlap = query_terms & doc_tokens
            if not id_hit and not overlap:
                continue

            if id_hit:
                score = 1.0
            else:
                score = min(0.99, 0.2 + (len(overlap) / max(1, len(query_terms))))

            hits.append(RetrievedItem(doc=doc, score=score, hit_type="keyword"))

        hits.sort(key=lambda item: item.score, reverse=True)
        return hits[: self.top_k]

    def _semantic_search(self, source: str, query_vec: List[float]) -> List[RetrievedItem]:
        docs = self.store.docs.get(source, [])
        vectors = self._index.get(source, [])
        scores: List[RetrievedItem] = []
        for doc, vec in zip(docs, vectors):
            score = cosine_sim(query_vec, vec)
            if score <= 0.0:
                continue
            scores.append(RetrievedItem(doc=doc, score=score, hit_type="semantic"))
        scores.sort(key=lambda item: item.score, reverse=True)
        return scores[: self.top_k]

    def _merge_hits(self, keyword_hits: List[RetrievedItem], semantic_hits: List[RetrievedItem]) -> List[RetrievedItem]:
        merged: Dict[str, RetrievedItem] = {}
        for item in semantic_hits:
            merged[item.doc.doc_id] = item

        for item in keyword_hits:
            prev = merged.get(item.doc.doc_id)
            if prev is None:
                merged[item.doc.doc_id] = item
                continue

            if prev.hit_type == "semantic":
                prev.hit_type = "hybrid"
                prev.score = max(prev.score, item.score)
            else:
                prev.score = max(prev.score, item.score)

        return list(merged.values())
