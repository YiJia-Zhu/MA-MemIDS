from __future__ import annotations

import json
import re
import uuid
from typing import Dict, Iterable, List, Optional, Tuple

from .embedding import HashingEmbedder
from .knowledge import DualPathRetriever
from .llm_client import BaseLLMClient
from .models import EnrichedKnowledge, LLMNoteExtraction, Note
from .prompts import NOTE_EXTRACTION_SYSTEM, NOTE_EXTRACTION_USER
from .rule_parser import parse_rule_fields
from .utils import dedupe_keep_order, now_iso


TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


class NoteBuilder:
    def __init__(self, retriever: DualPathRetriever, embedder: HashingEmbedder, llm_client: BaseLLMClient):
        self.retriever = retriever
        self.embedder = embedder
        self.llm = llm_client

    def build_rule_note(self, rule_text: str, note_id: Optional[str] = None) -> Note:
        fields = parse_rule_fields(rule_text)
        knowledge = self.retriever.retrieve(rule_text)
        extraction = self._extract_semantics(
            text=rule_text,
            knowledge=knowledge,
            seed_keywords=fields.get("keywords", []),
            seed_tactics=fields.get("tech_ids", []),
        )
        keywords = dedupe_keep_order(list(fields.get("keywords", [])) + extraction.keywords)
        tactics = dedupe_keep_order(list(fields.get("tech_ids", [])) + extraction.tactics + knowledge.tech_ids)
        intent = extraction.intent

        embed = self.embedder.embed_note(intent, keywords, tactics, knowledge.description_text(), rule_text)
        sid = fields.get("sid")
        if note_id is None:
            note_id = f"rule-{sid}" if sid else f"rule-{uuid.uuid4().hex[:8]}"

        return Note(
            note_id=note_id,
            note_type="rule",
            content=rule_text,
            intent=intent,
            keywords=keywords,
            tactics=tactics,
            embedding=embed,
            external_knowledge=knowledge,
            timestamp=now_iso(),
            protocol=fields.get("protocol"),
            sid=sid,
            metadata={
                "src_ip": fields.get("src_ip"),
                "src_port": fields.get("src_port"),
                "dst_ip": fields.get("dst_ip"),
                "dst_port": fields.get("dst_port"),
            },
        )

    def build_traffic_note(
        self,
        traffic_text: str,
        protocol: Optional[str] = None,
        metadata: Optional[Dict[str, object]] = None,
        note_id: Optional[str] = None,
    ) -> Note:
        knowledge = self.retriever.retrieve(traffic_text)
        extraction = self._extract_semantics(
            text=traffic_text,
            knowledge=knowledge,
            seed_keywords=self._extract_plain_keywords(traffic_text),
            seed_tactics=knowledge.tech_ids,
        )

        keywords = dedupe_keep_order(self._extract_plain_keywords(traffic_text) + extraction.keywords)
        tactics = dedupe_keep_order(extraction.tactics + knowledge.tech_ids)
        intent = extraction.intent

        embed = self.embedder.embed_note(intent, keywords, tactics, knowledge.description_text(), traffic_text)
        if note_id is None:
            note_id = f"traffic-{uuid.uuid4().hex[:8]}"

        return Note(
            note_id=note_id,
            note_type="traffic",
            content=traffic_text,
            intent=intent,
            keywords=keywords,
            tactics=tactics,
            embedding=embed,
            external_knowledge=knowledge,
            timestamp=now_iso(),
            protocol=(protocol or "").upper() or None,
            metadata=metadata or {},
        )

    def reembed_note(self, note: Note) -> Note:
        note.embedding = self.embedder.embed_note(
            note.intent,
            note.keywords,
            note.tactics,
            note.external_knowledge.description_text(),
            note.content,
        )
        note.timestamp = now_iso()
        return note

    def _extract_semantics(
        self,
        text: str,
        knowledge: EnrichedKnowledge,
        seed_keywords: Iterable[str],
        seed_tactics: Iterable[str],
    ) -> LLMNoteExtraction:
        cve_desc = "\n".join(item.doc.text for item in knowledge.cve_docs[:3])
        attack_desc = "\n".join(item.doc.text for item in knowledge.attack_docs[:3])
        messages = [
            {"role": "system", "content": NOTE_EXTRACTION_SYSTEM},
            {
                "role": "user",
                "content": NOTE_EXTRACTION_USER.format(
                    text=text,
                    cve_description=cve_desc or "N/A",
                    attack_description=attack_desc or "N/A",
                ),
            },
        ]
        try:
            response = self.llm.chat(messages, temperature=0.2)
            parsed = self._try_parse_json(response)
            if parsed is not None:
                intent = str(parsed.get("intent") or "").strip()
                keywords = [str(x).strip() for x in parsed.get("keywords", []) if str(x).strip()]
                tactics = [str(x).upper().strip() for x in parsed.get("tactics", []) if str(x).strip()]
                if intent:
                    return LLMNoteExtraction(intent=intent, keywords=keywords, tactics=tactics)
        except Exception:
            pass

        # Heuristic fallback
        fallback_tactics = dedupe_keep_order(
            [x.upper() for x in seed_tactics if x] +
            [m.group(0).upper() for m in TECH_RE.finditer(text)] +
            knowledge.tech_ids
        )
        fallback_keywords = dedupe_keep_order([str(x) for x in seed_keywords if str(x).strip()])
        if knowledge.cve_ids:
            intent = f"Detect exploit behavior related to {'/'.join(knowledge.cve_ids[:2])}"
        elif fallback_tactics:
            intent = f"Detect traffic mapped to ATT&CK {fallback_tactics[0]}"
        elif fallback_keywords:
            intent = f"Detect suspicious traffic using indicator {fallback_keywords[0]}"
        else:
            intent = "Detect suspicious intrusion traffic"

        return LLMNoteExtraction(intent=intent, keywords=fallback_keywords, tactics=fallback_tactics)

    def _extract_plain_keywords(self, text: str) -> List[str]:
        # Prefer payload/URI indicators; filter transport/meta noise.
        lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
        candidates: List[str] = []

        for ln in lines:
            lower = ln.lower()
            if lower.startswith(("pcap=", "protocol=", "src=", "dst=", "headers=")):
                continue
            if lower.startswith("http="):
                candidates.extend(self._tokenize_signal_text(ln[5:]))
                continue
            if lower.startswith("payload="):
                candidates.extend(self._tokenize_signal_text(ln[8:]))
                continue
            candidates.extend(self._tokenize_signal_text(ln))

        return dedupe_keep_order(candidates)[:30]

    def _tokenize_signal_text(self, text: str) -> List[str]:
        raw = re.findall(r"[A-Za-z0-9_./<>=:%'\"-]{3,}", text)
        out: List[str] = []
        noise = {
            "http", "https", "host", "user-agent", "mozilla", "accept", "connection",
            "pcap", "protocol", "payload", "src", "dst", "tcp", "udp",
        }
        for tok in raw:
            t = tok.strip()
            if not t or t.isdigit():
                continue
            low = t.lower()
            if low in noise:
                continue
            if low.startswith(("/mnt/", "/tmp/", "pcap=", "protocol=", "src=", "dst=")):
                continue
            if len(t) > 64:
                t = t[:64]
            out.append(t)
        return out

    def _try_parse_json(self, text: str) -> Optional[Dict[str, object]]:
        text = text.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try extracting first JSON object.
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            chunk = text[start : end + 1]
            try:
                return json.loads(chunk)
            except json.JSONDecodeError:
                return None
        return None
