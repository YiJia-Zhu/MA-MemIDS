from __future__ import annotations

import ipaddress
import json
import re
import uuid
from typing import Dict, Iterable, List, Optional, Tuple

from .embedding import HashingEmbedder
from .knowledge import DualPathRetriever
from .llm_client import BaseLLMClient
from .models import EnrichedKnowledge, ExternalDoc, LLMNoteExtraction, Note, RetrievedItem
from .prompts import NOTE_EXTRACTION_SYSTEM, NOTE_EXTRACTION_USER
from .rule_parser import parse_rule_fields
from .utils import dedupe_keep_order, now_iso


TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


class NoteBuilder:
    def __init__(self, retriever: DualPathRetriever, embedder: HashingEmbedder, llm_client: BaseLLMClient):
        self.retriever = retriever
        self.embedder = embedder
        self.llm = llm_client

    def build_rule_note(
        self,
        rule_text: str,
        note_id: Optional[str] = None,
        analysis_note: Optional[Note] = None,
        intent_hint: Optional[str] = None,
        keyword_hints: Optional[Iterable[str]] = None,
        tactic_hints: Optional[Iterable[str]] = None,
        extra_knowledge: Optional[EnrichedKnowledge] = None,
        extra_metadata: Optional[Dict[str, object]] = None,
    ) -> Note:
        fields = parse_rule_fields(rule_text)
        seeded_keywords = list(keyword_hints or [])
        seeded_tactics = [str(x).upper().strip() for x in (tactic_hints or []) if str(x).strip()]
        if analysis_note is not None:
            seeded_keywords = seeded_keywords + list(analysis_note.keywords)
            seeded_tactics = seeded_tactics + list(analysis_note.tactics)

        hint_knowledge: List[EnrichedKnowledge] = []
        if extra_knowledge is not None:
            hint_knowledge.append(extra_knowledge)
        if analysis_note is not None:
            hint_knowledge.append(analysis_note.external_knowledge)

        if hint_knowledge:
            knowledge = self._merge_knowledge(*hint_knowledge)
        else:
            knowledge = self.retriever.retrieve(rule_text)

        if analysis_note is not None:
            extraction = LLMNoteExtraction(
                intent=analysis_note.intent,
                keywords=list(analysis_note.keywords),
                tactics=list(analysis_note.tactics),
            )
        else:
            extraction = self._extract_semantics(
                text=rule_text,
                knowledge=knowledge,
                seed_keywords=list(fields.get("keywords", [])) + seeded_keywords,
                seed_tactics=list(fields.get("tech_ids", [])) + seeded_tactics,
            )

        keywords = dedupe_keep_order(list(fields.get("keywords", [])) + seeded_keywords + extraction.keywords)
        tactics = dedupe_keep_order(list(fields.get("tech_ids", [])) + seeded_tactics + extraction.tactics + knowledge.tech_ids)
        intent = (intent_hint or extraction.intent).strip()

        embed = self.embedder.embed_note(intent, keywords, tactics, knowledge.description_text(), rule_text)
        sid = fields.get("sid")
        if note_id is None:
            note_id = f"rule-{sid}" if sid else f"rule-{uuid.uuid4().hex[:8]}"

        metadata: Dict[str, object] = dict(extra_metadata or {})
        metadata.update(
            {
                "src_ip": fields.get("src_ip"),
                "src_port": fields.get("src_port"),
                "dst_ip": fields.get("dst_ip"),
                "dst_port": fields.get("dst_port"),
            }
        )
        if analysis_note is not None:
            network_context = analysis_note.metadata.get("network_context", {}) if isinstance(analysis_note.metadata, dict) else {}
            metadata["analysis_cache"] = {
                "intent": analysis_note.intent,
                "keywords": list(analysis_note.keywords)[:20],
                "tactics": list(analysis_note.tactics)[:10],
                "cve_ids": list(analysis_note.external_knowledge.cve_ids)[:10],
                "network_context": dict(network_context) if isinstance(network_context, dict) else {},
            }

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
            metadata=metadata,
        )

    def build_traffic_note(
        self,
        traffic_text: str,
        protocol: Optional[str] = None,
        metadata: Optional[Dict[str, object]] = None,
        note_id: Optional[str] = None,
    ) -> Note:
        metadata_out: Dict[str, object] = dict(metadata or {})
        network_context = self._build_network_context(traffic_text, protocol=protocol, metadata=metadata_out)
        if network_context:
            metadata_out["network_context"] = network_context

        knowledge = self.retriever.retrieve(traffic_text)
        extraction = self._extract_semantics(
            text=traffic_text,
            knowledge=knowledge,
            seed_keywords=self._extract_plain_keywords(traffic_text) + self._network_keywords(network_context),
            seed_tactics=knowledge.tech_ids,
        )

        keywords = dedupe_keep_order(
            self._extract_plain_keywords(traffic_text)
            + self._network_keywords(network_context)
            + extraction.keywords
        )
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
            metadata=metadata_out,
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

    def _build_network_context(
        self,
        text: str,
        protocol: Optional[str],
        metadata: Dict[str, object],
    ) -> Dict[str, object]:
        context: Dict[str, object] = {}

        def _to_int(value: object) -> Optional[int]:
            try:
                if value is None or value == "":
                    return None
                return int(value)
            except (TypeError, ValueError):
                return None

        proto = (protocol or metadata.get("protocol") or "").strip()
        if proto:
            context["protocol"] = proto.upper()

        src_ip = str(metadata.get("src_ip") or "").strip()
        dst_ip = str(metadata.get("dst_ip") or "").strip()
        src_port = _to_int(metadata.get("src_port"))
        dst_port = _to_int(metadata.get("dst_port"))

        if (not src_ip or not dst_ip) or (src_port is None or dst_port is None):
            for ln in (text or "").splitlines():
                line = ln.strip()
                if not line.lower().startswith("src="):
                    continue
                match = re.match(
                    r"^src=(?P<src_ip>[^:\s]+):(?P<src_port>\d+)\s+dst=(?P<dst_ip>[^:\s]+):(?P<dst_port>\d+)\s*$",
                    line,
                    flags=re.IGNORECASE,
                )
                if not match:
                    continue
                src_ip = src_ip or match.group("src_ip")
                dst_ip = dst_ip or match.group("dst_ip")
                if src_port is None:
                    src_port = _to_int(match.group("src_port"))
                if dst_port is None:
                    dst_port = _to_int(match.group("dst_port"))
                break

        if src_ip:
            context["src_ip"] = src_ip
            context["src_zone"] = self._ip_zone(src_ip)
        if dst_ip:
            context["dst_ip"] = dst_ip
            context["dst_zone"] = self._ip_zone(dst_ip)
        if src_port is not None:
            context["src_port"] = src_port
        if dst_port is not None:
            context["dst_port"] = dst_port

        if "src_zone" in context and "dst_zone" in context:
            context["direction_hint"] = f"{context['src_zone']}_to_{context['dst_zone']}"

        return context

    def _ip_zone(self, value: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(value)
        except ValueError:
            return "unknown"
        if ip_obj.is_private:
            return "private"
        if ip_obj.is_loopback:
            return "loopback"
        if ip_obj.is_link_local:
            return "link_local"
        return "public"

    def _network_keywords(self, network_context: Dict[str, object]) -> List[str]:
        if not network_context:
            return []
        tokens: List[str] = []
        for key in ("protocol", "src_ip", "dst_ip", "src_port", "dst_port", "src_zone", "dst_zone", "direction_hint"):
            value = network_context.get(key)
            if value is None or value == "":
                continue
            tokens.append(f"{key}={value}")
        return tokens

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

    def _merge_knowledge(self, *knowledge_items: EnrichedKnowledge) -> EnrichedKnowledge:
        merged = EnrichedKnowledge()
        debug: Dict[str, object] = {}

        def _clone_doc_item(item: RetrievedItem) -> RetrievedItem:
            return RetrievedItem(
                doc=ExternalDoc(
                    doc_id=item.doc.doc_id,
                    source=item.doc.source,
                    title=item.doc.title,
                    text=item.doc.text,
                    metadata=dict(item.doc.metadata),
                ),
                score=float(item.score),
                hit_type=item.hit_type,
            )

        def _merge_bucket(attr: str) -> List[RetrievedItem]:
            out: List[RetrievedItem] = []
            seen: Dict[tuple[str, str, str], int] = {}
            for knowledge in knowledge_items:
                for item in getattr(knowledge, attr, []):
                    key = (item.doc.doc_id, item.doc.source, item.hit_type)
                    pos = seen.get(key)
                    cloned = _clone_doc_item(item)
                    if pos is None:
                        seen[key] = len(out)
                        out.append(cloned)
                    elif cloned.score > out[pos].score:
                        out[pos] = cloned
            return out

        merged.cve_docs = _merge_bucket("cve_docs")
        merged.attack_docs = _merge_bucket("attack_docs")
        merged.cti_docs = _merge_bucket("cti_docs")

        cve_ids: List[str] = []
        tech_ids: List[str] = []
        for knowledge in knowledge_items:
            cve_ids.extend(list(knowledge.cve_ids))
            tech_ids.extend(list(knowledge.tech_ids))
            debug.update(dict(knowledge.debug))

        merged.cve_ids = dedupe_keep_order([str(x).strip() for x in cve_ids if str(x).strip()])
        merged.tech_ids = dedupe_keep_order([str(x).upper().strip() for x in tech_ids if str(x).strip()])
        merged.debug = debug
        return merged
