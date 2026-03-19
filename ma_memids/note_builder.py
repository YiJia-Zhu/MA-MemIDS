from __future__ import annotations

import ipaddress
import json
import re
import uuid
from typing import Dict, Iterable, List, Optional, Tuple

from .embedding import SentenceTransformerEmbedder
from .knowledge import DualPathRetriever
from .llm_client import BaseLLMClient
from .models import EnrichedKnowledge, ExternalDoc, LLMNoteExtraction, Note, RetrievalPlan, RetrievedItem
from .prompts import (
    NOTE_EXTRACTION_SYSTEM,
    NOTE_EXTRACTION_USER,
    RETRIEVAL_PLANNER_SYSTEM,
    RETRIEVAL_PLANNER_USER,
)
from .rule_parser import parse_rule_fields
from .utils import dedupe_keep_order, now_iso


TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
COMMON_SERVICE_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161,
    389, 443, 445, 465, 514, 587, 631, 636, 873, 902, 993, 995, 1433, 1434, 1521, 1883, 2049,
    2375, 2376, 3306, 3389, 5000, 5432, 5601, 5672, 5900, 6379, 6443, 8000, 8080, 8081, 8088,
    8443, 9000, 9042, 9200, 9300, 9443,
}


class NoteBuilder:
    def __init__(self, retriever: DualPathRetriever, embedder: SentenceTransformerEmbedder, llm_client: BaseLLMClient):
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

        rule_network_context = self._compact_rule_network_context(fields)
        feature_inventory = self._build_rule_feature_inventory(rule_text, fields, rule_network_context)
        retrieval_plan = self._plan_retrieval(
            artifact_type="rule",
            text=rule_text,
            feature_inventory=feature_inventory,
            network_context=rule_network_context,
            seed_keywords=list(fields.get("keywords", [])) + seeded_keywords,
            seed_tactics=list(fields.get("tech_ids", [])) + seeded_tactics,
            known_cves=list(fields.get("cve_ids", [])),
            known_techs=list(fields.get("tech_ids", [])),
        )

        hint_knowledge: List[EnrichedKnowledge] = []
        if extra_knowledge is not None:
            hint_knowledge.append(extra_knowledge)
        if analysis_note is not None:
            hint_knowledge.append(analysis_note.external_knowledge)

        if hint_knowledge:
            knowledge = self._merge_knowledge(*hint_knowledge)
        else:
            knowledge = self.retriever.retrieve(rule_text, plan=retrieval_plan)
        self._attach_retrieval_debug(knowledge, retrieval_plan=retrieval_plan, feature_inventory=feature_inventory)

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
                seed_keywords=list(fields.get("keywords", [])) + seeded_keywords + retrieval_plan.seed_keywords(),
                seed_tactics=list(fields.get("tech_ids", [])) + seeded_tactics + retrieval_plan.tech_ids,
            )

        keywords = dedupe_keep_order(
            list(fields.get("keywords", []))
            + seeded_keywords
            + retrieval_plan.seed_keywords()
            + extraction.keywords
        )
        tactics = dedupe_keep_order(
            list(fields.get("tech_ids", []))
            + seeded_tactics
            + retrieval_plan.tech_ids
            + extraction.tactics
            + knowledge.tech_ids
        )
        intent = (intent_hint or extraction.intent or retrieval_plan.intent).strip()

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

        feature_inventory = self._build_traffic_feature_inventory(traffic_text, network_context)
        retrieval_plan = self._plan_retrieval(
            artifact_type="traffic",
            text=traffic_text,
            feature_inventory=feature_inventory,
            network_context=network_context,
            seed_keywords=self._extract_plain_keywords(traffic_text),
            seed_tactics=[m.group(0).upper() for m in TECH_RE.finditer(traffic_text)],
            known_cves=[m.group(0).upper() for m in CVE_RE.finditer(traffic_text)],
            known_techs=[m.group(0).upper() for m in TECH_RE.finditer(traffic_text)],
        )

        knowledge = self.retriever.retrieve(traffic_text, plan=retrieval_plan)
        self._attach_retrieval_debug(knowledge, retrieval_plan=retrieval_plan, feature_inventory=feature_inventory)
        extraction = self._extract_semantics(
            text=traffic_text,
            knowledge=knowledge,
            seed_keywords=(
                self._extract_plain_keywords(traffic_text)
                + self._network_keywords(network_context)
                + retrieval_plan.seed_keywords()
            ),
            seed_tactics=retrieval_plan.tech_ids + knowledge.tech_ids,
        )

        keywords = dedupe_keep_order(
            self._extract_plain_keywords(traffic_text)
            + self._network_keywords(network_context)
            + retrieval_plan.seed_keywords()
            + extraction.keywords
        )
        tactics = dedupe_keep_order(retrieval_plan.tech_ids + extraction.tactics + knowledge.tech_ids)
        intent = extraction.intent or retrieval_plan.intent

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

    def _plan_retrieval(
        self,
        *,
        artifact_type: str,
        text: str,
        feature_inventory: Dict[str, object],
        network_context: Optional[Dict[str, object]],
        seed_keywords: Iterable[str],
        seed_tactics: Iterable[str],
        known_cves: Iterable[str],
        known_techs: Iterable[str],
    ) -> RetrievalPlan:
        fallback = self._heuristic_retrieval_plan(
            artifact_type=artifact_type,
            text=text,
            network_context=network_context or {},
            seed_keywords=seed_keywords,
            seed_tactics=seed_tactics,
            known_cves=known_cves,
            known_techs=known_techs,
        )
        messages = [
            {"role": "system", "content": RETRIEVAL_PLANNER_SYSTEM},
            {
                "role": "user",
                "content": RETRIEVAL_PLANNER_USER.format(
                    artifact_type=artifact_type,
                    text=text,
                    feature_inventory=json.dumps(feature_inventory, ensure_ascii=False),
                    network_context=json.dumps(network_context or {}, ensure_ascii=False),
                    seed_keywords=json.dumps(dedupe_keep_order([str(x).strip() for x in seed_keywords if str(x).strip()])[:20], ensure_ascii=False),
                    seed_tactics=json.dumps(dedupe_keep_order([str(x).upper().strip() for x in seed_tactics if str(x).strip()])[:10], ensure_ascii=False),
                ),
            },
        ]
        try:
            response = self.llm.chat(messages, temperature=0.1)
            parsed = self._try_parse_json(response)
            if parsed is not None:
                return self._parse_retrieval_plan(parsed, fallback)
        except Exception:
            pass
        return fallback

    def _parse_retrieval_plan(self, parsed: Dict[str, object], fallback: RetrievalPlan) -> RetrievalPlan:
        sparse_terms = dedupe_keep_order(
            fallback.sparse_terms
            + self._clean_retrieval_terms(self._listify(parsed.get("sparse_terms")))
        )[:24]
        payload_signals = dedupe_keep_order(
            fallback.payload_signals
            + self._clean_retrieval_terms(self._listify(parsed.get("payload_signals")))
        )[:10]
        cve_ids = dedupe_keep_order(
            fallback.cve_ids
            + [m.group(0).upper() for m in CVE_RE.finditer(" ".join(str(x) for x in self._listify(parsed.get("cve_ids"))))]
        )[:10]
        tech_ids = dedupe_keep_order(
            fallback.tech_ids
            + [m.group(0).upper() for m in TECH_RE.finditer(" ".join(str(x) for x in self._listify(parsed.get("tech_ids"))))]
        )[:10]
        protocols = dedupe_keep_order(
            fallback.protocols
            + [str(x).upper().strip() for x in self._listify(parsed.get("protocols")) if str(x).strip()]
        )[:6]
        network_roles = dedupe_keep_order(
            fallback.network_roles
            + [str(x).strip().lower() for x in self._listify(parsed.get("network_roles")) if str(x).strip()]
        )[:6]
        selected_features = dedupe_keep_order(
            fallback.selected_features
            + [str(x).strip() for x in self._listify(parsed.get("selected_features")) if str(x).strip()]
        )[:24]
        discarded_features = dedupe_keep_order(
            fallback.discarded_features
            + [str(x).strip() for x in self._listify(parsed.get("discarded_features")) if str(x).strip()]
        )[:24]

        service_ports: List[int] = list(fallback.service_ports)
        for raw_port in self._listify(parsed.get("service_ports")):
            try:
                port = int(raw_port)
            except (TypeError, ValueError):
                continue
            if self._is_semantic_service_port(port) and port not in service_ports:
                service_ports.append(port)

        intent = str(parsed.get("intent") or "").strip() or fallback.intent
        dense_query = str(parsed.get("dense_query") or "").strip() or fallback.dense_query
        dense_query = self._sanitize_dense_query(dense_query)
        if not dense_query:
            dense_query = fallback.dense_query

        return RetrievalPlan(
            intent=intent,
            sparse_terms=sparse_terms,
            dense_query=dense_query,
            cve_ids=cve_ids,
            tech_ids=tech_ids,
            protocols=protocols,
            payload_signals=payload_signals,
            network_roles=network_roles,
            service_ports=service_ports[:8],
            selected_features=selected_features,
            discarded_features=discarded_features,
        )

    def _heuristic_retrieval_plan(
        self,
        *,
        artifact_type: str,
        text: str,
        network_context: Dict[str, object],
        seed_keywords: Iterable[str],
        seed_tactics: Iterable[str],
        known_cves: Iterable[str],
        known_techs: Iterable[str],
    ) -> RetrievalPlan:
        sparse_terms = dedupe_keep_order(
            self._clean_retrieval_terms(seed_keywords)
            + [m.group(0).upper() for m in CVE_RE.finditer(text)]
            + [m.group(0).upper() for m in TECH_RE.finditer(text)]
        )[:24]
        cve_ids = dedupe_keep_order(
            [m.group(0).upper() for m in CVE_RE.finditer(text)]
            + [str(x).upper().strip() for x in known_cves if str(x).strip()]
        )[:10]
        tech_ids = dedupe_keep_order(
            [m.group(0).upper() for m in TECH_RE.finditer(text)]
            + [str(x).upper().strip() for x in known_techs if str(x).strip()]
            + [str(x).upper().strip() for x in seed_tactics if str(x).strip()]
        )[:10]
        protocol_value = str(network_context.get("protocol") or "").upper().strip()
        protocols = [protocol_value] if protocol_value else []
        payload_candidates = list(seed_keywords) if artifact_type == "rule" else self._extract_plain_keywords(text)
        payload_signals = dedupe_keep_order(
            self._clean_retrieval_terms(payload_candidates)
        )[:8]
        network_roles = dedupe_keep_order(self._network_roles(network_context))[:4]
        service_ports = self._semantic_service_ports(network_context)

        intent = self._fallback_retrieval_intent(
            artifact_type=artifact_type,
            cve_ids=cve_ids,
            tech_ids=tech_ids,
            protocols=protocols,
            payload_signals=payload_signals,
            network_roles=network_roles,
        )
        dense_query = self._build_dense_query(
            intent=intent,
            protocols=protocols,
            payload_signals=payload_signals,
            cve_ids=cve_ids,
            tech_ids=tech_ids,
            network_roles=network_roles,
            service_ports=service_ports,
        )

        return RetrievalPlan(
            intent=intent,
            sparse_terms=sparse_terms,
            dense_query=dense_query,
            cve_ids=cve_ids,
            tech_ids=tech_ids,
            protocols=protocols,
            payload_signals=payload_signals,
            network_roles=network_roles,
            service_ports=service_ports,
            selected_features=dedupe_keep_order(sparse_terms + payload_signals + tech_ids + cve_ids + protocols + network_roles)[:24],
            discarded_features=self._heuristic_discarded_features(network_context),
        )

    def _build_rule_feature_inventory(
        self,
        rule_text: str,
        fields: Dict[str, object],
        network_context: Dict[str, object],
    ) -> Dict[str, object]:
        raw_keywords = [str(x).strip() for x in fields.get("keywords", []) if str(x).strip()]
        clean_keywords = self._clean_retrieval_terms(raw_keywords)
        return {
            "artifact_type": "rule",
            "network_context": dict(network_context or {}),
            "protocol": fields.get("protocol"),
            "header": {
                "src_ip": fields.get("src_ip"),
                "src_port": fields.get("src_port"),
                "dst_ip": fields.get("dst_ip"),
                "dst_port": fields.get("dst_port"),
            },
            "raw_keywords": raw_keywords[:20],
            "clean_keyword_candidates": clean_keywords[:20],
            "explicit_ids": {
                "cve_ids": [str(x).upper().strip() for x in fields.get("cve_ids", []) if str(x).strip()],
                "tech_ids": [str(x).upper().strip() for x in fields.get("tech_ids", []) if str(x).strip()],
            },
            "line_features": self._top_text_lines(rule_text, limit=8),
        }

    def _build_traffic_feature_inventory(
        self,
        traffic_text: str,
        network_context: Dict[str, object],
    ) -> Dict[str, object]:
        http_features = self._http_features_from_text(traffic_text)
        plain_keywords = self._extract_plain_keywords(traffic_text)
        return {
            "artifact_type": "traffic",
            "network_context": dict(network_context or {}),
            "plain_keywords": plain_keywords[:30],
            "clean_keyword_candidates": self._clean_retrieval_terms(plain_keywords)[:24],
            "http_features": http_features,
            "payload_features": self._payload_features_from_text(traffic_text)[:16],
            "observed_headers": self._observed_headers_from_text(traffic_text)[:20],
            "explicit_ids": {
                "cve_ids": [m.group(0).upper() for m in CVE_RE.finditer(traffic_text)],
                "tech_ids": [m.group(0).upper() for m in TECH_RE.finditer(traffic_text)],
            },
            "line_features": self._top_text_lines(traffic_text, limit=10),
        }

    def _attach_retrieval_debug(
        self,
        knowledge: EnrichedKnowledge,
        *,
        retrieval_plan: RetrievalPlan,
        feature_inventory: Dict[str, object],
    ) -> None:
        debug = dict(knowledge.debug) if isinstance(knowledge.debug, dict) else {}
        debug["plan"] = retrieval_plan.to_dict()
        debug["feature_inventory"] = dict(feature_inventory)
        knowledge.debug = debug

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

    def _fallback_retrieval_intent(
        self,
        *,
        artifact_type: str,
        cve_ids: List[str],
        tech_ids: List[str],
        protocols: List[str],
        payload_signals: List[str],
        network_roles: List[str],
    ) -> str:
        role = network_roles[0] if network_roles else ""
        proto = protocols[0] if protocols else "network"
        if cve_ids:
            return f"Exploit activity related to {', '.join(cve_ids[:2])} over {proto}"
        if tech_ids:
            return f"Traffic associated with ATT&CK {tech_ids[0]} over {proto}"
        if payload_signals:
            return f"Suspicious {artifact_type} with payload indicator {payload_signals[0]} over {proto}"
        if role:
            return f"Suspicious {artifact_type} activity from {role} over {proto}"
        return f"Suspicious {artifact_type} activity over {proto}"

    def _build_dense_query(
        self,
        *,
        intent: str,
        protocols: List[str],
        payload_signals: List[str],
        cve_ids: List[str],
        tech_ids: List[str],
        network_roles: List[str],
        service_ports: List[int],
    ) -> str:
        parts: List[str] = []
        if intent:
            parts.append(intent)
        if protocols:
            parts.append(f"protocols: {', '.join(protocols[:4])}")
        if payload_signals:
            parts.append(f"payload signals: {', '.join(payload_signals[:6])}")
        if cve_ids:
            parts.append(f"related CVEs: {', '.join(cve_ids[:4])}")
        if tech_ids:
            parts.append(f"ATT&CK techniques: {', '.join(tech_ids[:4])}")
        if network_roles:
            parts.append(f"traffic roles: {', '.join(network_roles[:4])}")
        if service_ports:
            parts.append(f"service ports: {', '.join(str(port) for port in service_ports[:6])}")
        return self._sanitize_dense_query(". ".join(part for part in parts if part))

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

    def _compact_rule_network_context(self, fields: Dict[str, object]) -> Dict[str, object]:
        context: Dict[str, object] = {}
        for key in ("protocol", "src_ip", "src_port", "dst_ip", "dst_port"):
            value = fields.get(key)
            if value is None or value == "":
                continue
            context[key] = value
        src_ip = str(context.get("src_ip") or "").strip()
        dst_ip = str(context.get("dst_ip") or "").strip()
        if src_ip:
            context["src_zone"] = self._ip_zone(src_ip)
        if dst_ip:
            context["dst_zone"] = self._ip_zone(dst_ip)
        if "src_zone" in context and "dst_zone" in context:
            context["direction_hint"] = f"{context['src_zone']}_to_{context['dst_zone']}"
        return context

    def _top_text_lines(self, text: str, limit: int = 8) -> List[str]:
        out: List[str] = []
        for line in (text or "").splitlines():
            cleaned = line.strip()
            if not cleaned:
                continue
            out.append(cleaned[:180])
            if len(out) >= limit:
                break
        return out

    def _payload_features_from_text(self, text: str) -> List[str]:
        payload_chunks: List[str] = []
        for line in (text or "").splitlines():
            cleaned = line.strip()
            lower = cleaned.lower()
            if lower.startswith("payload="):
                payload_chunks.append(cleaned[8:])
            elif lower.startswith("http="):
                payload_chunks.append(cleaned[5:])
        if not payload_chunks:
            payload_chunks.append(text)
        features: List[str] = []
        for chunk in payload_chunks:
            features.extend(self._extract_plain_keywords(chunk))
        return dedupe_keep_order([self._trim_signal(item, limit=96) for item in features if str(item).strip()])

    def _observed_headers_from_text(self, text: str) -> List[str]:
        headers: List[str] = []
        for line in (text or "").splitlines():
            cleaned = line.strip()
            if not cleaned or "=" in cleaned.split(":", 1)[0]:
                continue
            if ": " not in cleaned:
                continue
            key, value = cleaned.split(": ", 1)
            if not key or not value:
                continue
            headers.append(f"{key}: {value[:80]}")
        return dedupe_keep_order(headers)

    def _http_features_from_text(self, text: str) -> Dict[str, object]:
        method = ""
        uri = ""
        header_names: List[str] = []
        for line in (text or "").splitlines():
            cleaned = line.strip()
            lower = cleaned.lower()
            if lower.startswith("http="):
                request_line = cleaned[5:].strip()
                match = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)", request_line, flags=re.IGNORECASE)
                if match:
                    method = match.group(1).upper()
                    uri = match.group(2)
                continue
            if ": " in cleaned and "=" not in cleaned.split(":", 1)[0]:
                header_name = cleaned.split(": ", 1)[0].strip()
                if header_name:
                    header_names.append(header_name)
        return {
            "method": method,
            "uri": uri,
            "header_names": dedupe_keep_order(header_names)[:20],
        }

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
        if not proto:
            for ln in (text or "").splitlines():
                line = ln.strip()
                if line.lower().startswith("protocol="):
                    proto = line.split("=", 1)[1].strip()
                    break
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

    def _network_roles(self, network_context: Dict[str, object]) -> List[str]:
        roles: List[str] = []
        direction = str(network_context.get("direction_hint") or "").strip().lower()
        protocol = str(network_context.get("protocol") or "").strip().lower()
        src_zone = str(network_context.get("src_zone") or "").strip().lower()
        dst_zone = str(network_context.get("dst_zone") or "").strip().lower()

        if direction:
            roles.append(direction)
            aliases = {
                "public_to_private": "internet_to_server",
                "public_to_public": "internet_to_internet",
                "private_to_private": "internal_lateral_movement",
                "private_to_public": "client_to_server",
            }
            if direction in aliases:
                roles.append(aliases[direction])
        elif src_zone or dst_zone:
            roles.append(f"{src_zone or 'unknown'}_to_{dst_zone or 'unknown'}")

        if protocol in {"http", "https", "dns", "smtp", "imap", "pop3", "ftp", "smb", "ldap", "rdp", "ssh"}:
            roles.append("client_to_server")
        elif protocol:
            roles.append(f"{protocol}_session")

        return dedupe_keep_order([role for role in roles if role])

    def _heuristic_discarded_features(self, network_context: Dict[str, object]) -> List[str]:
        discarded: List[str] = []
        for key in ("src_ip", "dst_ip"):
            value = network_context.get(key)
            if value:
                discarded.append(f"{key}={value}")
        for key in ("src_port", "dst_port"):
            value = network_context.get(key)
            try:
                port = int(value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            if not self._is_semantic_service_port(port):
                discarded.append(f"{key}={port}")
        return dedupe_keep_order(discarded)[:12]

    def _semantic_service_ports(self, network_context: Dict[str, object]) -> List[int]:
        ports: List[int] = []
        for key in ("src_port", "dst_port"):
            value = network_context.get(key)
            try:
                port = int(value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            if self._is_semantic_service_port(port) and port not in ports:
                ports.append(port)
        return ports[:8]

    def _is_semantic_service_port(self, port: int) -> bool:
        return port in COMMON_SERVICE_PORTS or 1 <= port <= 1024

    def _trim_signal(self, value: str, limit: int = 64) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        if len(text) > limit:
            text = text[:limit]
        return text

    def _clean_retrieval_term(self, value: str) -> str:
        text = self._trim_signal(value, limit=96).strip(" \t\r\n\"'()[]{};,")
        if not text:
            return ""
        low = text.lower()
        normalized = low.strip(":")
        if normalized in {
            "alert", "drop", "pass", "reject", "any", "flow", "to_server", "to_client", "established",
            "content", "nocase", "metadata", "msg", "sid", "rev", "http", "https", "host", "user-agent",
            "payload", "protocol", "src", "dst", "src_ip", "dst_ip", "src_port", "dst_port", "src_zone",
            "dst_zone", "direction_hint",
        }:
            return ""
        if low.startswith(("protocol=", "src_ip=", "dst_ip=", "src_port=", "dst_port=", "src_zone=", "dst_zone=", "direction_hint=")):
            return ""
        if re.fullmatch(r"\d{1,5}", text):
            return ""
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
            return ""
        return text

    def _clean_retrieval_terms(self, values: Iterable[object]) -> List[str]:
        out: List[str] = []
        for value in values:
            cleaned = self._clean_retrieval_term(str(value))
            if cleaned:
                out.append(cleaned)
        return out

    def _sanitize_dense_query(self, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "host", text)
        text = re.sub(r"\b[A-Za-z0-9]{20,}\b", "", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:512]

    def _listify(self, value: object) -> List[object]:
        if isinstance(value, list):
            return value
        if value is None or value == "":
            return []
        return [value]

    def _tokenize_signal_text(self, text: str) -> List[str]:
        raw = re.findall(r"[A-Za-z0-9_./<>=:%'\"-]{3,}", text)
        out: List[str] = []
        noise = {
            "http", "https", "host", "user-agent", "mozilla", "accept", "connection",
            "pcap", "protocol", "payload", "src", "dst", "tcp", "udp", "alert", "any",
            "content", "msg", "metadata", "flow", "established", "nocase",
        }
        for tok in raw:
            t = tok.strip().strip(" \t\r\n\"'()[]{};,")
            if not t or t.isdigit():
                continue
            low = t.lower()
            normalized = low.strip(":")
            if normalized in noise:
                continue
            if low.startswith(("/mnt/", "/tmp/", "pcap=", "protocol=", "src=", "dst=")):
                continue
            if low.startswith(("src_ip=", "dst_ip=", "src_port=", "dst_port=", "src_zone=", "dst_zone=", "direction_hint=")):
                continue
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", t):
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
