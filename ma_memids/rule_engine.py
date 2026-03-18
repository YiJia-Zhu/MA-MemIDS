from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .config import RuntimeConfig, Thresholds
from .llm_client import BaseLLMClient
from .models import FailureDiagnosis, Note, RuleProposal
from .prompts import (
    FAILURE_ANALYSIS_USER,
    RULE_GENERATE_SYSTEM,
    RULE_GENERATE_USER,
    RULE_REPAIR_SYSTEM,
    RULE_REPAIR_USER,
)
from .rule_parser import bump_rev, ensure_sid, extract_sid
from .utils import dedupe_keep_order


RULE_LINE_RE = re.compile(r"^(alert|drop|pass|reject)\s+", re.IGNORECASE)
RULE_HEADER_RE = re.compile(
    r"^(?P<action>alert|drop|pass|reject)\s+"
    r"(?P<proto>\S+)\s+"
    r"(?P<src_net>\S+)\s+(?P<src_port>\S+)\s+->\s+"
    r"(?P<dst_net>\S+)\s+(?P<dst_port>\S+)\s+\(",
    re.IGNORECASE,
)


class RuleGenerationEngine:
    def __init__(
        self,
        llm_client: BaseLLMClient,
        thresholds: Optional[Thresholds] = None,
        runtime: Optional[RuntimeConfig] = None,
    ):
        self.llm = llm_client
        self.thresholds = thresholds or Thresholds()
        self.runtime = runtime or RuntimeConfig()

    def decide_mode(self, max_similarity: float) -> str:
        if max_similarity >= self.thresholds.high:
            return "repair"
        if max_similarity >= self.thresholds.med:
            return "reference_generate"
        return "scratch_generate"

    def propose_rule(
        self,
        traffic_note: Note,
        candidate_notes: Sequence[Note],
        all_rule_notes: Iterable[Note],
    ) -> RuleProposal:
        if candidate_notes:
            base_note = candidate_notes[0]
            max_similarity = max(0.0, min(1.0, self._similarity_hint(traffic_note, base_note)))
        else:
            base_note = None
            max_similarity = 0.0

        mode = self.decide_mode(max_similarity)
        next_sid = self._next_sid(all_rule_notes)

        if mode == "repair" and base_note is not None:
            rule = self._repair_rule(traffic_note, base_note)
            return RuleProposal(rule_text=rule, mode=mode, base_note_id=base_note.note_id, max_similarity=max_similarity)

        refs = [n.content for n in candidate_notes[:5]]
        rule = self._generate_rule(traffic_note, refs, sid=next_sid)
        return RuleProposal(rule_text=rule, mode=mode, base_note_id=(base_note.note_id if base_note else None), max_similarity=max_similarity)

    def regenerate_with_diagnosis(
        self,
        previous_rule: str,
        traffic_note: Note,
        diagnosis: FailureDiagnosis,
        sid_hint: Optional[int],
    ) -> str:
        if diagnosis.failure_type in {"syntax", "overfitting"}:
            sid = sid_hint if sid_hint is not None else self.runtime.sid_start
            return self._fallback_rule(traffic_note, sid=sid, msg_prefix="Regenerated")

        messages = [
            {"role": "system", "content": RULE_GENERATE_SYSTEM},
            {
                "role": "user",
                "content": FAILURE_ANALYSIS_USER.format(
                    recall=0.0,
                    fpr=0.0,
                    score=0.0,
                    diagnosis=diagnosis.suggestion,
                ),
            },
        ]
        try:
            response = self.llm.chat(messages, temperature=0.3)
            rule = self._extract_rule_line(response)
            if rule:
                if sid_hint:
                    rule = ensure_sid(rule, sid_hint)
                return self._normalize_rule_header_by_context(rule, traffic_note)
        except Exception:
            pass

        sid = sid_hint if sid_hint is not None else self.runtime.sid_start
        return self._fallback_rule(traffic_note, sid=sid, msg_prefix="Regenerated")

    def _repair_rule(self, traffic_note: Note, base_note: Note) -> str:
        base_rule = base_note.content
        new_features = [k for k in traffic_note.keywords if k not in set(base_note.keywords)]
        messages = [
            {"role": "system", "content": RULE_REPAIR_SYSTEM},
            {
                "role": "user",
                "content": RULE_REPAIR_USER.format(
                    base_rule=base_rule,
                    base_intent=base_note.intent,
                    new_features=new_features[:10],
                ),
            },
        ]
        sid = extract_sid(base_rule)

        try:
            response = self.llm.chat(messages, temperature=0.2)
            rule = self._extract_rule_line(response)
            if rule:
                if sid is not None:
                    rule = ensure_sid(rule, sid)
                return bump_rev(self._normalize_rule_header_by_context(rule, traffic_note))
        except Exception:
            pass

        # Heuristic repair fallback with same SID and incremented revision.
        repaired = self._fallback_rule(
            traffic_note,
            sid=sid if sid is not None else self.runtime.sid_start,
            msg_prefix="Repaired variant",
        )
        return bump_rev(ensure_sid(repaired, sid if sid is not None else self.runtime.sid_start))

    def _generate_rule(self, traffic_note: Note, reference_rules: Sequence[str], sid: int) -> str:
        ref_text = "\n".join(reference_rules) if reference_rules else "N/A"
        network_context = self._network_context_from_note(traffic_note)
        messages = [
            {"role": "system", "content": RULE_GENERATE_SYSTEM},
            {
                "role": "user",
                "content": RULE_GENERATE_USER.format(
                    intent=traffic_note.intent,
                    keywords=traffic_note.keywords[:20],
                    network_context=self._format_network_context(network_context),
                    tactics=traffic_note.tactics[:10],
                    cve_ids=traffic_note.external_knowledge.cve_ids[:5],
                    generation_constraints=self._generation_constraints(network_context),
                    reference_rules=ref_text,
                ),
            },
        ]
        try:
            response = self.llm.chat(messages, temperature=0.4)
            rule = self._extract_rule_line(response)
            if rule:
                return self._normalize_rule_header_by_context(ensure_sid(rule, sid), traffic_note)
        except Exception:
            pass

        return self._normalize_rule_header_by_context(
            self._fallback_rule(traffic_note, sid=sid, msg_prefix="Generated"),
            traffic_note,
        )

    def _fallback_rule(self, traffic_note: Note, sid: int, msg_prefix: str) -> str:
        protocol = (traffic_note.protocol or "http").lower()
        if protocol not in {"tcp", "udp", "icmp", "ip", "http"}:
            protocol = "http"

        keywords = self._select_detection_keywords(traffic_note.keywords)
        if not keywords:
            keywords = ["/", "http"]

        tactic_meta = ",".join(traffic_note.tactics[:3]) if traffic_note.tactics else "T1190"
        cve_meta = ",".join(traffic_note.external_knowledge.cve_ids[:3]) if traffic_note.external_knowledge.cve_ids else "none"

        options = [
            f'msg:"{msg_prefix}: {self._sanitize_msg(traffic_note.intent)}"',
            "flow:to_server,established",
        ]
        if protocol == "http":
            options.append("http.uri")
        for kw in keywords:
            options.append(f'content:"{kw}"')
            options.append("nocase")
        options.append(f"metadata:attack_target Server,mitre_tactic {tactic_meta},cve {cve_meta}")
        options.append(f"sid:{sid}")
        options.append("rev:1")

        return f"alert {protocol} any any -> any any ({'; '.join(options)}; )".replace("; )", ";)")

    def _extract_rule_line(self, text: str) -> Optional[str]:
        for line in text.splitlines():
            line = line.strip()
            if line.upper().startswith("RULE:"):
                line = line[5:].strip()
            if RULE_LINE_RE.match(line):
                return line

        # Code block fallback
        match = re.search(r"```(?:suricata)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE)
        if match:
            for line in match.group(1).splitlines():
                candidate = line.strip()
                if RULE_LINE_RE.match(candidate):
                    return candidate
        return None

    def _next_sid(self, all_rule_notes: Iterable[Note]) -> int:
        max_sid = self.runtime.sid_start - 1
        for note in all_rule_notes:
            if note.sid and note.sid > max_sid:
                max_sid = note.sid
            parsed = extract_sid(note.content)
            if parsed and parsed > max_sid:
                max_sid = parsed
        return max_sid + 1

    def _sanitize_keyword(self, token: str) -> str:
        token = token.strip().replace('"', "")
        if not token:
            return ""
        if len(token) > 64:
            token = token[:64]
        return token

    def _select_detection_keywords(self, keywords: Sequence[str]) -> List[str]:
        sanitized = [self._sanitize_keyword(k) for k in keywords]
        sanitized = [k for k in sanitized if k]

        def is_noise(tok: str) -> bool:
            low = tok.lower()
            if low in {"http", "https", "host", "user-agent", "tcp", "udp", "pcap", "protocol"}:
                return True
            if low.startswith(("/mnt/", "/tmp/", "pcap=", "protocol=", "src=", "dst=")):
                return True
            return low.startswith(
                (
                    "src_ip=",
                    "dst_ip=",
                    "src_port=",
                    "dst_port=",
                    "src_zone=",
                    "dst_zone=",
                    "direction_hint=",
                )
            )

        signal_patterns = [
            r"<script", r"script>", r"alert", r"onerror", r"javascript",
            r"union", r"select", r"or 1=1", r"\.\./", r"/etc/passwd",
            r"cmd", r"powershell", r"eval", r"base64", r"xss", r"sqli",
        ]

        signal: List[str] = []
        normal: List[str] = []
        for tok in sanitized:
            if is_noise(tok):
                continue
            low = tok.lower()
            if any(re.search(pat, low) for pat in signal_patterns):
                signal.append(tok)
            else:
                normal.append(tok)

        selected = dedupe_keep_order(signal + normal)
        return selected[:2]

    def _sanitize_msg(self, text: str) -> str:
        text = text.strip().replace('"', "'")
        return text[:120] if len(text) > 120 else text

    def _similarity_hint(self, traffic_note: Note, base_note: Note) -> float:
        # Use metadata if caller already sorted by combined similarity.
        common = set(traffic_note.keywords) & set(base_note.keywords)
        if not traffic_note.keywords:
            return 0.0
        return len(common) / max(len(set(traffic_note.keywords)), 1)

    def _network_context_from_note(self, note: Note) -> Dict[str, Any]:
        meta = note.metadata if isinstance(note.metadata, dict) else {}
        net = meta.get("network_context")
        context: Dict[str, Any] = dict(net) if isinstance(net, dict) else {}

        context.setdefault("protocol", (note.protocol or "").upper() or None)
        for key in ("src_ip", "dst_ip", "src_port", "dst_port"):
            if context.get(key) in (None, "") and meta.get(key) not in (None, ""):
                context[key] = meta.get(key)

        if context.get("src_zone") in (None, "") and context.get("src_ip"):
            context["src_zone"] = self._ip_zone(str(context["src_ip"]))
        if context.get("dst_zone") in (None, "") and context.get("dst_ip"):
            context["dst_zone"] = self._ip_zone(str(context["dst_ip"]))
        if context.get("direction_hint") in (None, "") and context.get("src_zone") and context.get("dst_zone"):
            context["direction_hint"] = f"{context['src_zone']}_to_{context['dst_zone']}"
        return context

    def _ip_zone(self, ip_value: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(ip_value)
        except ValueError:
            return "unknown"
        if ip_obj.is_private:
            return "private"
        if ip_obj.is_loopback:
            return "loopback"
        if ip_obj.is_link_local:
            return "link_local"
        return "public"

    def _format_network_context(self, context: Dict[str, Any]) -> str:
        if not context:
            return "N/A"
        fields = [
            ("protocol", context.get("protocol")),
            ("src_ip", context.get("src_ip")),
            ("src_zone", context.get("src_zone")),
            ("src_port", context.get("src_port")),
            ("dst_ip", context.get("dst_ip")),
            ("dst_zone", context.get("dst_zone")),
            ("dst_port", context.get("dst_port")),
            ("direction_hint", context.get("direction_hint")),
        ]
        lines = [f"{k}={v}" for k, v in fields if v not in (None, "")]
        return "\n".join(lines) if lines else "N/A"

    def _generation_constraints(self, context: Dict[str, Any]) -> str:
        lines = [
            "1) 不确定源网段归属时，不要把源固定为 $EXTERNAL_NET，优先使用 any 作为源网段。",
            "2) 仅当确认 src 不属于 HOME_NET 时，才使用 $EXTERNAL_NET -> $HOME_NET。",
            "3) HTTP 攻击优先使用 to_server 方向；必要时使用 any any -> $HOME_NET any 以避免方向误判。",
            "4) 保持检测原语聚焦 payload/URI，不要把 IP 字段写进 content 匹配。",
        ]
        src_zone = str(context.get("src_zone") or "")
        dst_zone = str(context.get("dst_zone") or "")
        if src_zone == "private" and dst_zone == "private":
            lines.append("5) 当前样本为 private_to_private，禁止把源写成 $EXTERNAL_NET。")
        elif src_zone == "private":
            lines.append("5) 当前样本源为私网，源网段应为 any 或 $HOME_NET。")
        elif src_zone == "public" and dst_zone == "private":
            lines.append("5) 当前样本为 public_to_private，可考虑使用 $EXTERNAL_NET -> $HOME_NET。")
        return "\n".join(lines)

    def _normalize_rule_header_by_context(self, rule: str, traffic_note: Note) -> str:
        context = self._network_context_from_note(traffic_note)
        src_zone = str(context.get("src_zone") or "")
        dst_zone = str(context.get("dst_zone") or "")
        match = RULE_HEADER_RE.match(rule.strip())
        if not match:
            return rule

        action = match.group("action")
        proto = match.group("proto")
        src_net = match.group("src_net")
        src_port = match.group("src_port")
        dst_net = match.group("dst_net")
        dst_port = match.group("dst_port")
        changed = False

        if src_zone == "private" and src_net.upper() == "$EXTERNAL_NET":
            src_net = "any"
            changed = True

        if dst_zone == "private" and dst_net.lower() == "any" and proto.lower() in {"http", "tcp"}:
            dst_net = "$HOME_NET"
            changed = True

        if not changed:
            return rule

        old_header = match.group(0)
        new_header = f"{action} {proto} {src_net} {src_port} -> {dst_net} {dst_port} ("
        return rule.replace(old_header, new_header, 1)
