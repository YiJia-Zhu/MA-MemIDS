from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from .config import RuntimeConfig, SimilarityWeights, Thresholds
from .embedding import HashingEmbedder
from .graph import NoteGraph
from .knowledge import DualPathRetriever
from .llm_client import BaseLLMClient, create_llm_client
from .models import Link, Note, ProcessResult
from .note_builder import NoteBuilder
from .pcap_parser import PCAPParser
from .rule_engine import RuleGenerationEngine
from .rule_parser import extract_sid
from .utils import dedupe_keep_order, now_iso
from .validation import SandboxEvaluator, SuricataValidator


class MAMemIDSPipeline:
    def __init__(
        self,
        state_path: str = "./memory/state.json",
        llm_client: Optional[BaseLLMClient] = None,
        llm_model: Optional[str] = None,
        cve_knowledge_path: Optional[str] = None,
        attack_knowledge_path: Optional[str] = None,
        cti_knowledge_path: Optional[str] = None,
        suricata_path: str = "/usr/bin/suricata",
        suricata_config: str = "/etc/suricata/suricata.yaml",
        validation_mode: str = "strict",
    ):
        self.state_path = Path(state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)

        self.thresholds = Thresholds()
        self.runtime = RuntimeConfig()
        self.weights = SimilarityWeights()

        self.embedder = HashingEmbedder(dim=self.runtime.embedding_dim)
        self.retriever = DualPathRetriever(embedder=self.embedder)
        self.retriever.load_knowledge(
            cve_path=cve_knowledge_path,
            attack_path=attack_knowledge_path,
            cti_path=cti_knowledge_path,
        )

        self.llm = llm_client or create_llm_client(model=llm_model)
        self.note_builder = NoteBuilder(self.retriever, self.embedder, self.llm)
        self.graph = NoteGraph(weights=self.weights, thresholds=self.thresholds)

        self.validator = SuricataValidator(
            suricata_path=suricata_path,
            suricata_config=suricata_config,
            validation_mode=validation_mode,
        )
        self.sandbox = SandboxEvaluator(self.validator, thresholds=self.thresholds)
        self.rule_engine = RuleGenerationEngine(self.llm, thresholds=self.thresholds, runtime=self.runtime)

        if self.state_path.exists():
            self.load_state()

    def initialize_from_rules_file(self, rules_file: str) -> int:
        path = Path(rules_file)
        if not path.exists():
            raise FileNotFoundError(f"Rules file not found: {rules_file}")

        count = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            rule = line.strip()
            if not rule or rule.startswith("#"):
                continue
            if not rule.lower().startswith(("alert ", "drop ", "pass ", "reject ")):
                continue
            note = self.note_builder.build_rule_note(rule)
            self.graph.add_or_update(note)
            count += 1

        self.save_state()
        return count

    def process_unmatched_traffic(
        self,
        *,
        pcap_path: Optional[str] = None,
        traffic_text: Optional[str] = None,
        attack_pcaps: Optional[List[str]] = None,
        benign_pcaps: Optional[List[str]] = None,
        human_override: Optional[Dict[str, object]] = None,
    ) -> ProcessResult:
        result, _ = self._process_unmatched_traffic_core(
            pcap_path=pcap_path,
            traffic_text=traffic_text,
            attack_pcaps=attack_pcaps,
            benign_pcaps=benign_pcaps,
            human_override=human_override,
            with_trace=False,
        )
        return result

    def process_unmatched_traffic_with_trace(
        self,
        *,
        pcap_path: Optional[str] = None,
        traffic_text: Optional[str] = None,
        attack_pcaps: Optional[List[str]] = None,
        benign_pcaps: Optional[List[str]] = None,
        human_override: Optional[Dict[str, object]] = None,
    ) -> Dict[str, object]:
        result, trace = self._process_unmatched_traffic_core(
            pcap_path=pcap_path,
            traffic_text=traffic_text,
            attack_pcaps=attack_pcaps,
            benign_pcaps=benign_pcaps,
            human_override=human_override,
            with_trace=True,
        )
        return {
            "result": result.__dict__,
            "trace": trace,
        }

    def _process_unmatched_traffic_core(
        self,
        *,
        pcap_path: Optional[str],
        traffic_text: Optional[str],
        attack_pcaps: Optional[List[str]],
        benign_pcaps: Optional[List[str]],
        human_override: Optional[Dict[str, object]],
        with_trace: bool,
    ) -> tuple[ProcessResult, Dict[str, object]]:
        trace: Dict[str, object] = {
            "inputs": {
                "pcap_path": pcap_path,
                "has_traffic_text": bool(traffic_text),
                "attack_pcaps": attack_pcaps or [],
                "benign_pcaps": benign_pcaps or [],
                "human_override": human_override or {},
            },
            "steps": [],
        }

        if not pcap_path and not traffic_text:
            raise ValueError("Either pcap_path or traffic_text must be provided")

        if pcap_path:
            summary = PCAPParser.parse(pcap_path)
            traffic_text = summary.to_text()
            protocol = summary.protocol
            traffic_metadata = {
                "pcap": pcap_path,
                "src_ip": summary.src_ip,
                "dst_ip": summary.dst_ip,
                "src_port": summary.src_port,
                "dst_port": summary.dst_port,
            }
            if with_trace:
                trace["steps"].append(
                    {
                        "name": "pcap_parse",
                        "output": {
                            "protocol": summary.protocol,
                            "src_ip": summary.src_ip,
                            "dst_ip": summary.dst_ip,
                            "src_port": summary.src_port,
                            "dst_port": summary.dst_port,
                            "http_method": summary.http_method,
                            "http_uri": summary.http_uri,
                            "payload_preview": summary.payload_text[:300],
                        },
                    }
                )
        else:
            protocol = None
            traffic_metadata = {}

        traffic_note = self.note_builder.build_traffic_note(
            traffic_text=traffic_text or "",
            protocol=protocol,
            metadata=traffic_metadata,
        )
        if with_trace:
            trace["steps"].append(
                {
                    "name": "traffic_note",
                    "output": {
                        "note_id": traffic_note.note_id,
                        "intent": traffic_note.intent,
                        "keywords": traffic_note.keywords[:20],
                        "tactics": traffic_note.tactics[:10],
                        "cve_ids": traffic_note.external_knowledge.cve_ids[:10],
                        "tech_ids": traffic_note.external_knowledge.tech_ids[:10],
                    },
                }
            )

        if human_override:
            self._apply_human_override(traffic_note, human_override)
            if with_trace:
                trace["steps"].append(
                    {
                        "name": "human_override",
                        "output": {
                            "intent": traffic_note.intent,
                            "keywords": traffic_note.keywords[:20],
                            "tactics": traffic_note.tactics[:10],
                        },
                    }
                )

        ranked = self.graph.search_top_k(traffic_note)
        candidate_notes = [self.graph.get(item.note_id) for item in ranked if self.graph.get(item.note_id) is not None]
        candidate_notes = [n for n in candidate_notes if n is not None]
        if with_trace:
            trace["steps"].append(
                {
                    "name": "topk_search",
                    "output": [
                        {"note_id": item.note_id, "score": item.score}
                        for item in ranked
                    ],
                }
            )

        proposal = self.rule_engine.propose_rule(
            traffic_note=traffic_note,
            candidate_notes=candidate_notes,
            all_rule_notes=self._rule_notes(),
        )
        if with_trace:
            trace["steps"].append(
                {
                    "name": "rule_proposal",
                    "output": {
                        "mode": proposal.mode,
                        "base_note_id": proposal.base_note_id,
                        "max_similarity": proposal.max_similarity,
                        "rule_text": proposal.rule_text,
                    },
                }
            )

        attack_set = attack_pcaps or ([pcap_path] if pcap_path else [])
        benign_set = benign_pcaps or []

        if not attack_set and not benign_set:
            ok, err = self.validator.validate_rule_format(proposal.rule_text)
            if ok:
                merge_candidates, linked_notes = self._solidify_memory(traffic_note, proposal)
                self.save_state()
                result = ProcessResult(
                    success=True,
                    mode=proposal.mode,
                    rule_text=proposal.rule_text,
                    score=None,
                    reason="syntax-only pass (no replay dataset)",
                    retries=0,
                    merge_candidates=merge_candidates,
                    linked_notes=linked_notes,
                )
                if with_trace:
                    trace["steps"].append(
                        {
                            "name": "syntax_only_validation",
                            "output": {"format_ok": True, "error": None},
                        }
                    )
                return result, trace
            result = ProcessResult(
                success=False,
                mode=proposal.mode,
                rule_text=proposal.rule_text,
                score=None,
                reason=f"syntax check failed: {err}",
                retries=0,
            )
            if with_trace:
                trace["steps"].append(
                    {
                        "name": "syntax_only_validation",
                        "output": {"format_ok": False, "error": err},
                    }
                )
            return result, trace

        retries = 0
        while retries < self.thresholds.max_regen:
            sandbox_result = self.sandbox.evaluate(proposal.rule_text, attack_set, benign_set)
            if with_trace:
                trace["steps"].append(
                    {
                        "name": "sandbox_validation",
                        "output": {
                            "attempt": retries + 1,
                            "passed": sandbox_result.passed,
                            "reason": sandbox_result.reason,
                            "metrics": (
                                sandbox_result.metrics.__dict__
                                if sandbox_result.metrics is not None
                                else None
                            ),
                        },
                    }
                )
            if sandbox_result.passed:
                merge_candidates, linked_notes = self._solidify_memory(traffic_note, proposal)
                self.save_state()
                result = ProcessResult(
                    success=True,
                    mode=proposal.mode,
                    rule_text=proposal.rule_text,
                    score=(sandbox_result.metrics.score if sandbox_result.metrics else None),
                    reason="pass",
                    retries=retries,
                    merge_candidates=merge_candidates,
                    linked_notes=linked_notes,
                )
                if with_trace:
                    trace["steps"].append(
                        {
                            "name": "memory_solidify",
                            "output": {
                                "linked_notes": linked_notes,
                                "merge_candidates": merge_candidates,
                            },
                        }
                    )
                return result, trace

            diagnosis = self.sandbox.diagnose_failure(sandbox_result.metrics)
            retries += 1
            if with_trace:
                trace["steps"].append(
                    {
                        "name": "failure_diagnosis",
                        "output": diagnosis.__dict__,
                    }
                )
            if retries >= self.thresholds.max_regen:
                result = ProcessResult(
                    success=False,
                    mode=proposal.mode,
                    rule_text=proposal.rule_text,
                    score=(sandbox_result.metrics.score if sandbox_result.metrics else None),
                    reason=f"validation failed: {diagnosis.failure_type}; manual review required",
                    retries=retries,
                )
                return result, trace

            sid_hint = extract_sid(proposal.rule_text)
            proposal.rule_text = self.rule_engine.regenerate_with_diagnosis(
                previous_rule=proposal.rule_text,
                traffic_note=traffic_note,
                diagnosis=diagnosis,
                sid_hint=sid_hint,
            )
            if with_trace:
                trace["steps"].append(
                    {
                        "name": "rule_regenerate",
                        "output": {
                            "sid_hint": sid_hint,
                            "rule_text": proposal.rule_text,
                        },
                    }
                )

        result = ProcessResult(
            success=False,
            mode=proposal.mode,
            rule_text=proposal.rule_text,
            score=None,
            reason="unexpected validation loop exit",
            retries=retries,
        )
        return result, trace

    def export_ruleset(self, output_file: str) -> int:
        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)
        rules = sorted(self._rule_notes(), key=lambda n: (n.sid or 10**12, n.note_id))
        with out.open("w", encoding="utf-8") as f:
            f.write("# MA-MemIDS Generated Ruleset\n")
            f.write(f"# Generated at: {now_iso()}\n")
            f.write(f"# Total rules: {len(rules)}\n\n")
            for note in rules:
                f.write(note.content.rstrip() + "\n")
        return len(rules)

    def stats(self) -> Dict[str, object]:
        notes = self.graph.all_notes()
        rule_notes = [n for n in notes if n.note_type == "rule"]
        traffic_notes = [n for n in notes if n.note_type == "traffic"]
        return {
            "total_notes": len(notes),
            "rule_notes": len(rule_notes),
            "traffic_notes": len(traffic_notes),
            "llm_model": self.llm.model_name(),
            "thresholds": self.thresholds.__dict__,
        }

    def save_state(self) -> None:
        payload = {
            "graph": self.graph.to_dict(),
        }
        self.state_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def load_state(self) -> None:
        raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        graph_data = raw.get("graph") if isinstance(raw, dict) else {}
        if isinstance(graph_data, dict):
            self.graph = NoteGraph.from_dict(graph_data)

    def _apply_human_override(self, note: Note, override: Dict[str, object]) -> None:
        if "intent" in override and isinstance(override["intent"], str):
            note.intent = override["intent"].strip()
        if "tactics" in override and isinstance(override["tactics"], list):
            note.tactics = dedupe_keep_order([str(x).upper().strip() for x in override["tactics"] if str(x).strip()])
        if "keywords" in override and isinstance(override["keywords"], list):
            note.keywords = dedupe_keep_order([str(x).strip() for x in override["keywords"] if str(x).strip()])
        self.note_builder.reembed_note(note)

    def _rule_notes(self) -> List[Note]:
        return [note for note in self.graph.all_notes() if note.note_type == "rule"]

    def _solidify_memory(self, traffic_note: Note, proposal) -> tuple[list[str], list[str]]:
        linked: List[str] = []
        merge_candidates: List[str] = []

        self.graph.add_or_update(traffic_note)

        if proposal.mode == "repair" and proposal.base_note_id:
            base = self.graph.get(proposal.base_note_id)
            if base is None:
                # Fallback as new rule when base cannot be found.
                new_note = self.note_builder.build_rule_note(proposal.rule_text)
                self.graph.add_or_update(new_note)
                linked.append(new_note.note_id)
                merge_candidates = self.graph.find_merge_candidates(new_note.note_id)
            else:
                base.content = proposal.rule_text
                base.version += 1
                base.timestamp = now_iso()
                base.intent = base.intent + f"; covers variant from {traffic_note.note_id}"
                base.keywords = dedupe_keep_order(base.keywords + traffic_note.keywords)
                base.tactics = dedupe_keep_order(base.tactics + traffic_note.tactics)
                base.external_knowledge.cve_ids = dedupe_keep_order(
                    base.external_knowledge.cve_ids + traffic_note.external_knowledge.cve_ids
                )
                self.note_builder.reembed_note(base)
                self.graph.add_or_update(base)
                self._add_link(base.note_id, traffic_note.note_id, "l_strengthen", 0.95)
                self._cascade_chain_context(base, traffic_note)
                linked.append(base.note_id)
                merge_candidates = self.graph.find_merge_candidates(base.note_id)
        else:
            new_note = self.note_builder.build_rule_note(proposal.rule_text)
            self.graph.add_or_update(new_note)
            self._add_link(new_note.note_id, traffic_note.note_id, "l_strengthen", 0.95)
            linked.append(new_note.note_id)
            merge_candidates = self.graph.find_merge_candidates(new_note.note_id)

        return merge_candidates, linked

    def _cascade_chain_context(self, base_note: Note, traffic_note: Note) -> None:
        neighbors = self.graph.neighbors(base_note.note_id, link_type="exploit_chain")
        for link in neighbors:
            other = self.graph.get(link.target_id)
            if other is None:
                continue
            context = other.metadata.get("context", "")
            context += f" | related rule covered variant from {traffic_note.note_id}"
            other.metadata["context"] = context.strip()
            self.note_builder.reembed_note(other)
            self.graph.add_or_update(other)

    def _add_link(self, a_id: str, b_id: str, link_type: str, weight: float) -> None:
        a = self.graph.get(a_id)
        b = self.graph.get(b_id)
        if not a or not b:
            return

        def upsert(src: Note, target: str) -> None:
            for link in src.links:
                if link.target_id == target and link.link_type == link_type:
                    if weight > link.weight:
                        link.weight = weight
                    return
            src.links.append(Link(target_id=target, link_type=link_type, weight=weight))

        upsert(a, b_id)
        upsert(b, a_id)


__all__ = ["MAMemIDSPipeline"]
