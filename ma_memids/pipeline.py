from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import RuntimeConfig, SimilarityWeights, Thresholds
from .embedding import SentenceTransformerEmbedder
from .graph import NoteGraph
from .knowledge import DualPathRetriever
from .llm_client import BaseLLMClient, create_llm_client
from .models import Link, Note, ProcessResult
from .note_builder import NoteBuilder
from .pcap_parser import PCAPParser
from .prompts import TRAFFIC_CLASSIFICATION_SYSTEM, TRAFFIC_CLASSIFICATION_USER
from .rule_engine import RuleGenerationEngine
from .rule_parser import extract_sid, parse_rule_fields
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
        knowledge_cache_dir: Optional[str] = None,
        suricata_path: str = "/usr/bin/suricata",
        suricata_config: str = "/etc/suricata/suricata.yaml",
        validation_mode: str = "strict",
        knowledge_build_if_missing: bool = True,
    ):
        self.state_path = Path(state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)

        self.thresholds = Thresholds()
        self.runtime = RuntimeConfig()
        self.weights = SimilarityWeights()

        self.embedder = SentenceTransformerEmbedder(model_name=self.runtime.embedding_model)
        self.retriever = DualPathRetriever(embedder=self.embedder, cache_dir=knowledge_cache_dir)
        self.retriever.load_knowledge(
            cve_path=cve_knowledge_path,
            attack_path=attack_knowledge_path,
            cti_path=cti_knowledge_path,
            build_if_missing=knowledge_build_if_missing,
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
        self.sandbox_baseline: Dict[str, Any] = {}
        self.score_improve_epsilon = self._load_score_improve_epsilon()

        if self.state_path.exists():
            self.load_state()

    def initialize_from_rules_file(
        self,
        rules_file: str,
        max_rules: Optional[int] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> int:
        path = Path(rules_file)
        if not path.exists():
            raise FileNotFoundError(f"Rules path not found: {rules_file}")
        if max_rules is not None and max_rules <= 0:
            raise ValueError("max_rules must be a positive integer")

        rules: List[str] = []
        for rule in self._iter_rules_from_path(path):
            rules.append(rule)
            if max_rules is not None and len(rules) >= max_rules:
                break

        total_rules = len(rules)
        if progress_callback:
            progress_callback(
                {
                    "event": "init_prepare",
                    "count": total_rules,
                    "source_path": str(path),
                    "max_rules": max_rules,
                }
            )

        parsed_rules = [parse_rule_fields(rule) for rule in rules]

        def _emit_reference_progress(event: Dict[str, Any]) -> None:
            if progress_callback is None:
                return
            payload = dict(event)
            payload.setdefault("source_path", str(path))
            payload.setdefault("max_rules", max_rules)
            progress_callback(payload)

        prefetched_reference_evidence = self.note_builder.resolve_rule_reference_evidence_batch(
            parsed_rules,
            progress_callback=_emit_reference_progress,
        )

        count = 0
        new_notes: List[Note] = []
        for idx, rule in enumerate(rules):
            fields = parsed_rules[idx]
            reference_evidence = prefetched_reference_evidence[idx] if idx < len(prefetched_reference_evidence) else {}
            note = self.note_builder.build_rule_note(
                rule,
                parsed_fields=fields,
                reference_evidence=reference_evidence,
            )
            new_notes.append(note)
            count += 1
            if progress_callback and (count == 1 or count % 25 == 0 or count == total_rules):
                progress_callback(
                    {
                        "event": "init_progress",
                        "count": count,
                        "total_rules": total_rules,
                        "source_path": str(path),
                        "max_rules": max_rules,
                    }
                )

        self.graph.add_or_update_many(new_notes)
        self.save_state()
        if progress_callback:
            progress_callback(
                {
                    "event": "init_done",
                    "count": count,
                    "total_rules": total_rules,
                    "source_path": str(path),
                }
            )
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
            progress_callback=None,
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
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, object]:
        result, trace = self._process_unmatched_traffic_core(
            pcap_path=pcap_path,
            traffic_text=traffic_text,
            attack_pcaps=attack_pcaps,
            benign_pcaps=benign_pcaps,
            human_override=human_override,
            with_trace=True,
            progress_callback=progress_callback,
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
        progress_callback: Optional[Callable[[Dict[str, Any]], None]],
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
        steps: List[Dict[str, object]] = trace["steps"]  # type: ignore[assignment]

        def _emit_progress(payload: Dict[str, Any]) -> None:
            if progress_callback is not None:
                progress_callback(payload)

        def _record_step(name: str, output: Dict[str, Any] | List[Dict[str, Any]]) -> None:
            if with_trace:
                steps.append({"name": name, "output": output})
            _emit_progress({"event": "step", "name": name, "output": output})

        _emit_progress(
            {
                "event": "process_started",
                "pcap_path": pcap_path,
                "has_traffic_text": bool(traffic_text),
            }
        )

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
            _record_step(
                "pcap_parse",
                {
                    "parser_backend": summary.parser_backend,
                    "packets_seen": summary.packets_seen,
                    "packets_sampled": summary.packets_sampled,
                    "packet_limit_reached": summary.packet_limit_reached,
                    "primary_flow": summary.primary_flow,
                    "protocol": summary.protocol,
                    "src_ip": summary.src_ip,
                    "dst_ip": summary.dst_ip,
                    "src_port": summary.src_port,
                    "dst_port": summary.dst_port,
                    "http_method": summary.http_method,
                    "http_uri": summary.http_uri,
                    "payload_bytes_seen": summary.payload_bytes_seen,
                    "payload_bytes_kept": summary.payload_bytes_kept,
                    "payload_truncated": summary.payload_truncated,
                    "binary_payload_skipped": summary.binary_payload_skipped,
                    "payload_preview": summary.payload_text[:300],
                },
            )
        else:
            protocol = None
            traffic_metadata = {}

        base_traffic_text = traffic_text or ""

        if pcap_path:
            precheck = self._precheck_existing_ruleset(pcap_path)
            _record_step("existing_ruleset_precheck", precheck)
            if precheck.get("confirmed_hit"):
                matched_note_ids = precheck.get("matched_note_ids", [])
                alert_count = int(precheck.get("alert_count") or 0)
                result = ProcessResult(
                    success=True,
                    mode="already_covered",
                    rule_text=None,
                    score=None,
                    reason=(
                        f"existing ruleset already triggered on analyzed pcap "
                        f"(alerts={alert_count}, matched_sids={precheck.get('matched_sids', [])})"
                    ),
                    retries=0,
                    merge_candidates=[],
                    linked_notes=matched_note_ids if isinstance(matched_note_ids, list) else [],
                )
                return result, trace

        def _build_candidate_with_dual_retrieval(feedback_blocks: List[str], retry_index: int) -> tuple[Note, List[object], object]:
            text_for_note = base_traffic_text
            if feedback_blocks:
                feedback_blob = "\n".join(feedback_blocks)
                text_for_note = f"{base_traffic_text}\n\n[FAILURE_FEEDBACK]\n{feedback_blob}"

            traffic_note_local = self.note_builder.build_traffic_note(
                traffic_text=text_for_note,
                protocol=protocol,
                metadata=traffic_metadata,
            )

            suffix = "" if retry_index == 0 else f"_retry{retry_index}"
            _record_step(
                f"dual_retrieval{suffix}",
                {
                    "retrieval_plan": (
                        traffic_note_local.external_knowledge.debug.get("plan", {})
                        if isinstance(traffic_note_local.external_knowledge.debug, dict)
                        else {}
                    ),
                    "feature_inventory": (
                        traffic_note_local.external_knowledge.debug.get("feature_inventory", {})
                        if isinstance(traffic_note_local.external_knowledge.debug, dict)
                        else {}
                    ),
                    "sparse_query": (
                        traffic_note_local.external_knowledge.debug.get("sparse_query", "")
                        if isinstance(traffic_note_local.external_knowledge.debug, dict)
                        else ""
                    ),
                    "dense_query": (
                        traffic_note_local.external_knowledge.debug.get("dense_query", "")
                        if isinstance(traffic_note_local.external_knowledge.debug, dict)
                        else ""
                    ),
                    "cve_ids": traffic_note_local.external_knowledge.cve_ids[:10],
                    "tech_ids": traffic_note_local.external_knowledge.tech_ids[:10],
                    "feedback_blocks": feedback_blocks[-3:],
                },
            )
            _record_step(
                f"traffic_note{suffix}",
                {
                    "note_id": traffic_note_local.note_id,
                    "intent": traffic_note_local.intent,
                    "keywords": traffic_note_local.keywords[:20],
                    "tactics": traffic_note_local.tactics[:10],
                    "cve_ids": traffic_note_local.external_knowledge.cve_ids[:10],
                    "tech_ids": traffic_note_local.external_knowledge.tech_ids[:10],
                    "network_context": (
                        traffic_note_local.metadata.get("network_context", {})
                        if isinstance(traffic_note_local.metadata, dict)
                        else {}
                    ),
                },
            )

            if human_override:
                self._apply_human_override(traffic_note_local, human_override)
                _record_step(
                    f"human_override{suffix}",
                    {
                        "intent": traffic_note_local.intent,
                        "keywords": traffic_note_local.keywords[:20],
                        "tactics": traffic_note_local.tactics[:10],
                    },
                )

            ranked_local = self.graph.search_top_k(traffic_note_local)
            candidate_notes_local = [
                self.graph.get(item.note_id)
                for item in ranked_local
                if self.graph.get(item.note_id) is not None
            ]
            candidate_notes_local = [n for n in candidate_notes_local if n is not None]
            _record_step(
                f"topk_search{suffix}",
                [
                    {"note_id": item.note_id, "score": item.score}
                    for item in ranked_local
                ],
            )

            proposal_local = self.rule_engine.propose_rule(
                traffic_note=traffic_note_local,
                candidate_notes=candidate_notes_local,
                candidate_scores=ranked_local,
                all_rule_notes=self._rule_notes(),
            )
            _record_step(
                f"rule_proposal{suffix}",
                {
                    "mode": proposal_local.mode,
                    "base_note_id": proposal_local.base_note_id,
                    "max_similarity": proposal_local.max_similarity,
                    "rule_text": proposal_local.rule_text,
                },
            )

            return traffic_note_local, ranked_local, proposal_local

        feedback_blocks: List[str] = []
        traffic_note, _, proposal = _build_candidate_with_dual_retrieval(feedback_blocks=feedback_blocks, retry_index=0)

        attack_set, benign_set, classify_info = self._resolve_sandbox_sets(
            analyzed_pcap=pcap_path,
            traffic_note=traffic_note,
            attack_pcaps=(attack_pcaps or []),
            benign_pcaps=(benign_pcaps or []),
        )

        _record_step("analyzed_pcap_labeling", classify_info)
        _record_step(
            "sandbox_dataset_resolved",
            {
                "attack_count": len(attack_set),
                "benign_count": len(benign_set),
                "attack_pcaps_preview": attack_set[:5],
                "benign_pcaps_preview": benign_set[:5],
            },
        )

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
                _record_step("syntax_only_validation", {"format_ok": True, "error": None})
                return result, trace
            result = ProcessResult(
                success=False,
                mode=proposal.mode,
                rule_text=proposal.rule_text,
                score=None,
                reason=f"syntax check failed: {err}",
                retries=0,
            )
            _record_step("syntax_only_validation", {"format_ok": False, "error": err})
            return result, trace

        base_rule_notes = self._sorted_rule_notes()
        current_ruleset = [note.content for note in base_rule_notes]
        dataset_signature = self._sandbox_dataset_signature(attack_set, benign_set)
        current_ruleset_signature = self._ruleset_signature(current_ruleset)

        baseline_payload = self._get_or_compute_sandbox_baseline(
            dataset_signature=dataset_signature,
            ruleset_signature=current_ruleset_signature,
            ruleset=current_ruleset,
            attack_pcaps=attack_set,
            benign_pcaps=benign_set,
        )
        _record_step(
            "sandbox_baseline",
            {
                "source": baseline_payload.get("source"),
                "dataset_signature": dataset_signature,
                "ruleset_signature": current_ruleset_signature,
                "ruleset_size": len(current_ruleset),
                "metrics": baseline_payload.get("metrics"),
                "reason": baseline_payload.get("reason"),
            },
        )
        if not baseline_payload.get("ok"):
            result = ProcessResult(
                success=False,
                mode=proposal.mode,
                rule_text=proposal.rule_text,
                score=None,
                reason=f"baseline validation failed: {baseline_payload.get('reason')}",
                retries=0,
            )
            return result, trace
        if baseline_payload.get("source") == "computed":
            # Persist fresh baseline cache even when current candidate may not pass.
            self.save_state()

        baseline_metrics_raw = baseline_payload.get("metrics") or {}
        baseline_score = float(baseline_metrics_raw.get("score", 0.0))
        required_score = baseline_score + self.score_improve_epsilon

        retries = 0
        while retries < self.thresholds.max_regen:
            candidate_ruleset = self._build_candidate_ruleset(base_rule_notes, proposal)
            sandbox_result = self.sandbox.evaluate_ruleset(candidate_ruleset, attack_set, benign_set)
            candidate_metrics = (
                sandbox_result.metrics.__dict__
                if sandbox_result.metrics is not None
                else None
            )
            candidate_score = (
                float(candidate_metrics.get("score"))
                if isinstance(candidate_metrics, dict) and candidate_metrics.get("score") is not None
                else None
            )
            improved = (
                sandbox_result.syntax_ok
                and candidate_score is not None
                and candidate_score > required_score
            )
            delta_score = (candidate_score - baseline_score) if candidate_score is not None else None
            validation_reason = (
                "score improved vs baseline (epsilon)"
                if improved
                else "score not improved vs baseline (epsilon)"
            )
            if not sandbox_result.syntax_ok:
                validation_reason = sandbox_result.reason
            elif candidate_score is None:
                validation_reason = "metrics unavailable"

            _record_step(
                "sandbox_validation",
                {
                    "attempt": retries + 1,
                    "passed": improved,
                    "reason": validation_reason,
                    "baseline_score": baseline_score,
                    "required_score": required_score,
                    "candidate_score": candidate_score,
                    "delta_score": delta_score,
                    "score_improve_epsilon": self.score_improve_epsilon,
                    "baseline_metrics": baseline_metrics_raw,
                    "metrics": candidate_metrics,
                    "syntax_ok": sandbox_result.syntax_ok,
                    "candidate_ruleset_size": len(candidate_ruleset),
                },
            )
            if improved:
                merge_candidates, linked_notes = self._solidify_memory(traffic_note, proposal)
                accepted_ruleset = self._current_ruleset_texts()
                accepted_ruleset_signature = self._ruleset_signature(accepted_ruleset)
                if candidate_metrics is not None:
                    self._update_sandbox_baseline_cache(
                        dataset_signature=dataset_signature,
                        ruleset_signature=accepted_ruleset_signature,
                        metrics=candidate_metrics,
                        ruleset_size=len(accepted_ruleset),
                    )
                self.save_state()
                result = ProcessResult(
                    success=True,
                    mode=proposal.mode,
                    rule_text=proposal.rule_text,
                    score=candidate_score,
                    reason="score improved vs baseline (epsilon)",
                    retries=retries,
                    merge_candidates=merge_candidates,
                    linked_notes=linked_notes,
                )
                _record_step(
                    "memory_solidify",
                    {
                        "linked_notes": linked_notes,
                        "merge_candidates": merge_candidates,
                    },
                )
                return result, trace

            diagnosis = self.sandbox.diagnose_failure(sandbox_result.metrics)
            retries += 1
            _record_step("failure_diagnosis", diagnosis.__dict__)
            if retries >= self.thresholds.max_regen:
                tail_score = f"{candidate_score:.4f}" if candidate_score is not None else "na"
                result = ProcessResult(
                    success=False,
                    mode=proposal.mode,
                    rule_text=proposal.rule_text,
                    score=candidate_score,
                    reason=(
                        f"validation failed: score not improved "
                        f"(baseline={baseline_score:.4f}, epsilon={self.score_improve_epsilon:.6f}, "
                        f"required>{required_score:.4f}, candidate={tail_score}); "
                        f"diagnosis={diagnosis.failure_type}"
                    ),
                    retries=retries,
                )
                return result, trace

            sid_hint = extract_sid(proposal.rule_text)
            feedback_line = (
                f"type={diagnosis.failure_type}; "
                f"suggestion={diagnosis.suggestion}; "
                f"sid={sid_hint if sid_hint is not None else 'none'}; "
                f"baseline_score={baseline_score:.4f}; "
                f"required_score={required_score:.4f}; "
                f"candidate_score={(f'{candidate_score:.4f}' if candidate_score is not None else 'na')}; "
                f"delta_score={(f'{delta_score:.4f}' if delta_score is not None else 'na')}; "
                f"epsilon={self.score_improve_epsilon:.6f}"
            )
            metrics_obj = sandbox_result.metrics
            if metrics_obj is not None:
                feedback_line += (
                    f"; precision={metrics_obj.precision:.4f}; recall={metrics_obj.recall:.4f}; "
                    f"fpr={metrics_obj.fpr:.4f}"
                )
            feedback_blocks.append(feedback_line)

            _record_step(
                "feedback_loop_to_dual_retrieval",
                {
                    "retry_index": retries,
                    "feedback_line": feedback_line,
                },
            )

            traffic_note, _, proposal = _build_candidate_with_dual_retrieval(
                feedback_blocks=feedback_blocks,
                retry_index=retries,
            )
            _record_step(
                "rule_regenerate",
                {
                    "sid_hint": sid_hint,
                    "rule_text": proposal.rule_text,
                    "mode": proposal.mode,
                },
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
        baseline_metrics = self.sandbox_baseline.get("metrics") if isinstance(self.sandbox_baseline, dict) else None
        baseline_score = None
        if isinstance(baseline_metrics, dict):
            try:
                baseline_score = float(baseline_metrics.get("score")) if baseline_metrics.get("score") is not None else None
            except (TypeError, ValueError):
                baseline_score = None
        return {
            "total_notes": len(notes),
            "rule_notes": len(rule_notes),
            "traffic_notes": 0,
            "llm_model": self.llm.model_name(),
            "embedding": self.embedder.metadata(),
            "knowledge": self.retriever.stats(),
            "thresholds": self.thresholds.__dict__,
            "graph_index": self.graph.index_stats(),
            "sandbox_baseline": {
                "cached": bool(self.sandbox_baseline),
                "score": baseline_score,
                "updated_at": (self.sandbox_baseline.get("updated_at") if isinstance(self.sandbox_baseline, dict) else None),
            },
            "score_improve_epsilon": self.score_improve_epsilon,
        }

    def save_state(self) -> None:
        self._enforce_rule_only_graph()
        payload = {
            "graph": self.graph.to_dict(),
            "embedding": self.embedder.metadata(),
            "sandbox_baseline": self.sandbox_baseline,
        }
        self.state_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def load_state(self) -> None:
        raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        graph_data = raw.get("graph") if isinstance(raw, dict) else {}
        if isinstance(graph_data, dict):
            self.graph = NoteGraph.from_dict(graph_data)
            self.weights = self.graph.weights
            self.thresholds = self.graph.thresholds
            self.sandbox = SandboxEvaluator(self.validator, thresholds=self.thresholds)
            self.rule_engine = RuleGenerationEngine(self.llm, thresholds=self.thresholds, runtime=self.runtime)
        baseline_data = raw.get("sandbox_baseline") if isinstance(raw, dict) else {}
        if isinstance(baseline_data, dict):
            self.sandbox_baseline = baseline_data
        changed = self._enforce_rule_only_graph()
        embedding_meta = raw.get("embedding") if isinstance(raw, dict) and isinstance(raw.get("embedding"), dict) else {}
        migrated = self._migrate_state_embeddings(embedding_meta)
        if not migrated:
            self.graph.rebuild_all_links()
        if changed or migrated:
            self.save_state()

    def _migrate_state_embeddings(self, embedding_meta: Dict[str, object]) -> bool:
        notes = self.graph.all_notes()
        if not notes:
            return False

        current_model = self.embedder.model_name
        current_dim = self.embedder.dim

        stored_model = str(embedding_meta.get("model_name") or "").strip()
        try:
            stored_dim = int(embedding_meta.get("dim")) if embedding_meta.get("dim") is not None else 0
        except (TypeError, ValueError):
            stored_dim = 0

        note_dims = {len(note.embedding) for note in notes}
        needs_migration = (
            stored_model != current_model
            or stored_dim != current_dim
            or note_dims != {current_dim}
        )
        if not needs_migration:
            return False

        for note in notes:
            timestamp = note.timestamp
            self.note_builder.reembed_note(note)
            note.timestamp = timestamp
        self.graph.add_or_update_many(notes)
        return True

    def _enforce_rule_only_graph(self) -> bool:
        return self.graph.retain_note_types({"rule"})

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

    def _load_score_improve_epsilon(self) -> float:
        raw = os.getenv("MA_MEMIDS_SCORE_IMPROVE_EPSILON", "1e-6").strip()
        try:
            value = float(raw)
        except ValueError:
            return 1e-6
        if value < 0:
            return 0.0
        return value

    def _sorted_rule_notes(self) -> List[Note]:
        return sorted(self._rule_notes(), key=lambda n: (n.sid or 10**12, n.note_id))

    def _current_ruleset_texts(self) -> List[str]:
        return [note.content for note in self._sorted_rule_notes() if note.content.strip()]

    def _build_candidate_ruleset(self, base_rule_notes: List[Note], proposal) -> List[str]:
        candidate_rules: List[str] = []
        replaced = False

        if proposal.mode == "repair" and proposal.base_note_id:
            for note in base_rule_notes:
                if note.note_id == proposal.base_note_id:
                    candidate_rules.append(proposal.rule_text)
                    replaced = True
                elif note.content.strip():
                    candidate_rules.append(note.content)
            if not replaced and proposal.rule_text.strip():
                candidate_rules.append(proposal.rule_text)
            return candidate_rules

        for note in base_rule_notes:
            if note.content.strip():
                candidate_rules.append(note.content)
        if proposal.rule_text.strip():
            candidate_rules.append(proposal.rule_text)
        return candidate_rules

    def _ruleset_signature(self, ruleset: List[str]) -> str:
        blob = "\n\n".join(rule.strip() for rule in ruleset if rule.strip()).encode("utf-8", errors="ignore")
        return hashlib.sha256(blob).hexdigest()

    def _file_sha256(self, path: str) -> Optional[str]:
        if not path or not os.path.exists(path) or not os.path.isfile(path):
            return None
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
        except OSError:
            return None
        return h.hexdigest()

    def _sandbox_dataset_signature(self, attack_pcaps: List[str], benign_pcaps: List[str]) -> str:
        def _norm(items: List[str]) -> List[str]:
            out: List[str] = []
            for path in items:
                if not path:
                    continue
                digest = self._file_sha256(path)
                if digest:
                    out.append(f"sha256:{digest}")
                else:
                    out.append(f"path:{Path(path).resolve(strict=False)}")
            out.sort()
            return out

        payload = {
            "attack": _norm(attack_pcaps),
            "benign": _norm(benign_pcaps),
        }
        blob = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def _get_or_compute_sandbox_baseline(
        self,
        *,
        dataset_signature: str,
        ruleset_signature: str,
        ruleset: List[str],
        attack_pcaps: List[str],
        benign_pcaps: List[str],
    ) -> Dict[str, Any]:
        cached = self.sandbox_baseline if isinstance(self.sandbox_baseline, dict) else {}
        cached_metrics = cached.get("metrics")
        if (
            cached.get("dataset_signature") == dataset_signature
            and cached.get("ruleset_signature") == ruleset_signature
            and isinstance(cached_metrics, dict)
        ):
            return {
                "ok": True,
                "source": "cache",
                "metrics": cached_metrics,
                "reason": "reuse cached baseline metrics",
            }

        baseline_result = self.sandbox.evaluate_ruleset(ruleset, attack_pcaps, benign_pcaps)
        if not baseline_result.syntax_ok:
            return {
                "ok": False,
                "source": "computed",
                "reason": baseline_result.reason,
                "metrics": None,
            }
        if baseline_result.metrics is None:
            return {
                "ok": False,
                "source": "computed",
                "reason": "baseline metrics unavailable",
                "metrics": None,
            }

        metrics = baseline_result.metrics.__dict__
        self._update_sandbox_baseline_cache(
            dataset_signature=dataset_signature,
            ruleset_signature=ruleset_signature,
            metrics=metrics,
            ruleset_size=len(ruleset),
        )
        return {
            "ok": True,
            "source": "computed",
            "metrics": metrics,
            "reason": "baseline metrics computed",
        }

    def _update_sandbox_baseline_cache(
        self,
        *,
        dataset_signature: str,
        ruleset_signature: str,
        metrics: Dict[str, Any],
        ruleset_size: int,
    ) -> None:
        self.sandbox_baseline = {
            "dataset_signature": dataset_signature,
            "ruleset_signature": ruleset_signature,
            "ruleset_size": ruleset_size,
            "metrics": dict(metrics),
            "updated_at": now_iso(),
        }

    def _resolve_sandbox_sets(
        self,
        *,
        analyzed_pcap: Optional[str],
        traffic_note: Note,
        attack_pcaps: List[str],
        benign_pcaps: List[str],
    ) -> tuple[List[str], List[str], Dict[str, Any]]:
        hash_cache: Dict[str, Optional[str]] = {}

        def _file_hash(path: str) -> Optional[str]:
            if path in hash_cache:
                return hash_cache[path]
            if not path or not os.path.exists(path) or not os.path.isfile(path):
                hash_cache[path] = None
                return None
            h = hashlib.sha256()
            try:
                with open(path, "rb") as f:
                    while True:
                        chunk = f.read(1024 * 1024)
                        if not chunk:
                            break
                        h.update(chunk)
                digest = h.hexdigest()
                hash_cache[path] = digest
                return digest
            except OSError:
                hash_cache[path] = None
                return None

        def _file_key(path: str) -> str:
            digest = _file_hash(path)
            if digest:
                return f"sha256:{digest}"
            return f"path:{Path(path).resolve(strict=False)}"

        def _dedupe(paths: List[str]) -> List[str]:
            out: List[str] = []
            seen = set()
            for path in paths:
                if not path:
                    continue
                key = _file_key(path)
                if key in seen:
                    continue
                seen.add(key)
                out.append(path)
            return out

        attack_set = _dedupe(attack_pcaps)
        benign_set = _dedupe(benign_pcaps)
        classify_info: Dict[str, Any] = {
            "has_analyzed_pcap": bool(analyzed_pcap),
            "assigned_label": None,
            "attack_type": None,
            "reason": "no analyzed pcap",
            "confidence": "na",
            "source": "none",
        }

        if not analyzed_pcap:
            return attack_set, benign_set, classify_info

        label_info = self._classify_analyzed_pcap(traffic_note)
        classify_info.update(label_info)
        classify_info["has_analyzed_pcap"] = True
        classify_info["analyzed_pcap"] = analyzed_pcap
        classify_info["analyzed_pcap_hash"] = _file_hash(analyzed_pcap)

        analyzed_key = _file_key(analyzed_pcap)
        attack_set = [p for p in attack_set if _file_key(p) != analyzed_key]
        benign_set = [p for p in benign_set if _file_key(p) != analyzed_key]

        if label_info["assigned_label"] == "attack":
            attack_set.append(analyzed_pcap)
        else:
            benign_set.append(analyzed_pcap)

        attack_set = _dedupe(attack_set)
        benign_set = _dedupe(benign_set)
        classify_info["final_attack_count"] = len(attack_set)
        classify_info["final_benign_count"] = len(benign_set)
        return attack_set, benign_set, classify_info

    def _precheck_existing_ruleset(self, pcap_path: str) -> Dict[str, Any]:
        rule_notes = self._sorted_rule_notes()
        ruleset = [note.content for note in rule_notes if note.content.strip()]
        out: Dict[str, Any] = {
            "pcap_path": pcap_path,
            "ruleset_size": len(ruleset),
            "format_check_passed": None,
            "alerts_triggered": False,
            "confirmed_hit": False,
            "alert_count": 0,
            "matched_sids": [],
            "matched_messages": [],
            "matched_note_ids": [],
            "error_message": None,
            "reason": "",
        }

        if not ruleset:
            out["reason"] = "skip precheck: no existing rules in graph"
            return out

        result = self.validator.test_ruleset_against_pcap(ruleset, pcap_path)
        out["format_check_passed"] = result.format_check_passed
        out["alerts_triggered"] = bool(result.alerts_triggered)
        out["error_message"] = result.error_message

        matched_sids: List[int] = []
        matched_messages: List[str] = []
        for event in result.alert_details or []:
            alert = event.get("alert", {}) if isinstance(event, dict) else {}
            sid_raw = alert.get("signature_id")
            try:
                sid = int(sid_raw)
            except (TypeError, ValueError):
                sid = None
            if sid is not None:
                matched_sids.append(sid)
            signature = str(alert.get("signature") or "").strip()
            if signature:
                matched_messages.append(signature)

        matched_sids = dedupe_keep_order(matched_sids)
        matched_messages = dedupe_keep_order(matched_messages)
        matched_sid_set = set(matched_sids)
        matched_note_ids = [
            note.note_id
            for note in rule_notes
            if note.sid is not None and note.sid in matched_sid_set
        ]

        alert_count = len(result.alert_details or [])
        confirmed_hit = bool(result.alerts_triggered and alert_count > 0)

        out["confirmed_hit"] = confirmed_hit
        out["alert_count"] = alert_count
        out["matched_sids"] = matched_sids
        out["matched_messages"] = matched_messages[:10]
        out["matched_note_ids"] = matched_note_ids
        out["reason"] = (
            "existing rules matched analyzed pcap"
            if confirmed_hit
            else "no confirmed existing-rule hit on analyzed pcap"
        )
        return out

    def _classify_analyzed_pcap(self, traffic_note: Note) -> Dict[str, Any]:
        payload = {
            "assigned_label": "benign",
            "attack_type": "benign",
            "reason": "llm classification unavailable, fallback benign",
            "confidence": "low",
            "source": "fallback",
            "intent": traffic_note.intent,
            "tactics": traffic_note.tactics[:10],
            "cve_ids": traffic_note.external_knowledge.cve_ids[:10],
        }
        messages = [
            {"role": "system", "content": TRAFFIC_CLASSIFICATION_SYSTEM},
            {
                "role": "user",
                "content": TRAFFIC_CLASSIFICATION_USER.format(
                    intent=traffic_note.intent or "",
                    keywords=json.dumps(traffic_note.keywords[:20], ensure_ascii=False),
                    tactics=json.dumps(traffic_note.tactics[:12], ensure_ascii=False),
                    cve_ids=json.dumps(traffic_note.external_knowledge.cve_ids[:10], ensure_ascii=False),
                    content=(traffic_note.content or "")[:4000],
                ),
            },
        ]

        try:
            response = self.llm.chat(messages, temperature=0.0)
        except Exception as exc:
            payload["reason"] = f"llm classification call failed: {exc.__class__.__name__}"
            return payload

        parsed = self._try_parse_json(response)
        if parsed is None:
            payload["reason"] = "llm classification parse failed, fallback benign"
            payload["raw_response"] = response[:1000]
            return payload

        is_attack = self._coerce_bool(parsed.get("is_attack"))
        if is_attack is None:
            attack_type_raw = str(parsed.get("attack_type") or "").strip().lower()
            is_attack = attack_type_raw not in {"", "benign", "normal", "clean"}

        label = "attack" if is_attack else "benign"
        attack_type = self._normalize_attack_type(parsed.get("attack_type"), is_attack=is_attack)
        confidence = str(parsed.get("confidence") or "").strip().lower()
        if confidence not in {"high", "medium", "low"}:
            confidence = "medium"
        reason = str(parsed.get("reason") or "").strip() or "llm classification"

        payload.update(
            {
                "assigned_label": label,
                "attack_type": attack_type,
                "confidence": confidence,
                "reason": reason,
                "source": "llm",
                "raw_response": response[:1000],
            }
        )
        return payload

    def _coerce_bool(self, value: Any) -> Optional[bool]:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            low = value.strip().lower()
            if low in {"true", "1", "yes", "y", "attack", "malicious"}:
                return True
            if low in {"false", "0", "no", "n", "benign", "normal", "clean"}:
                return False
        return None

    def _normalize_attack_type(self, raw_value: Any, *, is_attack: bool) -> str:
        if not is_attack:
            return "benign"
        raw = str(raw_value or "").strip().lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "sqli": "sql_injection",
            "sqlinjection": "sql_injection",
            "sql_inject": "sql_injection",
            "sql": "sql_injection",
            "cmdi": "command_injection",
            "cmd_injection": "command_injection",
            "commandinject": "command_injection",
            "rce_attack": "rce",
            "remote_code_execution": "rce",
            "remote_code_exec": "rce",
            "path_traversal": "lfi",
            "directory_traversal": "lfi",
            "xxe": "other",
            "ssti": "other",
        }
        allowed = {
            "xss",
            "sql_injection",
            "rce",
            "lfi",
            "command_injection",
            "webshell",
            "other",
        }
        if raw in aliases:
            raw = aliases[raw]
        if raw in allowed:
            return raw
        if raw in {"", "benign", "normal", "clean"}:
            return "other"
        return raw[:64]

    def _try_parse_json(self, text: str) -> Optional[Dict[str, Any]]:
        text = (text or "").strip()
        if not text:
            return None
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            chunk = text[start : end + 1]
            try:
                parsed = json.loads(chunk)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                return None
        return None

    def _iter_rules_from_path(self, path: Path):
        if path.is_file():
            yield from self._iter_rules_from_file(path)
            return

        if path.is_dir():
            rule_files = [
                p
                for p in sorted(path.rglob("*"))
                if p.is_file() and p.suffix.lower() in {".rules", ".rule", ".txt"}
            ]
            if not rule_files:
                raise ValueError(f"No rule files found under directory: {path}")
            for rule_file in rule_files:
                yield from self._iter_rules_from_file(rule_file)
            return

        raise ValueError(f"Unsupported rules path: {path}")

    def _iter_rules_from_file(self, rule_file: Path):
        for line in rule_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            rule = line.strip()
            if not rule or rule.startswith("#"):
                continue
            if not rule.lower().startswith(("alert ", "drop ", "pass ", "reject ")):
                continue
            yield rule

    def _solidify_memory(self, traffic_note: Note, proposal) -> tuple[list[str], list[str]]:
        linked: List[str] = []
        merge_candidates: List[str] = []

        if proposal.mode == "repair" and proposal.base_note_id:
            base = self.graph.get(proposal.base_note_id)
            if base is None:
                # Fallback as new rule when base cannot be found.
                new_note = self.note_builder.build_rule_note(
                    proposal.rule_text,
                    analysis_note=traffic_note,
                )
                self.graph.add_or_update(new_note)
                linked.append(new_note.note_id)
                merge_candidates = self.graph.find_merge_candidates(new_note.note_id)
            else:
                rebuilt = self.note_builder.build_rule_note(
                    proposal.rule_text,
                    note_id=base.note_id,
                    analysis_note=traffic_note,
                    intent_hint=self._merge_rule_intent(base.intent, traffic_note),
                    keyword_hints=base.keywords,
                    tactic_hints=base.tactics,
                    extra_knowledge=base.external_knowledge,
                    extra_metadata=base.metadata,
                )
                rebuilt.version = base.version + 1
                rebuilt.timestamp = now_iso()
                self.graph.add_or_update(rebuilt)
                self._cascade_chain_context(rebuilt, traffic_note)
                linked.append(rebuilt.note_id)
                merge_candidates = self.graph.find_merge_candidates(rebuilt.note_id)
        else:
            new_note = self.note_builder.build_rule_note(
                proposal.rule_text,
                analysis_note=traffic_note,
            )
            self.graph.add_or_update(new_note)
            linked.append(new_note.note_id)
            merge_candidates = self.graph.find_merge_candidates(new_note.note_id)

        return merge_candidates, linked

    def _cascade_chain_context(self, base_note: Note, traffic_note: Note) -> None:
        variant_label = self._traffic_variant_label(traffic_note)
        neighbors = self.graph.neighbors(base_note.note_id, link_type="exploit_chain")
        for link in neighbors:
            other = self.graph.get(link.target_id)
            if other is None:
                continue
            context = other.metadata.get("context", "")
            context += f" | related rule covered variant: {variant_label}"
            other.metadata["context"] = context.strip()
            self.note_builder.reembed_note(other)
            self.graph.add_or_update(other)

    def _merge_rule_intent(self, base_intent: str, traffic_note: Note) -> str:
        current = (base_intent or "").strip()
        variant_label = self._traffic_variant_label(traffic_note)
        if not current:
            return variant_label
        if not variant_label:
            return current
        if variant_label.lower() in current.lower():
            return current
        return f"{current}; covers variant: {variant_label}"

    def _traffic_variant_label(self, traffic_note: Note) -> str:
        intent = (traffic_note.intent or "").strip()
        if intent:
            return intent[:220]
        keywords = [str(x).strip() for x in traffic_note.keywords[:4] if str(x).strip()]
        if keywords:
            return ", ".join(keywords)
        return "analyzed traffic variant"

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
