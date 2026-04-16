from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .llm_client import BaseLLMClient

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, set):
        return [json_safe(v) for v in sorted(value, key=lambda x: str(x))]
    return str(value)


def now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_safe(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def append_jsonl(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(json_safe(payload), ensure_ascii=False))
        f.write("\n")


class ProgressNormalizer:
    def __init__(self, kind: str):
        self.kind = kind
        self.last_percent = 0.0
        self.knowledge_ticks = 0

    def normalize(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        event = str(payload.get("event") or "progress")
        if self.kind == "init":
            normalized = self._normalize_init(event, payload)
        elif self.kind == "process_batch":
            normalized = self._normalize_process_batch(event, payload)
        else:
            normalized = self._normalize_process(event, payload)
        normalized["percent"] = max(self.last_percent, min(100.0, float(normalized.get("percent") or 0.0)))
        self.last_percent = float(normalized["percent"])
        normalized["at"] = now_iso()
        return normalized

    def _normalize_init(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if event == "pipeline_build_start":
            return {"stage": "pipeline", "label": "building pipeline", "percent": 1.0}
        if event == "pipeline_build_ready":
            return {"stage": "pipeline", "label": "pipeline ready", "percent": 12.0}
        if event in {"source_start", "cache_reuse", "source_done", "stage", "progress_start", "progress_update", "progress_end"}:
            self.knowledge_ticks += 1
            source = str(payload.get("source") or "knowledge")
            stage = str(payload.get("stage") or event).strip() or event
            label = str(payload.get("message") or f"{source}:{stage}")
            return {
                "stage": "knowledge",
                "label": label,
                "detail": {"source": source, "knowledge_stage": stage},
                "percent": min(10.0, 1.0 + self.knowledge_ticks * 1.2),
            }
        if event == "init_prepare":
            total = int(payload.get("count") or 0)
            return {
                "stage": "prepare",
                "label": f"loaded {total} rules",
                "detail": {"total_rules": total},
                "percent": 15.0,
            }
        if event == "init_resume":
            completed = int(payload.get("count") or 0)
            total = max(1, int(payload.get("total_rules") or 1))
            return {
                "stage": "rule_indexing",
                "label": f"resume rules {completed}/{total}",
                "detail": {"count": completed, "total": total, "checkpoint_dir": payload.get("checkpoint_dir")},
                "percent": 50.0 + (completed / total) * 48.0,
            }
        if event == "reference_prefetch_start":
            total = int(payload.get("references") or 0)
            return {
                "stage": "reference_prefetch",
                "label": f"prefetching {total} references",
                "detail": {"total_references": total, "max_workers": payload.get("max_workers")},
                "percent": 20.0,
            }
        if event == "reference_prefetch_progress":
            completed = int(payload.get("completed") or 0)
            total = max(1, int(payload.get("total") or 1))
            return {
                "stage": "reference_prefetch",
                "label": f"references {completed}/{total}",
                "detail": {"completed": completed, "total": total},
                "percent": 20.0 + (completed / total) * 30.0,
            }
        if event == "reference_prefetch_done":
            return {"stage": "reference_prefetch", "label": "reference prefetch done", "percent": 50.0}
        if event == "init_progress":
            count = int(payload.get("count") or 0)
            total = max(1, int(payload.get("total_rules") or payload.get("count") or 1))
            return {
                "stage": "rule_indexing",
                "label": f"rules {count}/{total}",
                "detail": {"count": count, "total": total},
                "percent": 50.0 + (count / total) * 48.0,
            }
        if event == "init_done":
            count = int(payload.get("count") or 0)
            return {
                "stage": "done",
                "label": f"initialized {count} rules",
                "detail": {"count": count},
                "percent": 100.0,
            }
        if event == "job_done":
            return {"stage": "done", "label": "init completed", "percent": 100.0}
        if event == "job_failed":
            return {"stage": "failed", "label": "init failed", "percent": self.last_percent}
        return {"stage": "running", "label": event, "percent": self.last_percent}

    def _normalize_process(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if event == "pipeline_build_start":
            return {"stage": "pipeline", "label": "building pipeline", "percent": 1.0}
        if event == "pipeline_build_ready":
            return {"stage": "pipeline", "label": "pipeline ready", "percent": 8.0}
        if event in {"source_start", "cache_reuse", "source_done", "stage", "progress_start", "progress_update", "progress_end"}:
            self.knowledge_ticks += 1
            source = str(payload.get("source") or "knowledge")
            stage = str(payload.get("stage") or event).strip() or event
            label = str(payload.get("message") or f"{source}:{stage}")
            return {
                "stage": "knowledge",
                "label": label,
                "detail": {"source": source, "knowledge_stage": stage},
                "percent": min(6.0, 1.0 + self.knowledge_ticks * 0.7),
            }
        if event == "process_started":
            return {"stage": "start", "label": "process started", "percent": 10.0}
        if event == "step":
            name = str(payload.get("name") or "")
            output = payload.get("output")
            attempt = 1
            if isinstance(output, dict):
                try:
                    attempt = int(output.get("attempt") or 1)
                except (TypeError, ValueError):
                    attempt = 1
            mapping = {
                "pcap_parse": (18.0, "pcap parsed"),
                "existing_ruleset_precheck": (24.0, "existing ruleset precheck"),
                "dual_retrieval": (34.0, "dual retrieval"),
                "traffic_note": (40.0, "traffic note built"),
                "human_override": (44.0, "human override applied"),
                "topk_search": (50.0, "top-k note search"),
                "rule_proposal": (58.0, "rule proposal generated"),
                "analyzed_pcap_labeling": (64.0, "pcap labeling"),
                "sandbox_dataset_resolved": (68.0, "sandbox dataset resolved"),
                "sandbox_baseline": (74.0, "sandbox baseline evaluated"),
                "failure_diagnosis": (92.0, "failure diagnosis"),
                "feedback_loop_to_dual_retrieval": (94.0, "retry feedback prepared"),
                "rule_regenerate": (96.0, "rule regenerated"),
                "syntax_only_validation": (100.0, "syntax validation done"),
                "memory_solidify": (100.0, "memory solidified"),
            }
            if name.startswith("dual_retrieval"):
                return {"stage": "retrieval", "label": name, "percent": 34.0}
            if name.startswith("traffic_note"):
                return {"stage": "analysis", "label": name, "percent": 40.0}
            if name.startswith("topk_search"):
                return {"stage": "search", "label": name, "percent": 50.0}
            if name.startswith("rule_proposal"):
                return {"stage": "proposal", "label": name, "percent": 58.0}
            if name.startswith("human_override"):
                return {"stage": "analysis", "label": name, "percent": 44.0}
            if name == "sandbox_validation":
                pct = min(90.0, 80.0 + max(0, attempt - 1) * 5.0)
                return {
                    "stage": "validation",
                    "label": f"sandbox validation attempt {attempt}",
                    "detail": {"attempt": attempt},
                    "percent": pct,
                }
            base = mapping.get(name)
            if base is not None:
                return {"stage": name, "label": base[1], "percent": base[0]}
        if event == "job_done":
            return {"stage": "done", "label": "process completed", "percent": 100.0}
        if event == "job_failed":
            return {"stage": "failed", "label": "process failed", "percent": self.last_percent}
        return {"stage": "running", "label": event, "percent": self.last_percent}

    def _normalize_process_batch(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if event == "pipeline_build_start":
            return {"stage": "pipeline", "label": "building pipeline", "percent": 1.0}
        if event == "pipeline_build_ready":
            return {"stage": "pipeline", "label": "pipeline ready", "percent": 4.0}
        if event in {"source_start", "cache_reuse", "source_done", "stage", "progress_start", "progress_update", "progress_end"}:
            return self._normalize_process(event, payload)
        if event == "batch_prepare":
            total = int(payload.get("count") or 0)
            return {"stage": "batch_prepare", "label": f"loaded {total} pcaps", "percent": 5.0}
        if event == "batch_resume":
            done = int(payload.get("count") or 0)
            total = max(1, int(payload.get("total_pcaps") or 1))
            return {"stage": "batch_resume", "label": f"resume pcaps {done}/{total}", "percent": 5.0 + (done / total) * 90.0}
        if event == "batch_item_start":
            index = int(payload.get("index") or 0)
            total = max(1, int(payload.get("total_pcaps") or 1))
            pcap_name = Path(str(payload.get("pcap_path") or "")).name
            return {"stage": "batch_item", "label": f"[{index}/{total}] {pcap_name}", "percent": 5.0 + ((max(0, index - 1)) / total) * 90.0}
        if event == "batch_item_done":
            done = int(payload.get("count") or 0)
            total = max(1, int(payload.get("total_pcaps") or 1))
            pcap_name = Path(str(payload.get("pcap_path") or "")).name
            return {"stage": "batch_item_done", "label": f"done {done}/{total} {pcap_name}", "percent": 5.0 + (done / total) * 90.0}
        if event == "batch_done":
            total = int(payload.get("total_pcaps") or payload.get("count") or 0)
            return {"stage": "done", "label": f"processed {total} pcaps", "percent": 100.0}
        if event == "job_done":
            return {"stage": "done", "label": "process-batch completed", "percent": 100.0}
        if event == "job_failed":
            return {"stage": "failed", "label": "process-batch failed", "percent": self.last_percent}
        inner = self._normalize_process(event, payload)
        inner["percent"] = min(99.0, float(inner.get("percent") or self.last_percent))
        return inner


class RunArtifacts:
    def __init__(self, log_dir: str | Path, *, kind: str, source: str, job_id: str = ""):
        self.log_dir = Path(log_dir)
        self.kind = kind
        self.source = source
        self.job_id = job_id
        self._lock = threading.Lock()
        self._normalizer = ProgressNormalizer(kind)
        self._llm_count = 0
        self._tool_count = 0
        self._latest_progress: Dict[str, Any] = {
            "stage": "pending",
            "label": "pending",
            "percent": 0.0,
            "at": now_iso(),
        }

    def record_progress(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        normalized = self._normalizer.normalize(dict(payload))
        record = {"at": now_iso(), "raw": json_safe(payload), "normalized": normalized}
        with self._lock:
            self._latest_progress = normalized
            append_jsonl(self.log_dir / "progress.jsonl", record)
            write_json(self.log_dir / "progress.json", normalized)
            self._write_summary_locked()
        return normalized

    def record_llm_call(
        self,
        *,
        model: str,
        temperature: float,
        messages: List[Dict[str, str]],
        response: Optional[str],
        latency_s: float,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            self._llm_count += 1
            record = {
                "at": now_iso(),
                "call_index": self._llm_count,
                "model": model,
                "temperature": temperature,
                "latency_s": round(latency_s, 3),
                "messages": messages,
                "response": response,
                "error": error,
                "status": ("error" if error else "ok"),
            }
            append_jsonl(self.log_dir / "llm_calls.jsonl", record)
            self._write_summary_locked()
            return record

    def record_tool_call(
        self,
        *,
        tool: str,
        action: str,
        input_payload: Dict[str, Any],
        output_payload: Optional[Dict[str, Any]] = None,
        latency_s: Optional[float] = None,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            self._tool_count += 1
            record = {
                "at": now_iso(),
                "call_index": self._tool_count,
                "tool": tool,
                "action": action,
                "latency_s": (round(latency_s, 3) if latency_s is not None else None),
                "input": input_payload,
                "output": output_payload,
                "error": error,
                "status": ("error" if error else "ok"),
            }
            append_jsonl(self.log_dir / "tool_calls.jsonl", record)
            self._write_summary_locked()
            return record

    def finalize(self, *, status: str, result: Any = None, error: Optional[str] = None) -> None:
        with self._lock:
            self._write_summary_locked(status=status, result=result, error=error)

    def latest_progress(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._latest_progress)

    def _write_summary_locked(self, *, status: str = "", result: Any = None, error: Optional[str] = None) -> None:
        summary = {
            "job_id": self.job_id,
            "kind": self.kind,
            "source": self.source,
            "updated_at": now_iso(),
            "status": status or "running",
            "llm_call_count": self._llm_count,
            "tool_call_count": self._tool_count,
            "latest_progress": self._latest_progress,
            "result_preview": json_safe(result) if result is not None else None,
            "error": error,
        }
        write_json(self.log_dir / "summary.json", summary)


class TracingLLMClient(BaseLLMClient):
    def __init__(self, inner: BaseLLMClient, artifacts: RunArtifacts, sink: Optional[List[Dict[str, Any]]] = None):
        self.inner = inner
        self.artifacts = artifacts
        self.sink = sink

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        t0 = time.time()
        response: Optional[str] = None
        error: Optional[str] = None
        try:
            response = self.inner.chat(messages, temperature=temperature)
            return response
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            record = self.artifacts.record_llm_call(
                model=self.inner.model_name(),
                temperature=temperature,
                messages=messages,
                response=response,
                latency_s=time.time() - t0,
                error=error,
            )
            if self.sink is not None:
                self.sink.append(record)

    def model_name(self) -> str:
        return self.inner.model_name()


class ConsoleProgressReporter:
    def __init__(self, kind: str):
        self.kind = kind
        self._bar = None
        self._last_percent = -1
        self._last_line = ""
        self._mode = "percent"
        self._init_total = 0
        self._reference_total = 0
        if tqdm is not None and sys.stderr.isatty():
            initial_total = 100
            initial_unit = "%"
            initial_desc = f"{kind:>7}"
            if kind == "init":
                initial_total = 0
                initial_unit = "item"
                initial_desc = " init"
            self._bar = tqdm(total=initial_total, desc=initial_desc, unit=initial_unit)

    def update(self, progress: Dict[str, Any], raw: Optional[Dict[str, Any]] = None) -> None:
        raw = raw or {}
        event = str(raw.get("event") or "")
        if self.kind == "init":
            if event == "init_prepare":
                self._mode = "rule_count"
                self._init_total = max(self._init_total, int(raw.get("count") or 0))
                self._prime_stage_bar(stage="rules", total=self._init_total, label=str(progress.get("label") or "rules prepared"))
                return
            if event == "init_resume":
                self._mode = "rule_count"
                self._init_total = max(self._init_total, int(raw.get("total_rules") or 0))
                self._update_stage_count_bar(
                    stage="rules",
                    current=int(raw.get("count") or 0),
                    total=self._init_total,
                    label=str(progress.get("label") or f"resume from {int(raw.get('count') or 0)}"),
                )
                return
            if event in {"reference_prefetch_start", "reference_prefetch_progress", "reference_prefetch_done"}:
                self._mode = "reference_count"
                total = int(raw.get("total") or raw.get("references") or self._reference_total or 0)
                if event == "reference_prefetch_start":
                    self._reference_total = max(self._reference_total, total)
                    self._prime_stage_bar(
                        stage="refs",
                        total=self._reference_total,
                        label=str(progress.get("label") or "reference prefetch"),
                    )
                    return
                if event == "reference_prefetch_progress":
                    self._reference_total = max(self._reference_total, total)
                    self._update_stage_count_bar(
                        stage="refs",
                        current=int(raw.get("completed") or 0),
                        total=self._reference_total,
                        label=str(progress.get("label") or "reference prefetch"),
                    )
                    return
                self._update_stage_count_bar(
                    stage="refs",
                    current=self._reference_total,
                    total=self._reference_total,
                    label=str(progress.get("label") or "reference prefetch done"),
                )
                return
            if event in {"init_progress", "init_done"}:
                self._mode = "rule_count"
                total_rules = int(raw.get("total_rules") or raw.get("count") or self._init_total or 0)
                self._init_total = max(self._init_total, total_rules)
                current = int(raw.get("count") or 0)
                if event == "init_done":
                    current = self._init_total
                self._update_stage_count_bar(
                    stage="rules",
                    current=current,
                    total=self._init_total,
                    label=str(progress.get("label") or "rule init"),
                )
                return
            self._set_status_only(progress)
            if self._mode == "rule_count":
                return

        percent = int(float(progress.get("percent") or 0.0))
        label = str(progress.get("label") or progress.get("stage") or self.kind)
        if self._bar is not None:
            delta = max(0, percent - int(self._bar.n))
            if delta:
                self._bar.update(delta)
            self._bar.set_postfix_str(label[:80], refresh=False)
            if percent >= 100:
                self._bar.refresh()
        else:
            line = f"[{self.kind}] {percent:3d}% {label}"
            if percent != self._last_percent or line != self._last_line:
                print(line, file=sys.stderr)
                self._last_percent = percent
                self._last_line = line

    def _set_status_only(self, progress: Dict[str, Any]) -> None:
        label = str(progress.get("label") or progress.get("stage") or self.kind)
        if self._bar is not None:
            self._bar.set_postfix_str(label[:80], refresh=False)
        else:
            line = f"[{self.kind}] {label}"
            if line != self._last_line:
                print(line, file=sys.stderr)
                self._last_line = line

    def _prime_stage_bar(self, *, stage: str, total: int, label: str) -> None:
        total = max(0, int(total))
        if self._bar is not None:
            self._bar.reset(total=total)
            self._bar.n = 0
            self._bar.set_description_str(f" {stage:>4}")
            self._bar.set_postfix_str(label[:80], refresh=False)
            self._bar.refresh()
        else:
            line = f"[{self.kind}] {stage} 0/{total} {label}"
            if line != self._last_line:
                print(line, file=sys.stderr)
                self._last_line = line

    def _update_stage_count_bar(self, *, stage: str, current: int, total: int, label: str) -> None:
        total = max(0, int(total))
        current = max(0, min(int(current), total if total > 0 else int(current)))
        if self._bar is not None:
            if self._bar.total != total:
                self._bar.reset(total=total)
            self._bar.set_description_str(f" {stage:>4}")
            delta = max(0, current - int(self._bar.n))
            if delta:
                self._bar.update(delta)
            self._bar.set_postfix_str(label[:80], refresh=False)
            self._bar.refresh()
        else:
            line = f"[{self.kind}] {stage} {current}/{total} {label}"
            if line != self._last_line:
                print(line, file=sys.stderr)
                self._last_line = line

    def close(self) -> None:
        if self._bar is not None:
            self._bar.close()
