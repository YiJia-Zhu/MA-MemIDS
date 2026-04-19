#!/usr/bin/env python3
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import shlex
import shutil
import sys
import time
import traceback
import uuid
from pathlib import Path
from typing import Callable, List

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False

from ma_memids.pipeline import MAMemIDSPipeline
from ma_memids.embedding import SentenceTransformerEmbedder
from ma_memids.llm_client import create_llm_client
from ma_memids.knowledge import (
    DualPathRetriever,
    load_knowledge_source_registry,
    save_knowledge_source_registry,
)
from ma_memids.run_trace import ConsoleProgressReporter, RunArtifacts, TracingLLMClient


ROOT = Path(__file__).resolve().parent
JOB_LOG_ROOT = ROOT / "memory" / "job_logs"


def _split_csv(value: str) -> List[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def _collect_pcap_files(path_value: str, *, limit: int = 0) -> List[str]:
    root = Path(path_value).expanduser()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"PCAP directory not found: {path_value}")
    files = [
        str(p.resolve(strict=False))
        for p in sorted(root.rglob("*"))
        if p.is_file() and p.suffix.lower() in {".pcap", ".pcapng", ".cap"}
    ]
    if limit > 0:
        files = files[:limit]
    return files


def _pcap_category_key(pcap_path: str) -> str:
    stem = Path(pcap_path).stem
    parts = stem.split("__")
    if len(parts) < 2:
        return stem
    dataset = parts[0].strip().lower()
    if dataset == "unsw" and len(parts) >= 3 and parts[1].startswith("event_"):
        return f"{parts[0]}__{parts[2]}"
    return f"{parts[0]}__{parts[1]}"


def _group_pcaps_by_category(pcaps: List[str]) -> List[tuple[str, List[str]]]:
    grouped: dict[str, List[str]] = {}
    for pcap_path in pcaps:
        key = _pcap_category_key(pcap_path)
        grouped.setdefault(key, []).append(pcap_path)
    return list(grouped.items())


def _chunk_list(items: List[str], chunk_size: int) -> List[List[str]]:
    if chunk_size <= 1:
        return [[item] for item in items]
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MA-MemIDS CLI")
    parser.add_argument("--state", default="./memory/state.json", help="State JSON path")
    parser.add_argument("--cve-kb", default="", help="CVE knowledge file or directory path")
    parser.add_argument("--attack-kb", default="", help="ATT&CK knowledge file or directory path")
    parser.add_argument("--cti-kb", default="", help="CTI knowledge file or directory path")
    parser.add_argument("--knowledge-cache-dir", default="./memory/knowledge_cache", help="Knowledge cache directory")
    parser.add_argument(
        "--knowledge-prebuilt-only",
        action="store_true",
        help="Require prebuilt knowledge cache and forbid on-the-fly index building",
    )
    parser.add_argument("--model", default=None, help="LLM model name from env configuration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    init_cmd = sub.add_parser("init", help="Stage-1 initialization from base rules")
    init_cmd.add_argument("--rules", required=True, help="Base Suricata rules file or directory")
    init_cmd.add_argument("--max-rules", type=int, default=0, help="Optional cap for initialized rules (0 = no limit)")
    init_cmd.add_argument("--no-resume", action="store_true", help="Disable init checkpoint resume")

    process_cmd = sub.add_parser("process", help="Stage-2 process unmatched traffic")
    process_cmd.add_argument("--pcap", default="", help="Unmatched traffic PCAP path")
    process_cmd.add_argument("--traffic-text", default="", help="Structured traffic summary text")
    process_cmd.add_argument("--attack-pcaps", default="", help="CSV list of attack pcaps for sandbox replay")
    process_cmd.add_argument("--benign-pcaps", default="", help="CSV list of benign pcaps for FPR estimation")
    process_cmd.add_argument("--override-intent", default="", help="Manual override for inferred intent")
    process_cmd.add_argument("--override-tactics", default="", help="CSV tactics override, e.g. T1190,T1059")
    process_cmd.add_argument("--override-keywords", default="", help="CSV keywords override")

    process_batch_cmd = sub.add_parser("process-batch", help="Stage-2 batch process unmatched traffic directory")
    process_batch_cmd.add_argument("--pcap-dir", required=True, help="Directory containing pcap/pcapng/cap files")
    process_batch_cmd.add_argument("--attack-pcaps", default="", help="CSV list of attack pcaps for sandbox replay")
    process_batch_cmd.add_argument("--benign-pcaps", default="", help="CSV list of benign pcaps for FPR estimation")
    process_batch_cmd.add_argument("--override-intent", default="", help="Manual override for inferred intent")
    process_batch_cmd.add_argument("--override-tactics", default="", help="CSV tactics override, e.g. T1190,T1059")
    process_batch_cmd.add_argument("--override-keywords", default="", help="CSV keywords override")
    process_batch_cmd.add_argument("--limit", type=int, default=0, help="Optional cap for processed pcaps (0 = no limit)")
    process_batch_cmd.add_argument("--no-resume", action="store_true", help="Disable process-batch checkpoint resume")
    process_batch_cmd.add_argument(
        "--category-batch-size",
        type=int,
        default=1,
        help="Process same-category pcaps in fixed-size batches. 1 keeps current fully serial logic.",
    )
    process_batch_cmd.add_argument(
        "--category-parallelism",
        type=int,
        default=1,
        help="Max parallel draft analyses inside one same-category batch.",
    )

    export_cmd = sub.add_parser("export", help="Export current ruleset")
    export_cmd.add_argument("--output", default="./output/rules.rules", help="Output rules path")

    sub.add_parser("build-knowledge", help="Prebuild hybrid knowledge caches only")
    sub.add_parser("stats", help="Show state statistics")
    return parser


def _knowledge_progress_logger(payload: dict[str, object]) -> None:
    event = str(payload.get("event") or "")
    source = str(payload.get("source") or "knowledge")
    if event == "source_start":
        logging.info("[%s] start: %s", source, payload.get("path"))
    elif event == "cache_reuse":
        logging.info("[%s] reuse cache: docs=%s path=%s", source, payload.get("doc_count"), payload.get("path"))
    elif event == "source_done":
        logging.info("[%s] done: docs=%s path=%s", source, payload.get("doc_count"), payload.get("path"))
    elif event == "stage":
        logging.info("[%s] %s", source, payload.get("message"))
    elif event == "progress_start":
        logging.info(
            "[%s] %s start: total=%s unit=%s",
            source,
            payload.get("stage"),
            payload.get("total"),
            payload.get("unit") or "it",
        )
    elif event == "progress_update":
        logging.debug(
            "[%s] %s progress: +%s",
            source,
            payload.get("stage"),
            payload.get("advance"),
        )
    elif event == "progress_end":
        logging.info("[%s] %s done: total=%s", source, payload.get("stage"), payload.get("total"))


def _json_safe(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, set):
        return [_json_safe(v) for v in sorted(value, key=lambda x: str(x))]
    return str(value)


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_json_safe(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def _append_jsonl(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(_json_safe(payload), ensure_ascii=False))
        f.write("\n")


def _log_cli_job_start(kind: str, request_payload: dict, command: str) -> tuple[str, Path]:
    stamp = time.strftime("%Y%m%d_%H%M%S")
    short_id = uuid.uuid4().hex[:12]
    job_id = f"cli-{kind}-{stamp}-{short_id}"
    log_dir = JOB_LOG_ROOT / f"{stamp}_{kind}_{short_id}"
    created_at = _now_iso()
    log_dir.mkdir(parents=True, exist_ok=True)
    snapshot = {
        "job_id": job_id,
        "kind": kind,
        "source": "cli",
        "status": "running",
        "created_at": created_at,
        "updated_at": created_at,
        "events": [],
        "result": None,
        "error": None,
        "log_dir": str(log_dir),
        "request": _json_safe(request_payload),
        "terminal_command": command,
        "progress": {"stage": "pending", "label": "pending", "percent": 0.0, "at": created_at},
    }
    _write_json(log_dir / "meta.json", {"job_id": job_id, "kind": kind, "source": "cli", "created_at": created_at})
    _write_json(log_dir / "request.json", request_payload)
    _write_json(log_dir / "command.json", {"terminal_command": command})
    (log_dir / "command.sh").write_text(command + "\n", encoding="utf-8")
    _write_json(log_dir / "snapshot.json", snapshot)
    _append_jsonl(JOB_LOG_ROOT / "index.jsonl", {"at": created_at, "event": "job_created", "job_id": job_id, "kind": kind, "source": "cli", "log_dir": str(log_dir), "terminal_command": command, "request": request_payload})
    _write_json(JOB_LOG_ROOT / f"latest_{kind}.json", {"job_id": job_id, "kind": kind, "source": "cli", "log_dir": str(log_dir), "updated_at": created_at})
    return job_id, log_dir


def _log_cli_job_event(log_dir: Path, event_type: str, message: str, payload: dict | None = None) -> None:
    event = {"at": _now_iso(), "type": event_type, "message": message, "payload": payload or {}}
    _append_jsonl(log_dir / "events.jsonl", event)
    snapshot_path = log_dir / "snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    events = list(snapshot.get("events") or [])
    events.append(event)
    snapshot["events"] = events
    snapshot["updated_at"] = event["at"]
    progress_payload = payload or {}
    if event_type == "progress":
        normalized = progress_payload.get("normalized") or progress_payload.get("progress")
        if isinstance(normalized, dict):
            snapshot["progress"] = normalized
    _write_json(snapshot_path, snapshot)


def _log_cli_job_finish(log_dir: Path, *, status: str, result=None, error: str | None = None, traceback_text: str = "") -> None:
    snapshot_path = log_dir / "snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    snapshot["status"] = status
    snapshot["updated_at"] = _now_iso()
    snapshot["result"] = _json_safe(result)
    snapshot["error"] = error
    if status == "succeeded":
        snapshot["progress"] = {"stage": "done", "label": "done", "percent": 100.0, "at": snapshot["updated_at"]}
    elif status == "failed":
        current = snapshot.get("progress") or {}
        snapshot["progress"] = {
            "stage": "failed",
            "label": "failed",
            "percent": float(current.get("percent") or 0.0),
            "at": snapshot["updated_at"],
        }
    _write_json(snapshot_path, snapshot)
    if result is not None:
        _write_json(log_dir / "result.json", result)
    if error is not None:
        _write_json(log_dir / "error.json", {"error": error, "traceback": traceback_text, "failed_at": snapshot["updated_at"]})
    _append_jsonl(JOB_LOG_ROOT / "index.jsonl", {"at": snapshot["updated_at"], "event": f"job_{status}", "job_id": snapshot["job_id"], "kind": snapshot["kind"], "source": snapshot["source"], "log_dir": str(log_dir), "error": error})
    _write_json(JOB_LOG_ROOT / f"latest_{snapshot['kind']}.json", {"job_id": snapshot["job_id"], "kind": snapshot["kind"], "source": snapshot["source"], "log_dir": str(log_dir), "updated_at": snapshot["updated_at"]})


def _capture_state_snapshot(log_dir: Path, state_path: str) -> None:
    source_path = Path(state_path).expanduser()
    if not source_path.is_absolute():
        source_path = ROOT / source_path
    source_path = source_path.resolve(strict=False)
    if not source_path.exists():
        return

    snapshot_path = log_dir / "state_snapshot.json"
    shutil.copy2(source_path, snapshot_path)
    _write_json(
        log_dir / "state_snapshot_meta.json",
        {
            "source_state_path": str(source_path),
            "snapshot_path": str(snapshot_path),
            "captured_at": _now_iso(),
        },
    )


def _make_tool_callback(artifacts: RunArtifacts, sink: list[dict]) -> Callable[[dict], None]:
    def _callback(payload: dict) -> None:
        record = artifacts.record_tool_call(
            tool=str(payload.get("tool") or "tool"),
            action=str(payload.get("action") or "call"),
            input_payload=dict(payload.get("input") or {}),
            output_payload=(dict(payload.get("output") or {}) if isinstance(payload.get("output"), dict) else None),
            error=(str(payload.get("error")) if payload.get("error") else None),
        )
        sink.append(record)

    return _callback


def _make_cli_progress_callback(
    *,
    kind: str,
    log_dir: Path,
    artifacts: RunArtifacts,
    reporter: ConsoleProgressReporter,
) -> Callable[[dict], None]:
    def _callback(payload: dict) -> None:
        normalized = artifacts.record_progress(payload)
        reporter.update(normalized, payload)
        _log_cli_job_event(
            log_dir,
            "progress",
            str(normalized.get("label") or normalized.get("stage") or payload.get("event") or "progress"),
            {"raw": _json_safe(payload), "normalized": normalized},
        )

    return _callback


def _batch_checkpoint_paths(
    *,
    state_path: str,
    pcap_dir: str,
    pcaps: list[str],
    attack_pcaps: list[str],
    benign_pcaps: list[str],
    override: dict,
    limit: int,
) -> dict[str, Path]:
    payload = {
        "pcap_dir": str(Path(pcap_dir).expanduser().resolve(strict=False)),
        "pcaps_sha256": uuid.uuid5(uuid.NAMESPACE_URL, "\n".join(pcaps)).hex,
        "attack_pcaps": attack_pcaps,
        "benign_pcaps": benign_pcaps,
        "override": override,
        "limit": limit,
    }
    key = uuid.uuid5(uuid.NAMESPACE_OID, json.dumps(payload, ensure_ascii=False, sort_keys=True)).hex[:16]
    checkpoint_dir = Path(state_path).expanduser().resolve(strict=False).parent / "checkpoints" / f"process_batch_{key}"
    return {
        "dir": checkpoint_dir,
        "meta": checkpoint_dir / "meta.json",
        "results": checkpoint_dir / "results.jsonl",
    }


def _load_batch_completed_map(paths: dict[str, Path]) -> dict[str, dict]:
    results_path = paths["results"]
    out: dict[str, dict] = {}
    if not results_path.exists():
        return out
    with results_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            pcap_path = str(payload.get("pcap_path") or "").strip()
            if pcap_path:
                out[pcap_path] = payload
    return out


def _write_batch_meta(paths: dict[str, Path], payload: dict) -> None:
    _write_json(paths["meta"], payload)


def _append_batch_result(paths: dict[str, Path], payload: dict) -> None:
    _append_jsonl(paths["results"], payload)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    command_line = " ".join(shlex.quote(part) for part in ([Path(sys.executable).name] + sys.argv))
    load_dotenv()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    if args.command == "build-knowledge":
        if not any((args.cve_kb, args.attack_kb, args.cti_kb)):
            parser.error("build-knowledge requires at least one of --cve-kb / --attack-kb / --cti-kb")
        cache_dir = Path(args.knowledge_cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        embedder = SentenceTransformerEmbedder()
        retriever = DualPathRetriever(embedder=embedder, cache_dir=str(cache_dir))
        retriever.load_knowledge(
            cve_path=args.cve_kb or None,
            attack_path=args.attack_kb or None,
            cti_path=args.cti_kb or None,
            progress_callback=_knowledge_progress_logger,
            build_if_missing=True,
        )
        registry_path = save_knowledge_source_registry(
            cache_dir,
            cve_path=args.cve_kb or None,
            attack_path=args.attack_kb or None,
            cti_path=args.cti_kb or None,
        )
        logging.info("Knowledge source registry updated: %s", registry_path)
        print(json.dumps(retriever.stats(), ensure_ascii=False, indent=2))
        return

    registry_used = False
    if not any((args.cve_kb, args.attack_kb, args.cti_kb)):
        registry_sources = load_knowledge_source_registry(args.knowledge_cache_dir)
        if any(registry_sources.values()):
            args.cve_kb = registry_sources.get("cve") or ""
            args.attack_kb = registry_sources.get("attack") or ""
            args.cti_kb = registry_sources.get("cti") or ""
            registry_used = True
            logging.info(
                "Using knowledge sources from cache registry under %s: cve=%s attack=%s cti=%s",
                Path(args.knowledge_cache_dir).expanduser(),
                args.cve_kb or "-",
                args.attack_kb or "-",
                args.cti_kb or "-",
            )

    knowledge_build_if_missing = not args.knowledge_prebuilt_only
    if registry_used and not args.knowledge_prebuilt_only:
        knowledge_build_if_missing = False
        logging.info("Knowledge sources were inferred from cache registry; running in prebuilt-cache mode by default")

    if args.command == "init":
        request_payload = {
            "state": args.state,
            "model": args.model,
            "knowledge_cache_dir": args.knowledge_cache_dir,
            "knowledge_prebuilt_only": args.knowledge_prebuilt_only,
            "cve_kb": args.cve_kb,
            "attack_kb": args.attack_kb,
            "cti_kb": args.cti_kb,
            "rules": args.rules,
            "max_rules": (args.max_rules if args.max_rules > 0 else None),
            "resume": (not args.no_resume),
            "verbose": args.verbose,
        }
        _, log_dir = _log_cli_job_start("init", request_payload, command_line)
        max_rules = args.max_rules if args.max_rules > 0 else None
        artifacts = RunArtifacts(log_dir, kind="init", source="cli")
        reporter = ConsoleProgressReporter("init")
        llm_calls: list[dict] = []
        tool_calls: list[dict] = []
        progress_callback = _make_cli_progress_callback(kind="init", log_dir=log_dir, artifacts=artifacts, reporter=reporter)
        tool_callback = _make_tool_callback(artifacts, tool_calls)
        _log_cli_job_event(log_dir, "status", "init_started", {"rules": args.rules, "max_rules": max_rules})
        try:
            progress_callback({"event": "pipeline_build_start"})
            llm_client = TracingLLMClient(create_llm_client(model=args.model), artifacts, llm_calls)
            pipeline = MAMemIDSPipeline(
                state_path=args.state,
                llm_client=llm_client,
                cve_knowledge_path=args.cve_kb or None,
                attack_knowledge_path=args.attack_kb or None,
                cti_knowledge_path=args.cti_kb or None,
                knowledge_cache_dir=args.knowledge_cache_dir,
                validation_mode="strict",
                knowledge_build_if_missing=knowledge_build_if_missing,
                knowledge_progress_callback=progress_callback,
                tool_callback=tool_callback,
            )
            progress_callback({"event": "pipeline_build_ready"})
            count = pipeline.initialize_from_rules_file(
                args.rules,
                max_rules=max_rules,
                progress_callback=progress_callback,
                resume=(not args.no_resume),
            )
            progress_callback({"event": "job_done"})
            result = {
                "ok": True,
                "initialized_rules": count,
                "stats": pipeline.stats(),
                "llm_call_count": len(llm_calls),
                "tool_call_count": len(tool_calls),
            }
            _capture_state_snapshot(log_dir, args.state)
            _log_cli_job_event(log_dir, "status", "init_done", {"initialized_rules": count})
            artifacts.finalize(status="succeeded", result=result)
            _log_cli_job_finish(log_dir, status="succeeded", result=result)
            print(json.dumps({"initialized_rules": count, "log_dir": str(log_dir)}, ensure_ascii=False, indent=2))
            return
        except Exception as exc:
            tb = traceback.format_exc()
            progress_callback({"event": "job_failed"})
            artifacts.finalize(status="failed", error=f"{type(exc).__name__}: {exc}")
            _log_cli_job_event(log_dir, "error", "init_failed", {"error": str(exc), "traceback": tb})
            _log_cli_job_finish(log_dir, status="failed", error=f"{type(exc).__name__}: {exc}", traceback_text=tb)
            raise
        finally:
            reporter.close()

    if args.command == "process":
        request_payload = {
            "state": args.state,
            "model": args.model,
            "knowledge_cache_dir": args.knowledge_cache_dir,
            "knowledge_prebuilt_only": args.knowledge_prebuilt_only,
            "cve_kb": args.cve_kb,
            "attack_kb": args.attack_kb,
            "cti_kb": args.cti_kb,
            "pcap": args.pcap,
            "traffic_text": args.traffic_text,
            "attack_pcaps": args.attack_pcaps,
            "benign_pcaps": args.benign_pcaps,
            "override_intent": args.override_intent,
            "override_tactics": args.override_tactics,
            "override_keywords": args.override_keywords,
            "verbose": args.verbose,
        }
        _, log_dir = _log_cli_job_start("process", request_payload, command_line)
        artifacts = RunArtifacts(log_dir, kind="process", source="cli")
        reporter = ConsoleProgressReporter("process")
        llm_calls: list[dict] = []
        tool_calls: list[dict] = []
        progress_callback = _make_cli_progress_callback(kind="process", log_dir=log_dir, artifacts=artifacts, reporter=reporter)
        tool_callback = _make_tool_callback(artifacts, tool_calls)
        override = {}
        if args.override_intent:
            override["intent"] = args.override_intent
        if args.override_tactics:
            override["tactics"] = _split_csv(args.override_tactics)
        if args.override_keywords:
            override["keywords"] = _split_csv(args.override_keywords)
        attack_pcaps = _split_csv(args.attack_pcaps)
        benign_pcaps = _split_csv(args.benign_pcaps)

        _log_cli_job_event(
            log_dir,
            "status",
            "process_started",
            {
                "pcap": args.pcap or None,
                "has_traffic_text": bool(args.traffic_text),
                "attack_count": len(attack_pcaps),
                "benign_count": len(benign_pcaps),
            },
        )
        try:
            progress_callback({"event": "pipeline_build_start"})
            llm_client = TracingLLMClient(create_llm_client(model=args.model), artifacts, llm_calls)
            pipeline = MAMemIDSPipeline(
                state_path=args.state,
                llm_client=llm_client,
                cve_knowledge_path=args.cve_kb or None,
                attack_knowledge_path=args.attack_kb or None,
                cti_knowledge_path=args.cti_kb or None,
                knowledge_cache_dir=args.knowledge_cache_dir,
                validation_mode="strict",
                knowledge_build_if_missing=knowledge_build_if_missing,
                knowledge_progress_callback=progress_callback,
                tool_callback=tool_callback,
            )
            progress_callback({"event": "pipeline_build_ready"})
            outcome = pipeline.process_unmatched_traffic_with_trace(
                pcap_path=args.pcap or None,
                traffic_text=args.traffic_text or None,
                attack_pcaps=(attack_pcaps or None),
                benign_pcaps=(benign_pcaps or None),
                human_override=override or None,
                progress_callback=progress_callback,
            )
            progress_callback({"event": "job_done"})
            result = dict(outcome.get("result") or {})
            result_payload = {
                "ok": True,
                "result": result,
                "trace": outcome.get("trace"),
                "stats": pipeline.stats(),
                "llm_call_count": len(llm_calls),
                "tool_call_count": len(tool_calls),
            }
            _capture_state_snapshot(log_dir, args.state)
            _log_cli_job_event(
                log_dir,
                "status",
                "process_done",
                {"success": result.get("success"), "mode": result.get("mode")},
            )
            artifacts.finalize(status="succeeded", result=result_payload)
            _log_cli_job_finish(log_dir, status="succeeded", result=result_payload)
            print(json.dumps({"result": result, "log_dir": str(log_dir)}, ensure_ascii=False, indent=2))
            return
        except Exception as exc:
            tb = traceback.format_exc()
            progress_callback({"event": "job_failed"})
            artifacts.finalize(status="failed", error=f"{type(exc).__name__}: {exc}")
            _log_cli_job_event(log_dir, "error", "process_failed", {"error": str(exc), "traceback": tb})
            _log_cli_job_finish(log_dir, status="failed", error=f"{type(exc).__name__}: {exc}", traceback_text=tb)
            raise
        finally:
            reporter.close()

    if args.command == "process-batch":
        if args.category_batch_size <= 0:
            parser.error("--category-batch-size must be a positive integer")
        if args.category_parallelism <= 0:
            parser.error("--category-parallelism must be a positive integer")
        override = {}
        if args.override_intent:
            override["intent"] = args.override_intent
        if args.override_tactics:
            override["tactics"] = _split_csv(args.override_tactics)
        if args.override_keywords:
            override["keywords"] = _split_csv(args.override_keywords)

        attack_pcaps = _split_csv(args.attack_pcaps)
        benign_pcaps = _split_csv(args.benign_pcaps)
        pcaps = _collect_pcap_files(args.pcap_dir, limit=args.limit)
        if not pcaps:
            raise ValueError(f"No pcap files found under: {args.pcap_dir}")

        checkpoint_paths = _batch_checkpoint_paths(
            state_path=args.state,
            pcap_dir=args.pcap_dir,
            pcaps=pcaps,
            attack_pcaps=attack_pcaps,
            benign_pcaps=benign_pcaps,
            override=override,
            limit=args.limit,
        )
        completed_map = {} if args.no_resume else _load_batch_completed_map(checkpoint_paths)

        request_payload = {
            "state": args.state,
            "model": args.model,
            "knowledge_cache_dir": args.knowledge_cache_dir,
            "knowledge_prebuilt_only": args.knowledge_prebuilt_only,
            "cve_kb": args.cve_kb,
            "attack_kb": args.attack_kb,
            "cti_kb": args.cti_kb,
            "pcap_dir": args.pcap_dir,
            "pcap_count": len(pcaps),
            "attack_pcaps": attack_pcaps,
            "benign_pcaps": benign_pcaps,
            "override": override,
            "limit": (args.limit if args.limit > 0 else None),
            "resume": (not args.no_resume),
            "checkpoint_dir": str(checkpoint_paths["dir"]),
            "category_batch_size": args.category_batch_size,
            "category_parallelism": args.category_parallelism,
            "verbose": args.verbose,
        }
        _, log_dir = _log_cli_job_start("process_batch", request_payload, command_line)
        artifacts = RunArtifacts(log_dir, kind="process_batch", source="cli")
        reporter = ConsoleProgressReporter("process")
        llm_calls: list[dict] = []
        tool_calls: list[dict] = []
        progress_callback = _make_cli_progress_callback(
            kind="process_batch",
            log_dir=log_dir,
            artifacts=artifacts,
            reporter=reporter,
        )
        tool_callback = _make_tool_callback(artifacts, tool_calls)
        _log_cli_job_event(
            log_dir,
            "status",
            "process_batch_started",
            {
                "pcap_dir": args.pcap_dir,
                "pcap_count": len(pcaps),
                "resume": (not args.no_resume),
                "completed_count": len(completed_map),
                "checkpoint_dir": str(checkpoint_paths["dir"]),
                "category_batch_size": args.category_batch_size,
                "category_parallelism": args.category_parallelism,
            },
        )
        try:
            progress_callback({"event": "pipeline_build_start"})
            llm_client = TracingLLMClient(create_llm_client(model=args.model), artifacts, llm_calls)
            pipeline = MAMemIDSPipeline(
                state_path=args.state,
                llm_client=llm_client,
                cve_knowledge_path=args.cve_kb or None,
                attack_knowledge_path=args.attack_kb or None,
                cti_knowledge_path=args.cti_kb or None,
                knowledge_cache_dir=args.knowledge_cache_dir,
                validation_mode="strict",
                knowledge_build_if_missing=knowledge_build_if_missing,
                knowledge_progress_callback=progress_callback,
                tool_callback=tool_callback,
            )
            progress_callback({"event": "pipeline_build_ready"})

            _write_batch_meta(
                checkpoint_paths,
                {
                    "pcap_dir": str(Path(args.pcap_dir).expanduser().resolve(strict=False)),
                    "pcap_count": len(pcaps),
                    "completed_count": len(completed_map),
                    "updated_at": _now_iso(),
                },
            )

            progress_callback({"event": "batch_prepare", "count": len(pcaps), "completed_count": len(completed_map)})
            if completed_map:
                progress_callback(
                    {"event": "batch_resume", "count": len(completed_map), "total_pcaps": len(pcaps), "checkpoint_dir": str(checkpoint_paths["dir"])}
                )

            batch_results_map: dict[str, dict] = {pcap_path: dict(record) for pcap_path, record in completed_map.items()}
            completed_count = len(completed_map)
            if args.category_batch_size == 1:
                for index, pcap_path in enumerate(pcaps, start=1):
                    if pcap_path in completed_map:
                        continue

                    progress_callback(
                        {
                            "event": "batch_item_start",
                            "index": index,
                            "count": completed_count,
                            "total_pcaps": len(pcaps),
                            "pcap_path": pcap_path,
                        }
                    )
                    outcome = pipeline.process_unmatched_traffic_with_trace(
                        pcap_path=pcap_path,
                        traffic_text=None,
                        attack_pcaps=(attack_pcaps or None),
                        benign_pcaps=(benign_pcaps or None),
                        human_override=override or None,
                        progress_callback=progress_callback,
                    )
                    result = dict(outcome.get("result") or {})
                    pipeline.save_state()
                    record = {
                        "at": _now_iso(),
                        "pcap_path": pcap_path,
                        "index": index,
                        "result": result,
                        "trace": outcome.get("trace"),
                    }
                    _append_batch_result(checkpoint_paths, record)
                    batch_results_map[pcap_path] = record
                    completed_count += 1
                    _write_batch_meta(
                        checkpoint_paths,
                        {
                            "pcap_dir": str(Path(args.pcap_dir).expanduser().resolve(strict=False)),
                            "pcap_count": len(pcaps),
                            "completed_count": completed_count,
                            "updated_at": _now_iso(),
                        },
                    )
                    progress_callback(
                        {
                            "event": "batch_item_done",
                            "index": index,
                            "count": completed_count,
                            "total_pcaps": len(pcaps),
                            "pcap_path": pcap_path,
                            "success": result.get("success"),
                            "mode": result.get("mode"),
                        }
                    )
            else:
                grouped_pcaps = _group_pcaps_by_category(pcaps)
                pcap_index_map = {pcap_path: index for index, pcap_path in enumerate(pcaps, start=1)}
                for category_key, category_pcaps in grouped_pcaps:
                    pending_pcaps = [pcap_path for pcap_path in category_pcaps if pcap_path not in completed_map]
                    if not pending_pcaps:
                        continue

                    _log_cli_job_event(
                        log_dir,
                        "status",
                        "process_batch_category_start",
                        {
                            "category": category_key,
                            "pcap_count": len(pending_pcaps),
                            "batch_size": args.category_batch_size,
                            "parallelism": args.category_parallelism,
                        },
                    )

                    for chunk_index, chunk in enumerate(_chunk_list(pending_pcaps, args.category_batch_size), start=1):
                        for pcap_path in chunk:
                            progress_callback(
                                {
                                    "event": "batch_item_start",
                                    "index": pcap_index_map[pcap_path],
                                    "count": completed_count,
                                    "total_pcaps": len(pcaps),
                                    "pcap_path": pcap_path,
                                }
                            )

                        analyses: dict[str, dict] = {}
                        max_workers = min(args.category_parallelism, len(chunk))
                        if max_workers <= 1 or len(chunk) <= 1:
                            for pcap_path in chunk:
                                analyses[pcap_path] = pipeline.analyze_unmatched_traffic_draft(
                                    pcap_path=pcap_path,
                                    traffic_text=None,
                                    attack_pcaps=(attack_pcaps or None),
                                    benign_pcaps=(benign_pcaps or None),
                                    human_override=override or None,
                                    progress_callback=None,
                                )
                        else:
                            with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="process-batch-cat") as executor:
                                future_map = {
                                    executor.submit(
                                        pipeline.analyze_unmatched_traffic_draft,
                                        pcap_path=pcap_path,
                                        traffic_text=None,
                                        attack_pcaps=(attack_pcaps or None),
                                        benign_pcaps=(benign_pcaps or None),
                                        human_override=override or None,
                                        progress_callback=None,
                                    ): pcap_path
                                    for pcap_path in chunk
                                }
                                for future in as_completed(future_map):
                                    analyses[future_map[future]] = future.result()

                        _log_cli_job_event(
                            log_dir,
                            "status",
                            "process_batch_category_chunk_analyzed",
                            {
                                "category": category_key,
                                "chunk_index": chunk_index,
                                "chunk_size": len(chunk),
                                "parallelism": max_workers,
                            },
                        )

                        for pcap_path in chunk:
                            analysis = analyses[pcap_path]
                            if analysis.get("kind") == "result":
                                outcome = {
                                    "result": dict(analysis.get("result") or {}),
                                    "trace": analysis.get("trace"),
                                }
                            else:
                                outcome = pipeline.execute_unmatched_traffic_draft_with_trace(
                                    draft=dict(analysis.get("draft") or {}),
                                    trace=(dict(analysis.get("trace") or {}) if isinstance(analysis.get("trace"), dict) else None),
                                    progress_callback=progress_callback,
                                )

                            result = dict(outcome.get("result") or {})
                            pipeline.save_state()
                            record = {
                                "at": _now_iso(),
                                "pcap_path": pcap_path,
                                "index": pcap_index_map[pcap_path],
                                "result": result,
                                "trace": outcome.get("trace"),
                                "category": category_key,
                                "category_chunk_index": chunk_index,
                            }
                            _append_batch_result(checkpoint_paths, record)
                            batch_results_map[pcap_path] = record
                            completed_count += 1
                            _write_batch_meta(
                                checkpoint_paths,
                                {
                                    "pcap_dir": str(Path(args.pcap_dir).expanduser().resolve(strict=False)),
                                    "pcap_count": len(pcaps),
                                    "completed_count": completed_count,
                                    "updated_at": _now_iso(),
                                },
                            )
                            progress_callback(
                                {
                                    "event": "batch_item_done",
                                    "index": pcap_index_map[pcap_path],
                                    "count": completed_count,
                                    "total_pcaps": len(pcaps),
                                    "pcap_path": pcap_path,
                                    "success": result.get("success"),
                                    "mode": result.get("mode"),
                                }
                            )

            progress_callback({"event": "batch_done", "count": completed_count, "total_pcaps": len(pcaps)})
            batch_results = [batch_results_map[pcap_path] for pcap_path in pcaps if pcap_path in batch_results_map]
            result_payload = {
                "ok": True,
                "pcap_count": len(pcaps),
                "completed_count": completed_count,
                "checkpoint_dir": str(checkpoint_paths["dir"]),
                "results": batch_results,
                "stats": pipeline.stats(),
                "llm_call_count": len(llm_calls),
                "tool_call_count": len(tool_calls),
            }
            _capture_state_snapshot(log_dir, args.state)
            artifacts.finalize(status="succeeded", result=result_payload)
            _log_cli_job_finish(log_dir, status="succeeded", result=result_payload)
            print(json.dumps({"completed_count": completed_count, "pcap_count": len(pcaps), "log_dir": str(log_dir)}, ensure_ascii=False, indent=2))
            return
        except Exception as exc:
            tb = traceback.format_exc()
            progress_callback({"event": "job_failed"})
            artifacts.finalize(status="failed", error=f"{type(exc).__name__}: {exc}")
            _log_cli_job_event(log_dir, "error", "process_batch_failed", {"error": str(exc), "traceback": tb})
            _log_cli_job_finish(log_dir, status="failed", error=f"{type(exc).__name__}: {exc}", traceback_text=tb)
            raise
        finally:
            reporter.close()

    pipeline = MAMemIDSPipeline(
        state_path=args.state,
        llm_model=args.model,
        cve_knowledge_path=args.cve_kb or None,
        attack_knowledge_path=args.attack_kb or None,
        cti_knowledge_path=args.cti_kb or None,
        knowledge_cache_dir=args.knowledge_cache_dir,
        validation_mode="strict",
        knowledge_build_if_missing=knowledge_build_if_missing,
    )

    if args.command == "export":
        count = pipeline.export_ruleset(args.output)
        print(f"Exported {count} rules to {args.output}")
        return

    if args.command == "stats":
        print(json.dumps(pipeline.stats(), ensure_ascii=False, indent=2))
        return


if __name__ == "__main__":
    main()
