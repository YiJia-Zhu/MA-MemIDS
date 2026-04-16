#!/usr/bin/env python3
from __future__ import annotations

import atexit
import json
import logging
import os
import shlex
import shutil
import sys
import tempfile
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from flask import Flask, jsonify, request, send_from_directory

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args: Any, **kwargs: Any) -> bool:
        return False

from ma_memids.graph import NoteGraph
from ma_memids.llm_client import BaseLLMClient, create_llm_client
from ma_memids.knowledge import load_knowledge_source_registry
from ma_memids.pipeline import MAMemIDSPipeline
from ma_memids.run_trace import RunArtifacts, TracingLLMClient


ROOT = Path(__file__).resolve().parent
DEMO_DIR = ROOT / "demo"
STATE_PATH = ROOT / "memory" / "state.json"
LOG_PATH = ROOT / "memory" / "demo_server.log"
DEFAULT_RULES_PATH = ROOT / "rules"
DEFAULT_SANDBOX_ROOT = ROOT / "sandbox_samples"
DEFAULT_ATTACK_SANDBOX_DIR = DEFAULT_SANDBOX_ROOT / "attack"
DEFAULT_BENIGN_SANDBOX_DIR = DEFAULT_SANDBOX_ROOT / "benign"
DEFAULT_KNOWLEDGE_CACHE_DIR = ROOT / "memory" / "knowledge_cache"
JOB_LOG_ROOT = ROOT / "memory" / "job_logs"

MAX_JOB_EVENTS = 1200
MAX_JOBS = 120

JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
STATE_SNAPSHOT_LOCK = threading.Lock()
STATE_SNAPSHOT_CACHE: Dict[str, Any] = {
    "graph": None,
    "raw": None,
    "mtime_ns": None,
}
PIPELINE_CACHE_LOCK = threading.Condition(threading.Lock())
PIPELINE_CACHE: Dict[str, Any] = {
    "pipeline": None,
    "cache_key": None,
    "state_mtime_ns": None,
    "building": False,
    "error": None,
}


def _configure_logging() -> logging.Logger:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("ma_memids.demo_server")
    if logger.handlers:
        return logger

    level_name = (os.getenv("MA_MEMIDS_DEMO_LOG_LEVEL") or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    logger.propagate = False
    return logger


LOGGER = _configure_logging()
DOTENV_LOADED = load_dotenv()
LOGGER.info(
    "demo_server bootstrap: cwd=%s python=%s argv=%s dotenv_loaded=%s log_path=%s",
    os.getcwd(),
    sys.executable,
    sys.argv,
    DOTENV_LOADED,
    LOG_PATH,
)


def _log_process_exit() -> None:
    LOGGER.info("demo_server process exiting")


def _log_uncaught_exception(exc_type, exc_value, exc_traceback) -> None:
    if issubclass(exc_type, KeyboardInterrupt):
        LOGGER.info("demo_server interrupted by KeyboardInterrupt")
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    LOGGER.critical("demo_server uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


atexit.register(_log_process_exit)
sys.excepthook = _log_uncaught_exception

def _resolve_pipeline_setup() -> Dict[str, Any]:
    knowledge_cache_dir = _resolve_app_path(os.getenv("MA_MEMIDS_KNOWLEDGE_CACHE_DIR", str(DEFAULT_KNOWLEDGE_CACHE_DIR)))
    registry_sources = load_knowledge_source_registry(knowledge_cache_dir)
    cve_kb = registry_sources.get("cve") or (os.getenv("MA_MEMIDS_DEFAULT_CVE_KB") or "").strip()
    attack_kb = registry_sources.get("attack") or (os.getenv("MA_MEMIDS_DEFAULT_ATTACK_KB") or "").strip()
    cti_kb = registry_sources.get("cti") or (os.getenv("MA_MEMIDS_DEFAULT_CTI_KB") or "").strip()
    registry_used = any(registry_sources.values())
    knowledge_build_if_missing = not registry_used
    return {
        "knowledge_cache_dir": knowledge_cache_dir,
        "cve_kb": cve_kb,
        "attack_kb": attack_kb,
        "cti_kb": cti_kb,
        "registry_used": registry_used,
        "knowledge_build_if_missing": knowledge_build_if_missing,
    }


def _log_pipeline_setup(setup: Dict[str, Any], *, context: str) -> None:
    if setup["registry_used"]:
        LOGGER.info(
            "%s using knowledge registry from %s: cve=%s attack=%s cti=%s",
            context,
            setup["knowledge_cache_dir"],
            setup["cve_kb"] or "-",
            setup["attack_kb"] or "-",
            setup["cti_kb"] or "-",
        )
    else:
        LOGGER.info(
            "%s knowledge registry missing under %s; falling back to default knowledge loading",
            context,
            setup["knowledge_cache_dir"],
        )


def _build_pipeline(
    *,
    llm_client: Optional[BaseLLMClient] = None,
    llm_model: Optional[str] = None,
    context: str,
    knowledge_progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    tool_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> MAMemIDSPipeline:
    setup = _resolve_pipeline_setup()
    _log_pipeline_setup(setup, context=context)
    return MAMemIDSPipeline(
        state_path=str(STATE_PATH),
        llm_client=llm_client,
        llm_model=(None if llm_client is not None else llm_model),
        cve_knowledge_path=setup["cve_kb"] or None,
        attack_knowledge_path=setup["attack_kb"] or None,
        cti_knowledge_path=setup["cti_kb"] or None,
        knowledge_cache_dir=str(setup["knowledge_cache_dir"]),
        knowledge_build_if_missing=setup["knowledge_build_if_missing"],
        knowledge_progress_callback=knowledge_progress_callback,
        tool_callback=tool_callback,
    )


def create_pipeline_with_trace(
    artifacts: RunArtifacts,
    llm_calls: List[Dict[str, Any]],
    *,
    llm_model: Optional[str] = None,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    tool_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> MAMemIDSPipeline:
    base_client = create_llm_client(model=llm_model)
    tracing_client = TracingLLMClient(base_client, artifacts, llm_calls)
    return _build_pipeline(
        llm_client=tracing_client,
        context="demo pipeline",
        knowledge_progress_callback=progress_callback,
        tool_callback=tool_callback,
    )


def _shared_pipeline_cache_key() -> tuple[str, str, str, str]:
    setup = _resolve_pipeline_setup()
    return (
        str(setup["knowledge_cache_dir"]),
        str(setup["cve_kb"] or ""),
        str(setup["attack_kb"] or ""),
        str(setup["cti_kb"] or ""),
    )


def _current_state_mtime_ns() -> Optional[int]:
    if not STATE_PATH.exists():
        return None
    return STATE_PATH.stat().st_mtime_ns


def _invalidate_state_snapshot(reason: str) -> None:
    with STATE_SNAPSHOT_LOCK:
        STATE_SNAPSHOT_CACHE["graph"] = None
        STATE_SNAPSHOT_CACHE["raw"] = None
        STATE_SNAPSHOT_CACHE["mtime_ns"] = None
    LOGGER.info("demo state snapshot invalidated: %s", reason)


def _get_state_snapshot() -> tuple[NoteGraph, Dict[str, Any]]:
    state_mtime_ns = _current_state_mtime_ns()
    with STATE_SNAPSHOT_LOCK:
        if (
            STATE_SNAPSHOT_CACHE["graph"] is not None
            and STATE_SNAPSHOT_CACHE["raw"] is not None
            and STATE_SNAPSHOT_CACHE["mtime_ns"] == state_mtime_ns
        ):
            return STATE_SNAPSHOT_CACHE["graph"], STATE_SNAPSHOT_CACHE["raw"]

    if STATE_PATH.exists():
        raw = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    else:
        raw = {}
    graph_data = raw.get("graph") if isinstance(raw, dict) else {}
    graph = NoteGraph.from_dict(graph_data) if isinstance(graph_data, dict) else NoteGraph()

    with STATE_SNAPSHOT_LOCK:
        STATE_SNAPSHOT_CACHE["graph"] = graph
        STATE_SNAPSHOT_CACHE["raw"] = raw
        STATE_SNAPSHOT_CACHE["mtime_ns"] = state_mtime_ns
    return graph, raw


def _state_stats_payload(graph: NoteGraph, raw: Dict[str, Any]) -> Dict[str, Any]:
    notes = graph.all_notes()
    rule_notes = [n for n in notes if n.note_type == "rule"]
    baseline = raw.get("sandbox_baseline") if isinstance(raw, dict) else {}
    embedding = raw.get("embedding") if isinstance(raw, dict) else {}
    knowledge_cache_dir = _resolve_app_path(os.getenv("MA_MEMIDS_KNOWLEDGE_CACHE_DIR", str(DEFAULT_KNOWLEDGE_CACHE_DIR)))
    knowledge_sources = load_knowledge_source_registry(knowledge_cache_dir)
    return {
        "total_notes": len(notes),
        "rule_notes": len(rule_notes),
        "traffic_notes": 0,
        "llm_model": (os.getenv("LLM_MODEL") or "gpt-4.1").strip() or "gpt-4.1",
        "embedding": embedding if isinstance(embedding, dict) else {},
        "knowledge": {
            "cache_dir": str(knowledge_cache_dir),
            "sources": _knowledge_source_status(knowledge_cache_dir, knowledge_sources),
        },
        "thresholds": graph.thresholds.__dict__,
        "graph_index": graph.index_stats(),
        "sandbox_baseline": baseline if isinstance(baseline, dict) else {},
    }


def _knowledge_source_status(cache_root: Path, sources: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    status: Dict[str, Dict[str, Any]] = {}
    for source_name in ("cve", "attack", "cti"):
        input_path = str(sources.get(source_name) or "").strip()
        record: Dict[str, Any] = {
            "path": input_path,
            "configured": bool(input_path),
            "cache_ready": False,
            "doc_count": 0,
            "manifest_path": None,
        }
        if input_path:
            manifest_glob = cache_root / source_name
            if manifest_glob.exists():
                for manifest_path in sorted(manifest_glob.glob("*/manifest.json")):
                    try:
                        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    except Exception:
                        continue
                    if str(manifest.get("input_path") or "").strip() != input_path:
                        continue
                    record["cache_ready"] = True
                    record["doc_count"] = int(manifest.get("doc_count") or 0)
                    record["manifest_path"] = str(manifest_path)
                    break
        status[source_name] = record
    return status


def _invalidate_shared_pipeline(reason: str) -> None:
    _invalidate_state_snapshot(reason)
    with PIPELINE_CACHE_LOCK:
        PIPELINE_CACHE["pipeline"] = None
        PIPELINE_CACHE["cache_key"] = None
        PIPELINE_CACHE["state_mtime_ns"] = None
        PIPELINE_CACHE["error"] = None
        PIPELINE_CACHE_LOCK.notify_all()
    LOGGER.info("shared demo pipeline invalidated: %s", reason)


def _get_shared_pipeline() -> MAMemIDSPipeline:
    cache_key = _shared_pipeline_cache_key()
    state_mtime_ns = _current_state_mtime_ns()

    with PIPELINE_CACHE_LOCK:
        while PIPELINE_CACHE["building"]:
            if (
                PIPELINE_CACHE["pipeline"] is not None
                and PIPELINE_CACHE["cache_key"] == cache_key
                and PIPELINE_CACHE["state_mtime_ns"] == state_mtime_ns
            ):
                return PIPELINE_CACHE["pipeline"]
            PIPELINE_CACHE_LOCK.wait()

        if (
            PIPELINE_CACHE["pipeline"] is not None
            and PIPELINE_CACHE["cache_key"] == cache_key
            and PIPELINE_CACHE["state_mtime_ns"] == state_mtime_ns
        ):
            return PIPELINE_CACHE["pipeline"]

        PIPELINE_CACHE["building"] = True
        PIPELINE_CACHE["error"] = None

    t0 = time.time()
    try:
        pipeline = _build_pipeline(context="shared demo pipeline")
        pipeline.stats()
    except Exception as exc:
        with PIPELINE_CACHE_LOCK:
            PIPELINE_CACHE["building"] = False
            PIPELINE_CACHE["error"] = exc
            PIPELINE_CACHE_LOCK.notify_all()
        raise

    dt = time.time() - t0
    with PIPELINE_CACHE_LOCK:
        PIPELINE_CACHE["pipeline"] = pipeline
        PIPELINE_CACHE["cache_key"] = cache_key
        PIPELINE_CACHE["state_mtime_ns"] = state_mtime_ns
        PIPELINE_CACHE["building"] = False
        PIPELINE_CACHE["error"] = None
        PIPELINE_CACHE_LOCK.notify_all()
    LOGGER.info("shared demo pipeline ready in %.3fs", dt)
    return pipeline


def _warm_shared_pipeline(reason: str) -> None:
    try:
        LOGGER.info("shared demo pipeline warmup start: %s", reason)
        _get_shared_pipeline()
    except Exception:
        LOGGER.exception("shared demo pipeline warmup failed: %s", reason)


def _schedule_shared_pipeline_warmup(reason: str) -> None:
    threading.Thread(
        target=_warm_shared_pipeline,
        args=(reason,),
        daemon=True,
        name=f"demo-pipeline-warmup-{reason}",
    ).start()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json_safe(value: Any) -> Any:
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


def _job_log_dir(job_id: str) -> Path:
    if job_id.startswith("web-"):
        _, kind, stamp, short_id = job_id.split("-", 3)
        return JOB_LOG_ROOT / f"{stamp}_{kind}_{short_id}"
    return JOB_LOG_ROOT / job_id


def _job_log_path(job_id: str, name: str) -> Path:
    return _job_log_dir(job_id) / name


def _write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_json_safe(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def _append_jsonl_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(_json_safe(payload), ensure_ascii=False))
        f.write("\n")


def _sanitize_job_request(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    data = dict(payload or {})
    cleanup_paths = data.get("cleanup_paths")
    if isinstance(cleanup_paths, list):
        data["cleanup_paths"] = [str(Path(p).name) for p in cleanup_paths]
    return _json_safe(data)


def _make_demo_tool_callback(artifacts: RunArtifacts, sink: List[Dict[str, Any]]) -> Callable[[Dict[str, Any]], None]:
    def _callback(payload: Dict[str, Any]) -> None:
        record = artifacts.record_tool_call(
            tool=str(payload.get("tool") or "tool"),
            action=str(payload.get("action") or "call"),
            input_payload=dict(payload.get("input") or {}),
            output_payload=(dict(payload.get("output") or {}) if isinstance(payload.get("output"), dict) else None),
            error=(str(payload.get("error")) if payload.get("error") else None),
        )
        sink.append(record)

    return _callback


def _make_demo_progress_callback(
    job_id: str,
    artifacts: RunArtifacts,
) -> Callable[[Dict[str, Any]], None]:
    def _callback(payload: Dict[str, Any]) -> None:
        normalized = artifacts.record_progress(payload)
        _append_job_event(
            job_id,
            "progress",
            str(normalized.get("label") or normalized.get("stage") or payload.get("event") or "progress"),
            {"raw": _json_safe(payload), "normalized": normalized},
        )

    return _callback


def _quote_command(parts: List[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts if str(part) != "")


def _request_to_terminal_command(kind: str, request_payload: Optional[Dict[str, Any]]) -> str:
    payload = dict(request_payload or {})
    parts = ["python", "main.py"]
    if kind == "init":
        parts.append("init")
        if payload.get("llm_model"):
            parts.extend(["--model", str(payload["llm_model"])])
        max_rules = payload.get("max_rules")
        if max_rules is not None:
            parts.extend(["--max-rules", str(max_rules)])
        if payload.get("source") == "upload":
            rules_arg = f"<upload:{payload.get('source_label') or 'rules.rules'}>"
        else:
            rules_arg = str(payload.get("rules_path") or payload.get("source_label") or "rules")
        parts.extend(["--rules", rules_arg])
        return _quote_command(parts)

    if kind == "process":
        parts.append("process")
        if payload.get("llm_model"):
            parts.extend(["--model", str(payload["llm_model"])])
        if payload.get("pcap_path"):
            pcap_label = str(payload.get("pcap_label") or "").strip()
            parts.extend(["--pcap", pcap_label or "<upload:pcap_file>"])
        if payload.get("traffic_text"):
            parts.extend(["--traffic-text", str(payload["traffic_text"])])
        attack_pcaps = [str(x) for x in (payload.get("attack_pcaps") or []) if str(x).strip()]
        if attack_pcaps:
            attack_labels = [str(x) for x in (payload.get("attack_labels") or []) if str(x).strip()]
            parts.extend(["--attack-pcaps", ",".join(attack_labels or attack_pcaps)])
        benign_pcaps = [str(x) for x in (payload.get("benign_pcaps") or []) if str(x).strip()]
        if benign_pcaps:
            benign_labels = [str(x) for x in (payload.get("benign_labels") or []) if str(x).strip()]
            parts.extend(["--benign-pcaps", ",".join(benign_labels or benign_pcaps)])
        human_override = payload.get("human_override") or {}
        if isinstance(human_override, dict):
            if human_override.get("intent"):
                parts.extend(["--override-intent", str(human_override["intent"])])
            tactics = human_override.get("tactics") or []
            if tactics:
                parts.extend(["--override-tactics", ",".join(str(x) for x in tactics if str(x).strip())])
            keywords = human_override.get("keywords") or []
            if keywords:
                parts.extend(["--override-keywords", ",".join(str(x) for x in keywords if str(x).strip())])
        return _quote_command(parts)

    return _quote_command(parts)


def _write_latest_job_marker(kind: str, job_id: str, log_dir: Path) -> None:
    marker = {
        "job_id": job_id,
        "kind": kind,
        "log_dir": str(log_dir),
        "updated_at": _now_iso(),
    }
    _write_json_file(JOB_LOG_ROOT / f"latest_{kind}.json", marker)


def _append_job_index(event: str, payload: Dict[str, Any]) -> None:
    record = {"at": _now_iso(), "event": event, **_json_safe(payload)}
    _append_jsonl_file(JOB_LOG_ROOT / "index.jsonl", record)


def _write_job_snapshot(job_id: str) -> None:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        snapshot = {
            "job_id": job["job_id"],
            "kind": job["kind"],
            "source": job.get("source"),
            "status": job["status"],
            "created_at": job["created_at"],
            "updated_at": job["updated_at"],
            "events": list(job.get("events", [])),
            "result": job.get("result"),
            "error": job.get("error"),
            "log_dir": job.get("log_dir"),
            "request": job.get("request"),
            "terminal_command": job.get("terminal_command"),
            "progress": job.get("progress"),
        }
    _write_json_file(_job_log_path(job_id, "snapshot.json"), snapshot)


def _cleanup_files(paths: List[str]) -> None:
    for path in paths:
        try:
            os.unlink(path)
        except OSError:
            pass


def _resolve_app_path(path_value: str) -> Path:
    candidate = Path(path_value).expanduser()
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    return candidate.resolve(strict=False)


def _display_app_path(path_value: str | Path) -> str:
    candidate = _resolve_app_path(str(path_value))
    try:
        return candidate.relative_to(ROOT).as_posix()
    except ValueError:
        return str(candidate)


def _collect_pcap_files(path_str: str) -> List[str]:
    path = Path(path_str)
    if not path.exists() or not path.is_dir():
        return []
    out: List[str] = []
    for item in sorted(path.rglob("*")):
        if item.is_file() and item.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
            out.append(str(item))
    return out


def _trim_jobs_if_needed() -> None:
    if len(JOBS) <= MAX_JOBS:
        return
    removable = [
        (jid, item.get("updated_at_epoch", 0.0))
        for jid, item in JOBS.items()
        if item.get("status") in {"succeeded", "failed"}
    ]
    removable.sort(key=lambda x: x[1])
    while len(JOBS) > MAX_JOBS and removable:
        jid, _ = removable.pop(0)
        JOBS.pop(jid, None)


def _create_job(kind: str, request_payload: Optional[Dict[str, Any]] = None) -> str:
    now_epoch = time.time()
    now_iso = _now_iso()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    short_id = uuid.uuid4().hex[:12]
    job_id = f"web-{kind}-{stamp}-{short_id}"
    log_dir = _job_log_dir(job_id)
    log_dir.mkdir(parents=True, exist_ok=True)
    sanitized_request = _sanitize_job_request(request_payload)
    terminal_command = _request_to_terminal_command(kind, sanitized_request)
    with JOBS_LOCK:
        JOBS[job_id] = {
            "job_id": job_id,
            "kind": kind,
            "source": "web",
            "status": "running",
            "created_at": now_iso,
            "updated_at": now_iso,
            "created_at_epoch": now_epoch,
            "updated_at_epoch": now_epoch,
            "events": [],
            "result": None,
            "error": None,
            "log_dir": str(log_dir),
            "request": sanitized_request,
            "terminal_command": terminal_command,
            "progress": {"stage": "pending", "label": "pending", "percent": 0.0, "at": now_iso},
        }
        _trim_jobs_if_needed()
    _write_json_file(
        _job_log_path(job_id, "meta.json"),
        {
            "job_id": job_id,
            "kind": kind,
            "created_at": now_iso,
            "log_dir": str(log_dir),
        },
    )
    _write_json_file(_job_log_path(job_id, "request.json"), sanitized_request)
    _write_json_file(_job_log_path(job_id, "command.json"), {"terminal_command": terminal_command})
    (_job_log_path(job_id, "command.sh")).write_text(terminal_command + "\n", encoding="utf-8")
    _append_job_index(
        "job_created",
        {
            "job_id": job_id,
            "kind": kind,
            "source": "web",
            "log_dir": str(log_dir),
            "request": sanitized_request,
            "terminal_command": terminal_command,
        },
    )
    _write_latest_job_marker(kind, job_id, log_dir)
    _write_job_snapshot(job_id)
    return job_id


def _append_job_event(job_id: str, event_type: str, message: str, payload: Optional[Dict[str, Any]] = None) -> None:
    now_epoch = time.time()
    now_iso = _now_iso()
    event_record = {
        "at": now_iso,
        "type": event_type,
        "message": message,
        "payload": payload or {},
    }
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        events = job.setdefault("events", [])
        events.append(event_record)
        if len(events) > MAX_JOB_EVENTS:
            del events[: len(events) - MAX_JOB_EVENTS]
        job["updated_at"] = now_iso
        job["updated_at_epoch"] = now_epoch
        if event_type == "progress":
            normalized = ((payload or {}).get("normalized") if isinstance(payload, dict) else None)
            if isinstance(normalized, dict):
                job["progress"] = normalized
    _append_jsonl_file(_job_log_path(job_id, "events.jsonl"), event_record)
    _write_job_snapshot(job_id)


def _finish_job_success(job_id: str, result: Dict[str, Any]) -> None:
    now_epoch = time.time()
    now_iso = _now_iso()
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job["status"] = "succeeded"
        job["result"] = result
        job["error"] = None
        job["updated_at"] = now_iso
        job["updated_at_epoch"] = now_epoch
        job["progress"] = {"stage": "done", "label": "done", "percent": 100.0, "at": now_iso}
        kind = str(job.get("kind") or "")
        log_dir = str(job.get("log_dir") or "")
    _write_json_file(_job_log_path(job_id, "result.json"), result)
    _append_job_index("job_succeeded", {"job_id": job_id, "kind": kind, "log_dir": log_dir})
    _write_job_snapshot(job_id)


def _finish_job_failed(job_id: str, error: str, traceback_text: str = "") -> None:
    now_epoch = time.time()
    now_iso = _now_iso()
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job["status"] = "failed"
        job["error"] = error
        job["updated_at"] = now_iso
        job["updated_at_epoch"] = now_epoch
        job["progress"] = {
            "stage": "failed",
            "label": "failed",
            "percent": float((job.get("progress") or {}).get("percent") or 0.0),
            "at": now_iso,
        }
        kind = str(job.get("kind") or "")
        log_dir = str(job.get("log_dir") or "")
    _write_json_file(
        _job_log_path(job_id, "error.json"),
        {
            "error": error,
            "traceback": traceback_text,
            "failed_at": now_iso,
        },
    )
    _append_job_index("job_failed", {"job_id": job_id, "kind": kind, "log_dir": log_dir, "error": error})
    _write_job_snapshot(job_id)


def _get_job_snapshot(job_id: str) -> Optional[Dict[str, Any]]:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return None
        return {
            "job_id": job["job_id"],
            "kind": job["kind"],
            "status": job["status"],
            "created_at": job["created_at"],
            "updated_at": job["updated_at"],
            "events": list(job.get("events", [])),
            "result": job.get("result"),
            "error": job.get("error"),
            "log_dir": job.get("log_dir"),
            "request": job.get("request"),
            "terminal_command": job.get("terminal_command"),
            "progress": job.get("progress"),
        }


def _load_job_snapshot_from_disk(job_id: str) -> Optional[Dict[str, Any]]:
    snapshot_path = _job_log_path(job_id, "snapshot.json")
    if not snapshot_path.exists():
        return None
    try:
        raw = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    return raw


def _recent_job_snapshots(limit: int = 20) -> List[Dict[str, Any]]:
    snapshots: List[Dict[str, Any]] = []
    if not JOB_LOG_ROOT.exists():
        return snapshots
    for snapshot_path in JOB_LOG_ROOT.glob("*/snapshot.json"):
        try:
            raw = json.loads(snapshot_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue
        raw.setdefault("log_dir", str(snapshot_path.parent))
        snapshots.append(raw)
    snapshots.sort(key=lambda item: str(item.get("updated_at") or item.get("created_at") or ""), reverse=True)
    return snapshots[:limit]


def _parse_max_rules(value: str) -> Optional[int]:
    max_rules_raw = value.strip()
    if not max_rules_raw:
        return None
    try:
        max_rules = int(max_rules_raw)
    except ValueError as exc:
        raise ValueError("max_rules must be an integer") from exc
    if max_rules < 0:
        raise ValueError("max_rules must be >= 0")
    if max_rules == 0:
        return None
    return max_rules


def _resolve_init_request() -> Dict[str, Any]:
    rules_file = request.files.get("rules_file")
    llm_model = request.form.get("model") or None
    max_rules = _parse_max_rules(request.form.get("max_rules") or "")

    tmp_paths: List[str] = []
    source: str
    source_label: str
    rules_path: str

    if rules_file is not None and rules_file.filename:
        suffix = Path(rules_file.filename).suffix or ".rules"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(rules_file.read())
            tmp_path = tmp.name
            tmp_paths.append(tmp_path)
        source = "upload"
        source_label = rules_file.filename
        rules_path = tmp_path
    else:
        default_rules_path = (request.form.get("default_rules_path") or "").strip()
        resolved_rules_path = _resolve_app_path(
            default_rules_path or os.getenv("MA_MEMIDS_DEFAULT_RULES_PATH", str(DEFAULT_RULES_PATH))
        )
        rules_path = str(resolved_rules_path)
        source = "default_path"
        source_label = _display_app_path(resolved_rules_path)
        if not resolved_rules_path.exists():
            raise ValueError(f"default rules path not found: {source_label}")

    return {
        "rules_path": rules_path,
        "source": source,
        "source_label": source_label,
        "max_rules": max_rules,
        "resume": True,
        "llm_model": llm_model,
        "cleanup_paths": tmp_paths,
    }


def _resolve_process_request() -> Dict[str, Any]:
    llm_model = request.form.get("model") or None
    traffic_text = (request.form.get("traffic_text") or "").strip() or None

    override_intent = (request.form.get("override_intent") or "").strip()
    override_tactics = (request.form.get("override_tactics") or "").strip()
    override_keywords = (request.form.get("override_keywords") or "").strip()

    human_override: Dict[str, Any] = {}
    if override_intent:
        human_override["intent"] = override_intent
    if override_tactics:
        human_override["tactics"] = [x.strip() for x in override_tactics.split(",") if x.strip()]
    if override_keywords:
        human_override["keywords"] = [x.strip() for x in override_keywords.split(",") if x.strip()]

    pcap_file = request.files.get("pcap_file")
    attack_files = [f for f in request.files.getlist("attack_pcap") if f and f.filename]
    benign_files = [f for f in request.files.getlist("benign_pcap") if f and f.filename]
    default_attack_dir = os.getenv("MA_MEMIDS_DEFAULT_ATTACK_SANDBOX_DIR", str(DEFAULT_ATTACK_SANDBOX_DIR))
    default_benign_dir = os.getenv("MA_MEMIDS_DEFAULT_BENIGN_SANDBOX_DIR", str(DEFAULT_BENIGN_SANDBOX_DIR))

    upload_paths: List[str] = []

    def _save_upload(file_obj, default_suffix: str = ".pcap") -> Optional[str]:
        if file_obj is None or not file_obj.filename:
            return None
        suffix = Path(file_obj.filename).suffix or default_suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(file_obj.read())
            path = tmp.name
            upload_paths.append(path)
            return path

    def _save_upload_many(files: List[Any], default_suffix: str = ".pcap") -> List[str]:
        out: List[str] = []
        for file_obj in files:
            path = _save_upload(file_obj, default_suffix=default_suffix)
            if path:
                out.append(path)
        return out

    pcap_path = _save_upload(pcap_file)
    attack_paths = _save_upload_many(attack_files)
    benign_paths = _save_upload_many(benign_files)
    pcap_label = (pcap_file.filename if pcap_file is not None and pcap_file.filename else "")
    attack_labels = [f.filename for f in attack_files if f.filename]
    benign_labels = [f.filename for f in benign_files if f.filename]

    if not pcap_path and not traffic_text:
        _cleanup_files(upload_paths)
        raise ValueError("Either pcap_file or traffic_text is required")

    attack_pcaps: List[str] = []
    benign_pcaps: List[str] = []
    attack_source = "empty"
    benign_source = "empty"
    default_attack_pcaps = _collect_pcap_files(default_attack_dir)
    default_benign_pcaps = _collect_pcap_files(default_benign_dir)

    if attack_paths:
        attack_pcaps.extend(attack_paths)
        attack_source = "upload"
    elif default_attack_pcaps:
        attack_pcaps.extend(default_attack_pcaps)
        attack_source = "default_sandbox_dir"
    elif pcap_path:
        attack_pcaps.append(pcap_path)
        attack_source = "main_pcap_fallback"

    if benign_paths:
        benign_pcaps.extend(benign_paths)
        benign_source = "upload"
    elif default_benign_pcaps:
        benign_pcaps.extend(default_benign_pcaps)
        benign_source = "default_sandbox_dir"

    return {
        "llm_model": llm_model,
        "traffic_text": traffic_text,
        "pcap_path": pcap_path,
        "pcap_label": pcap_label,
        "attack_pcaps": attack_pcaps,
        "attack_labels": attack_labels,
        "benign_pcaps": benign_pcaps,
        "benign_labels": benign_labels,
        "sandbox_config": {
            "attack_source": attack_source,
            "attack_count": len(attack_pcaps),
            "benign_source": benign_source,
            "benign_count": len(benign_pcaps),
            "default_attack_dir": default_attack_dir,
            "default_benign_dir": default_benign_dir,
        },
        "human_override": (human_override or None),
        "cleanup_paths": upload_paths,
    }


def _run_init_payload(
    init_args: Dict[str, Any],
    artifacts: RunArtifacts,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    tool_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    llm_calls: List[Dict[str, Any]] = []
    tool_calls: List[Dict[str, Any]] = []
    pipeline = create_pipeline_with_trace(
        artifacts,
        llm_calls,
        llm_model=init_args["llm_model"],
        progress_callback=progress_callback,
        tool_callback=(tool_callback or _make_demo_tool_callback(artifacts, tool_calls)),
    )
    if progress_callback is not None:
        progress_callback({"event": "pipeline_build_ready"})
    count = pipeline.initialize_from_rules_file(
        init_args["rules_path"],
        max_rules=init_args["max_rules"],
        progress_callback=progress_callback,
        resume=bool(init_args.get("resume", True)),
    )
    _invalidate_shared_pipeline("init_complete")
    return {
        "ok": True,
        "initialized_rules": count,
        "init_source": init_args["source"],
        "init_source_label": init_args["source_label"],
        "max_rules": init_args["max_rules"],
        "resume": bool(init_args.get("resume", True)),
        "stats": pipeline.stats(),
        "llm_calls": llm_calls,
        "tool_calls": tool_calls,
    }


def _run_process_payload(
    process_args: Dict[str, Any],
    artifacts: RunArtifacts,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    tool_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    llm_calls: List[Dict[str, Any]] = []
    tool_calls: List[Dict[str, Any]] = []
    pipeline = create_pipeline_with_trace(
        artifacts,
        llm_calls,
        llm_model=process_args["llm_model"],
        progress_callback=progress_callback,
        tool_callback=(tool_callback or _make_demo_tool_callback(artifacts, tool_calls)),
    )
    if progress_callback is not None:
        progress_callback({"event": "pipeline_build_ready"})
    outcome = pipeline.process_unmatched_traffic_with_trace(
        pcap_path=process_args["pcap_path"],
        traffic_text=process_args["traffic_text"],
        attack_pcaps=process_args["attack_pcaps"],
        benign_pcaps=process_args["benign_pcaps"],
        human_override=process_args["human_override"],
        progress_callback=progress_callback,
    )
    _invalidate_shared_pipeline("process_complete")
    trace_steps = (((outcome or {}).get("trace") or {}).get("steps") or [])
    resolved_step = next((s for s in trace_steps if s.get("name") == "sandbox_dataset_resolved"), None)
    label_step = next((s for s in trace_steps if s.get("name") == "analyzed_pcap_labeling"), None)
    return {
        "ok": True,
        "outcome": outcome,
        "llm_calls": llm_calls,
        "tool_calls": tool_calls,
        "stats": pipeline.stats(),
        "sandbox_config": {
            "input": process_args.get("sandbox_config", {}),
            "resolved": ((resolved_step or {}).get("output") or {}),
            "analyzed_pcap_labeling": ((label_step or {}).get("output") or {}),
        },
    }


def _parse_int(value: Optional[str], default: int, min_value: int, max_value: int) -> int:
    if value is None or value.strip() == "":
        return default
    parsed = int(value)
    if parsed < min_value:
        return min_value
    if parsed > max_value:
        return max_value
    return parsed


def _note_preview(note: Any) -> Dict[str, Any]:
    if isinstance(note, dict):
        note_raw = note
    else:
        note_raw = note.to_dict()
    content = str(note_raw.get("content") or "")
    links_raw = note_raw.get("links") or []
    links_preview = []
    for raw in links_raw:
        if not isinstance(raw, dict):
            continue
        links_preview.append(
            {
                "target_id": raw.get("target_id"),
                "link_type": raw.get("link_type"),
                "weight": round(float(raw.get("weight", 0.0)), 4),
            }
        )
    links_preview.sort(key=lambda item: (-item["weight"], str(item["target_id"] or ""), str(item["link_type"] or "")))
    return {
        "note_id": note_raw.get("note_id"),
        "note_type": note_raw.get("note_type"),
        "sid": note_raw.get("sid"),
        "version": note_raw.get("version"),
        "timestamp": note_raw.get("timestamp"),
        "intent": note_raw.get("intent"),
        "protocol": note_raw.get("protocol"),
        "keywords": (note_raw.get("keywords") or [])[:12],
        "tactics": (note_raw.get("tactics") or [])[:8],
        "link_count": len(links_raw),
        "links_preview": links_preview[:12],
        "content_preview": content[:240],
    }


def _note_matches_keyword(note: Any, keyword: str) -> bool:
    if not keyword:
        return True
    payload = note.to_dict() if hasattr(note, "to_dict") else dict(note)
    haystacks: List[str] = [
        str(payload.get("note_id") or ""),
        str(payload.get("note_type") or ""),
        str(payload.get("intent") or ""),
        str(payload.get("content") or ""),
        str(payload.get("protocol") or ""),
    ]
    haystacks.extend(str(x) for x in (payload.get("keywords") or []))
    haystacks.extend(str(x) for x in (payload.get("tactics") or []))
    return keyword in "\n".join(haystacks).lower()


def _graph_node_payload(note: Any, *, is_center: bool = False) -> Dict[str, Any]:
    payload = note.to_dict() if hasattr(note, "to_dict") else dict(note)
    sid = payload.get("sid")
    note_id = str(payload.get("note_id") or "")
    note_type = str(payload.get("note_type") or "")
    label = f"SID {sid}" if sid is not None else note_id
    subtitle_parts = [note_type]
    if payload.get("protocol"):
        subtitle_parts.append(str(payload["protocol"]))
    return {
        "id": note_id,
        "label": label,
        "subtitle": " · ".join(part for part in subtitle_parts if part),
        "note_id": note_id,
        "note_type": note_type,
        "intent": str(payload.get("intent") or ""),
        "protocol": payload.get("protocol"),
        "sid": sid,
        "keywords": list(payload.get("keywords") or [])[:10],
        "tactics": list(payload.get("tactics") or [])[:8],
        "timestamp": payload.get("timestamp"),
        "link_count": len(payload.get("links") or []),
        "links_preview": _note_preview(payload).get("links_preview", []),
        "content_preview": str(payload.get("content") or "")[:180],
        "is_center": is_center,
    }


app = Flask(__name__, static_folder=str(DEMO_DIR), static_url_path="/demo")


@app.get("/")
def root() -> Any:
    return send_from_directory(str(DEMO_DIR), "index.html")


@app.get("/api/status")
def api_status() -> Any:
    graph, raw = _get_state_snapshot()
    default_attack_dir = os.getenv("MA_MEMIDS_DEFAULT_ATTACK_SANDBOX_DIR", str(DEFAULT_ATTACK_SANDBOX_DIR))
    default_benign_dir = os.getenv("MA_MEMIDS_DEFAULT_BENIGN_SANDBOX_DIR", str(DEFAULT_BENIGN_SANDBOX_DIR))
    default_attack_pcaps = _collect_pcap_files(default_attack_dir)
    default_benign_pcaps = _collect_pcap_files(default_benign_dir)
    with JOBS_LOCK:
        running_jobs = sum(1 for item in JOBS.values() if item.get("status") == "running")
    return jsonify(
        {
            "ok": True,
            "stats": _state_stats_payload(graph, raw),
            "state_path": str(STATE_PATH),
            "default_rules_path": _display_app_path(
                os.getenv("MA_MEMIDS_DEFAULT_RULES_PATH", str(DEFAULT_RULES_PATH))
            ),
            "running_jobs": running_jobs,
            "default_sandbox": {
                "attack_dir": default_attack_dir,
                "attack_count": len(default_attack_pcaps),
                "benign_dir": default_benign_dir,
                "benign_count": len(default_benign_pcaps),
            },
        }
    )


@app.get("/api/graph/summary")
def api_graph_summary() -> Any:
    graph, raw = _get_state_snapshot()
    notes = graph.all_notes()
    rule_notes = [n for n in notes if n.note_type == "rule"]
    total_links = sum(len(n.links) for n in notes)
    latest_notes = sorted(notes, key=lambda n: n.timestamp, reverse=True)[:10]
    return jsonify(
        {
            "ok": True,
            "summary": {
                "total_notes": len(notes),
                "rule_notes": len(rule_notes),
                "traffic_notes": 0,
                "total_links": total_links,
                "state_path": str(STATE_PATH),
                "knowledge": _state_stats_payload(graph, raw).get("knowledge"),
            },
            "latest_notes": [_note_preview(n) for n in latest_notes],
        }
    )


@app.get("/api/graph/view")
def api_graph_view() -> Any:
    try:
        limit = _parse_int(request.args.get("limit"), default=80, min_value=1, max_value=240)
    except ValueError:
        return jsonify({"ok": False, "error": "limit must be integer"}), 400

    note_type = (request.args.get("note_type") or "").strip().lower()
    if note_type not in {"", "rule"}:
        return jsonify({"ok": False, "error": "note_type must be one of: rule"}), 400
    keyword = (request.args.get("q") or "").strip().lower()
    center_note_id = (request.args.get("note_id") or "").strip()

    graph, _ = _get_state_snapshot()
    notes = sorted(graph.all_notes(), key=lambda n: n.timestamp, reverse=True)

    def _match_type(note: Any) -> bool:
        return note_type in {"", getattr(note, "note_type", "")}

    filtered_notes = [n for n in notes if _match_type(n) and _note_matches_keyword(n, keyword)]

    center_note = graph.get(center_note_id) if center_note_id else None
    if center_note_id and center_note is None:
        return jsonify({"ok": False, "error": f"note not found: {center_note_id}"}), 404

    selected_notes: List[Any] = []
    if center_note is not None:
        selected_notes.append(center_note)
        neighbor_ids = {link.target_id for link in center_note.links}
        for other in notes:
            if other.note_id == center_note.note_id:
                continue
            if any(link.target_id == center_note.note_id for link in other.links):
                neighbor_ids.add(other.note_id)

        neighbors = []
        for nid in neighbor_ids:
            target = graph.get(nid)
            if target is None:
                continue
            if note_type and target.note_type != note_type:
                continue
            if keyword and not _note_matches_keyword(target, keyword):
                continue
            neighbors.append(target)
        neighbors = sorted(neighbors, key=lambda n: n.timestamp, reverse=True)
        for item in neighbors:
            if len(selected_notes) >= limit:
                break
            selected_notes.append(item)
        view_mode = "focus"
        truncated = len(neighbors) + 1 > len(selected_notes)
    else:
        selected_notes = filtered_notes[:limit]
        view_mode = "filtered"
        truncated = len(filtered_notes) > len(selected_notes)

    selected_ids = {note.note_id for note in selected_notes}
    edge_map: Dict[tuple[str, str], Dict[str, Any]] = {}
    for note in selected_notes:
        for link in note.links:
            if link.target_id not in selected_ids:
                continue
            pair = tuple(sorted((note.note_id, link.target_id)))
            entry = edge_map.get(pair)
            if entry is None:
                entry = {
                    "source": pair[0],
                    "target": pair[1],
                    "weight": 0.0,
                    "primary_type": "related",
                    "link_types": set(),
                }
                edge_map[pair] = entry
            entry["link_types"].add(link.link_type or "related")
            if float(link.weight) >= float(entry["weight"]):
                entry["weight"] = float(link.weight)
                entry["primary_type"] = link.link_type or "related"

    edges: List[Dict[str, Any]] = []
    link_type_counts: Dict[str, int] = {}
    degree: Dict[str, int] = {note.note_id: 0 for note in selected_notes}
    for item in edge_map.values():
        edge = {
            "source": item["source"],
            "target": item["target"],
            "weight": round(float(item["weight"]), 4),
            "link_type": item["primary_type"],
            "link_types": sorted(item["link_types"]),
        }
        edges.append(edge)
        link_type_counts[edge["link_type"]] = link_type_counts.get(edge["link_type"], 0) + 1
        degree[edge["source"]] = degree.get(edge["source"], 0) + 1
        degree[edge["target"]] = degree.get(edge["target"], 0) + 1
    edges.sort(key=lambda item: (item["source"], item["target"], item["link_type"]))

    nodes: List[Dict[str, Any]] = []
    type_counts: Dict[str, int] = {}
    for note in selected_notes:
        node = _graph_node_payload(note, is_center=bool(center_note and note.note_id == center_note.note_id))
        node["degree"] = degree.get(note.note_id, 0)
        node["radius"] = 20 if node["is_center"] else 12 + min(8, node["degree"] * 1.4)
        nodes.append(node)
        ntype = note.note_type
        type_counts[ntype] = type_counts.get(ntype, 0) + 1

    return jsonify(
        {
            "ok": True,
            "filters": {
                "note_type": note_type or "all",
                "q": keyword,
                "note_id": center_note_id or None,
                "limit": limit,
            },
            "graph": {
                "mode": view_mode,
                "nodes": nodes,
                "edges": edges,
                "stats": {
                    "rendered_nodes": len(nodes),
                    "rendered_edges": len(edges),
                    "matching_notes": len(filtered_notes),
                    "type_counts": type_counts,
                    "link_type_counts": link_type_counts,
                    "center_note": (_note_preview(center_note) if center_note is not None else None),
                    "truncated": truncated,
                },
            },
        }
    )


@app.get("/api/graph/notes")
def api_graph_notes() -> Any:
    try:
        limit = _parse_int(request.args.get("limit"), default=50, min_value=1, max_value=500)
        offset = _parse_int(request.args.get("offset"), default=0, min_value=0, max_value=100000)
    except ValueError:
        return jsonify({"ok": False, "error": "limit/offset must be integer"}), 400

    note_type = (request.args.get("note_type") or "").strip().lower()
    keyword = (request.args.get("q") or "").strip().lower()

    graph, _ = _get_state_snapshot()
    notes = graph.all_notes()

    if note_type not in {"", "rule"}:
        return jsonify({"ok": False, "error": "note_type must be one of: rule"}), 400

    if note_type == "rule":
        notes = [n for n in notes if n.note_type == note_type]

    if keyword:
        notes = [
            n
            for n in notes
            if (
                keyword in n.note_id.lower()
                or keyword in (n.intent or "").lower()
                or keyword in (n.content or "").lower()
            )
        ]

    notes = sorted(notes, key=lambda n: n.timestamp, reverse=True)
    total = len(notes)
    page = notes[offset : offset + limit]
    return jsonify(
        {
            "ok": True,
            "pagination": {
                "offset": offset,
                "limit": limit,
                "total": total,
            },
            "filters": {
                "note_type": note_type or "all",
                "q": keyword,
            },
            "notes": [_note_preview(n) for n in page],
        }
    )


@app.get("/api/graph/note/<note_id>")
def api_graph_note_detail(note_id: str) -> Any:
    graph, _ = _get_state_snapshot()
    note = graph.get(note_id)
    if note is None:
        return jsonify({"ok": False, "error": f"note not found: {note_id}"}), 404
    return jsonify({"ok": True, "note": note.to_dict()})


@app.post("/api/graph/clear")
def api_graph_clear() -> Any:
    data = request.get_json(silent=True) or {}
    confirm = str(data.get("confirm") or request.form.get("confirm") or "").strip().upper()
    if confirm != "CLEAR":
        return jsonify({"ok": False, "error": "confirmation required: set confirm=CLEAR"}), 400

    graph, raw = _get_state_snapshot()
    before = _state_stats_payload(graph, raw)

    backup_path = None
    if STATE_PATH.exists():
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = STATE_PATH.with_name(f"state.backup.{ts}.json")
        shutil.copy2(STATE_PATH, backup_file)
        backup_path = str(backup_file)

    graph.notes.clear()
    state_payload = dict(raw) if isinstance(raw, dict) else {}
    state_payload["graph"] = graph.to_dict()
    STATE_PATH.write_text(json.dumps(state_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    _invalidate_shared_pipeline("graph_clear")
    after = _state_stats_payload(graph, state_payload)

    return jsonify(
        {
            "ok": True,
            "message": "graph cleared",
            "backup_path": backup_path,
            "before": before,
            "after": after,
        }
    )


@app.post("/api/init")
def api_init() -> Any:
    try:
        init_args = _resolve_init_request()
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    try:
        log_dir = JOB_LOG_ROOT / f"adhoc_init_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        artifacts = RunArtifacts(log_dir, kind="init", source="web")
        progress_callback = lambda event: artifacts.record_progress(event)
        payload = _run_init_payload(init_args, artifacts, progress_callback=progress_callback)
        artifacts.finalize(status="succeeded", result=payload)
        return jsonify(payload)
    except Exception as exc:
        try:
            artifacts.finalize(status="failed", error=f"{type(exc).__name__}: {exc}")  # type: ignore[name-defined]
        except Exception:
            pass
        return jsonify({"ok": False, "error": f"init failed: {type(exc).__name__}: {exc}"}), 500
    finally:
        _cleanup_files(init_args["cleanup_paths"])


@app.post("/api/process")
def api_process() -> Any:
    try:
        process_args = _resolve_process_request()
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    try:
        log_dir = JOB_LOG_ROOT / f"adhoc_process_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        artifacts = RunArtifacts(log_dir, kind="process", source="web")
        progress_callback = lambda event: artifacts.record_progress(event)
        payload = _run_process_payload(process_args, artifacts, progress_callback=progress_callback)
        artifacts.finalize(status="succeeded", result=payload)
        return jsonify(payload)
    except Exception as exc:
        try:
            artifacts.finalize(status="failed", error=f"{type(exc).__name__}: {exc}")  # type: ignore[name-defined]
        except Exception:
            pass
        return jsonify({"ok": False, "error": f"process failed: {type(exc).__name__}: {exc}"}), 500
    finally:
        _cleanup_files(process_args["cleanup_paths"])


@app.post("/api/init_async")
def api_init_async() -> Any:
    try:
        init_args = _resolve_init_request()
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    job_id = _create_job("init", request_payload=init_args)
    log_dir = str(_job_log_dir(job_id))
    _append_job_event(
        job_id,
        "status",
        "init_task_created",
        {
            "source": init_args["source"],
            "source_label": init_args["source_label"],
            "max_rules": init_args["max_rules"],
            "job_log_dir": log_dir,
        },
    )

    def _worker() -> None:
        artifacts = RunArtifacts(log_dir, kind="init", source="web", job_id=job_id)
        progress_callback = _make_demo_progress_callback(job_id, artifacts)
        try:
            progress_callback({"event": "pipeline_build_start"})
            payload = _run_init_payload(
                init_args,
                artifacts,
                progress_callback=progress_callback,
            )
            progress_callback({"event": "job_done"})
            _append_job_event(job_id, "status", "init_task_done", {"initialized_rules": payload["initialized_rules"]})
            artifacts.finalize(status="succeeded", result=payload)
            _finish_job_success(job_id, payload)
        except Exception as exc:
            message = f"init failed: {type(exc).__name__}: {exc}"
            traceback_text = traceback.format_exc()
            progress_callback({"event": "job_failed"})
            artifacts.finalize(status="failed", error=message)
            _append_job_event(job_id, "error", "init_task_failed", {"error": message, "traceback": traceback_text})
            _finish_job_failed(job_id, message, traceback_text=traceback_text)
        finally:
            _cleanup_files(init_args["cleanup_paths"])

    threading.Thread(target=_worker, daemon=True, name=f"demo-init-{job_id}").start()
    return jsonify({"ok": True, "job_id": job_id, "job_log_dir": log_dir})


@app.post("/api/process_async")
def api_process_async() -> Any:
    try:
        process_args = _resolve_process_request()
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    job_id = _create_job("process", request_payload=process_args)
    log_dir = str(_job_log_dir(job_id))
    _append_job_event(
        job_id,
        "status",
        "process_task_created",
        {
            "has_traffic_text": bool(process_args["traffic_text"]),
            "pcap_path": process_args["pcap_path"],
            "sandbox_config": process_args.get("sandbox_config", {}),
            "attack_preview": process_args["attack_pcaps"][:3],
            "benign_preview": process_args["benign_pcaps"][:3],
            "job_log_dir": log_dir,
        },
    )

    def _worker() -> None:
        artifacts = RunArtifacts(log_dir, kind="process", source="web", job_id=job_id)
        progress_callback = _make_demo_progress_callback(job_id, artifacts)
        try:
            progress_callback({"event": "pipeline_build_start"})
            payload = _run_process_payload(
                process_args,
                artifacts,
                progress_callback=progress_callback,
            )
            progress_callback({"event": "job_done"})
            _append_job_event(
                job_id,
                "status",
                "process_task_done",
                {
                    "success": payload["outcome"]["result"]["success"],
                    "mode": payload["outcome"]["result"]["mode"],
                },
            )
            artifacts.finalize(status="succeeded", result=payload)
            _finish_job_success(job_id, payload)
        except Exception as exc:
            message = f"process failed: {type(exc).__name__}: {exc}"
            traceback_text = traceback.format_exc()
            progress_callback({"event": "job_failed"})
            artifacts.finalize(status="failed", error=message)
            _append_job_event(job_id, "error", "process_task_failed", {"error": message, "traceback": traceback_text})
            _finish_job_failed(job_id, message, traceback_text=traceback_text)
        finally:
            _cleanup_files(process_args["cleanup_paths"])

    threading.Thread(target=_worker, daemon=True, name=f"demo-process-{job_id}").start()
    return jsonify({"ok": True, "job_id": job_id, "job_log_dir": log_dir})


@app.get("/api/job/<job_id>")
def api_job(job_id: str) -> Any:
    snapshot = _get_job_snapshot(job_id)
    if snapshot is None:
        snapshot = _load_job_snapshot_from_disk(job_id)
    if snapshot is None:
        return jsonify({"ok": False, "error": f"job not found: {job_id}"}), 404
    return jsonify({"ok": True, "job": snapshot})


@app.get("/api/jobs/recent")
def api_jobs_recent() -> Any:
    try:
        limit = _parse_int(request.args.get("limit"), default=20, min_value=1, max_value=100)
    except ValueError:
        return jsonify({"ok": False, "error": "limit must be integer"}), 400

    jobs = []
    for item in _recent_job_snapshots(limit):
        preview = {
            "job_id": item.get("job_id"),
            "kind": item.get("kind"),
            "source": item.get("source") or "unknown",
            "status": item.get("status"),
            "created_at": item.get("created_at"),
            "updated_at": item.get("updated_at"),
            "log_dir": item.get("log_dir"),
            "terminal_command": item.get("terminal_command"),
            "error": item.get("error"),
            "request": item.get("request"),
            "result": item.get("result"),
            "progress": item.get("progress"),
            "event_count": len(item.get("events") or []),
            "events_tail": (item.get("events") or [])[-10:],
        }
        jobs.append(preview)
    return jsonify({"ok": True, "jobs": jobs})


if __name__ == "__main__":
    host = os.getenv("MA_MEMIDS_DEMO_HOST", "127.0.0.1")
    port = int(os.getenv("MA_MEMIDS_DEMO_PORT", "8090"))
    LOGGER.info("starting flask dev server host=%s port=%s", host, port)
    try:
        app.run(host=host, port=port, debug=False)
        LOGGER.warning("flask app.run returned unexpectedly")
    except SystemExit as exc:
        LOGGER.error("demo_server SystemExit code=%s", exc.code, exc_info=True)
        raise
    except BaseException:
        LOGGER.exception("demo_server fatal error during app.run")
        raise
