#!/usr/bin/env python3
from __future__ import annotations

import atexit
import json
import logging
import os
import shutil
import sys
import tempfile
import threading
import time
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


ROOT = Path(__file__).resolve().parent
DEMO_DIR = ROOT / "demo"
STATE_PATH = ROOT / "memory" / "state.json"
LOG_PATH = ROOT / "memory" / "demo_server.log"
DEFAULT_RULES_PATH = ROOT / "rules"
DEFAULT_SANDBOX_ROOT = ROOT / "sandbox_samples"
DEFAULT_ATTACK_SANDBOX_DIR = DEFAULT_SANDBOX_ROOT / "attack"
DEFAULT_BENIGN_SANDBOX_DIR = DEFAULT_SANDBOX_ROOT / "benign"
DEFAULT_KNOWLEDGE_CACHE_DIR = ROOT / "memory" / "knowledge_cache"

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


class TracingLLMClient(BaseLLMClient):
    def __init__(self, inner: BaseLLMClient, sink: List[Dict[str, Any]]):
        self.inner = inner
        self.sink = sink

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        t0 = time.time()
        response = self.inner.chat(messages, temperature=temperature)
        dt = time.time() - t0
        self.sink.append(
            {
                "model": self.inner.model_name(),
                "temperature": temperature,
                "latency_s": round(dt, 3),
                "messages": messages,
                "response": response,
            }
        )
        return response

    def model_name(self) -> str:
        return self.inner.model_name()


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
    )


def create_pipeline_with_trace(llm_calls: List[Dict[str, Any]], llm_model: Optional[str] = None) -> MAMemIDSPipeline:
    base_client = create_llm_client(model=llm_model)
    tracing_client = TracingLLMClient(base_client, llm_calls)
    return _build_pipeline(llm_client=tracing_client, context="demo pipeline")


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
    return {
        "total_notes": len(notes),
        "rule_notes": len(rule_notes),
        "traffic_notes": 0,
        "llm_model": (os.getenv("LLM_MODEL") or "gpt-4.1").strip() or "gpt-4.1",
        "embedding": embedding if isinstance(embedding, dict) else {},
        "knowledge": {
            "cache_dir": str(_resolve_app_path(os.getenv("MA_MEMIDS_KNOWLEDGE_CACHE_DIR", str(DEFAULT_KNOWLEDGE_CACHE_DIR)))),
            "sources": load_knowledge_source_registry(
                _resolve_app_path(os.getenv("MA_MEMIDS_KNOWLEDGE_CACHE_DIR", str(DEFAULT_KNOWLEDGE_CACHE_DIR)))
            ),
        },
        "thresholds": graph.thresholds.__dict__,
        "graph_index": graph.index_stats(),
        "sandbox_baseline": baseline if isinstance(baseline, dict) else {},
    }


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


def _create_job(kind: str) -> str:
    now_epoch = time.time()
    now_iso = _now_iso()
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "job_id": job_id,
            "kind": kind,
            "status": "running",
            "created_at": now_iso,
            "updated_at": now_iso,
            "created_at_epoch": now_epoch,
            "updated_at_epoch": now_epoch,
            "events": [],
            "result": None,
            "error": None,
        }
        _trim_jobs_if_needed()
    return job_id


def _append_job_event(job_id: str, event_type: str, message: str, payload: Optional[Dict[str, Any]] = None) -> None:
    now_epoch = time.time()
    now_iso = _now_iso()
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        events = job.setdefault("events", [])
        events.append(
            {
                "at": now_iso,
                "type": event_type,
                "message": message,
                "payload": payload or {},
            }
        )
        if len(events) > MAX_JOB_EVENTS:
            del events[: len(events) - MAX_JOB_EVENTS]
        job["updated_at"] = now_iso
        job["updated_at_epoch"] = now_epoch


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


def _finish_job_failed(job_id: str, error: str) -> None:
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
        }


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
        "attack_pcaps": attack_pcaps,
        "benign_pcaps": benign_pcaps,
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
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    llm_calls: List[Dict[str, Any]] = []
    pipeline = create_pipeline_with_trace(llm_calls, llm_model=init_args["llm_model"])
    count = pipeline.initialize_from_rules_file(
        init_args["rules_path"],
        max_rules=init_args["max_rules"],
        progress_callback=progress_callback,
    )
    _invalidate_shared_pipeline("init_complete")
    return {
        "ok": True,
        "initialized_rules": count,
        "init_source": init_args["source"],
        "init_source_label": init_args["source_label"],
        "max_rules": init_args["max_rules"],
        "stats": pipeline.stats(),
        "llm_calls": llm_calls,
    }


def _run_process_payload(
    process_args: Dict[str, Any],
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    llm_calls: List[Dict[str, Any]] = []
    pipeline = create_pipeline_with_trace(llm_calls, llm_model=process_args["llm_model"])
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
    graph, _ = _get_state_snapshot()
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
        payload = _run_init_payload(init_args)
        return jsonify(payload)
    except Exception as exc:
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
        payload = _run_process_payload(process_args)
        return jsonify(payload)
    except Exception as exc:
        return jsonify({"ok": False, "error": f"process failed: {type(exc).__name__}: {exc}"}), 500
    finally:
        _cleanup_files(process_args["cleanup_paths"])


@app.post("/api/init_async")
def api_init_async() -> Any:
    try:
        init_args = _resolve_init_request()
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    job_id = _create_job("init")
    _append_job_event(
        job_id,
        "status",
        "init_task_created",
        {
            "source": init_args["source"],
            "source_label": init_args["source_label"],
            "max_rules": init_args["max_rules"],
        },
    )

    def _worker() -> None:
        try:
            payload = _run_init_payload(
                init_args,
                progress_callback=lambda event: _append_job_event(
                    job_id,
                    "progress",
                    str(event.get("event") or "progress"),
                    event,
                ),
            )
            _append_job_event(job_id, "status", "init_task_done", {"initialized_rules": payload["initialized_rules"]})
            _finish_job_success(job_id, payload)
        except Exception as exc:
            message = f"init failed: {type(exc).__name__}: {exc}"
            _append_job_event(job_id, "error", "init_task_failed", {"error": message})
            _finish_job_failed(job_id, message)
        finally:
            _cleanup_files(init_args["cleanup_paths"])

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id})


@app.post("/api/process_async")
def api_process_async() -> Any:
    try:
        process_args = _resolve_process_request()
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    job_id = _create_job("process")
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
        },
    )

    def _worker() -> None:
        try:
            payload = _run_process_payload(
                process_args,
                progress_callback=lambda event: _append_job_event(
                    job_id,
                    "progress",
                    str(event.get("event") or "progress"),
                    event,
                ),
            )
            _append_job_event(
                job_id,
                "status",
                "process_task_done",
                {
                    "success": payload["outcome"]["result"]["success"],
                    "mode": payload["outcome"]["result"]["mode"],
                },
            )
            _finish_job_success(job_id, payload)
        except Exception as exc:
            message = f"process failed: {type(exc).__name__}: {exc}"
            _append_job_event(job_id, "error", "process_task_failed", {"error": message})
            _finish_job_failed(job_id, message)
        finally:
            _cleanup_files(process_args["cleanup_paths"])

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id})


@app.get("/api/job/<job_id>")
def api_job(job_id: str) -> Any:
    snapshot = _get_job_snapshot(job_id)
    if snapshot is None:
        return jsonify({"ok": False, "error": f"job not found: {job_id}"}), 404
    return jsonify({"ok": True, "job": snapshot})


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
