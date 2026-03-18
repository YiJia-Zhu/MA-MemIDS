#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

from ma_memids.llm_client import BaseLLMClient, create_llm_client
from ma_memids.pipeline import MAMemIDSPipeline


ROOT = Path(__file__).resolve().parent
DEMO_DIR = ROOT / "demo"
STATE_PATH = ROOT / "memory" / "state.json"
DEFAULT_RULES_PATH = ROOT / "rules"
DEFAULT_SANDBOX_ROOT = ROOT / "sandbox_samples"
DEFAULT_ATTACK_SANDBOX_DIR = DEFAULT_SANDBOX_ROOT / "attack"
DEFAULT_BENIGN_SANDBOX_DIR = DEFAULT_SANDBOX_ROOT / "benign"

MAX_JOB_EVENTS = 1200
MAX_JOBS = 120

JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()

load_dotenv()


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


def create_pipeline_with_trace(llm_calls: List[Dict[str, Any]], llm_model: Optional[str] = None) -> MAMemIDSPipeline:
    base_client = create_llm_client(model=llm_model)
    tracing_client = TracingLLMClient(base_client, llm_calls)
    return MAMemIDSPipeline(
        state_path=str(STATE_PATH),
        llm_client=tracing_client,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _cleanup_files(paths: List[str]) -> None:
    for path in paths:
        try:
            os.unlink(path)
        except OSError:
            pass


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
        rules_path = default_rules_path or os.getenv("MA_MEMIDS_DEFAULT_RULES_PATH", str(DEFAULT_RULES_PATH))
        source = "default_path"
        source_label = rules_path
        if not Path(rules_path).exists():
            raise ValueError(f"default rules path not found: {rules_path}")

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
        "link_count": len(note_raw.get("links") or []),
        "content_preview": content[:240],
    }


app = Flask(__name__, static_folder=str(DEMO_DIR), static_url_path="/demo")


@app.get("/")
def root() -> Any:
    return send_from_directory(str(DEMO_DIR), "index.html")


@app.get("/api/status")
def api_status() -> Any:
    llm_calls: List[Dict[str, Any]] = []
    pipeline = create_pipeline_with_trace(llm_calls)
    default_attack_dir = os.getenv("MA_MEMIDS_DEFAULT_ATTACK_SANDBOX_DIR", str(DEFAULT_ATTACK_SANDBOX_DIR))
    default_benign_dir = os.getenv("MA_MEMIDS_DEFAULT_BENIGN_SANDBOX_DIR", str(DEFAULT_BENIGN_SANDBOX_DIR))
    default_attack_pcaps = _collect_pcap_files(default_attack_dir)
    default_benign_pcaps = _collect_pcap_files(default_benign_dir)
    with JOBS_LOCK:
        running_jobs = sum(1 for item in JOBS.values() if item.get("status") == "running")
    return jsonify(
        {
            "ok": True,
            "stats": pipeline.stats(),
            "state_path": str(STATE_PATH),
            "default_rules_path": os.getenv("MA_MEMIDS_DEFAULT_RULES_PATH", str(DEFAULT_RULES_PATH)),
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
    llm_calls: List[Dict[str, Any]] = []
    pipeline = create_pipeline_with_trace(llm_calls)
    notes = pipeline.graph.all_notes()
    rule_notes = [n for n in notes if n.note_type == "rule"]
    traffic_notes = [n for n in notes if n.note_type == "traffic"]
    total_links = sum(len(n.links) for n in notes)
    latest_notes = sorted(notes, key=lambda n: n.timestamp, reverse=True)[:10]
    return jsonify(
        {
            "ok": True,
            "summary": {
                "total_notes": len(notes),
                "rule_notes": len(rule_notes),
                "traffic_notes": len(traffic_notes),
                "total_links": total_links,
                "state_path": str(STATE_PATH),
            },
            "latest_notes": [_note_preview(n) for n in latest_notes],
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

    llm_calls: List[Dict[str, Any]] = []
    pipeline = create_pipeline_with_trace(llm_calls)
    notes = pipeline.graph.all_notes()

    if note_type in {"rule", "traffic"}:
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
    llm_calls: List[Dict[str, Any]] = []
    pipeline = create_pipeline_with_trace(llm_calls)
    note = pipeline.graph.get(note_id)
    if note is None:
        return jsonify({"ok": False, "error": f"note not found: {note_id}"}), 404
    return jsonify({"ok": True, "note": note.to_dict()})


@app.post("/api/graph/clear")
def api_graph_clear() -> Any:
    data = request.get_json(silent=True) or {}
    confirm = str(data.get("confirm") or request.form.get("confirm") or "").strip().upper()
    if confirm != "CLEAR":
        return jsonify({"ok": False, "error": "confirmation required: set confirm=CLEAR"}), 400

    llm_calls: List[Dict[str, Any]] = []
    pipeline = create_pipeline_with_trace(llm_calls)
    before = pipeline.stats()

    backup_path = None
    if STATE_PATH.exists():
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = STATE_PATH.with_name(f"state.backup.{ts}.json")
        shutil.copy2(STATE_PATH, backup_file)
        backup_path = str(backup_file)

    pipeline.graph.notes.clear()
    pipeline.save_state()
    after = pipeline.stats()

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
    app.run(host=host, port=port, debug=False)
