#!/usr/bin/env python3
from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

from ma_memids.llm_client import BaseLLMClient, create_llm_client
from ma_memids.pipeline import MAMemIDSPipeline


ROOT = Path(__file__).resolve().parent
DEMO_DIR = ROOT / "demo"
STATE_PATH = ROOT / "memory" / "state.json"


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


app = Flask(__name__, static_folder=str(DEMO_DIR), static_url_path="/demo")


@app.get("/")
def root() -> Any:
    return send_from_directory(str(DEMO_DIR), "index.html")


@app.get("/api/status")
def api_status() -> Any:
    llm_calls: List[Dict[str, Any]] = []
    pipeline = create_pipeline_with_trace(llm_calls)
    return jsonify(
        {
            "ok": True,
            "stats": pipeline.stats(),
            "state_path": str(STATE_PATH),
        }
    )


@app.post("/api/init")
def api_init() -> Any:
    rules_file = request.files.get("rules_file")
    llm_model = request.form.get("model") or None

    if rules_file is None or not rules_file.filename:
        return jsonify({"ok": False, "error": "rules_file is required"}), 400

    suffix = Path(rules_file.filename).suffix or ".rules"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(rules_file.read())
        tmp_path = tmp.name

    llm_calls: List[Dict[str, Any]] = []
    try:
        pipeline = create_pipeline_with_trace(llm_calls, llm_model=llm_model)
        count = pipeline.initialize_from_rules_file(tmp_path)
        payload = {
            "ok": True,
            "initialized_rules": count,
            "stats": pipeline.stats(),
            "llm_calls": llm_calls,
        }
        return jsonify(payload)
    except Exception as exc:
        return jsonify({"ok": False, "error": f"init failed: {type(exc).__name__}: {exc}"}), 500
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


@app.post("/api/process")
def api_process() -> Any:
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
    attack_file = request.files.get("attack_pcap")
    benign_file = request.files.get("benign_pcap")

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

    pcap_path = _save_upload(pcap_file)
    attack_path = _save_upload(attack_file)
    benign_path = _save_upload(benign_file)

    if not pcap_path and not traffic_text:
        for p in upload_paths:
            try:
                os.unlink(p)
            except OSError:
                pass
        return jsonify({"ok": False, "error": "Either pcap_file or traffic_text is required"}), 400

    attack_pcaps: List[str] = []
    benign_pcaps: List[str] = []

    if attack_path:
        attack_pcaps.append(attack_path)
    elif pcap_path:
        attack_pcaps.append(pcap_path)

    if benign_path:
        benign_pcaps.append(benign_path)

    llm_calls: List[Dict[str, Any]] = []
    try:
        pipeline = create_pipeline_with_trace(llm_calls, llm_model=llm_model)
        outcome = pipeline.process_unmatched_traffic_with_trace(
            pcap_path=pcap_path,
            traffic_text=traffic_text,
            attack_pcaps=attack_pcaps,
            benign_pcaps=benign_pcaps,
            human_override=(human_override or None),
        )
        payload = {
            "ok": True,
            "outcome": outcome,
            "llm_calls": llm_calls,
            "stats": pipeline.stats(),
        }
        return jsonify(payload)
    except Exception as exc:
        return jsonify({"ok": False, "error": f"process failed: {type(exc).__name__}: {exc}", "llm_calls": llm_calls}), 500
    finally:
        for path in upload_paths:
            try:
                os.unlink(path)
            except OSError:
                pass


if __name__ == "__main__":
    load_dotenv()
    host = os.getenv("MA_MEMIDS_DEMO_HOST", "127.0.0.1")
    port = int(os.getenv("MA_MEMIDS_DEMO_PORT", "8090"))
    app.run(host=host, port=port, debug=False)
