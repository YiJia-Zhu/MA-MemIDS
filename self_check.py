#!/usr/bin/env python3
"""
MA-MemIDS self check

Checks:
- Environment and provider config (.env)
- Optional API network reachability (DNS/TCP)
- Core module smoke tests (embedding/retrieval/note/graph/rule parser)
- PCAP parser (if a PCAP is provided)
- Suricata validator (portable fallback + optional local Suricata runtime)
- Pipeline smoke run
- Optional real LLM API call
"""

from __future__ import annotations

import argparse
import os
import socket
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

from ma_memids.embedding import HashingEmbedder
from ma_memids.graph import NoteGraph
from ma_memids.knowledge import DualPathRetriever
from ma_memids.llm_client import NullLLMClient, create_llm_client
from ma_memids.note_builder import NoteBuilder
from ma_memids.pcap_parser import PCAPParser
from ma_memids.pipeline import MAMemIDSPipeline
from ma_memids.rule_parser import parse_rule_fields
from ma_memids.validation import SandboxEvaluator, SuricataValidator


@dataclass
class CheckResult:
    name: str
    ok: bool
    message: str


def _mask_secret(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    if len(v) <= 8:
        return "*" * len(v)
    return v[:3] + "*" * (len(v) - 7) + v[-4:]


def _parse_host_port(url_or_host: str, default_port: int = 443) -> Tuple[Optional[str], int]:
    if not url_or_host:
        return None, default_port
    parsed = urlparse(url_or_host)
    if parsed.hostname:
        port = parsed.port
        if port is not None:
            return parsed.hostname, port
        if parsed.scheme == "http":
            return parsed.hostname, 80
        return parsed.hostname, 443

    if ":" in url_or_host and url_or_host.count(":") == 1:
        host, port_str = url_or_host.split(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            return host, default_port
    return url_or_host, default_port


def _dns_tcp_check(host: str, port: int, timeout: float) -> Tuple[bool, str]:
    try:
        socket.getaddrinfo(host, port)
    except Exception as exc:
        return False, f"DNS failed: {type(exc).__name__}: {exc}"

    try:
        conn = socket.create_connection((host, port), timeout=timeout)
        conn.close()
        return True, "TCP connect ok"
    except Exception as exc:
        return False, f"TCP failed: {type(exc).__name__}: {exc}"


def _pick_provider(model: str) -> Tuple[str, str, str]:
    model_l = model.lower()
    if model_l.startswith("deepseek"):
        return "deepseek", "DEEPSEEK_API_KEY", os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
    if model_l.startswith("glm"):
        return "glm", "ZHIPU_API_KEY", os.getenv("ZHIPU_BASE_URL", "https://open.bigmodel.cn/api/paas/v4")
    return "openai", "OPENAI_API_KEY", os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")


def _pick_default_pcap() -> Optional[str]:
    samples = Path("./samples")
    if not samples.exists():
        return None
    files = sorted([p for p in samples.glob("**/*") if p.suffix.lower() in {".pcap", ".pcapng", ".cap"}])
    if not files:
        return None
    return str(files[0])


def check_env(model_arg: Optional[str], skip_api: bool) -> CheckResult:
    model = model_arg or os.getenv("LLM_MODEL", "gpt-4.1")
    provider, key_var, base_url = _pick_provider(model)
    key = os.getenv(key_var, "")
    ok = bool(key) or skip_api
    return CheckResult(
        "env",
        ok,
        f"model={model}; provider={provider}; {key_var}={'set' if key else 'missing'}({_mask_secret(key)}); base_url={base_url}",
    )


def check_network(model_arg: Optional[str], timeout: float, skip_api: bool) -> CheckResult:
    model = model_arg or os.getenv("LLM_MODEL", "gpt-4.1")
    _, key_var, base_url = _pick_provider(model)
    key = os.getenv(key_var, "")
    if not key:
        return CheckResult("api.network", bool(skip_api), f"{key_var} missing; network check skipped")

    host, port = _parse_host_port(base_url, 443)
    if not host:
        return CheckResult("api.network", False, f"Invalid base URL: {base_url}")
    ok, msg = _dns_tcp_check(host, port, timeout)
    return CheckResult("api.network", ok or skip_api, f"{host}:{port} -> {msg}")


def check_embedding_and_retrieval() -> CheckResult:
    embedder = HashingEmbedder()
    retriever = DualPathRetriever(embedder=embedder)
    q = "Exploit CVE-2024-12345 against public-facing app T1190 with SQL injection payload"
    res = retriever.retrieve(q)
    v = embedder.embed(q)
    ok = len(v) > 0 and "CVE-2024-12345" in res.cve_ids and "T1190" in res.tech_ids
    return CheckResult(
        "embedding+retrieval",
        ok,
        f"dim={len(v)}; cve_ids={res.cve_ids[:3]}; tech_ids={res.tech_ids[:3]}",
    )


def check_rule_parser_and_note_builder() -> CheckResult:
    rule = (
        'alert http any any -> any any '
        '(msg:"SelfCheck SQLi"; flow:to_server,established; http.uri; '
        'content:"union select"; nocase; metadata:mitre_tactic T1190,cve CVE-2024-12345; sid:1234567; rev:1;)'
    )
    fields = parse_rule_fields(rule)
    retriever = DualPathRetriever(embedder=HashingEmbedder())
    builder = NoteBuilder(retriever=retriever, embedder=HashingEmbedder(), llm_client=NullLLMClient())
    note = builder.build_rule_note(rule)

    ok = (
        fields.get("sid") == 1234567
        and fields.get("protocol") == "HTTP"
        and note.note_type == "rule"
        and note.sid == 1234567
        and len(note.embedding) > 0
    )
    return CheckResult(
        "rule_parser+note_builder",
        ok,
        f"sid={fields.get('sid')}; protocol={fields.get('protocol')}; kw={len(note.keywords)}; tactics={note.tactics[:3]}",
    )


def check_graph_search() -> CheckResult:
    builder = NoteBuilder(
        retriever=DualPathRetriever(embedder=HashingEmbedder()),
        embedder=HashingEmbedder(),
        llm_client=NullLLMClient(),
    )
    graph = NoteGraph()

    rule1 = 'alert http any any -> any any (msg:"A"; flow:to_server,established; http.uri; content:"/login"; sid:2000001; rev:1;)'
    rule2 = 'alert http any any -> any any (msg:"B"; flow:to_server,established; http.uri; content:"/admin"; sid:2000002; rev:1;)'
    n1 = builder.build_rule_note(rule1)
    n2 = builder.build_rule_note(rule2)
    graph.add_or_update(n1)
    graph.add_or_update(n2)

    traffic = builder.build_traffic_note("GET /admin HTTP/1.1\nHost: example.com\n")
    ranked = graph.search_top_k(traffic)
    ok = len(ranked) > 0 and graph.count() == 2
    return CheckResult("graph.search", ok, f"notes={graph.count()}; top={[(x.note_id, round(x.score, 3)) for x in ranked[:3]]}")


def check_pcap_parser(pcap_path: Optional[str]) -> CheckResult:
    if not pcap_path:
        return CheckResult("pcap.parser", True, "No pcap provided/found, skipped")
    if not os.path.exists(pcap_path):
        return CheckResult("pcap.parser", False, f"PCAP not found: {pcap_path}")
    try:
        summary = PCAPParser.parse(pcap_path)
    except Exception as exc:
        return CheckResult("pcap.parser", False, f"parse failed: {type(exc).__name__}: {exc}")

    preview = summary.payload_text.replace("\n", " ")[:120]
    return CheckResult(
        "pcap.parser",
        True,
        f"pcap={pcap_path}; protocol={summary.protocol}; http={summary.http_method} {summary.http_uri}; preview={preview}",
    )


def check_validator_portable() -> CheckResult:
    rule = 'alert http any any -> any any (msg:"SelfCheck"; flow:to_server,established; content:"test"; sid:2999999; rev:1;)'
    validator = SuricataValidator(suricata_path="/__not_found_suricata__", suricata_config="/__none__")
    ok, err = validator.validate_rule_format(rule)
    return CheckResult("validator.portable", ok, "basic syntax fallback ok" if ok else f"fallback syntax failed: {err}")


def check_validator_runtime(pcap_path: Optional[str]) -> CheckResult:
    rule = 'alert http any any -> any any (msg:"RuntimeCheck"; flow:to_server,established; content:"GET"; sid:2999998; rev:1;)'
    validator = SuricataValidator()
    ok, err = validator.validate_rule_format(rule)
    if not ok:
        return CheckResult("validator.runtime", False, f"format failed with local Suricata: {err}")

    if not pcap_path:
        return CheckResult("validator.runtime", True, "format ok; no pcap provided/found, replay skipped")

    res = validator.test_rule_against_pcap(rule, pcap_path)
    return CheckResult(
        "validator.runtime",
        res.format_check_passed,
        f"format={res.format_check_passed}; alerts={res.alerts_triggered}; msg={res.error_message or 'none'}",
    )


def check_sandbox_formula() -> CheckResult:
    validator = SuricataValidator(suricata_path="/__not_found_suricata__", suricata_config="/__none__")
    sandbox = SandboxEvaluator(validator)
    rule = 'alert http any any -> any any (msg:"SandboxCheck"; flow:to_server,established; content:"test"; sid:2999997; rev:1;)'
    result = sandbox.evaluate(rule, attack_pcaps=[], benign_pcaps=[])
    ok = (result.metrics is not None) and (result.metrics.score == 0.0)
    score = result.metrics.score if result.metrics else None
    return CheckResult("sandbox.formula", ok, f"syntax_ok={result.syntax_ok}; score={score}; passed={result.passed}")


def check_pipeline_smoke() -> CheckResult:
    with tempfile.TemporaryDirectory() as td:
        state = str(Path(td) / "state.json")
        pipeline = MAMemIDSPipeline(
            state_path=state,
            llm_client=NullLLMClient(),
            suricata_path="/__not_found_suricata__",
            suricata_config="/__none__",
        )
        res = pipeline.process_unmatched_traffic(traffic_text="GET /selfcheck?id=1 HTTP/1.1\nHost: test.local\n")
        ok = res.success and bool(res.rule_text)
        return CheckResult("pipeline.smoke", ok, f"success={res.success}; mode={res.mode}; reason={res.reason}; retries={res.retries}")


def check_api_call(model_arg: Optional[str], skip_api: bool) -> CheckResult:
    if skip_api:
        return CheckResult("llm.api", True, "skipped by --skip-api")

    model = model_arg or os.getenv("LLM_MODEL", "gpt-4.1")
    client = create_llm_client(model=model)
    if isinstance(client, NullLLMClient):
        return CheckResult("llm.api", False, "LLM client is offline fallback (key missing or provider config invalid)")

    t0 = time.time()
    try:
        content = client.chat([{"role": "user", "content": "Reply only: pong"}], temperature=0)
        dt = time.time() - t0
        preview = (content or "").strip().replace("\n", " ")[:120]
        return CheckResult("llm.api", True, f"model={client.model_name()}; latency={dt:.2f}s; preview={preview}")
    except Exception as exc:
        dt = time.time() - t0
        if isinstance(exc, httpx.HTTPStatusError):
            status = exc.response.status_code
            if status == 401:
                hint = "Unauthorized: 请检查 API key 或 base URL。"
            elif status == 402:
                hint = "Payment Required: 账号余额/配额不足。"
            elif status == 429:
                hint = "Rate Limited: 请求频率或并发超限。"
            else:
                hint = f"HTTP {status}"
            return CheckResult("llm.api", False, f"call failed in {dt:.2f}s: {hint}")
        return CheckResult("llm.api", False, f"call failed in {dt:.2f}s: {type(exc).__name__}: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(description="MA-MemIDS self-check")
    parser.add_argument("--model", default=None, help="Override model (default from .env LLM_MODEL)")
    parser.add_argument("--pcap", default=None, help="PCAP path for parser/replay check")
    parser.add_argument("--skip-api", action="store_true", help="Skip real LLM API call")
    parser.add_argument("--timeout", type=float, default=2.0, help="Network DNS/TCP timeout in seconds")
    args = parser.parse_args()

    load_dotenv()
    pcap_path = args.pcap or _pick_default_pcap()

    checks = [
        check_env(args.model, args.skip_api),
        check_network(args.model, args.timeout, args.skip_api),
        check_embedding_and_retrieval(),
        check_rule_parser_and_note_builder(),
        check_graph_search(),
        check_pcap_parser(pcap_path),
        check_validator_portable(),
        check_validator_runtime(pcap_path),
        check_sandbox_formula(),
        check_pipeline_smoke(),
        check_api_call(args.model, args.skip_api),
    ]

    all_ok = True
    for item in checks:
        all_ok = all_ok and item.ok
        print(f"[{'OK' if item.ok else 'FAIL'}] {item.name}: {item.message}")

    if all_ok:
        print("\n结论: 自检全部通过。")
        return 0

    print("\n结论: 存在失败项，请按失败项提示修复后重试。")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
