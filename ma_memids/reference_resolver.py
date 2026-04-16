from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
import hashlib
import html
import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from .llm_client import BaseLLMClient
from .prompts import REFERENCE_PARSE_SYSTEM, REFERENCE_PARSE_USER
from .utils import dedupe_keep_order, now_iso


LOGGER = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
SCRIPT_RE = re.compile(r"<script\b.*?</script>", re.IGNORECASE | re.DOTALL)
STYLE_RE = re.compile(r"<style\b.*?</style>", re.IGNORECASE | re.DOTALL)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
WORD_RE = re.compile(r"[A-Za-z0-9_./:+-]{3,}")
URL_WITHOUT_SCHEME_RE = re.compile(r"^(?:www\.)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?(?:[/?#].*)?$", re.IGNORECASE)
SECURITY_SIGNAL_RE = re.compile(
    r"\b(?:"
    r"remote code execution|command injection|sql injection|directory traversal|path traversal|"
    r"server-side request forgery|cross-site scripting|deserialization|prototype pollution|"
    r"privilege escalation|rce|xss|ssrf|webshell|jndi|ldap|rmi|cmd\\.exe|powershell|log4j|struts|"
    r"weblogic|exchange|confluence|jenkins|citrix|fortinet|ivanti|apache|spring|openssl"
    r")\b",
    re.IGNORECASE,
)

CACHE_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 3.0
DEFAULT_MAX_DOWNLOAD_BYTES = 2_000_000
DEFAULT_MAX_TEXT_CHARS = 12_000
DEFAULT_LLM_CHUNK_CHARS = 4_000
DEFAULT_LLM_MAX_CHUNKS = 3
DEFAULT_LLM_MIN_TEXT_CHARS = 800
DEFAULT_CACHE_MAX_AGE_DAYS = 14
DEFAULT_CACHE_MAX_FILES = 2000
DEFAULT_CACHE_MAX_SIZE_BYTES = 256 * 1024 * 1024
DEFAULT_CACHE_CLEANUP_EVERY_WRITES = 32
DEFAULT_MAX_WORKERS = 4


class ReferenceResolver:
    def __init__(
        self,
        llm_client: BaseLLMClient,
        cache_dir: Optional[str] = None,
        tool_callback: Optional[Callable[[Dict[str, object]], None]] = None,
    ):
        self.llm = llm_client
        self.tool_callback = tool_callback
        self.cache_dir = Path(
            cache_dir
            or (os.getenv("MA_MEMIDS_REFERENCE_CACHE_DIR") or "").strip()
            or "./memory/reference_cache"
        )
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = float(os.getenv("MA_MEMIDS_REFERENCE_TIMEOUT", DEFAULT_TIMEOUT_SECONDS))
        self.max_download_bytes = int(os.getenv("MA_MEMIDS_REFERENCE_MAX_BYTES", DEFAULT_MAX_DOWNLOAD_BYTES))
        self.max_text_chars = int(os.getenv("MA_MEMIDS_REFERENCE_MAX_TEXT_CHARS", DEFAULT_MAX_TEXT_CHARS))
        self.llm_chunk_chars = int(os.getenv("MA_MEMIDS_REFERENCE_LLM_CHUNK_CHARS", DEFAULT_LLM_CHUNK_CHARS))
        self.llm_max_chunks = int(os.getenv("MA_MEMIDS_REFERENCE_LLM_MAX_CHUNKS", DEFAULT_LLM_MAX_CHUNKS))
        self.llm_min_text_chars = max(
            0,
            int(os.getenv("MA_MEMIDS_REFERENCE_LLM_MIN_TEXT_CHARS", DEFAULT_LLM_MIN_TEXT_CHARS)),
        )
        self.cache_max_age_days = max(0, int(os.getenv("MA_MEMIDS_REFERENCE_CACHE_MAX_AGE_DAYS", DEFAULT_CACHE_MAX_AGE_DAYS)))
        self.cache_max_files = max(0, int(os.getenv("MA_MEMIDS_REFERENCE_CACHE_MAX_FILES", DEFAULT_CACHE_MAX_FILES)))
        self.cache_max_size_bytes = max(0, int(os.getenv("MA_MEMIDS_REFERENCE_CACHE_MAX_SIZE_BYTES", DEFAULT_CACHE_MAX_SIZE_BYTES)))
        self.cache_cleanup_every_writes = max(
            1,
            int(os.getenv("MA_MEMIDS_REFERENCE_CACHE_CLEANUP_EVERY_WRITES", DEFAULT_CACHE_CLEANUP_EVERY_WRITES)),
        )
        self.max_workers = max(1, int(os.getenv("MA_MEMIDS_REFERENCE_MAX_WORKERS", DEFAULT_MAX_WORKERS)))
        self._writes_since_cleanup = 0
        self._cache_lock = threading.Lock()
        self._http = httpx.Client(
            timeout=self.timeout_seconds,
            follow_redirects=True,
            headers={
                "User-Agent": "MA-MemIDS/1.0 (+https://github.com/)"
            },
        )
        self._cleanup_cache(force=True)

    def resolve_rule_references(self, references: Iterable[Dict[str, object]]) -> Dict[str, object]:
        ref_list = [dict(item) for item in references if isinstance(item, dict)]
        if not ref_list:
            return {
                "trusted_cve_ids": [],
                "trusted_tech_ids": [],
                "trusted_terms": [],
                "reference_summary": "",
                "source_urls": [],
                "resolved_references": [],
            }

        if self.max_workers > 1 and len(ref_list) > 1:
            return self.resolve_reference_batches([ref_list])[0]

        resolved_references = [self._resolve_reference(reference) for reference in ref_list]
        return self._aggregate_resolved_references(resolved_references)

    def resolve_reference_batches(
        self,
        reference_batches: Iterable[Iterable[Dict[str, object]]],
        *,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        batch_result_callback: Optional[Callable[[int, Dict[str, object]], None]] = None,
    ) -> List[Dict[str, object]]:
        prepared_batches = [
            [dict(item) for item in batch if isinstance(item, dict)]
            for batch in reference_batches
        ]
        if not prepared_batches:
            return []

        results: List[List[Optional[Dict[str, object]]]] = [
            [None] * len(batch) for batch in prepared_batches
        ]
        pending_per_batch = [len(batch) for batch in prepared_batches]
        emitted_batches = [False] * len(prepared_batches)
        task_specs: List[Tuple[int, int, Dict[str, object]]] = []
        for batch_idx, batch in enumerate(prepared_batches):
            for ref_idx, reference in enumerate(batch):
                task_specs.append((batch_idx, ref_idx, reference))

        total_tasks = len(task_specs)
        if total_tasks == 0:
            aggregated_empty = [self._aggregate_resolved_references([]) for _ in prepared_batches]
            if batch_result_callback is not None:
                for batch_idx, payload in enumerate(aggregated_empty):
                    batch_result_callback(batch_idx, dict(payload))
            return aggregated_empty

        worker_count = min(self.max_workers, total_tasks)
        if progress_callback is not None:
            progress_callback(
                {
                    "event": "reference_prefetch_start",
                    "rules": len(prepared_batches),
                    "references": total_tasks,
                    "max_workers": worker_count,
                }
            )

        if worker_count <= 1:
            completed = 0
            for batch_idx, ref_idx, reference in task_specs:
                results[batch_idx][ref_idx] = self._resolve_reference(reference)
                completed += 1
                pending_per_batch[batch_idx] = max(0, pending_per_batch[batch_idx] - 1)
                if pending_per_batch[batch_idx] == 0 and not emitted_batches[batch_idx]:
                    aggregated = self._aggregate_resolved_references(
                        [item for item in results[batch_idx] if isinstance(item, dict)]
                    )
                    emitted_batches[batch_idx] = True
                    if batch_result_callback is not None:
                        batch_result_callback(batch_idx, dict(aggregated))
                if progress_callback is not None:
                    progress_callback(
                        {
                            "event": "reference_prefetch_progress",
                            "completed": completed,
                            "total": total_tasks,
                        }
                    )
        else:
            completed = 0
            future_map: Dict[Future[Dict[str, object]], List[Tuple[int, int]]] = {}
            dedupe_map: Dict[str, Future[Dict[str, object]]] = {}
            with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="ref-prefetch") as executor:
                for batch_idx, ref_idx, reference in task_specs:
                    signature = self._reference_signature(reference)
                    future = dedupe_map.get(signature)
                    if future is None:
                        future = executor.submit(self._resolve_reference, reference)
                        dedupe_map[signature] = future
                    future_map.setdefault(future, []).append((batch_idx, ref_idx))

                for future in as_completed(future_map):
                    resolved = future.result()
                    for batch_idx, ref_idx in future_map[future]:
                        results[batch_idx][ref_idx] = dict(resolved)
                        completed += 1
                        pending_per_batch[batch_idx] = max(0, pending_per_batch[batch_idx] - 1)
                        if pending_per_batch[batch_idx] == 0 and not emitted_batches[batch_idx]:
                            aggregated = self._aggregate_resolved_references(
                                [item for item in results[batch_idx] if isinstance(item, dict)]
                            )
                            emitted_batches[batch_idx] = True
                            if batch_result_callback is not None:
                                batch_result_callback(batch_idx, dict(aggregated))
                    if progress_callback is not None:
                        progress_callback(
                            {
                                "event": "reference_prefetch_progress",
                                "completed": completed,
                                "total": total_tasks,
                            }
                        )

        if progress_callback is not None:
            progress_callback(
                {
                    "event": "reference_prefetch_done",
                    "completed": total_tasks,
                    "total": total_tasks,
                }
            )

        aggregated: List[Dict[str, object]] = []
        for batch_results in results:
            resolved_batch = [item for item in batch_results if isinstance(item, dict)]
            aggregated.append(self._aggregate_resolved_references(resolved_batch))
        return aggregated

    def _aggregate_resolved_references(self, resolved_references: Iterable[Dict[str, object]]) -> Dict[str, object]:
        trusted_cve_ids: List[str] = []
        trusted_tech_ids: List[str] = []
        trusted_terms: List[str] = []
        summaries: List[str] = []
        source_urls: List[str] = []

        normalized_results = [dict(item) for item in resolved_references if isinstance(item, dict)]
        for resolved in normalized_results:
            trusted_cve_ids.extend(str(item).upper().strip() for item in resolved.get("cve_ids", []) if str(item).strip())
            trusted_tech_ids.extend(str(item).upper().strip() for item in resolved.get("tech_ids", []) if str(item).strip())
            trusted_terms.extend(str(item).strip() for item in resolved.get("trusted_terms", []) if str(item).strip())
            summary = str(resolved.get("reference_summary") or "").strip()
            if summary:
                summaries.append(summary)
            source_url = str(resolved.get("source_url") or "").strip()
            if source_url:
                source_urls.append(source_url)

        return {
            "trusted_cve_ids": dedupe_keep_order(trusted_cve_ids)[:12],
            "trusted_tech_ids": dedupe_keep_order(trusted_tech_ids)[:12],
            "trusted_terms": dedupe_keep_order(trusted_terms)[:20],
            "reference_summary": self._merge_summaries(summaries),
            "source_urls": dedupe_keep_order(source_urls),
            "resolved_references": normalized_results,
        }

    def _resolve_reference(self, reference: Dict[str, object]) -> Dict[str, object]:
        ref_type = str(reference.get("type") or "raw").strip().lower() or "raw"
        raw_value = str(reference.get("value") or reference.get("raw") or "").strip()
        source_url = str(reference.get("url") or "").strip()

        cve_ids = dedupe_keep_order(
            [m.group(0).upper() for m in CVE_RE.finditer(raw_value)]
            + [str(item).upper().strip() for item in reference.get("cve_ids", []) if str(item).strip()]
        )
        tech_ids = dedupe_keep_order(
            [m.group(0).upper() for m in TECH_RE.finditer(raw_value)]
            + [str(item).upper().strip() for item in reference.get("tech_ids", []) if str(item).strip()]
        )

        if ref_type == "cve" and not cve_ids:
            cve_ids = self._normalize_cve_reference(raw_value)

        if source_url or ref_type == "url":
            url = source_url or raw_value
            return self._resolve_url_reference(url, reference, seeded_cve_ids=cve_ids, seeded_tech_ids=tech_ids)

        summary = raw_value[:220]
        return {
            "type": ref_type,
            "value": raw_value,
            "status": "structured_reference",
            "resolved_via": "rule",
            "source_url": "",
            "http_status": None,
            "content_type": "",
            "cve_ids": cve_ids,
            "tech_ids": tech_ids,
            "trusted_terms": self._structured_reference_terms(ref_type, raw_value, cve_ids, tech_ids),
            "reference_summary": summary,
            "error": "",
        }

    def _resolve_url_reference(
        self,
        url: str,
        reference: Dict[str, object],
        *,
        seeded_cve_ids: List[str],
        seeded_tech_ids: List[str],
    ) -> Dict[str, object]:
        raw_url = str(url or "").strip()
        candidate_urls = self._candidate_urls(raw_url)
        normalized_url = candidate_urls[0] if candidate_urls else raw_url
        url_hints = self._extract_url_hints(normalized_url or raw_url)
        cache_key = self._cache_key(raw_url or normalized_url)
        cached = self._read_cache(cache_key)
        self._emit_tool_call(
            "reference_cache_lookup",
            input_payload={"url": raw_url, "cache_key": cache_key},
            output_payload={
                "hit": cached is not None,
                "cached_status": (cached.get("status") if isinstance(cached, dict) else None),
                "source_url": (cached.get("source_url") if isinstance(cached, dict) else None),
            },
        )
        if cached is not None:
            cached_result = dict(cached)
            cached_result["status"] = str(cached_result.get("status") or "resolved")
            cached_result["resolved_via"] = "cache"
            cached_result.setdefault("source_url", normalized_url or raw_url)
            cached_result.setdefault("normalized_url", normalized_url or raw_url)
            cached_result["cve_ids"] = dedupe_keep_order(
                seeded_cve_ids + url_hints["cve_ids"] + [str(item).upper().strip() for item in cached_result.get("cve_ids", []) if str(item).strip()]
            )[:12]
            cached_result["tech_ids"] = dedupe_keep_order(
                seeded_tech_ids + url_hints["tech_ids"] + [str(item).upper().strip() for item in cached_result.get("tech_ids", []) if str(item).strip()]
            )[:12]
            cached_result["trusted_terms"] = dedupe_keep_order(
                url_hints["trusted_terms"] + [str(item).strip() for item in cached_result.get("trusted_terms", []) if str(item).strip()]
            )[:16]
            cached_result["reference_summary"] = str(cached_result.get("reference_summary") or "").strip()
            cached_result["error"] = ""
            return cached_result

        last_exc: Optional[Exception] = None
        for candidate_url in candidate_urls or [raw_url]:
            try:
                fetched = self._fetch_url(candidate_url)
                parsed = self._parse_reference_page(candidate_url, fetched)
                result = {
                    "type": "url",
                    "value": str(reference.get("value") or reference.get("raw") or raw_url).strip(),
                    "status": "resolved",
                    "resolved_via": "network",
                    "source_url": str(fetched.get("final_url") or candidate_url),
                    "http_status": fetched.get("http_status"),
                    "content_type": fetched.get("content_type"),
                    "normalized_url": candidate_url,
                    "cve_ids": dedupe_keep_order(seeded_cve_ids + url_hints["cve_ids"] + parsed.get("cve_ids", []))[:12],
                    "tech_ids": dedupe_keep_order(seeded_tech_ids + url_hints["tech_ids"] + parsed.get("tech_ids", []))[:12],
                    "trusted_terms": dedupe_keep_order(url_hints["trusted_terms"] + parsed.get("trusted_terms", []))[:16],
                    "reference_summary": str(parsed.get("reference_summary") or "").strip(),
                    "error": "",
                    "fetched_at": now_iso(),
                    "cache_version": CACHE_VERSION,
                    "title": str(fetched.get("title") or "").strip(),
                    "parser_mode": str(parsed.get("parser_mode") or "heuristic"),
                }
                self._write_cache(cache_key, result)
                return result
            except Exception as exc:
                last_exc = exc

        message = self._classify_reference_error(last_exc or RuntimeError("reference_fetch_failed"))
        LOGGER.warning("Reference resolver failed for %s: %s", raw_url, message)
        if cached is not None:
            stale = dict(cached)
            stale["status"] = "stale_cache"
            stale["resolved_via"] = "stale_cache"
            stale["error"] = message
            stale.setdefault("source_url", normalized_url or raw_url)
            stale.setdefault("normalized_url", normalized_url or raw_url)
            stale["cve_ids"] = dedupe_keep_order(
                seeded_cve_ids + url_hints["cve_ids"] + [str(item).upper().strip() for item in stale.get("cve_ids", []) if str(item).strip()]
            )[:12]
            stale["tech_ids"] = dedupe_keep_order(
                seeded_tech_ids + url_hints["tech_ids"] + [str(item).upper().strip() for item in stale.get("tech_ids", []) if str(item).strip()]
            )[:12]
            stale["trusted_terms"] = dedupe_keep_order(
                url_hints["trusted_terms"] + [str(item).strip() for item in stale.get("trusted_terms", []) if str(item).strip()]
            )[:16]
            return stale

        return {
            "type": "url",
            "value": str(reference.get("value") or reference.get("raw") or raw_url).strip(),
            "status": "error",
            "resolved_via": "fallback",
            "source_url": normalized_url or raw_url,
            "http_status": None,
            "content_type": "",
            "normalized_url": normalized_url or raw_url,
            "cve_ids": dedupe_keep_order(seeded_cve_ids + url_hints["cve_ids"])[:12],
            "tech_ids": dedupe_keep_order(seeded_tech_ids + url_hints["tech_ids"])[:12],
            "trusted_terms": url_hints["trusted_terms"][:12],
            "reference_summary": "",
            "error": message,
        }

    def _fetch_url(self, url: str) -> Dict[str, object]:
        t0 = time.time()
        try:
            response = self._http.get(url)
            response.raise_for_status()

            content_length = int(response.headers.get("content-length") or 0)
            if content_length > self.max_download_bytes:
                raise ValueError(f"content_too_large:{content_length}")
            raw_bytes = response.content
            if len(raw_bytes) > self.max_download_bytes:
                raise ValueError(f"content_too_large:{len(raw_bytes)}")

            content_type = str(response.headers.get("content-type") or "").lower()
            if "html" in content_type:
                text = response.text
                title = self._extract_html_title(text)
                clean_text = self._clean_html(text)
            elif any(token in content_type for token in ("json", "text/plain", "text/markdown", "xml")):
                text = response.text
                title = ""
                clean_text = self._clean_text(text)
            else:
                raise ValueError(f"unsupported_content_type:{content_type or 'unknown'}")

            if not clean_text:
                raise ValueError("empty_content")

            fetched = {
                "http_status": response.status_code,
                "content_type": content_type,
                "final_url": str(response.url),
                "title": title,
                "clean_text": clean_text[: self.max_text_chars],
            }
            self._emit_tool_call(
                "reference_http_fetch",
                input_payload={"method": "GET", "url": url, "timeout_s": self.timeout_seconds},
                output_payload={
                    "http_status": fetched["http_status"],
                    "content_type": fetched["content_type"],
                    "final_url": fetched["final_url"],
                    "title": fetched["title"],
                    "clean_text": fetched["clean_text"],
                    "latency_s": round(time.time() - t0, 3),
                },
            )
            return fetched
        except Exception as exc:
            self._emit_tool_call(
                "reference_http_fetch",
                input_payload={"method": "GET", "url": url, "timeout_s": self.timeout_seconds},
                error=f"{type(exc).__name__}: {exc}",
            )
            raise

    def _parse_reference_page(self, url: str, fetched: Dict[str, object]) -> Dict[str, object]:
        clean_text = str(fetched.get("clean_text") or "").strip()
        title = str(fetched.get("title") or "").strip()
        heuristic = self._heuristic_parse(clean_text, title=title, source_url=url)

        parsed = dict(heuristic)
        use_llm = self._should_use_llm(clean_text, heuristic)
        if use_llm:
            llm_result = self._parse_with_llm(url=url, title=title, text=clean_text)
            if llm_result is not None:
                parsed["cve_ids"] = dedupe_keep_order(parsed.get("cve_ids", []) + llm_result.get("cve_ids", []))[:12]
                parsed["tech_ids"] = dedupe_keep_order(parsed.get("tech_ids", []) + llm_result.get("tech_ids", []))[:12]
                parsed["trusted_terms"] = dedupe_keep_order(parsed.get("trusted_terms", []) + llm_result.get("trusted_terms", []))[:16]
                parsed["reference_summary"] = str(llm_result.get("reference_summary") or parsed.get("reference_summary") or "").strip()
                parsed["parser_mode"] = str(llm_result.get("parser_mode") or "llm")
        return parsed

    def _heuristic_parse(self, text: str, *, title: str, source_url: str) -> Dict[str, object]:
        cve_ids = dedupe_keep_order(m.group(0).upper() for m in CVE_RE.finditer(text))[:12]
        tech_ids = dedupe_keep_order(m.group(0).upper() for m in TECH_RE.finditer(text))[:12]
        trusted_terms = self._extract_trusted_terms("\n".join(part for part in (title, text, source_url) if part))[:16]
        reference_summary = self._fallback_summary(title=title, text=text)
        return {
            "cve_ids": cve_ids,
            "tech_ids": tech_ids,
            "trusted_terms": trusted_terms,
            "reference_summary": reference_summary,
            "parser_mode": "heuristic",
        }

    def _should_use_llm(self, text: str, heuristic: Dict[str, object]) -> bool:
        if not text:
            return False
        if heuristic.get("cve_ids") or heuristic.get("tech_ids"):
            return False
        return len(text) >= self.llm_min_text_chars

    def _parse_with_llm(self, *, url: str, title: str, text: str) -> Optional[Dict[str, object]]:
        chunks = self._chunk_text(text)
        if not chunks:
            return None

        summaries: List[str] = []
        cve_ids: List[str] = []
        tech_ids: List[str] = []
        trusted_terms: List[str] = []

        for chunk in chunks:
            try:
                messages = [
                    {"role": "system", "content": REFERENCE_PARSE_SYSTEM},
                    {
                        "role": "user",
                        "content": REFERENCE_PARSE_USER.format(
                            source_url=url,
                            title=title or "N/A",
                            reference_text=chunk,
                        ),
                    },
                ]
                t0 = time.time()
                response = self.llm.chat(messages, temperature=0.1)
                parsed = self._try_parse_json(response)
                self._emit_tool_call(
                    "reference_llm_parse",
                    input_payload={"url": url, "title": title, "messages": messages},
                    output_payload={
                        "response": response,
                        "parsed": parsed,
                        "latency_s": round(time.time() - t0, 3),
                    },
                )
                if parsed is None:
                    continue
                summaries.append(str(parsed.get("reference_summary") or "").strip())
                cve_ids.extend(m.group(0).upper() for m in CVE_RE.finditer(" ".join(str(item) for item in self._listify(parsed.get("cve_ids")))))
                tech_ids.extend(m.group(0).upper() for m in TECH_RE.finditer(" ".join(str(item) for item in self._listify(parsed.get("tech_ids")))))
                trusted_terms.extend(str(item).strip() for item in self._listify(parsed.get("trusted_terms")) if str(item).strip())
            except Exception as exc:
                self._emit_tool_call(
                    "reference_llm_parse",
                    input_payload={"url": url, "title": title},
                    error=f"{type(exc).__name__}: {exc}",
                )
                LOGGER.warning("Reference LLM parse failed for %s: %s", url, exc)

        if not summaries and not cve_ids and not tech_ids and not trusted_terms:
            return None
        return {
            "reference_summary": self._merge_summaries(summaries),
            "cve_ids": dedupe_keep_order(cve_ids)[:12],
            "tech_ids": dedupe_keep_order(tech_ids)[:12],
            "trusted_terms": dedupe_keep_order(trusted_terms)[:16],
            "parser_mode": "llm_chunked" if len(chunks) > 1 else "llm",
        }

    def _extract_url_hints(self, url: str) -> Dict[str, List[str]]:
        if not url:
            return {"cve_ids": [], "tech_ids": [], "trusted_terms": []}
        parsed = urlparse(url)
        text = html.unescape(url)
        cve_ids = dedupe_keep_order(m.group(0).upper() for m in CVE_RE.finditer(text))[:12]
        tech_ids = dedupe_keep_order(m.group(0).upper() for m in TECH_RE.finditer(text))[:12]
        terms: List[str] = []
        host = parsed.netloc.lower().split(":", 1)[0]
        if host:
            terms.append(host)
        for token in WORD_RE.findall(parsed.path or ""):
            clean = token.strip().strip("-_/.")
            low = clean.lower()
            if not clean or low.startswith(("http", "www")):
                continue
            if clean.upper().startswith("CVE-") or TECH_RE.fullmatch(clean.upper()):
                continue
            if len(clean) > 32:
                clean = clean[:32]
            if any(ch.isalpha() for ch in clean):
                terms.append(clean)
        return {
            "cve_ids": cve_ids,
            "tech_ids": tech_ids,
            "trusted_terms": dedupe_keep_order(terms)[:10],
        }

    def _candidate_urls(self, raw_url: str) -> List[str]:
        value = str(raw_url or "").strip()
        if not value:
            return []
        lower = value.lower()
        if lower.startswith(("http://", "https://")):
            return [value]
        if value.startswith("//"):
            return [f"https:{value}", f"http:{value}"]
        if URL_WITHOUT_SCHEME_RE.match(value):
            return [f"https://{value}", f"http://{value}"]
        return [value]

    def _structured_reference_terms(self, ref_type: str, raw_value: str, cve_ids: List[str], tech_ids: List[str]) -> List[str]:
        terms: List[str] = []
        if ref_type and ref_type not in {"raw", "url", "cve", "attack"}:
            terms.append(ref_type)
        terms.extend(cve_ids)
        terms.extend(tech_ids)
        for token in WORD_RE.findall(raw_value):
            clean = token.strip().strip("-_/.")
            if not clean or clean.isdigit():
                continue
            if len(clean) > 32:
                clean = clean[:32]
            if any(ch.isalpha() for ch in clean):
                terms.append(clean)
        return dedupe_keep_order(terms)[:12]

    def _extract_trusted_terms(self, text: str) -> List[str]:
        terms: List[str] = []
        for match in SECURITY_SIGNAL_RE.finditer(text):
            terms.append(match.group(0).strip())
        for token in WORD_RE.findall(text):
            clean = token.strip().strip("-_/.")
            low = clean.lower()
            if not clean or len(clean) < 4 or clean.isdigit():
                continue
            if low in {
                "http", "https", "www", "html", "json", "text", "page", "article", "title", "github",
                "mitre", "attack", "cve", "advisory", "security", "vulnerability", "release", "update",
            }:
                continue
            if clean.upper().startswith("CVE-") or TECH_RE.fullmatch(clean.upper()):
                continue
            if low.startswith(("http", "www")):
                continue
            if len(clean) > 32:
                clean = clean[:32]
            if any(ch.isalpha() for ch in clean):
                terms.append(clean)
            if len(terms) >= 16:
                break
        return dedupe_keep_order(terms)

    def _fallback_summary(self, *, title: str, text: str) -> str:
        first_sentence = ""
        for chunk in re.split(r"(?<=[。.!?])\s+", text):
            clean = self._clean_text(chunk)
            if len(clean) >= 24:
                first_sentence = clean
                break
        if title and first_sentence:
            return f"{title}: {first_sentence}"[:280]
        if title:
            return title[:280]
        return first_sentence[:280]

    def _merge_summaries(self, summaries: Iterable[str]) -> str:
        merged = dedupe_keep_order(str(item).strip() for item in summaries if str(item).strip())
        return " | ".join(merged[:3])[:360]

    def _normalize_cve_reference(self, raw_value: str) -> List[str]:
        compact = re.findall(r"\b(\d{4})[-_ ]?(\d{4,})\b", raw_value)
        return dedupe_keep_order(f"CVE-{year}-{seq}" for year, seq in compact)

    def _chunk_text(self, text: str) -> List[str]:
        clean = str(text or "").strip()
        if not clean:
            return []
        if len(clean) <= self.llm_chunk_chars:
            return [clean]
        out: List[str] = []
        start = 0
        while start < len(clean) and len(out) < self.llm_max_chunks:
            out.append(clean[start : start + self.llm_chunk_chars])
            start += self.llm_chunk_chars
        return out

    def _clean_html(self, text: str) -> str:
        stripped = SCRIPT_RE.sub(" ", text)
        stripped = STYLE_RE.sub(" ", stripped)
        stripped = TAG_RE.sub(" ", stripped)
        return self._clean_text(stripped)

    def _clean_text(self, text: str) -> str:
        clean = html.unescape(str(text or ""))
        clean = clean.replace("\x00", " ")
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean

    def _extract_html_title(self, text: str) -> str:
        match = TITLE_RE.search(text or "")
        if not match:
            return ""
        return self._clean_text(match.group(1))[:200]

    def _cache_key(self, url: str) -> str:
        return hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()

    def _cache_path(self, cache_key: str) -> Path:
        return self.cache_dir / f"{cache_key}.json"

    def _read_cache(self, cache_key: str) -> Optional[Dict[str, object]]:
        path = self._cache_path(cache_key)
        with self._cache_lock:
            if not path.exists():
                return None
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return None
            if not isinstance(raw, dict):
                return None
            if int(raw.get("cache_version") or 0) != CACHE_VERSION:
                return None
            try:
                os.utime(path, None)
            except OSError:
                pass
            return raw

    def _write_cache(self, cache_key: str, payload: Dict[str, object]) -> None:
        path = self._cache_path(cache_key)
        with self._cache_lock:
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            self._writes_since_cleanup += 1
            self._cleanup_cache_locked(force=False)

    def _cleanup_cache(self, force: bool) -> None:
        with self._cache_lock:
            self._cleanup_cache_locked(force=force)

    def _cleanup_cache_locked(self, force: bool) -> None:
        if not self.cache_dir.exists():
            return
        if not force and self._writes_since_cleanup < self.cache_cleanup_every_writes:
            return

        try:
            cache_files = [path for path in self.cache_dir.glob("*.json") if path.is_file()]
        except OSError as exc:
            LOGGER.warning("Reference cache cleanup skipped: %s", exc)
            return

        removed = 0
        now = time.time()
        valid_entries: List[tuple[Path, float, int]] = []
        expire_before = now - (self.cache_max_age_days * 86400) if self.cache_max_age_days > 0 else None

        for path in cache_files:
            try:
                stat = path.stat()
            except OSError:
                continue

            if expire_before is not None and stat.st_mtime < expire_before:
                if self._delete_cache_file(path):
                    removed += 1
                continue
            valid_entries.append((path, stat.st_mtime, stat.st_size))

        valid_entries.sort(key=lambda item: item[1], reverse=True)
        total_size = sum(item[2] for item in valid_entries)

        trimmed_entries: List[tuple[Path, float, int]] = []
        kept_size = 0
        for path, mtime, size in valid_entries:
            keep_by_count = self.cache_max_files <= 0 or len(trimmed_entries) < self.cache_max_files
            keep_by_size = self.cache_max_size_bytes <= 0 or (kept_size + size) <= self.cache_max_size_bytes
            if keep_by_count and keep_by_size:
                trimmed_entries.append((path, mtime, size))
                kept_size += size
                continue
            if self._delete_cache_file(path):
                removed += 1

        self._writes_since_cleanup = 0
        if removed > 0:
            LOGGER.info(
                "Reference cache cleanup removed %s files from %s; kept=%s files, kept_size=%s bytes, previous_size=%s bytes",
                removed,
                self.cache_dir,
                len(trimmed_entries),
                kept_size,
                total_size,
            )

    def _delete_cache_file(self, path: Path) -> bool:
        try:
            path.unlink(missing_ok=True)
            return True
        except OSError as exc:
            LOGGER.warning("Failed to delete reference cache file %s: %s", path, exc)
            return False

    def _classify_reference_error(self, exc: Exception) -> str:
        if isinstance(exc, httpx.TimeoutException):
            return "timeout"
        if isinstance(exc, httpx.HTTPStatusError):
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            return f"http_{status_code}"
        if isinstance(exc, httpx.ConnectError):
            return "connection_error"
        if isinstance(exc, httpx.TransportError):
            return f"transport_error:{type(exc).__name__}"
        return str(exc) or type(exc).__name__

    def _listify(self, value: object) -> List[object]:
        if isinstance(value, list):
            return value
        if value is None or value == "":
            return []
        return [value]

    def _try_parse_json(self, text: str) -> Optional[Dict[str, object]]:
        text = str(text or "").strip()
        if not text:
            return None
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            pass
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            chunk = text[start : end + 1]
            try:
                parsed = json.loads(chunk)
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
        return None

    def _reference_signature(self, reference: Dict[str, object]) -> str:
        try:
            return json.dumps(reference, ensure_ascii=False, sort_keys=True, default=str)
        except TypeError:
            return repr(sorted((str(key), str(value)) for key, value in reference.items()))

    def _emit_tool_call(
        self,
        action: str,
        *,
        input_payload: Dict[str, object],
        output_payload: Optional[Dict[str, object]] = None,
        error: Optional[str] = None,
    ) -> None:
        if self.tool_callback is None:
            return
        self.tool_callback(
            {
                "tool": "reference_resolver",
                "action": action,
                "input": input_payload,
                "output": output_payload,
                "error": error,
            }
        )
