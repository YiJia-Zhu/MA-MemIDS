#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import List

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False

from ma_memids.pipeline import MAMemIDSPipeline
from ma_memids.embedding import SentenceTransformerEmbedder
from ma_memids.knowledge import (
    DualPathRetriever,
    load_knowledge_source_registry,
    save_knowledge_source_registry,
)


def _split_csv(value: str) -> List[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


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

    process_cmd = sub.add_parser("process", help="Stage-2 process unmatched traffic")
    process_cmd.add_argument("--pcap", default="", help="Unmatched traffic PCAP path")
    process_cmd.add_argument("--traffic-text", default="", help="Structured traffic summary text")
    process_cmd.add_argument("--attack-pcaps", default="", help="CSV list of attack pcaps for sandbox replay")
    process_cmd.add_argument("--benign-pcaps", default="", help="CSV list of benign pcaps for FPR estimation")
    process_cmd.add_argument("--override-intent", default="", help="Manual override for inferred intent")
    process_cmd.add_argument("--override-tactics", default="", help="CSV tactics override, e.g. T1190,T1059")
    process_cmd.add_argument("--override-keywords", default="", help="CSV keywords override")

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


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    load_dotenv()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

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

    if args.command == "init":
        max_rules = args.max_rules if args.max_rules > 0 else None
        count = pipeline.initialize_from_rules_file(args.rules, max_rules=max_rules)
        print(f"Initialized {count} rule notes")
        return

    if args.command == "process":
        override = {}
        if args.override_intent:
            override["intent"] = args.override_intent
        if args.override_tactics:
            override["tactics"] = _split_csv(args.override_tactics)
        if args.override_keywords:
            override["keywords"] = _split_csv(args.override_keywords)
        attack_pcaps = _split_csv(args.attack_pcaps)
        benign_pcaps = _split_csv(args.benign_pcaps)

        result = pipeline.process_unmatched_traffic(
            pcap_path=args.pcap or None,
            traffic_text=args.traffic_text or None,
            attack_pcaps=(attack_pcaps or None),
            benign_pcaps=(benign_pcaps or None),
            human_override=override or None,
        )
        print(json.dumps(result.__dict__, ensure_ascii=False, indent=2))
        return

    if args.command == "export":
        count = pipeline.export_ruleset(args.output)
        print(f"Exported {count} rules to {args.output}")
        return

    if args.command == "stats":
        print(json.dumps(pipeline.stats(), ensure_ascii=False, indent=2))
        return


if __name__ == "__main__":
    main()
