#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from tqdm.auto import tqdm

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ma_memids.embedding import SentenceTransformerEmbedder
from ma_memids.knowledge import DualPathRetriever, save_knowledge_source_registry


class BuildProgressReporter:
    def __init__(self):
        self._bars: dict[tuple[str, str], tqdm] = {}

    def __call__(self, payload: dict[str, object]) -> None:
        event = str(payload.get("event") or "")
        source = str(payload.get("source") or "knowledge")
        stage = str(payload.get("stage") or "")
        key = (source, stage)

        if event == "source_start":
            tqdm.write(f"[{source}] start: {payload.get('path')}")
            return
        if event == "cache_reuse":
            tqdm.write(f"[{source}] reuse cache: docs={payload.get('doc_count')} path={payload.get('path')}")
            return
        if event == "source_done":
            tqdm.write(f"[{source}] done: docs={payload.get('doc_count')} path={payload.get('path')}")
            return
        if event == "stage":
            tqdm.write(f"[{source}] {payload.get('message')}")
            return
        if event == "progress_start":
            bar = self._bars.get(key)
            if bar is not None:
                bar.close()
            self._bars[key] = tqdm(
                total=payload.get("total"),
                desc=f"{source}:{stage}",
                unit=str(payload.get("unit") or "it"),
                leave=True,
            )
            return
        if event == "progress_update":
            bar = self._bars.get(key)
            if bar is not None:
                bar.update(int(payload.get("advance") or 0))
            return
        if event == "progress_end":
            bar = self._bars.pop(key, None)
            if bar is not None:
                total = payload.get("total")
                if isinstance(total, int) and bar.total is not None:
                    remaining = min(total, bar.total) - bar.n
                    if remaining > 0:
                        bar.update(remaining)
                bar.close()

    def close(self) -> None:
        for bar in self._bars.values():
            bar.close()
        self._bars.clear()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build MA-MemIDS hybrid knowledge indexes")
    parser.add_argument("--attack-kb", default="", help="ATT&CK STIX file or directory path")
    parser.add_argument("--cve-kb", default="", help="CVE JSON file or directory path")
    parser.add_argument("--cti-kb", default="", help="Generic CTI JSON/JSONL file or directory path")
    parser.add_argument("--cache-dir", default="./memory/knowledge_cache", help="Knowledge cache directory")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    cache_dir = Path(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    embedder = SentenceTransformerEmbedder()
    retriever = DualPathRetriever(embedder=embedder, cache_dir=str(cache_dir))
    reporter = BuildProgressReporter()
    try:
        retriever.load_knowledge(
            cve_path=args.cve_kb or None,
            attack_path=args.attack_kb or None,
            cti_path=args.cti_kb or None,
            progress_callback=reporter,
        )
    finally:
        reporter.close()
    registry_path = save_knowledge_source_registry(
        cache_dir,
        cve_path=args.cve_kb or None,
        attack_path=args.attack_kb or None,
        cti_path=args.cti_kb or None,
    )
    print(f"knowledge source registry: {registry_path}")
    print(json.dumps(retriever.stats(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
