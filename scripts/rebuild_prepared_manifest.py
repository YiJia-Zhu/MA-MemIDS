#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Tuple


ROOT = Path("/storage/zyj_data/MA-MemIDS")
IDS_ROOT = ROOT / "IDS_dataset"
PREPARED = IDS_ROOT / "prepared"
ATTACK_DIR = PREPARED / "attack"
BENIGN_DIR = PREPARED / "benign"
MANIFEST_PATH = PREPARED / "manifest.tsv"
SYRIUS_MANIFEST_PATH = IDS_ROOT / "SYRIUS" / "manifest.tsv"
UNSW_TASKS_PATH = PREPARED / "logs" / "unsw_attack_tasks.tsv"
UNSW_RUN_LOG = PREPARED / "logs" / "unsw-syrius-run-20260413-173426.log"
CIC_RUN_LOG = PREPARED / "logs" / "split-cic-fast-20260413-114110.log"
CIC_SOURCE_DIR = IDS_ROOT / "CIC-IoT2023"


def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "na"


def packet_count(path: Path) -> str:
    proc = subprocess.run(
        ["capinfos", "-T", "-m", "-B", "-N", "-c", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    rows = [line for line in proc.stdout.splitlines() if line.strip()]
    if len(rows) < 2:
        return "0"
    cols = rows[-1].split("\t")
    if len(cols) < 3:
        return "0"
    return cols[2].strip() or "0"


def build_cic_rows() -> List[Dict[str, str]]:
    slug_to_source = {
        slugify(path.stem): path.name
        for path in sorted(CIC_SOURCE_DIR.glob("*.pcap"))
    }
    pattern = re.compile(
        r"^\[split-cic-fast\] source=(?P<source>[^ ]+) proto=(?P<proto>tcp|udp) "
        r"accepted=(?P<accepted>\d+)/\d+ session_ord=(?P<session_ord>\d+) packets=(?P<packets>\d+)$"
    )
    rows: List[Dict[str, str]] = []
    seen = set()
    with CIC_RUN_LOG.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            match = pattern.match(line)
            if match is None:
                continue
            source = match.group("source")
            proto = match.group("proto")
            output_index = int(match.group("accepted")) - 1
            session_ord = match.group("session_ord")
            packets = match.group("packets")
            safe_stem = slugify(Path(source).stem)
            sample_name = f"ciciot2023__{safe_stem}__{proto}_stream_{output_index}.pcap"
            label = "benign" if "benign" in source.lower() else "attack"
            sample_path = (BENIGN_DIR if label == "benign" else ATTACK_DIR) / sample_name
            if not sample_path.exists():
                continue
            key = str(sample_path)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "sample_path": str(sample_path),
                    "label": label,
                    "dataset": "CIC-IoT2023",
                    "source_pcap": slug_to_source.get(safe_stem, source),
                    "split_kind": f"{proto}.stream",
                    "proto": proto,
                    "packets": packets,
                    "meta": (
                        f"profile=supported_cic_aligned;stream_id={output_index};"
                        f"session_ord={session_ord};restored_from=split_cic_log"
                    ),
                }
            )
    return rows


def build_unsw_rows() -> List[Dict[str, str]]:
    task_map: Dict[int, Dict[str, str]] = {}
    with UNSW_TASKS_PATH.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for index, row in enumerate(reader, start=1):
            task_map[index] = row

    kept_pattern = re.compile(
        r"^\[extract-unsw-attacks\] result sample=(?P<sample>\d+)/\d+ "
        r"category=(?P<category>.+?) subcategory=(?P<subcategory>.+?) "
        r"status=kept source=(?P<source>[^ ]+)$"
    )
    kept_sources: Dict[int, str] = {}
    with UNSW_RUN_LOG.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            match = kept_pattern.match(line)
            if match is None:
                continue
            kept_sources[int(match.group("sample"))] = match.group("source")

    rows: List[Dict[str, str]] = []
    missing = []
    for sample_index, source_pcap in sorted(kept_sources.items()):
        task = task_map.get(sample_index)
        if task is None:
            missing.append(sample_index)
            continue
        output_name = task["output_name"]
        sample_path = ATTACK_DIR / output_name
        if not sample_path.exists():
            missing.append(sample_index)
            continue
        rows.append(
            {
                "sample_path": str(sample_path),
                "label": "attack",
                "dataset": "UNSW-NB15",
                "source_pcap": source_pcap,
                "split_kind": "gt_time_5tuple",
                "proto": task["proto"],
                "packets": "",
                "meta": (
                    "profile=supported_cic_aligned;"
                    f"category={slugify(task['attack_category'])};"
                    f"subcategory={slugify(task['attack_subcategory'])};"
                    "restored_from=unsw_run_log"
                ),
            }
        )
    if missing:
        raise SystemExit(f"failed to restore some UNSW samples: {missing[:10]}")

    def fill_packets(row: Dict[str, str]) -> Dict[str, str]:
        row["packets"] = packet_count(Path(row["sample_path"]))
        return row

    with ThreadPoolExecutor(max_workers=min(32, (os.cpu_count() or 8))) as pool:
        rows = list(pool.map(fill_packets, rows))
    return rows


def build_syrius_rows() -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    with MANIFEST_PATH.open("r", encoding="utf-8") as f:
        current_rows = list(csv.DictReader(f, delimiter="\t"))
    for row in current_rows:
        if row["dataset"] == "SYRIUS":
            rows.append(row)
    return rows


def write_manifest(rows: List[Dict[str, str]]) -> None:
    fieldnames = [
        "sample_path",
        "label",
        "dataset",
        "source_pcap",
        "split_kind",
        "proto",
        "packets",
        "meta",
    ]
    backup_path = MANIFEST_PATH.with_suffix(".tsv.bak")
    if MANIFEST_PATH.exists():
        backup_path.write_text(MANIFEST_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    rows = sorted(rows, key=lambda row: (row["dataset"], row["sample_path"]))
    with MANIFEST_PATH.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    cic_rows = build_cic_rows()
    unsw_rows = build_unsw_rows()
    syrius_rows = build_syrius_rows()
    all_rows = cic_rows + unsw_rows + syrius_rows
    write_manifest(all_rows)
    print(f"CIC-IoT2023 rows: {len(cic_rows)}")
    print(f"UNSW-NB15 rows: {len(unsw_rows)}")
    print(f"SYRIUS rows: {len(syrius_rows)}")
    print(f"Total rows: {len(all_rows)}")
    print(f"Manifest: {MANIFEST_PATH}")
    print(f"Backup: {MANIFEST_PATH.with_suffix('.tsv.bak')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
