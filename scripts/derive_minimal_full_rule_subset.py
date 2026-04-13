#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bisect
import csv
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


RULE_LINE_RE = re.compile(r"^(alert|drop|pass|reject)\s+", re.IGNORECASE)
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)", re.IGNORECASE)
FLOWBITS_RE = re.compile(r"\bflowbits\s*:\s*([^;]+)", re.IGNORECASE)
XBITS_RE = re.compile(r"\bxbits\s*:\s*([^;]+)", re.IGNORECASE)
FLOWINT_RE = re.compile(r"\bflowint\s*:\s*([^;]+)", re.IGNORECASE)

KNOWN_FLOWBIT_FLAGS = {
    "noalert",
    "reset",
    "toggle",
    "set",
    "unset",
    "isset",
    "isnotset",
}


@dataclass(frozen=True)
class Sample:
    row_index: int
    sample_path: str
    label: str
    dataset: str
    source_pcap: str
    split_kind: str
    proto: str
    packets: int
    meta: str


@dataclass(frozen=True)
class RuleRecord:
    index: int
    source_file: str
    line_no: int
    text: str
    sid: Optional[int]
    state_names: Tuple[str, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Derive a minimal full-rule subset that preserves exact alerts on the prepared dataset.")
    parser.add_argument("--manifest", default="IDS_dataset/prepared/manifest.tsv", help="Prepared manifest TSV.")
    parser.add_argument("--current-rules", default="rules", help="Current rule directory or rule file.")
    parser.add_argument("--full-rules-tar", default="emerging.rules.tar.gz", help="Full EmergingThreats rules tarball.")
    parser.add_argument("--output-dir", default="output/full_rules_exact_compare", help="Output directory for caches and reports.")
    parser.add_argument(
        "--minimal-rules-dir",
        default="output/full_rules_exact_compare/minimal_ruleset",
        help="Directory to write the validated minimal full-equivalent ruleset.",
    )
    parser.add_argument(
        "--unmatched-dir",
        default="IDS_dataset/prepared/fullrules_unmatched",
        help="Directory to export flows unmatched even by the full ruleset.",
    )
    parser.add_argument("--suricata", default="/usr/bin/suricata", help="Suricata binary path.")
    parser.add_argument("--suricata-config", default="/etc/suricata/suricata.yaml", help="Suricata config path.")
    parser.add_argument("--mergecap", default="/usr/bin/mergecap", help="mergecap binary path.")
    parser.add_argument("--force", action="store_true", help="Rebuild merged pcap and rerun cached replays.")
    return parser.parse_args()


def read_manifest(path: Path) -> List[Sample]:
    rows: List[Sample] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for idx, row in enumerate(reader):
            rows.append(
                Sample(
                    row_index=idx,
                    sample_path=row["sample_path"],
                    label=row["label"],
                    dataset=row["dataset"],
                    source_pcap=row["source_pcap"],
                    split_kind=row["split_kind"],
                    proto=row["proto"],
                    packets=int(row["packets"]),
                    meta=row.get("meta", ""),
                )
            )
    return rows


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def run(cmd: Sequence[str], *, cwd: Optional[Path] = None) -> None:
    proc = subprocess.run(
        list(cmd),
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )


def merge_dataset_pcaps(samples: Sequence[Sample], mergecap_path: str, merged_pcap: Path, metadata_path: Path, *, force: bool) -> None:
    current_meta = {
        "sample_paths": [s.sample_path for s in samples],
        "packets": [s.packets for s in samples],
    }
    if merged_pcap.exists() and metadata_path.exists() and not force:
        try:
            existing = json.loads(metadata_path.read_text(encoding="utf-8"))
        except Exception:
            existing = None
        if existing == current_meta:
            return

    ensure_dir(merged_pcap.parent)
    if merged_pcap.exists():
        merged_pcap.unlink()
    cmd = [mergecap_path, "-a", "-w", str(merged_pcap)]
    cmd.extend(str(Path(s.sample_path)) for s in samples)
    run(cmd)
    metadata_path.write_text(json.dumps(current_meta, ensure_ascii=False, indent=2), encoding="utf-8")


def _parse_state_names(rule_text: str) -> Tuple[str, ...]:
    state_names: Set[str] = set()

    for raw in FLOWBITS_RE.findall(rule_text):
        parts = [part.strip() for part in raw.split(",") if part.strip()]
        if not parts:
            continue
        for name in parts[1:]:
            lowered = name.lower()
            if lowered in KNOWN_FLOWBIT_FLAGS:
                continue
            state_names.add(f"flowbits:{name}")

    for raw in XBITS_RE.findall(rule_text):
        parts = [part.strip() for part in raw.split(",") if part.strip()]
        if len(parts) >= 2:
            state_names.add(f"xbits:{parts[1]}")

    for raw in FLOWINT_RE.findall(rule_text):
        parts = [part.strip() for part in raw.split(",") if part.strip()]
        if parts:
            state_names.add(f"flowint:{parts[0]}")

    return tuple(sorted(state_names))


def collect_rule_records(path: Path) -> List[RuleRecord]:
    records: List[RuleRecord] = []

    def iter_rule_files(base: Path) -> Iterable[Path]:
        if base.is_file():
            yield base
            return
        for child in sorted(base.rglob("*")):
            if child.is_file() and child.suffix.lower() in {".rules", ".rule", ".txt"}:
                yield child

    for rule_file in iter_rule_files(path):
        rel = str(rule_file.relative_to(path if path.is_dir() else rule_file.parent))
        for line_no, line in enumerate(rule_file.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            rule = line.strip()
            if not rule or rule.startswith("#") or not RULE_LINE_RE.match(rule):
                continue
            sid_match = SID_RE.search(rule)
            sid = int(sid_match.group(1)) if sid_match else None
            records.append(
                RuleRecord(
                    index=len(records),
                    source_file=rel,
                    line_no=line_no,
                    text=rule,
                    sid=sid,
                    state_names=_parse_state_names(rule),
                )
            )
    if not records:
        raise ValueError(f"No active rules found under {path}")
    return records


def write_rule_file(records: Sequence[RuleRecord], selected_indices: Sequence[int], output_path: Path) -> None:
    ensure_dir(output_path.parent)
    with output_path.open("w", encoding="utf-8") as f:
        for idx in sorted(selected_indices):
            f.write(records[idx].text)
            f.write("\n")


def sample_packet_ends(samples: Sequence[Sample]) -> List[int]:
    ends: List[int] = []
    total = 0
    for sample in samples:
        total += sample.packets
        ends.append(total)
    return ends


def replay_rules(
    *,
    suricata_path: str,
    suricata_config: str,
    merged_pcap: Path,
    rule_file: Path,
    samples: Sequence[Sample],
    cache_path: Path,
    force: bool,
) -> Dict[str, Counter]:
    if cache_path.exists() and not force:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
        return {key: Counter({int(k): int(v) for k, v in value.items()}) for key, value in raw.items()}

    ensure_dir(cache_path.parent)
    ends = sample_packet_ends(samples)
    results: Dict[str, Counter] = {sample.sample_path: Counter() for sample in samples}

    with tempfile.TemporaryDirectory(prefix="suricata-replay-") as log_dir:
        proc = subprocess.run(
            [
                suricata_path,
                "-r",
                str(merged_pcap),
                "-S",
                str(rule_file),
                "-c",
                suricata_config,
                "-l",
                log_dir,
                "--runmode",
                "single",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"Suricata replay failed for {rule_file}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
            )

        eve_path = Path(log_dir) / "eve.json"
        if not eve_path.exists():
            raise FileNotFoundError(f"Expected eve.json not found in {log_dir}")

        with eve_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") != "alert":
                    continue
                pcap_cnt = event.get("pcap_cnt")
                sid = (((event.get("alert") or {}).get("signature_id")))
                if not isinstance(pcap_cnt, int) or not isinstance(sid, int):
                    continue
                sample_idx = bisect.bisect_left(ends, pcap_cnt)
                if sample_idx >= len(samples):
                    raise IndexError(f"pcap_cnt {pcap_cnt} out of range for merged packet boundaries")
                results[samples[sample_idx].sample_path][sid] += 1

    serializable = {sample_path: dict(sorted(counter.items())) for sample_path, counter in results.items()}
    cache_path.write_text(json.dumps(serializable, ensure_ascii=False, indent=2), encoding="utf-8")
    return results


def summarize_differences(reference: Dict[str, Counter], candidate: Dict[str, Counter]) -> List[Dict[str, object]]:
    diffs: List[Dict[str, object]] = []
    for sample_path in reference:
        ref = reference[sample_path]
        cand = candidate.get(sample_path, Counter())
        if ref == cand:
            continue
        missing = {}
        extra = {}
        for sid in sorted(set(ref) | set(cand)):
            rv = ref.get(sid, 0)
            cv = cand.get(sid, 0)
            if rv > cv:
                missing[sid] = rv - cv
            elif cv > rv:
                extra[sid] = cv - rv
        diffs.append(
            {
                "sample_path": sample_path,
                "reference_alert_count": int(sum(ref.values())),
                "candidate_alert_count": int(sum(cand.values())),
                "missing": missing,
                "extra": extra,
            }
        )
    return diffs


def exact_equal(reference: Dict[str, Counter], candidate: Dict[str, Counter]) -> bool:
    return not summarize_differences(reference, candidate)


def compute_state_closure(seed_indices: Set[int], rules: Sequence[RuleRecord]) -> Set[int]:
    selected = set(seed_indices)
    state_names: Set[str] = set()
    for idx in selected:
        state_names.update(rules[idx].state_names)

    changed = True
    while changed:
        changed = False
        for rule in rules:
            if rule.index in selected:
                continue
            if state_names.intersection(rule.state_names):
                selected.add(rule.index)
                state_names.update(rule.state_names)
                changed = True
    return selected


def ddmin_helpers(
    *,
    suricata_path: str,
    suricata_config: str,
    merged_pcap: Path,
    samples: Sequence[Sample],
    rules: Sequence[RuleRecord],
    base_indices: Set[int],
    helper_indices: Sequence[int],
    reference_results: Dict[str, Counter],
    cache_dir: Path,
) -> Set[int]:
    if not helper_indices:
        return set()

    validation_cache: Dict[Tuple[int, ...], bool] = {}

    def is_valid(helpers: Sequence[int]) -> bool:
        key = tuple(sorted(helpers))
        if key in validation_cache:
            return validation_cache[key]
        rule_file = cache_dir / f"candidate_{len(validation_cache):04d}.rules"
        chosen = sorted(base_indices.union(helpers))
        write_rule_file(rules, chosen, rule_file)
        replay_cache = cache_dir / f"candidate_{len(validation_cache):04d}.json"
        result = replay_rules(
            suricata_path=suricata_path,
            suricata_config=suricata_config,
            merged_pcap=merged_pcap,
            rule_file=rule_file,
            samples=samples,
            cache_path=replay_cache,
            force=False,
        )
        ok = exact_equal(reference_results, result)
        validation_cache[key] = ok
        return ok

    current = sorted(helper_indices)
    n = 2
    while len(current) >= 1:
        if len(current) == 1:
            if is_valid([]):
                return set()
            return set(current)
        chunk_size = max(1, len(current) // n)
        some_progress = False
        chunks = [current[i : i + chunk_size] for i in range(0, len(current), chunk_size)]
        for chunk in chunks:
            complement = [idx for idx in current if idx not in set(chunk)]
            if is_valid(complement):
                current = complement
                n = max(2, n - 1)
                some_progress = True
                break
        if some_progress:
            continue
        if n >= len(current):
            break
        n = min(len(current), n * 2)
    return set(current)


def export_unmatched_subset(samples: Sequence[Sample], full_results: Dict[str, Counter], output_dir: Path) -> Dict[str, int]:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    ensure_dir(output_dir / "attack")
    ensure_dir(output_dir / "benign")

    manifest_path = output_dir / "manifest.tsv"
    labels_path = output_dir / "labels.tsv"
    fieldnames = ["sample_path", "label", "dataset", "source_pcap", "split_kind", "proto", "packets", "meta"]
    stats = {"total": 0, "attack": 0, "benign": 0}

    with (
        manifest_path.open("w", encoding="utf-8", newline="") as manifest_f,
        labels_path.open("w", encoding="utf-8", newline="") as labels_f,
    ):
        writer = csv.DictWriter(manifest_f, fieldnames=fieldnames, delimiter="\t")
        label_writer = csv.DictWriter(labels_f, fieldnames=["sample_path", "label"], delimiter="\t")
        writer.writeheader()
        label_writer.writeheader()
        for sample in samples:
            if full_results.get(sample.sample_path):
                continue
            label_dir = output_dir / sample.label
            dst_path = label_dir / Path(sample.sample_path).name
            try:
                os.link(sample.sample_path, dst_path)
            except OSError:
                shutil.copy2(sample.sample_path, dst_path)
            resolved_dst = str(dst_path.resolve())
            writer.writerow(
                {
                    "sample_path": resolved_dst,
                    "label": sample.label,
                    "dataset": sample.dataset,
                    "source_pcap": sample.source_pcap,
                    "split_kind": sample.split_kind,
                    "proto": sample.proto,
                    "packets": sample.packets,
                    "meta": (sample.meta + ";full_rules_alerts=0").strip(";"),
                }
            )
            label_writer.writerow({"sample_path": resolved_dst, "label": sample.label})
            stats["total"] += 1
            stats[sample.label] += 1
    return stats


def write_minimal_ruleset(
    *,
    rules: Sequence[RuleRecord],
    selected_indices: Set[int],
    full_extract_rules_dir: Path,
    output_dir: Path,
) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    ensure_dir(output_dir)

    write_rule_file(rules, sorted(selected_indices), output_dir / "minimal.rules")

    selected_sids = {rules[idx].sid for idx in selected_indices if rules[idx].sid is not None}
    sid_map_src = full_extract_rules_dir / "sid-msg.map"
    if sid_map_src.exists():
        kept_lines = []
        for line in sid_map_src.read_text(encoding="utf-8", errors="ignore").splitlines():
            sid_match = re.match(r"^(\d+)\s+\|\|", line)
            if sid_match and int(sid_match.group(1)) in selected_sids:
                kept_lines.append(line)
        (output_dir / "sid-msg.map").write_text("\n".join(kept_lines) + ("\n" if kept_lines else ""), encoding="utf-8")

    for aux in ["classification.config", "LICENSE", "BSD-License.txt", "gpl-2.0.txt", "suricata-5.0-enhanced-open.txt"]:
        src = full_extract_rules_dir / aux
        if src.exists():
            shutil.copy2(src, output_dir / aux)

    metadata = {
        "rule_count": len(selected_indices),
        "sid_count": len(selected_sids),
        "source_files": sorted({rules[idx].source_file for idx in selected_indices}),
    }
    (output_dir / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    args = parse_args()

    manifest_path = Path(args.manifest).resolve()
    current_rules_path = Path(args.current_rules).resolve()
    full_rules_tar = Path(args.full_rules_tar).resolve()
    output_dir = Path(args.output_dir).resolve()
    minimal_rules_dir = Path(args.minimal_rules_dir).resolve()
    unmatched_dir = Path(args.unmatched_dir).resolve()

    ensure_dir(output_dir)

    samples = read_manifest(manifest_path)
    merged_pcap = output_dir / "prepared_dataset_merged.pcap"
    merged_meta = output_dir / "prepared_dataset_merged.json"
    merge_dataset_pcaps(samples, args.mergecap, merged_pcap, merged_meta, force=args.force)

    with tempfile.TemporaryDirectory(prefix="full-rules-") as td:
        td_path = Path(td)
        with tarfile.open(full_rules_tar, "r:gz") as tf:
            tf.extractall(td_path)
        full_extract_rules_dir = td_path / "rules"

        full_rules = collect_rule_records(full_extract_rules_dir)
        current_rules = collect_rule_records(current_rules_path)

        full_rule_file = output_dir / "full.rules"
        current_rule_file = output_dir / "current.rules"
        write_rule_file(full_rules, [rule.index for rule in full_rules], full_rule_file)
        write_rule_file(current_rules, [rule.index for rule in current_rules], current_rule_file)

        print(f"[info] samples={len(samples)} merged_pcap={merged_pcap}")
        print(f"[info] full_rules={len(full_rules)} current_rules={len(current_rules)}")

        full_results = replay_rules(
            suricata_path=args.suricata,
            suricata_config=args.suricata_config,
            merged_pcap=merged_pcap,
            rule_file=full_rule_file,
            samples=samples,
            cache_path=output_dir / "full_results.json",
            force=args.force,
        )
        current_results = replay_rules(
            suricata_path=args.suricata,
            suricata_config=args.suricata_config,
            merged_pcap=merged_pcap,
            rule_file=current_rule_file,
            samples=samples,
            cache_path=output_dir / "current_results.json",
            force=args.force,
        )

        unmatched_stats = export_unmatched_subset(samples, full_results, unmatched_dir)
        print(f"[info] unmatched_full_rules total={unmatched_stats['total']} attack={unmatched_stats['attack']} benign={unmatched_stats['benign']}")

        current_diffs = summarize_differences(full_results, current_results)
        print(f"[info] current_vs_full mismatched_pcaps={len(current_diffs)}")

        observed_alert_sids = sorted({sid for counter in full_results.values() for sid in counter})
        producer_indices = {rule.index for rule in full_rules if rule.sid in observed_alert_sids}
        print(f"[info] observed_alert_sids={len(observed_alert_sids)} producer_rules={len(producer_indices)}")

        candidate_defs: List[Tuple[str, Set[int]]] = []
        candidate_defs.append(("producers_only", set(producer_indices)))
        candidate_defs.append(("producers_plus_state_closure", compute_state_closure(set(producer_indices), full_rules)))
        producer_files = {full_rules[idx].source_file for idx in producer_indices}
        candidate_defs.append(("producer_source_files", {rule.index for rule in full_rules if rule.source_file in producer_files}))
        candidate_defs.append(("producer_source_files_plus_state_closure", compute_state_closure(candidate_defs[-1][1], full_rules)))
        candidate_defs.append(("all_full_rules", {rule.index for rule in full_rules}))

        best_name: Optional[str] = None
        best_indices: Optional[Set[int]] = None
        candidate_reports = []

        for candidate_name, candidate_indices in candidate_defs:
            rule_file = output_dir / f"{candidate_name}.rules"
            result_file = output_dir / f"{candidate_name}_results.json"
            write_rule_file(full_rules, sorted(candidate_indices), rule_file)
            candidate_results = replay_rules(
                suricata_path=args.suricata,
                suricata_config=args.suricata_config,
                merged_pcap=merged_pcap,
                rule_file=rule_file,
                samples=samples,
                cache_path=result_file,
                force=args.force,
            )
            diffs = summarize_differences(full_results, candidate_results)
            candidate_reports.append(
                {
                    "name": candidate_name,
                    "rule_count": len(candidate_indices),
                    "mismatched_pcaps": len(diffs),
                }
            )
            print(f"[info] candidate={candidate_name} rule_count={len(candidate_indices)} mismatched_pcaps={len(diffs)}")
            if not diffs:
                best_name = candidate_name
                best_indices = set(candidate_indices)
                break

        if best_name is None or best_indices is None:
            raise RuntimeError("Failed to find any full-equivalent subset candidate, even all_full_rules unexpectedly mismatched.")

        helper_indices = sorted(best_indices - producer_indices)
        helper_pruned = False
        if best_name != "producers_only" and best_name != "all_full_rules" and helper_indices and len(helper_indices) <= 512:
            print(f"[info] attempting_helper_prune helper_rules={len(helper_indices)}")
            pruned_helpers = ddmin_helpers(
                suricata_path=args.suricata,
                suricata_config=args.suricata_config,
                merged_pcap=merged_pcap,
                samples=samples,
                rules=full_rules,
                base_indices=producer_indices,
                helper_indices=helper_indices,
                reference_results=full_results,
                cache_dir=output_dir / "helper_prune",
            )
            pruned_indices = set(producer_indices).union(pruned_helpers)
            rule_file = output_dir / "pruned_candidate.rules"
            write_rule_file(full_rules, sorted(pruned_indices), rule_file)
            pruned_results = replay_rules(
                suricata_path=args.suricata,
                suricata_config=args.suricata_config,
                merged_pcap=merged_pcap,
                rule_file=rule_file,
                samples=samples,
                cache_path=output_dir / "pruned_candidate_results.json",
                force=args.force,
            )
            if exact_equal(full_results, pruned_results):
                best_name = f"{best_name}_pruned"
                best_indices = pruned_indices
                helper_pruned = True
                print(f"[info] helper_prune_success remaining_helpers={len(pruned_helpers)}")
            else:
                print("[info] helper_prune_kept_original")

        write_minimal_ruleset(
            rules=full_rules,
            selected_indices=best_indices,
            full_extract_rules_dir=full_extract_rules_dir,
            output_dir=minimal_rules_dir,
        )

        minimal_rule_file = minimal_rules_dir / "minimal.rules"
        minimal_results = replay_rules(
            suricata_path=args.suricata,
            suricata_config=args.suricata_config,
            merged_pcap=merged_pcap,
            rule_file=minimal_rule_file,
            samples=samples,
            cache_path=output_dir / "minimal_results.json",
            force=args.force,
        )
        minimal_diffs = summarize_differences(full_results, minimal_results)
        if minimal_diffs:
            raise RuntimeError(f"Written minimal ruleset is not equivalent to full rules. mismatches={len(minimal_diffs)}")

        report = {
            "manifest": str(manifest_path),
            "sample_count": len(samples),
            "merged_pcap": str(merged_pcap),
            "full_rule_count": len(full_rules),
            "current_rule_count": len(current_rules),
            "current_vs_full": {
                "equivalent": len(current_diffs) == 0,
                "mismatched_pcaps": len(current_diffs),
                "first_mismatches": current_diffs[:20],
            },
            "full_unmatched_subset": {
                "dir": str(unmatched_dir),
                "total": unmatched_stats["total"],
                "attack": unmatched_stats["attack"],
                "benign": unmatched_stats["benign"],
            },
            "observed_alert_sids": len(observed_alert_sids),
            "producer_rule_count": len(producer_indices),
            "candidate_reports": candidate_reports,
            "selected_candidate": best_name,
            "minimal_ruleset": {
                "dir": str(minimal_rules_dir),
                "rule_count": len(best_indices),
                "helper_rules": len(best_indices - producer_indices),
                "helper_pruned": helper_pruned,
                "equivalent_to_full": True,
            },
        }
        report_path = output_dir / "summary.json"
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[done] summary={report_path}")
        print(f"[done] minimal_ruleset={minimal_rules_dir}")
        print(f"[done] unmatched_subset={unmatched_dir}")


if __name__ == "__main__":
    main()
