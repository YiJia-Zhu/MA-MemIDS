#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

MANIFEST="${MANIFEST:-$ROOT_DIR/IDS_dataset/prepared/manifest.tsv}"
CURRENT_RULES="${CURRENT_RULES:-$ROOT_DIR/rules}"
FULL_RULES_TAR="${FULL_RULES_TAR:-$ROOT_DIR/emerging.rules.tar.gz}"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/output/full_rules_exact_compare}"
MINIMAL_RULES_DIR="${MINIMAL_RULES_DIR:-$OUTPUT_DIR/minimal_ruleset}"
UNMATCHED_DIR="${UNMATCHED_DIR:-$ROOT_DIR/IDS_dataset/prepared/fullrules_unmatched}"
SURICATA_BIN="${SURICATA_BIN:-/usr/bin/suricata}"
SURICATA_CONFIG="${SURICATA_CONFIG:-/etc/suricata/suricata.yaml}"
MERGECAP_BIN="${MERGECAP_BIN:-/usr/bin/mergecap}"
FORCE="${FORCE:-1}"

usage() {
  cat <<EOF
Usage:
  bash scripts/run_exact_rule_subset_compare.sh [--force]

Behavior:
  1. Exact replay comparison between:
     - current rules/ directory
     - full Emerging Threats tarball
  2. Derive the smallest full-equivalent ruleset for the current prepared dataset
  3. Export all samples unmatched even by the full ruleset, plus labels.tsv

Default inputs:
  MANIFEST=$MANIFEST
  CURRENT_RULES=$CURRENT_RULES
  FULL_RULES_TAR=$FULL_RULES_TAR
  OUTPUT_DIR=$OUTPUT_DIR
  MINIMAL_RULES_DIR=$MINIMAL_RULES_DIR
  UNMATCHED_DIR=$UNMATCHED_DIR
  SURICATA_BIN=$SURICATA_BIN
  SURICATA_CONFIG=$SURICATA_CONFIG
  MERGECAP_BIN=$MERGECAP_BIN

Environment overrides:
  MANIFEST=...
  CURRENT_RULES=...
  FULL_RULES_TAR=...
  OUTPUT_DIR=...
  MINIMAL_RULES_DIR=...
  UNMATCHED_DIR=...
  SURICATA_BIN=...
  SURICATA_CONFIG=...
  MERGECAP_BIN=...
  FORCE=1

Examples:
  bash scripts/run_exact_rule_subset_compare.sh
  FORCE=1 bash scripts/run_exact_rule_subset_compare.sh
  MANIFEST=/path/to/manifest.tsv bash scripts/run_exact_rule_subset_compare.sh --force
EOF
}

need_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "missing required file: $path" >&2
    exit 1
  fi
}

need_path() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    echo "missing required path: $path" >&2
    exit 1
  fi
}

need_cmd() {
  local cmd="$1"
  if [[ ! -x "$cmd" ]]; then
    echo "missing required executable: $cmd" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

need_file "$MANIFEST"
need_path "$CURRENT_RULES"
need_file "$FULL_RULES_TAR"
need_cmd "$SURICATA_BIN"
need_cmd "$MERGECAP_BIN"
need_file "$SURICATA_CONFIG"

cd "$ROOT_DIR"

echo "[run] exact full-vs-current rule replay"
echo "[run] manifest=$MANIFEST"
echo "[run] current_rules=$CURRENT_RULES"
echo "[run] full_rules_tar=$FULL_RULES_TAR"
echo "[run] output_dir=$OUTPUT_DIR"
echo "[run] unmatched_dir=$UNMATCHED_DIR"

PY_ARGS=(
  "scripts/derive_minimal_full_rule_subset.py"
  "--manifest" "$MANIFEST"
  "--current-rules" "$CURRENT_RULES"
  "--full-rules-tar" "$FULL_RULES_TAR"
  "--output-dir" "$OUTPUT_DIR"
  "--minimal-rules-dir" "$MINIMAL_RULES_DIR"
  "--unmatched-dir" "$UNMATCHED_DIR"
  "--suricata" "$SURICATA_BIN"
  "--suricata-config" "$SURICATA_CONFIG"
  "--mergecap" "$MERGECAP_BIN"
)

if [[ "$FORCE" == "1" ]]; then
  PY_ARGS+=("--force")
fi

python -u "${PY_ARGS[@]}"

SUMMARY_PATH="$OUTPUT_DIR/summary.json"
if [[ ! -f "$SUMMARY_PATH" ]]; then
  echo "expected summary not found: $SUMMARY_PATH" >&2
  exit 1
fi

echo
echo "[done] exact comparison finished"
python - <<PY
import json
from pathlib import Path

summary = json.loads(Path("$SUMMARY_PATH").read_text(encoding="utf-8"))
current_vs_full = summary["current_vs_full"]
minimal = summary["minimal_ruleset"]
unmatched = summary["full_unmatched_subset"]

print(f"sample_count={summary['sample_count']}")
print(f"full_rule_count={summary['full_rule_count']}")
print(f"current_rule_count={summary['current_rule_count']}")
print(f"current_vs_full_equivalent={current_vs_full['equivalent']}")
print(f"current_vs_full_mismatched_pcaps={current_vs_full['mismatched_pcaps']}")
print(f"selected_candidate={summary['selected_candidate']}")
print(f"minimal_rule_count={minimal['rule_count']}")
print(f"minimal_ruleset_dir={minimal['dir']}")
print(f"unmatched_total={unmatched['total']}")
print(f"unmatched_attack={unmatched['attack']}")
print(f"unmatched_benign={unmatched['benign']}")
print(f"unmatched_dir={unmatched['dir']}")
print(f"summary_path={Path('$SUMMARY_PATH').resolve()}")
print(f"labels_path={Path('$UNMATCHED_DIR/labels.tsv').resolve()}")
print(f"manifest_path={Path('$UNMATCHED_DIR/manifest.tsv').resolve()}")
PY
