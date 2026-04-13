#!/usr/bin/env bash
set -euo pipefail

# FORCE=1 PARALLEL_JOBS=16 bash scripts/prepare_ids_datasets.sh split-cic
# FORCE=1 PARALLEL_JOBS=16 bash scripts/prepare_ids_datasets.sh extract-unsw-attacks

ACTION="${1:-all}"
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

ROOT_DIR="${ROOT_DIR:-/storage/zyj_data/MA-MemIDS/IDS_dataset}"
UNSW_DIR="${UNSW_DIR:-$ROOT_DIR/UNSW}"
CIC_DIR="${CIC_DIR:-$ROOT_DIR/CIC-IoT2023}"
SYRIUS_SRC_DIR="${SYRIUS_SRC_DIR:-/storage/zyj_data/syrius/syrius/Datasets}"
SYRIUS_DIR="${SYRIUS_DIR:-$ROOT_DIR/SYRIUS}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/prepared}"

UNSW_ENET_DIR="${UNSW_ENET_DIR:-$OUT_DIR/unsw_enet}"
ATTACK_DIR="${ATTACK_DIR:-$OUT_DIR/attack}"
BENIGN_DIR="${BENIGN_DIR:-$OUT_DIR/benign}"
LOG_DIR="${LOG_DIR:-$OUT_DIR/logs}"
MANIFEST_PATH="${MANIFEST_PATH:-$OUT_DIR/manifest.tsv}"
SYRIUS_RAW_DIR="${SYRIUS_RAW_DIR:-$SYRIUS_DIR/raw}"
SYRIUS_CURATED_ATTACK_DIR="${SYRIUS_CURATED_ATTACK_DIR:-$SYRIUS_DIR/curated/attack}"
SYRIUS_CURATED_BENIGN_DIR="${SYRIUS_CURATED_BENIGN_DIR:-$SYRIUS_DIR/curated/benign}"
SYRIUS_CURATED_AMBIGUOUS_DIR="${SYRIUS_CURATED_AMBIGUOUS_DIR:-$SYRIUS_DIR/curated/ambiguous}"
SYRIUS_MANIFEST_PATH="${SYRIUS_MANIFEST_PATH:-$SYRIUS_DIR/manifest.tsv}"

MAX_CIC_TCP_STREAMS_PER_FILE="${MAX_CIC_TCP_STREAMS_PER_FILE:-50}"
MAX_CIC_UDP_STREAMS_PER_FILE="${MAX_CIC_UDP_STREAMS_PER_FILE:-50}"
MAX_UNSW_EVENTS="${MAX_UNSW_EVENTS:-500}"
SYRIUS_MAX_BENIGN_HTTP_STREAMS="${SYRIUS_MAX_BENIGN_HTTP_STREAMS:-50}"
UNSW_REWRITE_LIMIT="${UNSW_REWRITE_LIMIT:-0}"
MIN_PACKETS="${MIN_PACKETS:-5}"
TIME_SLACK_SECONDS="${TIME_SLACK_SECONDS:-1}"
FORCE="${FORCE:-0}"
REQUIRE_ETHERNET="${REQUIRE_ETHERNET:-1}"
REQUIRE_SINGLE_FLOW="${REQUIRE_SINGLE_FLOW:-1}"
REQUIRE_BIDIRECTIONAL="${REQUIRE_BIDIRECTIONAL:-1}"
REJECT_LOG_PATH="${REJECT_LOG_PATH:-$LOG_DIR/rejected.tsv}"
PROFILE="${PROFILE:-supported_cic_aligned}"
VERBOSE_PROGRESS="${VERBOSE_PROGRESS:-1}"
REQUIRE_ATTACK_SEMANTICS="${REQUIRE_ATTACK_SEMANTICS:-1}"
PARALLEL_JOBS="${PARALLEL_JOBS:-1}"
PREPARE_BACKEND="${PREPARE_BACKEND:-python}"
MANIFEST_LOCK_PATH="${MANIFEST_LOCK_PATH:-$LOG_DIR/manifest.lock}"
REJECT_LOCK_PATH="${REJECT_LOCK_PATH:-$LOG_DIR/rejected.lock}"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/prepare_ids_datasets.sh [all|rewrite-unsw|split-cic|extract-unsw-attacks|copy-syrius|prepare-syrius]

Outputs:
  IDS_dataset/prepared/
    attack/         # attack pcaps, one sample per flow/event
    benign/         # benign pcaps, one sample per flow
    unsw_enet/      # UNSW pcaps rewritten from Linux cooked capture to Ethernet
    logs/           # helper indexes and task files
    manifest.tsv    # sample metadata

  IDS_dataset/SYRIUS/
    raw/                # all original Syrius pcaps copied into the project
    curated/attack/     # attack-oriented Syrius samples for direct use
    curated/benign/     # benign Syrius samples for direct use
    curated/ambiguous/  # mixed/control/contrast Syrius samples kept separately
    manifest.tsv        # Syrius inventory with labels and notes

Important defaults:
  MAX_CIC_TCP_STREAMS_PER_FILE=20
  MAX_CIC_UDP_STREAMS_PER_FILE=20
  MAX_UNSW_EVENTS=200
  SYRIUS_MAX_BENIGN_HTTP_STREAMS=20
  MIN_PACKETS=5
  TIME_SLACK_SECONDS=1
  UNSW_REWRITE_LIMIT=0   # 0 means rewrite all UNSW pcaps
  FORCE=0                # 1 means overwrite existing outputs
  REQUIRE_ETHERNET=1
  REQUIRE_SINGLE_FLOW=1
  REQUIRE_BIDIRECTIONAL=1
  REQUIRE_ATTACK_SEMANTICS=1
  PARALLEL_JOBS=1
  PREPARE_BACKEND=python
  PROFILE=supported_cic_aligned
  VERBOSE_PROGRESS=1

Examples:
  bash scripts/prepare_ids_datasets.sh rewrite-unsw
  MAX_CIC_TCP_STREAMS_PER_FILE=5 MAX_CIC_UDP_STREAMS_PER_FILE=5 \
    bash scripts/prepare_ids_datasets.sh split-cic
  MAX_UNSW_EVENTS=100 bash scripts/prepare_ids_datasets.sh extract-unsw-attacks
  SYRIUS_MAX_BENIGN_HTTP_STREAMS=10 bash scripts/prepare_ids_datasets.sh copy-syrius
  bash scripts/prepare_ids_datasets.sh prepare-syrius

Profiles:
  PROFILE=all
    Keep all categories, only apply packet/flow validation.
  PROFILE=supported_cic_aligned
    Keep only the CIC attack categories that are semantically suitable for
    the current TCP/UDP single-flow pipeline, and align UNSW to nearby
    browser/web exploit, backdoor, and TCP/UDP reconnaissance events.
  REQUIRE_ATTACK_SEMANTICS=1
    For attack samples, require visible attack semantics in HTTP or textual
    payload before the sample can enter the prepared set.
  PARALLEL_JOBS=1
    Number of concurrent worker processes for `split-cic` and
    `extract-unsw-attacks`. Recommended starting range on this host: 8-24.
  PREPARE_BACKEND=python
    `split-cic` uses the Python/scapy backend by default. Set to `legacy`
    to force the old tshark-based splitter.
EOF
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

log_progress() {
  if [[ "$VERBOSE_PROGRESS" == "1" ]]; then
    echo "$@"
  fi
}

init_layout() {
  mkdir -p "$UNSW_ENET_DIR" "$ATTACK_DIR" "$BENIGN_DIR" "$LOG_DIR"
  if [[ "$FORCE" == "1" ]]; then
    rm -f "$MANIFEST_PATH" "$REJECT_LOG_PATH" "$MANIFEST_LOCK_PATH" "$REJECT_LOCK_PATH"
  fi
  if [[ ! -f "$MANIFEST_PATH" ]]; then
    printf 'sample_path\tlabel\tdataset\tsource_pcap\tsplit_kind\tproto\tpackets\tmeta\n' >"$MANIFEST_PATH"
  fi
  if [[ ! -f "$REJECT_LOG_PATH" ]]; then
    printf 'sample_path\tlabel\tdataset\tsource_pcap\tsplit_kind\texpected_proto\treason\tmeta\n' >"$REJECT_LOG_PATH"
  fi
}

init_syrius_layout() {
  mkdir -p \
    "$SYRIUS_RAW_DIR" \
    "$SYRIUS_CURATED_ATTACK_DIR" \
    "$SYRIUS_CURATED_BENIGN_DIR" \
    "$SYRIUS_CURATED_AMBIGUOUS_DIR"
  printf 'sample_path\tlabel\tfamily\tsource_pcap\tsplit_kind\tproto\tpackets\tnote\n' >"$SYRIUS_MANIFEST_PATH"
}

slugify() {
  printf '%s' "$*" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/[^a-z0-9]+/_/g; s/^_+//; s/_+$//; s/__+/_/g'
}

pcap_packets() {
  local pcap_path="$1"
  if [[ ! -f "$pcap_path" ]]; then
    echo 0
    return
  fi
  local packets
  packets="$(capinfos -T -m -B -N -c "$pcap_path" 2>/dev/null | awk 'NR==2 {print $2}')"
  if [[ -z "${packets:-}" ]]; then
    echo 0
  else
    echo "$packets"
  fi
}

append_manifest() {
  local sample_path="$1"
  local label="$2"
  local dataset="$3"
  local source_pcap="$4"
  local split_kind="$5"
  local proto="$6"
  local packets="$7"
  local meta="$8"
  {
    exec 9>>"$MANIFEST_LOCK_PATH"
    flock 9
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$sample_path" "$label" "$dataset" "$source_pcap" "$split_kind" "$proto" "$packets" "$meta" >>"$MANIFEST_PATH"
  }
}

append_rejection() {
  local sample_path="$1"
  local label="$2"
  local dataset="$3"
  local source_pcap="$4"
  local split_kind="$5"
  local expected_proto="$6"
  local reason="$7"
  local meta="$8"
  {
    exec 9>>"$REJECT_LOCK_PATH"
    flock 9
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$sample_path" "$label" "$dataset" "$source_pcap" "$split_kind" "$expected_proto" "$reason" "$meta" >>"$REJECT_LOG_PATH"
  }
}

append_syrius_manifest() {
  local sample_path="$1"
  local label="$2"
  local family="$3"
  local source_pcap="$4"
  local split_kind="$5"
  local proto="$6"
  local packets="$7"
  local note="$8"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sample_path" "$label" "$family" "$source_pcap" "$split_kind" "$proto" "$packets" "$note" >>"$SYRIUS_MANIFEST_PATH"
}

copy_file_if_needed() {
  local src="$1"
  local dst="$2"
  if [[ ! -f "$src" ]]; then
    echo "[copy] missing source: $src" >&2
    return 1
  fi
  if [[ -s "$dst" && "$FORCE" != "1" ]]; then
    return 0
  fi
  mkdir -p "$(dirname "$dst")"
  cp -f "$src" "$dst"
}

validate_sample() {
  local sample_path="$1"
  local expected_proto="$2"
  local label="${3:-}"
  local dataset="${4:-}"
  local source_pcap="${5:-}"
  local sample_meta="${6:-}"
  SAMPLE_PATH="$sample_path" \
  EXPECTED_PROTO="$expected_proto" \
  SAMPLE_LABEL="$label" \
  SAMPLE_DATASET="$dataset" \
  SOURCE_PCAP="$source_pcap" \
  SAMPLE_META="$sample_meta" \
  MIN_PACKETS="$MIN_PACKETS" \
  REQUIRE_ETHERNET="$REQUIRE_ETHERNET" \
  REQUIRE_SINGLE_FLOW="$REQUIRE_SINGLE_FLOW" \
  REQUIRE_BIDIRECTIONAL="$REQUIRE_BIDIRECTIONAL" \
  REQUIRE_ATTACK_SEMANTICS="$REQUIRE_ATTACK_SEMANTICS" \
  python - <<'PY'
import os
import re
import subprocess
import sys
from collections import defaultdict

sample_path = os.environ["SAMPLE_PATH"]
expected_proto = os.environ["EXPECTED_PROTO"].strip().lower()
sample_label = os.environ.get("SAMPLE_LABEL", "").strip().lower()
sample_dataset = os.environ.get("SAMPLE_DATASET", "").strip()
source_pcap = os.environ.get("SOURCE_PCAP", "").strip()
sample_meta = os.environ.get("SAMPLE_META", "").strip()
min_packets = int(os.environ["MIN_PACKETS"])
require_ethernet = os.environ["REQUIRE_ETHERNET"] == "1"
require_single_flow = os.environ["REQUIRE_SINGLE_FLOW"] == "1"
require_bidirectional = os.environ["REQUIRE_BIDIRECTIONAL"] == "1"
require_attack_semantics = os.environ.get("REQUIRE_ATTACK_SEMANTICS", "1") == "1"


def parse_meta(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in (text or "").split(";"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            out[key] = value
    return out


def decode_hex_payload(raw: str) -> bytes:
    text = (raw or "").replace(":", "").strip()
    if not text:
        return b""
    try:
        return bytes.fromhex(text)
    except ValueError:
        return text.encode("utf-8", errors="ignore")


def looks_textual(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:2048]
    if b"\x00" in sample:
        return False
    printable = 0
    control = 0
    alpha = 0
    for value in sample:
        if value in (9, 10, 13) or 32 <= value <= 126:
            printable += 1
            if chr(value).isalpha():
                alpha += 1
        else:
            control += 1
    if not sample:
        return False
    return (control / len(sample)) <= 0.30 and alpha >= 8


def collect_semantic_view(path: str) -> dict[str, object]:
    proc = subprocess.run(
        [
            "tshark",
            "-r",
            path,
            "-c",
            "256",
            "-T",
            "fields",
            "-e",
            "http.request.method",
            "-e",
            "http.request.uri",
            "-e",
            "http.host",
            "-e",
            "http.user_agent",
            "-e",
            "tcp.payload",
            "-e",
            "udp.payload",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    text_parts: list[str] = []
    payload_preview = bytearray()
    http_visible = False

    for line in lines:
        cols = line.split("\t")
        if len(cols) < 6:
            cols += [""] * (6 - len(cols))
        method, uri, host, user_agent, tcp_payload, udp_payload = [item.strip() for item in cols[:6]]
        if method or uri or host or user_agent:
            http_visible = True
        if method:
            text_parts.append(method)
        if uri:
            text_parts.append(uri)
        if host:
            text_parts.append(f"Host: {host}")
        if user_agent:
            text_parts.append(f"User-Agent: {user_agent}")

        raw_bytes = decode_hex_payload(tcp_payload or udp_payload)
        if raw_bytes and len(payload_preview) < 16384:
            remaining = 16384 - len(payload_preview)
            payload_preview.extend(raw_bytes[:remaining])

    payload_bytes = bytes(payload_preview)
    payload_text = payload_bytes.decode("utf-8", errors="replace") if payload_bytes else ""
    combined_text = "\n".join(text_parts + ([payload_text] if payload_text else []))
    lower_text = combined_text.lower()
    return {
        "http_visible": http_visible,
        "text_visible": bool(payload_text.strip()) and looks_textual(payload_bytes),
        "payload_bytes_seen": len(payload_bytes),
        "lower_text": lower_text,
    }


def contains_any(text: str, tokens: list[str]) -> bool:
    return any(token in text for token in tokens)


def matches_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def validate_attack_semantics(path: str, dataset: str, label: str, source_name: str, meta_text: str) -> tuple[bool, str, str]:
    if label != "attack" or not require_attack_semantics:
        return True, "semantic_check_skipped", "http_visible=na;text_visible=na;payload_signal=na"

    meta = parse_meta(meta_text)
    source_stem = os.path.splitext(os.path.basename(source_name))[0].strip().lower()
    view = collect_semantic_view(path)
    http_visible = bool(view["http_visible"])
    text_visible = bool(view["text_visible"])
    lower_text = str(view["lower_text"])
    payload_bytes_seen = int(view["payload_bytes_seen"])
    signal = False

    if dataset == "CIC-IoT2023":
        if source_stem == "browserhijacking":
            signal = http_visible and contains_any(
                lower_text,
                ["beefhook", "hook.js", "document.cookie", "<script", "</script>", "onmouseover", "beef"],
            )
        elif source_stem == "sqlinjection":
            signal = http_visible and matches_any(
                lower_text,
                [
                    r"\bselect\b.{0,32}\bfrom\b",
                    r"\bunion\b.{0,16}\bselect\b",
                    r"\bupdate\b.{0,16}\bset\b",
                    r"\binsert\b.{0,16}\binto\b",
                    r"\bdrop\b.{0,16}\btable\b",
                    r"\bdelete\b.{0,16}\bfrom\b",
                    r"xp_cmdshell",
                    r"into\s+outfile",
                    r"into\s+dumpfile",
                    r"information_schema",
                    r"load_file\s*\(",
                    r"benchmark\s*\(",
                    r"sleep\s*\(",
                    r"waitfor\s+delay",
                    r"\bor\b\s+1=1\b",
                ],
            )
        elif source_stem == "commandinjection":
            signal = (http_visible or text_visible) and contains_any(
                lower_text,
                [
                    "/bin/sh",
                    "/bin/bash",
                    "cmd.exe",
                    "powershell",
                    "bash -c",
                    "sh -c",
                    "wget ",
                    "curl ",
                    "busybox",
                    "chmod ",
                    "/tmp/",
                    "nc ",
                ],
            )
        elif source_stem == "uploading_attack":
            signal = http_visible and (
                contains_any(
                    lower_text,
                    [
                        "multipart/form-data",
                        "content-disposition: form-data",
                        "filename=",
                        "filename:",
                        "<?php",
                        ".php",
                        ".jsp",
                        ".asp",
                        ".war",
                    ],
                )
                or matches_any(lower_text, [r"\bpost\b", r"\bput\b"])
            )
        elif source_stem == "dictionarybruteforce":
            signal = http_visible and contains_any(
                lower_text,
                ["login", "username", "password", "passwd", "authorization:", "basic "],
            )
        elif source_stem == "backdoor_malware":
            signal = http_visible and contains_any(
                lower_text,
                ["cookie:", "set-cookie:", "user-agent:", "go-http-client", "python-requests", "<?php", "http"],
            )
        else:
            signal = http_visible or text_visible
    elif dataset == "UNSW-NB15":
        signal = (
            http_visible
            and contains_any(
                lower_text,
                [
                    "get ",
                    "post ",
                    "<?php",
                    "/etc/passwd",
                    "user-agent:",
                    "cookie:",
                    "host:",
                    "filename:",
                    "content-type:",
                    ".rar",
                    ".doc",
                    ".docx",
                    ".ppt",
                    ".pptm",
                    "xp_cmdshell",
                    "select ",
                    "union ",
                    "/bin/bash",
                    "cmd.exe",
                ],
            )
        ) or (
            text_visible
            and contains_any(
                lower_text,
                [
                    "filename:",
                    "content-type:",
                    "<?php",
                    "/etc/passwd",
                    "xp_cmdshell",
                    "select ",
                    "union ",
                    "update ",
                    "/bin/bash",
                    "cmd.exe",
                    ".rar",
                    ".doc",
                    ".docx",
                    ".ppt",
                    ".pptm",
                ],
            )
        )
    elif dataset == "SYRIUS":
        signal = http_visible or text_visible
    else:
        signal = http_visible or text_visible

    inspect = (
        f"http_visible={str(http_visible).lower()};"
        f"text_visible={str(text_visible).lower()};"
        f"payload_signal={str(signal).lower()};"
        f"semantic_bytes={payload_bytes_seen}"
    )
    if signal:
        return True, "semantic_pass", inspect
    return False, "attack_semantics_invisible", inspect

if not os.path.exists(sample_path):
    print("reject\tmissing_file\t0\tunknown\tmissing=true")
    sys.exit(0)

capinfos = subprocess.run(
    ["capinfos", "-T", "-m", "-B", "-N", "-E", "-c", sample_path],
    capture_output=True,
    text=True,
    check=False,
)
rows = [line for line in capinfos.stdout.splitlines() if line.strip()]
if len(rows) < 2:
    print("reject\tcapinfos_parse_failed\t0\tunknown\tmissing_capinfos=true")
    sys.exit(0)

cols = rows[-1].split("\t")
encapsulation = cols[1].strip() if len(cols) > 1 else "unknown"
try:
    total_packets = int(cols[2].strip()) if len(cols) > 2 else 0
except ValueError:
    total_packets = 0

if require_ethernet and encapsulation.lower() not in {"ethernet", "ether"}:
    print(f"reject\tnon_ethernet\t{total_packets}\tunknown\tencapsulation={encapsulation}")
    sys.exit(0)

tshark = subprocess.run(
    [
        "tshark",
        "-r",
        sample_path,
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
    ],
    capture_output=True,
    text=True,
    check=False,
)

canonical_flows = defaultdict(int)
directions = defaultdict(set)
protocols = set()
transport_packets = 0

for raw in tshark.stdout.splitlines():
    cols = raw.split("\t")
    if len(cols) < 6:
      cols += [""] * (6 - len(cols))
    src_ip, dst_ip, tcp_s, tcp_d, udp_s, udp_d = [item.strip() for item in cols[:6]]
    if not src_ip or not dst_ip:
        continue
    proto = None
    sport = dport = None
    if tcp_s or tcp_d:
        proto = "tcp"
        sport = tcp_s
        dport = tcp_d
    elif udp_s or udp_d:
        proto = "udp"
        sport = udp_s
        dport = udp_d
    if proto is None or not sport or not dport:
        continue
    transport_packets += 1
    protocols.add(proto)
    forward = (src_ip, sport, dst_ip, dport)
    reverse = (dst_ip, dport, src_ip, sport)
    flow_key = (proto, forward) if forward <= reverse else (proto, reverse)
    canonical_flows[flow_key] += 1
    directions[flow_key].add(forward)

if not protocols:
    print(f"reject\tno_tcp_udp_packets\t{total_packets}\tunknown\tencapsulation={encapsulation}")
    sys.exit(0)

if expected_proto and expected_proto not in protocols:
    print(
        "reject\tunexpected_protocol\t"
        f"{total_packets}\t{','.join(sorted(protocols))}\texpected_proto={expected_proto}"
    )
    sys.exit(0)

if len(protocols) != 1:
    print(
        "reject\tmixed_transport_protocols\t"
        f"{total_packets}\t{','.join(sorted(protocols))}\ttransport_packets={transport_packets}"
    )
    sys.exit(0)

actual_proto = next(iter(protocols))
flow_count = len(canonical_flows)

semantics_ok, semantics_reason, semantics_meta = validate_attack_semantics(
    sample_path,
    sample_dataset,
    sample_label,
    source_pcap,
    sample_meta,
)
semantic_override = sample_label == "attack" and semantics_ok and semantics_reason == "semantic_pass"

if total_packets < min_packets and not semantic_override:
    print(
        "reject\ttoo_few_packets\t"
        f"{total_packets}\t{actual_proto}\tmin_packets={min_packets};{semantics_meta}"
    )
    sys.exit(0)

if transport_packets < min_packets and not semantic_override:
    print(
        "reject\ttoo_few_transport_packets\t"
        f"{transport_packets}\t{actual_proto}\tmin_packets={min_packets};{semantics_meta}"
    )
    sys.exit(0)

if require_single_flow and flow_count != 1:
    print(
        "reject\tmulti_flow_sample\t"
        f"{total_packets}\t{actual_proto}\tflow_count={flow_count};transport_packets={transport_packets}"
    )
    sys.exit(0)

if not canonical_flows:
    print(f"reject\tno_flow_key\t{total_packets}\t{actual_proto}\ttransport_packets={transport_packets}")
    sys.exit(0)

flow_key = next(iter(canonical_flows))
direction_count = len(directions[flow_key])
if require_bidirectional and direction_count < 2:
    print(
        "reject\tunidirectional_flow\t"
        f"{total_packets}\t{actual_proto}\tdirection_count={direction_count};transport_packets={transport_packets}"
    )
    sys.exit(0)

if not semantics_ok:
    print(
        "reject\t"
        f"{semantics_reason}\t{total_packets}\t{actual_proto}\t"
        f"encapsulation={encapsulation};flow_count={flow_count};direction_count={direction_count};"
        f"transport_packets={transport_packets};{semantics_meta}"
    )
    sys.exit(0)

print(
    "ok\tpass\t"
    f"{total_packets}\t{actual_proto}\tencapsulation={encapsulation};"
    f"flow_count={flow_count};direction_count={direction_count};transport_packets={transport_packets};"
    f"{semantics_meta}"
)
PY
}

register_sample() {
  local sample_path="$1"
  local label="$2"
  local dataset="$3"
  local source_pcap="$4"
  local split_kind="$5"
  local expected_proto="$6"
  local meta="$7"

  local result status reason packets actual_proto inspect_meta merged_meta
  REGISTER_STATUS=""
  REGISTER_REASON=""
  result="$(validate_sample "$sample_path" "$expected_proto" "$label" "$dataset" "$source_pcap" "$meta")"
  IFS=$'\t' read -r status reason packets actual_proto inspect_meta <<<"$result"

  if [[ "$status" != "ok" ]]; then
    REGISTER_STATUS="rejected"
    REGISTER_REASON="$reason"
    rm -f "$sample_path"
    append_rejection \
      "$sample_path" \
      "$label" \
      "$dataset" \
      "$source_pcap" \
      "$split_kind" \
      "$expected_proto" \
      "$reason" \
      "${meta};${inspect_meta}"
    return 1
  fi

  REGISTER_STATUS="kept"
  REGISTER_REASON="pass"
  if [[ -n "$meta" ]]; then
    merged_meta="profile=${PROFILE};${meta};${inspect_meta}"
  else
    merged_meta="profile=${PROFILE};${inspect_meta}"
  fi
  append_manifest \
    "$sample_path" \
    "$label" \
    "$dataset" \
    "$source_pcap" \
    "$split_kind" \
    "$actual_proto" \
    "$packets" \
    "$merged_meta"
}

should_keep_cic_source() {
  local base="$1"
  local label="$2"
  if [[ "$label" == "benign" ]]; then
    return 0
  fi
  case "$PROFILE" in
    all|off|none)
      return 0
      ;;
    supported_cic_aligned)
      case "$base" in
        SqlInjection.pcap|CommandInjection.pcap|BrowserHijacking.pcap|Uploading_Attack.pcap|Backdoor_Malware.pcap|DictionaryBruteForce.pcap)
          return 0
          ;;
        *)
          return 1
          ;;
      esac
      ;;
    *)
      echo "unknown PROFILE=$PROFILE" >&2
      exit 1
      ;;
  esac
}

rewrite_unsw() {
  echo "[rewrite-unsw] source=$UNSW_DIR -> $UNSW_ENET_DIR"
  local count=0
  local src
  while IFS= read -r src; do
    count=$((count + 1))
    if [[ "$UNSW_REWRITE_LIMIT" != "0" && "$count" -gt "$UNSW_REWRITE_LIMIT" ]]; then
      echo "[rewrite-unsw] reached UNSW_REWRITE_LIMIT=$UNSW_REWRITE_LIMIT"
      break
    fi
    local base dst
    base="$(basename "$src")"
    dst="$UNSW_ENET_DIR/$base"
    if [[ -s "$dst" && "$FORCE" != "1" ]]; then
      echo "[rewrite-unsw] skip existing $dst"
      continue
    fi
    echo "[rewrite-unsw] tcprewrite $base"
    tcprewrite --dlt=enet --infile="$src" --outfile="$dst"
  done < <(find "$UNSW_DIR" -maxdepth 1 -type f -name '*.pcap' | sort -V)
}

build_unsw_index() {
  local index_path="$LOG_DIR/unsw_enet_index.tsv"
  UNSW_ENET_DIR="$UNSW_ENET_DIR" python - <<'PY' >"$index_path"
from pathlib import Path
import os
import subprocess
import sys

base = Path(os.environ["UNSW_ENET_DIR"])
files = sorted(
    base.glob("*.pcap"),
    key=lambda p: int(p.stem) if p.stem.isdigit() else 10**9,
)
print("pcap_path\tpcap_name\tstart_epoch\tend_epoch")
for path in files:
    try:
        out = subprocess.check_output(
            ["capinfos", "-T", "-m", "-B", "-N", "-a", "-e", "-S", str(path)],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        continue
    lines = [line for line in out.splitlines() if line.strip()]
    if len(lines) < 2:
        continue
    row = lines[-1].split("\t")
    if len(row) < 3:
        continue
    print(f"{path}\t{path.name}\t{row[1]}\t{row[2]}")
PY
  echo "$index_path"
}

extract_cic_streams_for_proto() {
  local src="$1"
  local label="$2"
  local proto="$3"
  local limit="$4"

  local stem safe_stem out_dir
  stem="$(basename "$src" .pcap)"
  safe_stem="$(slugify "$stem")"
  if [[ "$label" == "attack" ]]; then
    out_dir="$ATTACK_DIR"
  else
    out_dir="$BENIGN_DIR"
  fi

  if [[ "$limit" -le 0 ]]; then
    return
  fi

  if [[ "$FORCE" == "1" ]]; then
    rm -f "$out_dir/ciciot2023__${safe_stem}__${proto}_stream_"*.pcap
  fi

  echo "[split-cic] $stem proto=$proto limit=$limit label=$label"
  local stream_ids
  set +o pipefail
  stream_ids="$(tshark -r "$src" -T fields -e "${proto}.stream" 2>/dev/null \
    | awk 'NF && $1 != "" {print $1}' \
    | LC_ALL=C sort -n \
    | uniq)"
  set -o pipefail

  if [[ -z "${stream_ids:-}" ]]; then
    echo "[split-cic] no ${proto}.stream found in $src"
    return
  fi

  local sid stream_count stream_index accepted_count
  stream_count="$(printf '%s\n' "$stream_ids" | awk 'NF {count++} END {print count+0}')"
  stream_index=0
  accepted_count=0
  while IFS= read -r sid; do
    [[ -z "$sid" ]] && continue
    if [[ "$accepted_count" -ge "$limit" ]]; then
      break
    fi
    stream_index=$((stream_index + 1))
    local out_path
    out_path="$out_dir/ciciot2023__${safe_stem}__${proto}_stream_${sid}.pcap"
    log_progress "[split-cic] file=$stem label=$label proto=$proto sample=${stream_index}/${stream_count} stream_id=$sid accepted=${accepted_count}/${limit}"
    if [[ -s "$out_path" && "$FORCE" != "1" ]]; then
      echo "[split-cic] skip existing $out_path"
      accepted_count=$((accepted_count + 1))
      continue
    fi
    rm -f "$out_path"
    tshark -r "$src" -Y "${proto}.stream eq ${sid}" -w "$out_path" >/dev/null 2>&1 || true
    local packets
    packets="$(pcap_packets "$out_path")"
    if [[ "$packets" -lt "$MIN_PACKETS" ]]; then
      rm -f "$out_path"
      continue
    fi
    register_sample \
      "$out_path" \
      "$label" \
      "CIC-IoT2023" \
      "$(basename "$src")" \
      "${proto}.stream" \
      "$proto" \
      "stream_id=$sid" || true
    if [[ "${REGISTER_STATUS:-}" == "kept" ]]; then
      accepted_count=$((accepted_count + 1))
    fi
    log_progress "[split-cic] result file=$stem proto=$proto stream_id=$sid status=${REGISTER_STATUS:-unknown} reason=${REGISTER_REASON:-unknown}"
  done <<<"$stream_ids"
}

split_cic() {
  echo "[split-cic] source=$CIC_DIR"
  local -a sources=()
  mapfile -t sources < <(find "$CIC_DIR" -maxdepth 1 -type f -name '*.pcap' | sort)
  if [[ "$PARALLEL_JOBS" -le 1 ]]; then
    local src
    for src in "${sources[@]}"; do
      process_cic_source_path "$src"
    done
    return
  fi

  echo "[split-cic] parallel jobs=$PARALLEL_JOBS files=${#sources[@]}"
  printf '%s\0' "${sources[@]}" \
    | parallel -0 --will-cite -j "$PARALLEL_JOBS" "$SCRIPT_PATH" split-cic-one {}
}

process_cic_source_path() {
  local src="$1"
  local base lower label
  base="$(basename "$src")"
  lower="$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')"
  if [[ "$lower" == *benign* ]]; then
    label="benign"
  else
    label="attack"
  fi
  if ! should_keep_cic_source "$base" "$label"; then
    echo "[split-cic] skip source due to PROFILE=$PROFILE: $base"
    return
  fi
  extract_cic_streams_for_proto "$src" "$label" tcp "$MAX_CIC_TCP_STREAMS_PER_FILE"
  extract_cic_streams_for_proto "$src" "$label" udp "$MAX_CIC_UDP_STREAMS_PER_FILE"
}

build_unsw_tasks() {
  local index_path="$1"
  local task_path="$LOG_DIR/unsw_attack_tasks.tsv"
  INDEX_PATH="$index_path" \
  GT_PATH="$UNSW_DIR/NUSW-NB15_GT.csv" \
  MAX_UNSW_EVENTS="$MAX_UNSW_EVENTS" \
  TIME_SLACK_SECONDS="$TIME_SLACK_SECONDS" \
  PROFILE="$PROFILE" \
  python - <<'PY' >"$task_path"
import csv
import os
from pathlib import Path

index_path = Path(os.environ["INDEX_PATH"])
gt_path = Path(os.environ["GT_PATH"])
max_events = int(os.environ["MAX_UNSW_EVENTS"])
time_slack = float(os.environ["TIME_SLACK_SECONDS"])
profile = os.environ.get("PROFILE", "supported_cic_aligned").strip().lower()


def slugify(text: str) -> str:
    import re
    text = (text or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "na"


def row_allowed(category: str, subcategory: str) -> bool:
    cat = (category or "").strip().lower()
    sub = (subcategory or "").strip().lower()
    if profile in {"all", "off", "none"}:
        return True
    if profile != "supported_cic_aligned":
        raise SystemExit(f"unknown PROFILE={profile}")

    if cat in {"backdoor", "backdoors"}:
        return True

    if cat == "reconnaissance":
        return False

    if cat == "analysis":
        return sub in {"port scanner", "port scanners"}

    if cat == "exploits":
        exploit_keywords = (
            "web application",
            "browser",
            "clientside",
            "php",
            "apache",
            "webserver",
            "microsoft iis",
            "miscellaneous batch",
            "office document",
        )
        return any(keyword in sub for keyword in exploit_keywords)

    return False


index_rows = []
with index_path.open("r", encoding="utf-8") as f:
    reader = csv.DictReader(f, delimiter="\t")
    for row in reader:
        index_rows.append(
            {
                "pcap_path": row["pcap_path"],
                "pcap_name": row["pcap_name"],
                "start_epoch": float(row["start_epoch"]),
                "end_epoch": float(row["end_epoch"]),
            }
        )

print("output_name\tproto\tattack_category\tattack_subcategory\tcandidates\tfilter_expr")

written = 0
with gt_path.open("r", encoding="utf-8", errors="ignore") as f:
    reader = csv.DictReader(f)
    for row_id, row in enumerate(reader, start=1):
        proto = (row.get("Protocol") or "").strip().lower()
        if proto not in {"tcp", "udp"}:
            continue
        if written >= max_events:
            break
        try:
            start = float((row.get("Start time") or "").strip())
            end = float((row.get("Last time") or "").strip())
            src = (row.get("Source IP") or "").strip()
            dst = (row.get("Destination IP") or "").strip()
            sport = int((row.get("Source Port") or "").strip())
            dport = int((row.get("Destination Port") or "").strip())
        except (TypeError, ValueError):
            continue

        candidates = [
            item["pcap_path"]
            for item in index_rows
            if item["start_epoch"] <= start + time_slack and item["end_epoch"] >= end - time_slack
        ]
        if not candidates:
            continue

        category = (row.get("Attack category") or "").strip() or "unknown"
        subcategory = (row.get("Attack subcategory") or "").strip() or "unknown"
        if not row_allowed(category, subcategory):
            continue
        base = (
            f"unsw__event_{row_id:06d}__{slugify(category)}__"
            f"{slugify(subcategory)}__{proto}.pcap"
        )
        filter_expr = (
            f'frame.time_epoch >= {start - time_slack:.6f} && '
            f'frame.time_epoch <= {end + time_slack:.6f} && '
            f'((ip.src == {src} && ip.dst == {dst} && {proto}.srcport == {sport} && {proto}.dstport == {dport}) || '
            f'(ip.src == {dst} && ip.dst == {src} && {proto}.srcport == {dport} && {proto}.dstport == {sport}))'
        )
        print(
            "\t".join(
                [
                    base,
                    proto,
                    category,
                    subcategory,
                    "|".join(candidates),
                    filter_expr,
                ]
            )
        )
        written += 1
PY
  echo "$task_path"
}

extract_unsw_attacks() {
  if [[ ! -d "$UNSW_ENET_DIR" ]]; then
    echo "[extract-unsw-attacks] missing $UNSW_ENET_DIR, run rewrite-unsw first" >&2
    exit 1
  fi
  local index_path task_path
  index_path="$(build_unsw_index)"
  task_path="$(build_unsw_tasks "$index_path")"
  echo "[extract-unsw-attacks] tasks=$task_path"
  local total_tasks
  total_tasks="$(tail -n +2 "$task_path" | awk 'END {print NR+0}')"

  if [[ "$PARALLEL_JOBS" -le 1 ]]; then
    local task_index
    task_index=0
    while IFS=$'\t' read -r output_name proto category subcategory candidates filter_expr; do
      [[ -z "${output_name:-}" ]] && continue
      task_index=$((task_index + 1))
      process_unsw_task "$task_index" "$total_tasks" "$output_name" "$proto" "$category" "$subcategory" "$candidates" "$filter_expr"
    done < <(tail -n +2 "$task_path")
    return
  fi

  echo "[extract-unsw-attacks] parallel jobs=$PARALLEL_JOBS tasks=$total_tasks"
  seq 1 "$total_tasks" \
    | parallel --will-cite -j "$PARALLEL_JOBS" "$SCRIPT_PATH" extract-unsw-one "$task_path" {} "$total_tasks"
}

process_unsw_task() {
  local task_index="$1"
  local total_tasks="$2"
  local output_name="$3"
  local proto="$4"
  local category="$5"
  local subcategory="$6"
  local candidates="$7"
  local filter_expr="$8"

  local out_path meta found packets candidate
  out_path="$ATTACK_DIR/$output_name"
  meta="category=$(slugify "$category");subcategory=$(slugify "$subcategory")"
  log_progress "[extract-unsw-attacks] sample=${task_index}/${total_tasks} category=$category subcategory=$subcategory proto=$proto output=$output_name"
  if [[ -s "$out_path" && "$FORCE" != "1" ]]; then
    echo "[extract-unsw-attacks] skip existing $out_path"
    return
  fi
  rm -f "$out_path"
  found=0
  IFS='|' read -r -a candidate_list <<<"$candidates"
  for candidate in "${candidate_list[@]}"; do
    [[ -f "$candidate" ]] || continue
    rm -f "$out_path"
    tshark -r "$candidate" -Y "$filter_expr" -w "$out_path" >/dev/null 2>&1 || true
    packets="$(pcap_packets "$out_path")"
    if [[ "$packets" -ge "$MIN_PACKETS" ]]; then
      if register_sample \
        "$out_path" \
        "attack" \
        "UNSW-NB15" \
        "$(basename "$candidate")" \
        "gt_time_5tuple" \
        "$proto" \
        "$meta"; then
        log_progress "[extract-unsw-attacks] result sample=${task_index}/${total_tasks} category=$category subcategory=$subcategory status=${REGISTER_STATUS:-kept} source=$(basename "$candidate")"
        found=1
        break
      else
        log_progress "[extract-unsw-attacks] result sample=${task_index}/${total_tasks} category=$category subcategory=$subcategory status=${REGISTER_STATUS:-rejected} reason=${REGISTER_REASON:-unknown} source=$(basename "$candidate")"
      fi
    fi
  done
  if [[ "$found" != "1" ]]; then
    rm -f "$out_path"
    log_progress "[extract-unsw-attacks] result sample=${task_index}/${total_tasks} category=$category subcategory=$subcategory status=empty"
  fi
}

process_unsw_task_from_file() {
  local task_path="$1"
  local task_index="$2"
  local total_tasks="$3"
  local line
  line="$(tail -n +2 "$task_path" | sed -n "${task_index}p")"
  [[ -n "$line" ]] || return
  IFS=$'\t' read -r output_name proto category subcategory candidates filter_expr <<<"$line"
  [[ -n "${output_name:-}" ]] || return
  process_unsw_task "$task_index" "$total_tasks" "$output_name" "$proto" "$category" "$subcategory" "$candidates" "$filter_expr"
}

syrius_family_from_name() {
  local base="$1"
  case "$base" in
    positive-http.pcap) echo "http_background" ;;
    positive-icmp.pcap) echo "icmp_background" ;;
    nikto-adaptor.pcap|all-adaptor.pcap) echo "jboss_htmladaptor_probe" ;;
    nikto-coldfusion.pcap|all-coldfusion.pcap) echo "coldfusion_admin_access" ;;
    nikto-cron.pcap|all-cron.pcap) echo "cron_rfi_probe" ;;
    nikto-htaccess.pcap|all-htaccess.pcap) echo "htaccess_access" ;;
    nikto-idq.pcap|all-idq.pcap) echo "isapi_idq_exploit" ;;
    nikto-issadmin.pcap|all-issadmin.pcap) echo "iis_admin_access" ;;
    nikto-jsp.pcap|all-jsp.pcap) echo "jsp_probe" ;;
    nikto-script.pcap|all-script.pcap) echo "xss_attempt" ;;
    nikto-system.pcap|all-system.pcap) echo "system32_cmd_exec" ;;
    wordpress.pcap|all-wordpress.pcap) echo "wordpress_web_attack" ;;
    synflood.pcap|all-synflood.pcap) echo "syn_flood" ;;
    blacknurse.pcap|all-blacknurse.pcap) echo "blacknurse_icmp_flood" ;;
    pingscan.pcap|all-pingscan.pcap) echo "ping_scan" ;;
    ping-flood.pcap|ping-flood-sample.pcap) echo "ping_flood" ;;
    nikto.pcap) echo "nikto_attack_bundle" ;;
    nikto-without-*.pcap) echo "nikto_contrast_bundle" ;;
    training.pcap) echo "training_bundle" ;;
    test.pcap) echo "test_bundle" ;;
    process.pcap|all-process.pcap) echo "payload_only_bundle" ;;
    all-teardrop.pcap) echo "teardrop_fragmentation" ;;
    *) echo "$(slugify "${base%.pcap}")" ;;
  esac
}

syrius_proto_from_name() {
  local base="$1"
  case "$base" in
    positive-icmp.pcap|blacknurse.pcap|all-blacknurse.pcap|pingscan.pcap|all-pingscan.pcap|ping-flood.pcap|ping-flood-sample.pcap)
      echo "icmp"
      ;;
    all-teardrop.pcap)
      echo "ip"
      ;;
    *)
      echo "tcp"
      ;;
  esac
}

syrius_label_from_name() {
  local base="$1"
  case "$base" in
    positive-http.pcap|positive-icmp.pcap)
      echo "benign"
      ;;
    nikto-without-*.pcap|training.pcap|test.pcap|process.pcap|all-process.pcap)
      echo "ambiguous"
      ;;
    *)
      echo "attack"
      ;;
  esac
}

syrius_note_from_name() {
  local base="$1"
  case "$base" in
    positive-http.pcap)
      echo "benign_source=http_background;recommended_use=split_tcp_streams"
      ;;
    positive-icmp.pcap)
      echo "benign_source=icmp_background;recommended_use=raw_only"
      ;;
    nikto-without-*.pcap)
      echo "role=contrast_set;contains=nikto_scan_without_named_probe"
      ;;
    training.pcap|test.pcap)
      echo "role=mixed_bundle;kept_separate=true"
      ;;
    process.pcap|all-process.pcap)
      echo "role=payload_only_or_incomplete_flow;kept_separate=true"
      ;;
    *)
      echo ""
      ;;
  esac
}

syrius_excluded_from_gridai() {
  local base="$1"
  case "$base" in
    nikto.pcap|all-cron.pcap|nikto-cron.pcap|nikto-without-cron.pcap|all-jsp.pcap|nikto-jsp.pcap|nikto-without-jsp.pcap|all-synflood.pcap|synflood.pcap|all-blacknurse.pcap|blacknurse.pcap|all-pingscan.pcap|pingscan.pcap|ping-flood.pcap|ping-flood-sample.pcap|all-teardrop.pcap|all-wordpress.pcap|wordpress.pcap)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

copy_syrius_raw_inventory() {
  local src
  while IFS= read -r src; do
    local base dst label family proto packets note
    base="$(basename "$src")"
    if syrius_excluded_from_gridai "$base"; then
      continue
    fi
    dst="$SYRIUS_RAW_DIR/$base"
    label="$(syrius_label_from_name "$base")"
    family="$(syrius_family_from_name "$base")"
    proto="$(syrius_proto_from_name "$base")"
    note="$(syrius_note_from_name "$base")"
    copy_file_if_needed "$src" "$dst"
    packets="$(pcap_packets "$dst")"
    append_syrius_manifest \
      "$dst" \
      "$label" \
      "$family" \
      "$base" \
      "raw_copy" \
      "$proto" \
      "$packets" \
      "$note"
  done < <(find "$SYRIUS_SRC_DIR" -maxdepth 1 -type f -name '*.pcap' | sort)
}

extract_syrius_tcp_streams() {
  local src="$1"
  local out_dir="$2"
  local label="$3"
  local family="$4"
  local limit="$5"
  local source_base safe_family proto
  source_base="$(basename "$src")"
  safe_family="$(slugify "$family")"
  proto="tcp"

  local stream_ids
  set +o pipefail
  stream_ids="$(tshark -r "$src" -T fields -e tcp.stream 2>/dev/null \
    | awk 'NF && $1 != "" {print $1}' \
    | LC_ALL=C sort -n \
    | uniq)"
  set -o pipefail

  if [[ -n "$limit" && "$limit" -gt 0 ]]; then
    stream_ids="$(awk -v max_items="$limit" 'NF {print; count++; if (count >= max_items) exit}' <<<"$stream_ids")"
  fi

  [[ -n "${stream_ids:-}" ]] || return 0

  local sid out_path packets
  while IFS= read -r sid; do
    [[ -z "$sid" ]] && continue
    out_path="$out_dir/syrius__${safe_family}__tcp_stream_${sid}.pcap"
    rm -f "$out_path"
    tshark -r "$src" -Y "tcp.stream eq ${sid}" -w "$out_path" >/dev/null 2>&1 || true
    packets="$(pcap_packets "$out_path")"
    if [[ "$packets" -le 0 ]]; then
      rm -f "$out_path"
      continue
    fi
    append_syrius_manifest \
      "$out_path" \
      "$label" \
      "$family" \
      "$source_base" \
      "tcp.stream" \
      "$proto" \
      "$packets" \
      "stream_id=$sid"
  done <<<"$stream_ids"
}

copy_syrius_curated() {
  local src base safe_base label family proto note dst packets
  while IFS= read -r src; do
    base="$(basename "$src")"
    if syrius_excluded_from_gridai "$base"; then
      continue
    fi
    safe_base="$(slugify "${base%.pcap}")"
    label="$(syrius_label_from_name "$base")"
    family="$(syrius_family_from_name "$base")"
    proto="$(syrius_proto_from_name "$base")"
    note="$(syrius_note_from_name "$base")"

    case "$label" in
      benign)
        if [[ "$base" == "positive-http.pcap" ]]; then
          extract_syrius_tcp_streams "$src" "$SYRIUS_CURATED_BENIGN_DIR" "$label" "$family" "$SYRIUS_MAX_BENIGN_HTTP_STREAMS"
          dst="$SYRIUS_CURATED_BENIGN_DIR/syrius__${safe_base}__raw.pcap"
        else
          dst="$SYRIUS_CURATED_BENIGN_DIR/syrius__${safe_base}__raw.pcap"
        fi
        ;;
      attack)
        case "$base" in
          all-adaptor.pcap|all-coldfusion.pcap|all-cron.pcap|all-htaccess.pcap|all-idq.pcap|all-issadmin.pcap|all-jsp.pcap|all-script.pcap|all-system.pcap|all-wordpress.pcap)
            extract_syrius_tcp_streams "$src" "$SYRIUS_CURATED_ATTACK_DIR" "$label" "$family" 0
            dst="$SYRIUS_CURATED_ATTACK_DIR/syrius__${safe_base}__raw.pcap"
            ;;
          *)
            dst="$SYRIUS_CURATED_ATTACK_DIR/syrius__${safe_base}__raw.pcap"
            ;;
        esac
        ;;
      ambiguous)
        dst="$SYRIUS_CURATED_AMBIGUOUS_DIR/syrius__${safe_base}__raw.pcap"
        ;;
      *)
        dst="$SYRIUS_CURATED_AMBIGUOUS_DIR/syrius__${safe_base}__raw.pcap"
        ;;
    esac

    copy_file_if_needed "$src" "$dst"
    packets="$(pcap_packets "$dst")"
    append_syrius_manifest \
      "$dst" \
      "$label" \
      "$family" \
      "$base" \
      "curated_copy" \
      "$proto" \
      "$packets" \
      "$note"
  done < <(find "$SYRIUS_SRC_DIR" -maxdepth 1 -type f -name '*.pcap' | sort)
}

copy_syrius() {
  if [[ ! -d "$SYRIUS_SRC_DIR" ]]; then
    echo "[copy-syrius] missing source dir: $SYRIUS_SRC_DIR" >&2
    exit 1
  fi
  echo "[copy-syrius] source=$SYRIUS_SRC_DIR -> $SYRIUS_DIR"
  init_syrius_layout
  copy_syrius_raw_inventory
  copy_syrius_curated
}

prepare_syrius() {
  if [[ ! -f "$SYRIUS_MANIFEST_PATH" ]]; then
    echo "[prepare-syrius] missing $SYRIUS_MANIFEST_PATH, run copy-syrius first" >&2
    exit 1
  fi
  init_layout
  SYRIUS_MANIFEST_PATH="$SYRIUS_MANIFEST_PATH" \
  ATTACK_DIR="$ATTACK_DIR" \
  BENIGN_DIR="$BENIGN_DIR" \
  MANIFEST_PATH="$MANIFEST_PATH" \
  FORCE="$FORCE" \
  PROFILE="$PROFILE" \
  python - <<'PY'
import csv
import os
import shutil
from pathlib import Path

syrius_manifest_path = Path(os.environ["SYRIUS_MANIFEST_PATH"])
attack_dir = Path(os.environ["ATTACK_DIR"])
benign_dir = Path(os.environ["BENIGN_DIR"])
manifest_path = Path(os.environ["MANIFEST_PATH"])
force = os.environ.get("FORCE", "0") == "1"
profile = os.environ.get("PROFILE", "")

with syrius_manifest_path.open("r", encoding="utf-8") as f:
    rows = list(csv.DictReader(f, delimiter="\t"))

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

existing_rows = []
if manifest_path.exists():
    with manifest_path.open("r", encoding="utf-8") as f:
        existing_rows = list(csv.DictReader(f, delimiter="\t"))

if force:
    existing_rows = [row for row in existing_rows if row.get("dataset") != "SYRIUS"]

existing = {row["sample_path"] for row in existing_rows}
new_rows = []

for row in rows:
    label = row["label"].strip().lower()
    if label not in {"attack", "benign"}:
        continue
    if row["split_kind"] == "raw_copy":
        continue

    src = Path(row["sample_path"])
    if not src.exists():
        continue

    out_dir = attack_dir if label == "attack" else benign_dir
    dst = out_dir / src.name
    if dst.exists() and not force:
        continue

    shutil.copy2(src, dst)
    meta_parts = []
    if profile:
        meta_parts.append(f"profile={profile}")
    meta_parts.append(f"family={row['family']}")
    note = row.get("note", "").strip()
    if note:
        meta_parts.append(note)
    meta = ";".join(part for part in meta_parts if part)

    sample_path = str(dst)
    if sample_path in existing and not force:
        continue

    new_rows.append(
        {
            "sample_path": sample_path,
            "label": label,
            "dataset": "SYRIUS",
            "source_pcap": row["source_pcap"],
            "split_kind": row["split_kind"],
            "proto": row["proto"],
            "packets": row["packets"],
            "meta": meta,
        }
    )
    existing.add(sample_path)

with manifest_path.open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t")
    writer.writeheader()
    writer.writerows(existing_rows)
    writer.writerows(new_rows)
PY
}

main() {
  case "$ACTION" in
    -h|--help|help)
      usage
      ;;
    rewrite-unsw)
      init_layout
      need_cmd tcprewrite
      rewrite_unsw
      ;;
    split-cic)
      init_layout
      if [[ "$PREPARE_BACKEND" == "python" ]]; then
        python scripts/prepare_ids_datasets_fast.py split-cic
      else
        need_cmd tshark
        need_cmd capinfos
        split_cic
      fi
      ;;
    split-cic-one)
      need_cmd tshark
      need_cmd capinfos
      process_cic_source_path "$2"
      ;;
    extract-unsw-attacks)
      init_layout
      need_cmd tshark
      need_cmd capinfos
      extract_unsw_attacks
      ;;
    extract-unsw-one)
      need_cmd tshark
      need_cmd capinfos
      process_unsw_task_from_file "$2" "$3" "$4"
      ;;
    copy-syrius)
      need_cmd tshark
      need_cmd capinfos
      copy_syrius
      ;;
    prepare-syrius)
      prepare_syrius
      ;;
    all)
      init_layout
      need_cmd tcprewrite
      need_cmd tshark
      need_cmd capinfos
      rewrite_unsw
      split_cic
      extract_unsw_attacks
      copy_syrius
      prepare_syrius
      ;;
    *)
      echo "unknown action: $ACTION" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
