#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from scapy.all import Ether, IP, TCP, UDP, PcapWriter, RawPcapReader  # type: ignore


TCP_IDLE_TIMEOUT = float(os.environ.get("TCP_IDLE_TIMEOUT", "30"))
UDP_IDLE_TIMEOUT = float(os.environ.get("UDP_IDLE_TIMEOUT", "10"))
MAX_PAYLOAD_PREVIEW = int(os.environ.get("MAX_PAYLOAD_PREVIEW", "16384"))


def env_flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default) == "1"


def slugify(text: str) -> str:
    text = (text or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "na"


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
    return bool(sample) and (control / len(sample)) <= 0.30 and alpha >= 8


def source_stem_matches(source_name: str, label: str, profile: str) -> bool:
    if label == "benign":
        return True
    if profile in {"all", "off", "none"}:
        return True
    if profile != "supported_cic_aligned":
        raise ValueError(f"unknown PROFILE={profile}")
    return Path(source_name).name in {
        "SqlInjection.pcap",
        "CommandInjection.pcap",
        "BrowserHijacking.pcap",
        "Uploading_Attack.pcap",
        "Backdoor_Malware.pcap",
        "DictionaryBruteForce.pcap",
    }


@dataclass
class PacketMeta:
    ts: float
    proto: str
    key: Tuple[str, Tuple[str, int, str, int]]
    direction: Tuple[str, int, str, int]
    payload: bytes
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False


@dataclass
class ActiveSession:
    uid: str
    proto: str
    key: Tuple[str, Tuple[str, int, str, int]]
    order_in_key: int
    last_ts: float
    packet_count: int = 0
    closed: bool = False


@dataclass
class SessionStats:
    uid: str
    proto: str
    order_in_key: int
    first_packet_index: int
    packet_count: int = 0
    directions: set = field(default_factory=set)
    payload_preview: bytearray = field(default_factory=bytearray)
    http_visible: bool = False
    tls_like: bool = False

    def add_packet(self, meta: PacketMeta) -> None:
        self.packet_count += 1
        self.directions.add(meta.direction)
        if meta.payload and len(self.payload_preview) < MAX_PAYLOAD_PREVIEW:
            remaining = MAX_PAYLOAD_PREVIEW - len(self.payload_preview)
            self.payload_preview.extend(meta.payload[:remaining])
            if not self.tls_like and len(meta.payload) >= 3 and meta.payload[0] == 0x16 and meta.payload[1] == 0x03:
                self.tls_like = True
            preview = meta.payload[:512]
            preview_text = preview.decode("utf-8", errors="ignore").lower()
            if preview_text.startswith(("get ", "post ", "put ", "delete ", "head ", "options ", "patch ")):
                self.http_visible = True
            elif looks_textual(preview) and (
                preview_text.startswith("http/1.")
                or "\r\nhost:" in preview_text
                or "\r\ncontent-type:" in preview_text
                or "\r\nuser-agent:" in preview_text
                or "\r\ncookie:" in preview_text
            ):
                self.http_visible = True

    def semantic_view(self) -> Tuple[bool, bool, bool, int]:
        payload_bytes = bytes(self.payload_preview)
        text_visible = looks_textual(payload_bytes)
        return self.http_visible, text_visible, self.tls_like, len(payload_bytes)


def parse_packet(packet_bytes: bytes, sec: int, usec: int) -> Optional[PacketMeta]:
    try:
        pkt = Ether(packet_bytes)
    except Exception:
        return None
    if IP not in pkt:
        return None
    ip = pkt[IP]
    proto = None
    sport = dport = None
    payload = b""
    syn = ack = fin = rst = False
    if TCP in pkt:
        tcp = pkt[TCP]
        proto = "tcp"
        sport = int(tcp.sport)
        dport = int(tcp.dport)
        payload = bytes(tcp.payload)
        flags = int(tcp.flags)
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        fin = bool(flags & 0x01)
        rst = bool(flags & 0x04)
    elif UDP in pkt:
        udp = pkt[UDP]
        proto = "udp"
        sport = int(udp.sport)
        dport = int(udp.dport)
        payload = bytes(udp.payload)
    if proto is None:
        return None
    direction = (str(ip.src), sport, str(ip.dst), dport)
    reverse = (str(ip.dst), dport, str(ip.src), sport)
    canonical = direction if direction <= reverse else reverse
    return PacketMeta(
        ts=float(sec) + float(usec) / 1_000_000.0,
        proto=proto,
        key=(proto, canonical),
        direction=direction,
        payload=payload,
        syn=syn,
        ack=ack,
        fin=fin,
        rst=rst,
    )


def make_session_uid(key: Tuple[str, Tuple[str, int, str, int]], order_in_key: int) -> str:
    proto, flow = key
    return f"{proto}|{flow[0]}|{flow[1]}|{flow[2]}|{flow[3]}|{order_in_key}"


def iterate_session_assignments(pcap_path: Path):
    active: Dict[Tuple[str, Tuple[str, int, str, int]], ActiveSession] = {}
    counters: Dict[Tuple[str, Tuple[str, int, str, int]], int] = defaultdict(int)
    transport_index = 0
    reader = RawPcapReader(str(pcap_path))
    try:
        for raw, pkt_meta in reader:
            sec = int(pkt_meta.sec)
            usec = int(pkt_meta.usec)
            meta = parse_packet(raw, sec, usec)
            if meta is None:
                continue
            transport_index += 1
            current = active.get(meta.key)
            rotate = False
            if current is not None:
                idle = meta.ts - current.last_ts
                timeout = TCP_IDLE_TIMEOUT if meta.proto == "tcp" else UDP_IDLE_TIMEOUT
                if idle > timeout:
                    rotate = True
                elif meta.proto == "tcp" and meta.syn and not meta.ack and current.packet_count > 0:
                    rotate = True
                elif meta.proto == "tcp" and current.closed:
                    rotate = True
            if current is None or rotate:
                order_in_key = counters[meta.key]
                counters[meta.key] += 1
                current = ActiveSession(
                    uid=make_session_uid(meta.key, order_in_key),
                    proto=meta.proto,
                    key=meta.key,
                    order_in_key=order_in_key,
                    last_ts=meta.ts,
                )
                active[meta.key] = current
                is_new = True
            else:
                is_new = False
            current.last_ts = meta.ts
            current.packet_count += 1
            if meta.proto == "tcp" and (meta.fin or meta.rst):
                current.closed = True
            yield meta, current.uid, current.order_in_key, transport_index, is_new
    finally:
        reader.close()


def validate_attack_semantics(stats: SessionStats, require_attack_semantics: bool, label: str) -> Tuple[bool, str, str]:
    http_visible, text_visible, tls_like, payload_bytes_seen = stats.semantic_view()
    if label != "attack" or not require_attack_semantics:
        return True, "semantic_check_skipped", "http_visible=na;text_visible=na;tls_like=na;payload_signal=na"

    signal = http_visible or text_visible

    inspect = (
        f"http_visible={str(http_visible).lower()};"
        f"text_visible={str(text_visible).lower()};"
        f"tls_like={str(tls_like).lower()};"
        f"payload_signal={str(signal).lower()};"
        f"semantic_bytes={payload_bytes_seen}"
    )
    if signal:
        return True, "semantic_pass", inspect
    return False, "attack_semantics_invisible", inspect


def validate_session(
    stats: SessionStats,
    label: str,
    min_packets: int,
    require_bidirectional: bool,
    require_attack_semantics: bool,
) -> Tuple[bool, str, str]:
    semantics_ok, semantics_reason, semantics_meta = validate_attack_semantics(
        stats=stats,
        require_attack_semantics=require_attack_semantics,
        label=label,
    )
    semantic_override = label == "attack" and semantics_ok and semantics_reason == "semantic_pass"
    if stats.packet_count < min_packets and not semantic_override:
        return False, "too_few_transport_packets", f"min_packets={min_packets};{semantics_meta}"
    if require_bidirectional and len(stats.directions) < 2:
        return False, "unidirectional_flow", f"direction_count={len(stats.directions)};{semantics_meta}"
    if not semantics_ok:
        return False, semantics_reason, f"direction_count={len(stats.directions)};{semantics_meta}"
    return True, "pass", f"direction_count={len(stats.directions)};{semantics_meta}"


def analyze_source(
    src_path: str,
    attack_dir: str,
    benign_dir: str,
    max_tcp: int,
    max_udp: int,
    min_packets: int,
    require_bidirectional: bool,
    require_attack_semantics: bool,
    force: bool,
    profile: str,
    verbose: bool,
) -> Dict[str, object]:
    src = Path(src_path)
    base = src.name
    stem = src.stem
    safe_stem = slugify(stem)
    lower = base.lower()
    label = "benign" if "benign" in lower else "attack"
    if not source_stem_matches(base, label, profile):
        return {"status": "skipped", "source": base, "message": f"PROFILE={profile}"}

    out_dir = Path(attack_dir if label == "attack" else benign_dir)
    if force:
        for proto in ("tcp", "udp"):
            for old in out_dir.glob(f"ciciot2023__{safe_stem}__{proto}_stream_*.pcap"):
                old.unlink()

    sessions: Dict[str, SessionStats] = {}
    for meta, uid, order_in_key, transport_index, is_new in iterate_session_assignments(src):
        if is_new:
            sessions[uid] = SessionStats(
                uid=uid,
                proto=meta.proto,
                order_in_key=order_in_key,
                first_packet_index=transport_index,
            )
        sessions[uid].add_packet(meta)

    ordered = sorted(sessions.values(), key=lambda item: (item.first_packet_index, item.uid))
    selected: Dict[str, Dict[str, object]] = {}
    manifest_rows: List[List[str]] = []
    reject_rows: List[List[str]] = []
    accepted_counts = {"tcp": 0, "udp": 0}
    limits = {"tcp": max_tcp, "udp": max_udp}

    for stats in ordered:
        proto = stats.proto
        limit = limits[proto]
        if limit <= 0:
            continue
        ok, reason, inspect_meta = validate_session(
            stats=stats,
            label=label,
            min_packets=min_packets,
            require_bidirectional=require_bidirectional,
            require_attack_semantics=require_attack_semantics,
        )
        if not ok:
            reject_rows.append(
                [
                    str(out_dir / f"ciciot2023__{safe_stem}__{proto}_stream_{accepted_counts[proto]}.pcap"),
                    label,
                    "CIC-IoT2023",
                    base,
                    f"{proto}.stream",
                    proto,
                    reason,
                    f"stream_id={accepted_counts[proto]};session_ord={stats.order_in_key};{inspect_meta}",
                ]
            )
            continue
        if accepted_counts[proto] >= limit:
            continue
        output_index = accepted_counts[proto]
        out_path = out_dir / f"ciciot2023__{safe_stem}__{proto}_stream_{output_index}.pcap"
        meta = (
            f"profile={profile};stream_id={output_index};session_ord={stats.order_in_key};"
            f"first_packet_index={stats.first_packet_index};{inspect_meta}"
        )
        manifest_rows.append(
            [
                str(out_path),
                label,
                "CIC-IoT2023",
                base,
                f"{proto}.stream",
                proto,
                str(stats.packet_count),
                meta,
            ]
        )
        selected[stats.uid] = {
            "proto": proto,
            "out_path": out_path,
        }
        accepted_counts[proto] += 1
        if verbose:
            print(
                f"[split-cic-fast] source={base} proto={proto} accepted={accepted_counts[proto]}/{limit} "
                f"session_ord={stats.order_in_key} packets={stats.packet_count}"
            )

    if selected:
        writers: Dict[str, PcapWriter] = {}
        active: Dict[Tuple[str, Tuple[str, int, str, int]], ActiveSession] = {}
        counters: Dict[Tuple[str, Tuple[str, int, str, int]], int] = defaultdict(int)
        reader = RawPcapReader(str(src))
        try:
            for raw, pkt_meta in reader:
                sec = int(pkt_meta.sec)
                usec = int(pkt_meta.usec)
                meta = parse_packet(raw, sec, usec)
                if meta is None:
                    continue
                current = active.get(meta.key)
                rotate = False
                if current is not None:
                    idle = meta.ts - current.last_ts
                    timeout = TCP_IDLE_TIMEOUT if meta.proto == "tcp" else UDP_IDLE_TIMEOUT
                    if idle > timeout:
                        rotate = True
                    elif meta.proto == "tcp" and meta.syn and not meta.ack and current.packet_count > 0:
                        rotate = True
                    elif meta.proto == "tcp" and current.closed:
                        rotate = True
                if current is None or rotate:
                    order_in_key = counters[meta.key]
                    counters[meta.key] += 1
                    current = ActiveSession(
                        uid=make_session_uid(meta.key, order_in_key),
                        proto=meta.proto,
                        key=meta.key,
                        order_in_key=order_in_key,
                        last_ts=meta.ts,
                    )
                    active[meta.key] = current
                current.last_ts = meta.ts
                current.packet_count += 1
                if meta.proto == "tcp" and (meta.fin or meta.rst):
                    current.closed = True
                if current.uid not in selected:
                    continue
                out_path = Path(str(selected[current.uid]["out_path"]))
                writer = writers.get(current.uid)
                if writer is None:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    writer = PcapWriter(str(out_path), sync=False)
                    writers[current.uid] = writer
                pkt = Ether(raw)
                pkt.time = meta.ts
                writer.write(pkt)
        finally:
            reader.close()
            for writer in writers.values():
                writer.close()

    return {
        "status": "ok",
        "source": base,
        "accepted_tcp": accepted_counts["tcp"],
        "accepted_udp": accepted_counts["udp"],
        "manifest_rows": manifest_rows,
        "reject_rows": reject_rows,
    }


def init_layout(manifest_path: Path, reject_path: Path, log_dir: Path, attack_dir: Path, benign_dir: Path, force: bool) -> None:
    attack_dir.mkdir(parents=True, exist_ok=True)
    benign_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    if force:
        if manifest_path.exists():
            manifest_path.unlink()
        if reject_path.exists():
            reject_path.unlink()
    if not manifest_path.exists():
        manifest_path.write_text(
            "sample_path\tlabel\tdataset\tsource_pcap\tsplit_kind\tproto\tpackets\tmeta\n",
            encoding="utf-8",
        )
    if not reject_path.exists():
        reject_path.write_text(
            "sample_path\tlabel\tdataset\tsource_pcap\tsplit_kind\texpected_proto\treason\tmeta\n",
            encoding="utf-8",
        )


def append_tsv(path: Path, rows: List[List[str]]) -> None:
    if not rows:
        return
    with path.open("a", encoding="utf-8") as f:
        for row in rows:
            f.write("\t".join(row) + "\n")


def main() -> int:
    action = os.environ.get("FAST_ACTION", "split-cic")
    if len(sys.argv) > 1:
        action = sys.argv[1]
    if action != "split-cic":
        raise SystemExit(f"unsupported action for fast backend: {action}")

    root_dir = Path(os.environ.get("ROOT_DIR", "/storage/zyj_data/MA-MemIDS/IDS_dataset"))
    cic_dir = Path(os.environ.get("CIC_DIR", str(root_dir / "CIC-IoT2023")))
    out_dir = Path(os.environ.get("OUT_DIR", str(root_dir / "prepared")))
    attack_dir = Path(os.environ.get("ATTACK_DIR", str(out_dir / "attack")))
    benign_dir = Path(os.environ.get("BENIGN_DIR", str(out_dir / "benign")))
    log_dir = Path(os.environ.get("LOG_DIR", str(out_dir / "logs")))
    manifest_path = Path(os.environ.get("MANIFEST_PATH", str(out_dir / "manifest.tsv")))
    reject_path = Path(os.environ.get("REJECT_LOG_PATH", str(log_dir / "rejected.tsv")))

    max_tcp = int(os.environ.get("MAX_CIC_TCP_STREAMS_PER_FILE", "50"))
    max_udp = int(os.environ.get("MAX_CIC_UDP_STREAMS_PER_FILE", "50"))
    min_packets = int(os.environ.get("MIN_PACKETS", "5"))
    require_bidirectional = env_flag("REQUIRE_BIDIRECTIONAL", "1")
    require_attack_semantics = env_flag("REQUIRE_ATTACK_SEMANTICS", "1")
    force = env_flag("FORCE", "0")
    verbose = env_flag("VERBOSE_PROGRESS", "1")
    profile = os.environ.get("PROFILE", "supported_cic_aligned").strip().lower()
    parallel_jobs = max(1, int(os.environ.get("PARALLEL_JOBS", "1")))
    file_filter = os.environ.get("CIC_FILE_FILTER", "").strip()

    init_layout(manifest_path, reject_path, log_dir, attack_dir, benign_dir, force)

    sources = sorted(cic_dir.glob("*.pcap"))
    if file_filter:
        wanted = {item.strip() for item in file_filter.split(",") if item.strip()}
        sources = [src for src in sources if src.name in wanted or src.stem in wanted]

    if verbose:
        print(
            f"[split-cic-fast] sources={len(sources)} jobs={parallel_jobs} "
            f"max_tcp={max_tcp} max_udp={max_udp} profile={profile}"
        )

    futures = []
    manifest_rows: List[List[str]] = []
    reject_rows: List[List[str]] = []
    with ProcessPoolExecutor(max_workers=parallel_jobs) as pool:
        for src in sources:
            futures.append(
                pool.submit(
                    analyze_source,
                    str(src),
                    str(attack_dir),
                    str(benign_dir),
                    max_tcp,
                    max_udp,
                    min_packets,
                    require_bidirectional,
                    require_attack_semantics,
                    force,
                    profile,
                    verbose,
                )
            )
        for future in as_completed(futures):
            result = future.result()
            if result["status"] == "skipped":
                print(f"[split-cic-fast] skip {result['source']} {result['message']}")
                continue
            print(
                f"[split-cic-fast] done {result['source']} "
                f"tcp={result['accepted_tcp']} udp={result['accepted_udp']}"
            )
            manifest_rows.extend(result["manifest_rows"])
            reject_rows.extend(result["reject_rows"])

    manifest_rows.sort(key=lambda row: row[0])
    reject_rows.sort(key=lambda row: (row[3], row[0], row[6]))
    append_tsv(manifest_path, manifest_rows)
    append_tsv(reject_path, reject_rows)
    print(
        f"[split-cic-fast] complete manifest_rows={len(manifest_rows)} "
        f"reject_rows={len(reject_rows)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
