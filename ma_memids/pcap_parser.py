from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple


HTTP_REQUEST_RE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP", re.IGNORECASE)
HTTP_RESPONSE_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+\d{3}")
BINARY_URI_EXT_RE = re.compile(
    r"\.(?:exe|dll|so|bin|msi|zip|jar|war|ear|tar|gz|tgz|bz2|7z|rar|pdf|docx?|xlsx?|pptx?|"
    r"iso|img|dmg|apk|ipa|deb|rpm|png|jpe?g|gif|webp|bmp|ico|mp3|mp4|mov|avi|mkv)$",
    re.IGNORECASE,
)
TEXTUAL_CONTENT_TYPE_HINTS = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-www-form-urlencoded",
    "application/soap+xml",
    "application/graphql",
)
DEFAULT_PCAP_MAX_PACKETS = 4096
DEFAULT_PCAP_MAX_PAYLOAD_BYTES = 16384
DEFAULT_PCAP_MAX_PAYLOAD_TEXT_CHARS = 2000
DEFAULT_PCAP_MAX_HEADER_BYTES = 8192
DEFAULT_PCAP_MAX_HEADERS = 20
DEFAULT_PCAP_TSHARK_TIMEOUT = 30


@dataclass
class TrafficSummary:
    pcap_path: str
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_headers: Optional[Dict[str, str]] = None
    payload_text: str = ""
    parser_backend: str = ""
    packets_seen: int = 0
    packets_sampled: int = 0
    packet_limit_reached: bool = False
    primary_flow: Optional[str] = None
    payload_bytes_seen: int = 0
    payload_bytes_kept: int = 0
    payload_truncated: bool = False
    binary_payload_skipped: bool = False

    def to_text(self) -> str:
        parts = []
        if self.protocol:
            parts.append(f"protocol={self.protocol}")
        if self.src_ip and self.dst_ip:
            parts.append(f"src={self.src_ip}:{self.src_port} dst={self.dst_ip}:{self.dst_port}")
        if self.http_method and self.http_uri:
            parts.append(f"http={self.http_method} {self.http_uri}")
        if self.http_headers:
            parts.append(f"headers={self.http_headers}")
        if self.payload_text:
            parts.append(f"payload={self.payload_text}")
        return "\n".join(parts)


class PCAPParser:
    @staticmethod
    def parse(pcap_path: str, tool_callback: Optional[Callable[[Dict[str, object]], None]] = None) -> TrafficSummary:
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")
        try:
            summary = PCAPParser._parse_with_scapy(pcap_path)
            PCAPParser._emit_tool_call(tool_callback, "parse_with_scapy", pcap_path, summary)
            return summary
        except Exception:
            summary = PCAPParser._parse_with_tshark(pcap_path, tool_callback=tool_callback)
            PCAPParser._emit_tool_call(tool_callback, "parse_with_tshark", pcap_path, summary)
            return summary

    @staticmethod
    def _parse_with_scapy(pcap_path: str) -> TrafficSummary:
        from scapy.all import IP, TCP, UDP, Raw, PcapReader  # type: ignore

        limits = PCAPParser._limits()
        summary = TrafficSummary(pcap_path=pcap_path, http_headers={}, parser_backend="scapy_stream")
        payload_preview = bytearray()
        first_transport_meta: Optional[Dict[str, object]] = None

        reader = PcapReader(pcap_path)
        try:
            for pkt in reader:
                summary.packets_seen += 1
                if summary.packets_sampled >= limits["max_packets"]:
                    summary.packet_limit_reached = True
                    break
                summary.packets_sampled += 1

                meta = PCAPParser._packet_meta_from_scapy(pkt, IP=IP, TCP=TCP, UDP=UDP, Raw=Raw)
                if meta is None:
                    continue
                if first_transport_meta is None:
                    first_transport_meta = meta
                PCAPParser._ingest_packet_meta(summary, meta, payload_preview, limits)
        finally:
            reader.close()

        if summary.primary_flow is None and first_transport_meta is not None:
            PCAPParser._set_summary_flow(summary, first_transport_meta, mark_primary=False)

        if summary.packet_limit_reached and payload_preview:
            summary.payload_truncated = True

        PCAPParser._finalize_payload_summary(summary, bytes(payload_preview), limits)
        return summary

    @staticmethod
    def _parse_with_tshark(
        pcap_path: str,
        tool_callback: Optional[Callable[[Dict[str, object]], None]] = None,
    ) -> TrafficSummary:
        limits = PCAPParser._limits()
        summary = TrafficSummary(pcap_path=pcap_path, http_headers={}, parser_backend="tshark_stream")
        payload_preview = bytearray()
        first_transport_meta: Optional[Dict[str, object]] = None

        try:
            max_packets = limits["max_packets"] + 1
            cmd = [
                "tshark",
                "-r",
                pcap_path,
                "-c",
                str(max_packets),
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
                "-e",
                "http.request.method",
                "-e",
                "http.request.uri",
                "-e",
                "tcp.payload",
                "-e",
                "udp.payload",
            ]
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=limits["tshark_timeout"],
            )
            PCAPParser._emit_tool_call(
                tool_callback,
                "tshark_subprocess",
                pcap_path,
                summary=None,
                extra={
                    "command": cmd,
                    "returncode": proc.returncode,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                },
            )
            lines = [line for line in proc.stdout.splitlines() if line.strip()]
            if len(lines) > limits["max_packets"]:
                summary.packet_limit_reached = True
                lines = lines[: limits["max_packets"]]

            for line in lines:
                summary.packets_seen += 1
                summary.packets_sampled += 1
                meta = PCAPParser._packet_meta_from_tshark_line(line)
                if meta is None:
                    continue
                if first_transport_meta is None:
                    first_transport_meta = meta
                PCAPParser._ingest_packet_meta(summary, meta, payload_preview, limits)

            if summary.primary_flow is None and first_transport_meta is not None:
                PCAPParser._set_summary_flow(summary, first_transport_meta, mark_primary=False)

            if summary.packet_limit_reached and payload_preview:
                summary.payload_truncated = True
            PCAPParser._finalize_payload_summary(summary, bytes(payload_preview), limits)
        except Exception as exc:
            summary.payload_text = f"parse_error={exc}"
            PCAPParser._emit_tool_call(
                tool_callback,
                "tshark_subprocess",
                pcap_path,
                summary=None,
                extra={"error": str(exc)},
            )

        return summary

    @staticmethod
    def _emit_tool_call(
        tool_callback: Optional[Callable[[Dict[str, object]], None]],
        action: str,
        pcap_path: str,
        summary: Optional[TrafficSummary],
        extra: Optional[Dict[str, object]] = None,
    ) -> None:
        if tool_callback is None:
            return
        output: Dict[str, object] = dict(extra or {})
        if summary is not None:
            output.update(
                {
                    "parser_backend": summary.parser_backend,
                    "protocol": summary.protocol,
                    "packets_seen": summary.packets_seen,
                    "packets_sampled": summary.packets_sampled,
                    "primary_flow": summary.primary_flow,
                    "src_ip": summary.src_ip,
                    "dst_ip": summary.dst_ip,
                    "src_port": summary.src_port,
                    "dst_port": summary.dst_port,
                    "http_method": summary.http_method,
                    "http_uri": summary.http_uri,
                    "payload_text": summary.payload_text,
                    "payload_bytes_seen": summary.payload_bytes_seen,
                    "payload_bytes_kept": summary.payload_bytes_kept,
                    "payload_truncated": summary.payload_truncated,
                }
            )
        tool_callback(
            {
                "tool": "pcap_parser",
                "action": action,
                "input": {"pcap_path": pcap_path},
                "output": output,
            }
        )

    @staticmethod
    def _packet_meta_from_scapy(pkt, *, IP, TCP, UDP, Raw) -> Optional[Dict[str, object]]:
        if IP not in pkt:
            return None

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = None
        src_port = dst_port = None
        if TCP in pkt:
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
        elif UDP in pkt:
            protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        if protocol is None:
            return None

        raw_bytes = bytes(pkt[Raw]) if Raw in pkt else b""
        return {
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "flow_label": PCAPParser._flow_label(protocol, src_ip, dst_ip, src_port, dst_port),
            "raw_bytes": raw_bytes,
            "http_method": None,
            "http_uri": None,
        }

    @staticmethod
    def _packet_meta_from_tshark_line(line: str) -> Optional[Dict[str, object]]:
        cols = line.split("\t")
        if len(cols) < 10:
            cols += [""] * (10 - len(cols))

        src_ip = cols[0] or None
        dst_ip = cols[1] or None
        tcp_src = cols[2]
        tcp_dst = cols[3]
        udp_src = cols[4]
        udp_dst = cols[5]
        http_method = cols[6] or None
        http_uri = cols[7] or None
        tcp_payload = cols[8].replace(":", "").strip()
        udp_payload = cols[9].replace(":", "").strip()

        protocol = None
        src_port = dst_port = None
        hex_payload = ""
        if tcp_src or tcp_dst:
            protocol = "TCP"
            src_port = int(tcp_src) if tcp_src else None
            dst_port = int(tcp_dst) if tcp_dst else None
            hex_payload = tcp_payload
        elif udp_src or udp_dst:
            protocol = "UDP"
            src_port = int(udp_src) if udp_src else None
            dst_port = int(udp_dst) if udp_dst else None
            hex_payload = udp_payload
        if protocol is None or src_ip is None or dst_ip is None:
            return None

        raw_bytes = b""
        if hex_payload:
            try:
                raw_bytes = bytes.fromhex(hex_payload)
            except ValueError:
                raw_bytes = hex_payload.encode("utf-8", errors="ignore")

        return {
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "flow_label": PCAPParser._flow_label(protocol, src_ip, dst_ip, src_port, dst_port),
            "raw_bytes": raw_bytes,
            "http_method": http_method,
            "http_uri": http_uri,
        }

    @staticmethod
    def _ingest_packet_meta(
        summary: TrafficSummary,
        meta: Dict[str, object],
        payload_preview: bytearray,
        limits: Dict[str, int],
    ) -> None:
        if summary.protocol is None:
            PCAPParser._set_summary_flow(summary, meta, mark_primary=False)

        raw_bytes = bytes(meta.get("raw_bytes") or b"")
        flow_label = str(meta.get("flow_label") or "")
        if summary.primary_flow is None and raw_bytes:
            PCAPParser._set_summary_flow(summary, meta, mark_primary=True)
            summary.http_method = str(meta.get("http_method") or "").upper() or None
            summary.http_uri = str(meta.get("http_uri") or "").strip() or None
        elif summary.primary_flow is None and meta.get("http_method") and meta.get("http_uri"):
            PCAPParser._set_summary_flow(summary, meta, mark_primary=True)
            summary.http_method = str(meta.get("http_method") or "").upper() or None
            summary.http_uri = str(meta.get("http_uri") or "").strip() or None

        if summary.primary_flow and flow_label == summary.primary_flow and summary.http_method is None and meta.get("http_method"):
            summary.http_method = str(meta.get("http_method") or "").upper() or None
        if summary.primary_flow and flow_label == summary.primary_flow and summary.http_uri is None and meta.get("http_uri"):
            summary.http_uri = str(meta.get("http_uri") or "").strip() or None

        if not summary.primary_flow or flow_label != summary.primary_flow:
            return
        if not raw_bytes:
            return

        summary.payload_bytes_seen += len(raw_bytes)
        remaining = limits["max_payload_bytes"] - len(payload_preview)
        if remaining <= 0:
            summary.payload_truncated = True
            return
        payload_preview.extend(raw_bytes[:remaining])
        summary.payload_bytes_kept = len(payload_preview)
        if len(raw_bytes) > remaining:
            summary.payload_truncated = True

    @staticmethod
    def _set_summary_flow(summary: TrafficSummary, meta: Dict[str, object], *, mark_primary: bool) -> None:
        summary.protocol = str(meta.get("protocol") or "").upper() or summary.protocol
        summary.src_ip = str(meta.get("src_ip") or "").strip() or summary.src_ip
        summary.dst_ip = str(meta.get("dst_ip") or "").strip() or summary.dst_ip
        summary.src_port = int(meta.get("src_port")) if meta.get("src_port") is not None else summary.src_port
        summary.dst_port = int(meta.get("dst_port")) if meta.get("dst_port") is not None else summary.dst_port
        if mark_primary:
            summary.primary_flow = str(meta.get("flow_label") or "").strip() or summary.primary_flow

    @staticmethod
    def _finalize_payload_summary(summary: TrafficSummary, payload_preview: bytes, limits: Dict[str, int]) -> None:
        summary.payload_bytes_kept = len(payload_preview)
        summary.http_headers = summary.http_headers or {}
        if not payload_preview:
            return

        probe = payload_preview[: limits["max_header_bytes"]]
        decoded_probe = probe.decode("utf-8", errors="replace")
        method, uri, headers, body = PCAPParser._parse_http(decoded_probe, max_headers=limits["max_headers"])
        if summary.http_method is None and method:
            summary.http_method = method
        if summary.http_uri is None and uri:
            summary.http_uri = uri
        if headers:
            summary.http_headers = headers

        if summary.http_method or summary.http_uri or headers:
            if PCAPParser._should_skip_http_body(summary.http_uri, headers, payload_preview):
                summary.binary_payload_skipped = True
                summary.payload_text = ""
                return
            text_payload = body if body else decoded_probe
            summary.payload_text = PCAPParser._sanitize_payload_text(
                text_payload,
                limit=limits["max_payload_text_chars"],
            )
            return

        if PCAPParser._looks_binary_bytes(payload_preview):
            summary.binary_payload_skipped = True
            summary.payload_text = ""
            return

        summary.payload_text = PCAPParser._sanitize_payload_text(
            payload_preview.decode("utf-8", errors="replace"),
            limit=limits["max_payload_text_chars"],
        )

    @staticmethod
    def _should_skip_http_body(uri: Optional[str], headers: Optional[Dict[str, str]], payload_preview: bytes) -> bool:
        headers = headers or {}
        content_type = str(headers.get("Content-Type") or headers.get("content-type") or "").lower()
        disposition = str(headers.get("Content-Disposition") or headers.get("content-disposition") or "").lower()
        uri_value = str(uri or "")

        if disposition and "attachment" in disposition:
            return True
        if uri_value and BINARY_URI_EXT_RE.search(uri_value):
            return True
        if content_type:
            if any(hint in content_type for hint in TEXTUAL_CONTENT_TYPE_HINTS):
                return False
            if content_type.startswith(("image/", "audio/", "video/", "font/")):
                return True
            if content_type.startswith("application/") and not any(hint in content_type for hint in TEXTUAL_CONTENT_TYPE_HINTS):
                return True
        return PCAPParser._looks_binary_bytes(payload_preview)

    @staticmethod
    def _looks_binary_bytes(data: bytes) -> bool:
        if not data:
            return False
        sample = data[:2048]
        if b"\x00" in sample:
            return True
        printable = 0
        control = 0
        for value in sample:
            if value in (9, 10, 13) or 32 <= value <= 126:
                printable += 1
            else:
                control += 1
        if not sample:
            return False
        return (control / len(sample)) > 0.30 or (printable / len(sample)) < 0.60

    @staticmethod
    def _sanitize_payload_text(text: str, *, limit: int) -> str:
        clean = str(text or "").replace("\x00", " ")
        clean = re.sub(r"\s+", " ", clean).strip()
        if len(clean) > limit:
            clean = clean[:limit]
        return clean

    @staticmethod
    def _flow_label(protocol: str, src_ip: str, dst_ip: str, src_port: Optional[int], dst_port: Optional[int]) -> str:
        return f"{protocol.upper()} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

    @staticmethod
    def _limits() -> Dict[str, int]:
        def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
            raw = os.getenv(name, "").strip()
            if not raw:
                return default
            try:
                value = int(raw)
            except ValueError:
                return default
            return max(minimum, value)

        return {
            "max_packets": _env_int("MA_MEMIDS_PCAP_MAX_PACKETS", DEFAULT_PCAP_MAX_PACKETS),
            "max_payload_bytes": _env_int("MA_MEMIDS_PCAP_MAX_PAYLOAD_BYTES", DEFAULT_PCAP_MAX_PAYLOAD_BYTES),
            "max_payload_text_chars": _env_int("MA_MEMIDS_PCAP_MAX_PAYLOAD_TEXT_CHARS", DEFAULT_PCAP_MAX_PAYLOAD_TEXT_CHARS),
            "max_header_bytes": _env_int("MA_MEMIDS_PCAP_MAX_HEADER_BYTES", DEFAULT_PCAP_MAX_HEADER_BYTES),
            "max_headers": _env_int("MA_MEMIDS_PCAP_MAX_HEADERS", DEFAULT_PCAP_MAX_HEADERS),
            "tshark_timeout": _env_int("MA_MEMIDS_PCAP_TSHARK_TIMEOUT", DEFAULT_PCAP_TSHARK_TIMEOUT),
        }

    @staticmethod
    def _parse_http(text: str, max_headers: int = DEFAULT_PCAP_MAX_HEADERS) -> Tuple[Optional[str], Optional[str], Dict[str, str], Optional[str]]:
        if not text:
            return None, None, {}, None

        normalized = text.replace("\r\n", "\n")
        parts = normalized.split("\n\n", 1)
        headers_blob = parts[0]
        body = parts[1] if len(parts) > 1 else None
        lines = [line.strip() for line in headers_blob.split("\n") if line.strip()]
        if not lines:
            return None, None, {}, body

        method = uri = None
        req_match = HTTP_REQUEST_RE.match(lines[0])
        if req_match:
            method = req_match.group(1).upper()
            uri = req_match.group(2)
        elif not HTTP_RESPONSE_RE.match(lines[0]):
            return None, None, {}, body

        headers: Dict[str, str] = {}
        for line in lines[1 : max_headers + 1]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if not key or not value:
                continue
            headers[key] = value[:160]

        return method, uri, headers, body
