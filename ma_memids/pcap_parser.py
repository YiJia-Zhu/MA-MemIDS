from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


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

    def to_text(self) -> str:
        parts = [f"pcap={self.pcap_path}"]
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
    def parse(pcap_path: str) -> TrafficSummary:
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")
        try:
            return PCAPParser._parse_with_scapy(pcap_path)
        except Exception:
            return PCAPParser._parse_with_tshark(pcap_path)

    @staticmethod
    def _parse_with_scapy(pcap_path: str) -> TrafficSummary:
        from scapy.all import IP, TCP, UDP, Raw, rdpcap  # type: ignore

        payload_raw = b""
        summary = TrafficSummary(pcap_path=pcap_path, http_headers={})
        for pkt in rdpcap(pcap_path):
            if IP in pkt:
                summary.src_ip = summary.src_ip or pkt[IP].src
                summary.dst_ip = summary.dst_ip or pkt[IP].dst
            if TCP in pkt:
                summary.protocol = "TCP"
                summary.src_port = summary.src_port or int(pkt[TCP].sport)
                summary.dst_port = summary.dst_port or int(pkt[TCP].dport)
            elif UDP in pkt:
                summary.protocol = "UDP"
                summary.src_port = summary.src_port or int(pkt[UDP].sport)
                summary.dst_port = summary.dst_port or int(pkt[UDP].dport)
            if Raw in pkt:
                payload_raw += bytes(pkt[Raw])

        payload_text = payload_raw.decode("utf-8", errors="replace")
        method, uri, headers, body = PCAPParser._parse_http(payload_text)
        summary.http_method = method
        summary.http_uri = uri
        summary.http_headers = headers or {}
        summary.payload_text = payload_text if len(payload_text) < 2000 else payload_text[:2000]
        if body and body not in summary.payload_text:
            summary.payload_text += "\n" + body
        return summary

    @staticmethod
    def _parse_with_tshark(pcap_path: str) -> TrafficSummary:
        summary = TrafficSummary(pcap_path=pcap_path, http_headers={})
        try:
            payload_out = subprocess.run(
                ["tshark", "-r", pcap_path, "-T", "fields", "-e", "tcp.payload", "-e", "udp.payload"],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            hex_data = payload_out.stdout.replace(":", "").replace("\n", "").strip()
            payload_text = ""
            if hex_data:
                try:
                    payload_text = bytes.fromhex(hex_data).decode("utf-8", errors="replace")
                except ValueError:
                    payload_text = hex_data

            meta_out = subprocess.run(
                [
                    "tshark",
                    "-r",
                    pcap_path,
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
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            first_line = next((ln for ln in meta_out.stdout.splitlines() if ln.strip()), "")
            cols = first_line.split("\t")
            summary.src_ip = cols[0] if len(cols) > 0 and cols[0] else None
            summary.dst_ip = cols[1] if len(cols) > 1 and cols[1] else None
            tcp_src = cols[2] if len(cols) > 2 else ""
            tcp_dst = cols[3] if len(cols) > 3 else ""
            udp_src = cols[4] if len(cols) > 4 else ""
            udp_dst = cols[5] if len(cols) > 5 else ""
            if tcp_src or tcp_dst:
                summary.protocol = "TCP"
                summary.src_port = int(tcp_src) if tcp_src else None
                summary.dst_port = int(tcp_dst) if tcp_dst else None
            elif udp_src or udp_dst:
                summary.protocol = "UDP"
                summary.src_port = int(udp_src) if udp_src else None
                summary.dst_port = int(udp_dst) if udp_dst else None
            summary.http_method = cols[6] if len(cols) > 6 and cols[6] else None
            summary.http_uri = cols[7] if len(cols) > 7 and cols[7] else None

            method, uri, headers, body = PCAPParser._parse_http(payload_text)
            summary.http_method = summary.http_method or method
            summary.http_uri = summary.http_uri or uri
            summary.http_headers = headers or {}
            summary.payload_text = payload_text if len(payload_text) < 2000 else payload_text[:2000]
            if body and body not in summary.payload_text:
                summary.payload_text += "\n" + body
        except Exception as exc:
            summary.payload_text = f"parse_error={exc}"

        return summary

    @staticmethod
    def _parse_http(text: str) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, str]], Optional[str]]:
        if not text:
            return None, None, None, None

        parts = text.split("\r\n\r\n", 1)
        headers_blob = parts[0]
        body = parts[1] if len(parts) > 1 else None
        lines = headers_blob.split("\r\n")
        if not lines:
            return None, None, None, body

        method = uri = None
        req_match = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP", lines[0])
        if req_match:
            method = req_match.group(1)
            uri = req_match.group(2)

        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k] = v

        return method, uri, headers, body
