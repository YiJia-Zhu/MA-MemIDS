#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from scapy.all import IP, TCP, Raw, wrpcap  # type: ignore


SRC_IP = "192.168.56.10"
DST_IP = "10.0.0.20"
DST_PORT = 80


def build_http_flow_packets(request: str, sport: int, response: str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK") -> List:
    ip_c2s = IP(src=SRC_IP, dst=DST_IP)
    ip_s2c = IP(src=DST_IP, dst=SRC_IP)

    seq_c = 1000
    seq_s = 5000

    req_bytes = request.encode("utf-8", errors="ignore")
    resp_bytes = response.encode("utf-8", errors="ignore") if response else b""

    packets = [
        ip_c2s / TCP(sport=sport, dport=DST_PORT, flags="S", seq=seq_c),
        ip_s2c / TCP(sport=DST_PORT, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1),
        ip_c2s / TCP(sport=sport, dport=DST_PORT, flags="A", seq=seq_c + 1, ack=seq_s + 1),
        ip_c2s / TCP(sport=sport, dport=DST_PORT, flags="PA", seq=seq_c + 1, ack=seq_s + 1)
        / Raw(load=req_bytes),
        ip_s2c
        / TCP(
            sport=DST_PORT,
            dport=sport,
            flags="A",
            seq=seq_s + 1,
            ack=seq_c + 1 + len(req_bytes),
        ),
    ]

    if resp_bytes:
        packets.extend(
            [
                ip_s2c
                / TCP(
                    sport=DST_PORT,
                    dport=sport,
                    flags="PA",
                    seq=seq_s + 1,
                    ack=seq_c + 1 + len(req_bytes),
                )
                / Raw(load=resp_bytes),
                ip_c2s
                / TCP(
                    sport=sport,
                    dport=DST_PORT,
                    flags="A",
                    seq=seq_c + 1 + len(req_bytes),
                    ack=seq_s + 1 + len(resp_bytes),
                ),
            ]
        )

    return packets


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    out_root = root / "sandbox_samples"
    benign_dir = out_root / "benign"
    attack_dir = out_root / "attack"
    benign_dir.mkdir(parents=True, exist_ok=True)
    attack_dir.mkdir(parents=True, exist_ok=True)

    benign_requests: Dict[str, str] = {
        "benign_home": "GET /index.html HTTP/1.1\r\nHost: example.org\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        "benign_search": "GET /search?q=network+security HTTP/1.1\r\nHost: example.org\r\nUser-Agent: curl/8.0\r\n\r\n",
        "benign_login": (
            "POST /login HTTP/1.1\r\n"
            "Host: example.org\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 30\r\n\r\n"
            "username=alice&password=hello123"
        ),
        "benign_api": "GET /api/v1/profile?id=42 HTTP/1.1\r\nHost: internal.local\r\nAccept: application/json\r\n\r\n",
    }

    attack_requests: Dict[str, str] = {
        "attack_sqli_union": (
            "GET /search?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\r\n"
            "Host: vuln.local\r\n\r\n"
        ),
        "attack_sqli_or_true": (
            "GET /login?user=admin'%20OR%20'1'='1&pass=x HTTP/1.1\r\n"
            "Host: vuln.local\r\n\r\n"
        ),
        "attack_xss_script": (
            "GET /search?q=<script>alert('xss')</script> HTTP/1.1\r\n"
            "Host: vuln.local\r\n\r\n"
        ),
        "attack_lfi_passwd": (
            "GET /download?file=../../../../etc/passwd HTTP/1.1\r\n"
            "Host: vuln.local\r\n\r\n"
        ),
        "attack_cmd_inject": (
            "GET /ping?host=127.0.0.1;cat+/etc/passwd HTTP/1.1\r\n"
            "Host: vuln.local\r\n\r\n"
        ),
    }

    manifest: Dict[str, Dict[str, str]] = {"benign": {}, "attack": {}}

    sport = 41000
    for name, req in benign_requests.items():
        packets = build_http_flow_packets(req, sport=sport)
        path = benign_dir / f"{name}.pcap"
        wrpcap(str(path), packets)
        manifest["benign"][name] = str(path)
        sport += 1

    for name, req in attack_requests.items():
        packets = build_http_flow_packets(req, sport=sport)
        path = attack_dir / f"{name}.pcap"
        wrpcap(str(path), packets)
        manifest["attack"][name] = str(path)
        sport += 1

    manifest_path = out_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Generated benign pcaps: {len(manifest['benign'])}")
    print(f"Generated attack pcaps: {len(manifest['attack'])}")
    print(f"Manifest: {manifest_path}")


if __name__ == "__main__":
    main()
