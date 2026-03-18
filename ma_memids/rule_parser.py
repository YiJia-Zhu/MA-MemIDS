from __future__ import annotations

import re
from typing import Dict, List, Optional

from .utils import dedupe_keep_order


RULE_HEADER_RE = re.compile(
    r"^(alert|drop|pass|reject)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)",
    re.IGNORECASE,
)
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def extract_sid(rule_text: str) -> Optional[int]:
    match = re.search(r"\bsid\s*:\s*(\d+)", rule_text, flags=re.IGNORECASE)
    return int(match.group(1)) if match else None


def extract_rev(rule_text: str) -> Optional[int]:
    match = re.search(r"\brev\s*:\s*(\d+)", rule_text, flags=re.IGNORECASE)
    return int(match.group(1)) if match else None


def bump_rev(rule_text: str) -> str:
    rev = extract_rev(rule_text)
    if rev is None:
        if rule_text.strip().endswith(")"):
            return rule_text.rstrip(")") + " rev:1;)"
        return rule_text + " rev:1;"
    return re.sub(r"\brev\s*:\s*\d+", f"rev:{rev + 1}", rule_text, flags=re.IGNORECASE)


def ensure_sid(rule_text: str, sid: int) -> str:
    if extract_sid(rule_text) is not None:
        return rule_text
    if rule_text.strip().endswith(")"):
        return rule_text.rstrip(")") + f" sid:{sid};)"
    return rule_text + f" sid:{sid};"


def parse_rule_fields(rule_text: str) -> Dict[str, object]:
    header = RULE_HEADER_RE.search(rule_text.strip())
    protocol = None
    src_ip = src_port = dst_ip = dst_port = None
    if header:
        protocol = header.group(2).upper()
        src_ip = header.group(3)
        src_port = header.group(4)
        dst_ip = header.group(5)
        dst_port = header.group(6)

    contents = re.findall(r'content\s*:\s*"([^"]+)"', rule_text, flags=re.IGNORECASE)
    pcres = re.findall(r'pcre\s*:\s*"([^"]+)"', rule_text, flags=re.IGNORECASE)
    msg = re.search(r'msg\s*:\s*"([^"]+)"', rule_text, flags=re.IGNORECASE)

    cve_ids = dedupe_keep_order(m.group(0).upper() for m in CVE_RE.finditer(rule_text))
    tech_ids = dedupe_keep_order(m.group(0).upper() for m in TECH_RE.finditer(rule_text))

    keywords: List[str] = []
    keywords.extend(contents)
    keywords.extend(pcres)
    if msg:
        keywords.append(msg.group(1))

    return {
        "protocol": protocol,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "keywords": dedupe_keep_order(keywords),
        "cve_ids": cve_ids,
        "tech_ids": tech_ids,
        "sid": extract_sid(rule_text),
    }
