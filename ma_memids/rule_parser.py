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
REFERENCE_RE = re.compile(r"\breference\s*:\s*([^;]+)", re.IGNORECASE)


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


def _normalize_reference_type(value: str) -> str:
    ref_type = str(value or "").strip().lower()
    if ref_type in {"url", "uri", "link", "links"}:
        return "url"
    if ref_type in {"cve", "cveid", "candidate"}:
        return "cve"
    if ref_type in {"attack", "mitre", "mitre-attack", "attack-technique", "technique"}:
        return "attack"
    return ref_type or "raw"


def _normalize_cve_reference(value: str) -> List[str]:
    text = str(value or "").strip()
    if not text:
        return []
    matches = [m.group(0).upper() for m in CVE_RE.finditer(text)]
    if matches:
        return dedupe_keep_order(matches)
    compact = re.findall(r"\b(\d{4})[-_]?(\d{4,})\b", text)
    out: List[str] = []
    for year, seq in compact:
        out.append(f"CVE-{year}-{seq}")
    return dedupe_keep_order(out)


def parse_rule_references(rule_text: str) -> List[Dict[str, object]]:
    references: List[Dict[str, object]] = []
    for match in REFERENCE_RE.finditer(rule_text):
        raw_value = str(match.group(1) or "").strip()
        if not raw_value:
            continue

        ref_type = "raw"
        ref_value = raw_value
        if "," in raw_value:
            left, right = raw_value.split(",", 1)
            ref_type = _normalize_reference_type(left)
            ref_value = right.strip()
        elif raw_value.lower().startswith(("http://", "https://")):
            ref_type = "url"

        cve_ids = _normalize_cve_reference(ref_value if ref_type == "cve" else raw_value)
        tech_ids = dedupe_keep_order(m.group(0).upper() for m in TECH_RE.finditer(raw_value))
        url = ref_value if ref_type == "url" else ""

        references.append(
            {
                "type": ref_type,
                "value": ref_value,
                "raw": raw_value,
                "url": url,
                "cve_ids": cve_ids,
                "tech_ids": tech_ids,
            }
        )

    return references


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
    references = parse_rule_references(rule_text)

    cve_ids = dedupe_keep_order(m.group(0).upper() for m in CVE_RE.finditer(rule_text))
    tech_ids = dedupe_keep_order(m.group(0).upper() for m in TECH_RE.finditer(rule_text))
    for reference in references:
        cve_ids.extend(str(item).upper().strip() for item in reference.get("cve_ids", []) if str(item).strip())
        tech_ids.extend(str(item).upper().strip() for item in reference.get("tech_ids", []) if str(item).strip())
    cve_ids = dedupe_keep_order(cve_ids)
    tech_ids = dedupe_keep_order(tech_ids)

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
        "references": references,
        "reference_urls": dedupe_keep_order(
            str(item.get("url") or "").strip()
            for item in references
            if str(item.get("url") or "").strip()
        ),
        "sid": extract_sid(rule_text),
    }
