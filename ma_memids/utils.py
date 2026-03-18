from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Iterable, List


_TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def tokenize(text: str) -> List[str]:
    return [tok.lower() for tok in _TOKEN_RE.findall(text or "")]


def dedupe_keep_order(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def safe_div(num: float, den: float) -> float:
    if den == 0:
        return 0.0
    return num / den


def jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa = set(a)
    sb = set(b)
    if not sa and not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def cosine_sim(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / math.sqrt(na * nb)


def set_subset(a: Iterable[str], b: Iterable[str]) -> bool:
    sa = set(a)
    sb = set(b)
    return bool(sa) and sa.issubset(sb)
