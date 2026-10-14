"""Small numeric helpers: percentiles, buckets, bars."""

from __future__ import annotations

from typing import Sequence

US, MS, S = 1_000, 1_000_000, 1_000_000_000

LATENCY_EDGES = [100 * US, MS, 10 * MS, 100 * MS, S, 10 * S]
LATENCY_LABELS = ["<100us", "<1ms", "<10ms", "<100ms", "<1s", "<10s", ">=10s"]


def percentile(sorted_vals: Sequence[int], p: float) -> int:
    """Nearest-rank percentile of an ascending sequence."""
    if not sorted_vals:
        return 0
    k = max(0, min(len(sorted_vals) - 1, int(round(p / 100 * len(sorted_vals) + 0.5)) - 1))
    return sorted_vals[k]


def summarize(vals: Sequence[int]) -> dict:
    s = sorted(vals)
    n = len(s)
    if n == 0:
        return {"n": 0, "min": 0, "p50": 0, "p90": 0, "p99": 0, "max": 0,
                "mean": 0, "sum": 0}
    total = sum(s)
    return {
        "n": n, "min": s[0], "p50": percentile(s, 50), "p90": percentile(s, 90),
        "p99": percentile(s, 99), "max": s[-1], "mean": total // n,
        "sum": total,
    }


def latency_buckets(vals: Sequence[int]) -> list[int]:
    counts = [0] * (len(LATENCY_EDGES) + 1)
    for v in vals:
        for i, edge in enumerate(LATENCY_EDGES):
            if v < edge:
                counts[i] += 1
                break
        else:
            counts[-1] += 1
    return counts


def bar(value: float, maximum: float, width: int = 30) -> str:
    if maximum <= 0 or value <= 0:
        return ""
    n = int(round(width * value / maximum))
    return "#" * max(1, n)


def fmt_dur(ns: int | None) -> str:
    if ns is None:
        return "-"
    a = abs(ns)
    if a < US:
        return f"{ns}ns"
    if a < MS:
        return f"{ns / US:.1f}us"
    if a < S:
        return f"{ns / MS:.2f}ms"
    return f"{ns / S:.3f}s"


def fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    for unit in ("K", "M", "G", "T"):
        n /= 1024
        if n < 1024:
            return f"{n:.1f}{unit}"
    return f"{n:.1f}P"


def fmt_pct(part: float, whole: float) -> str:
    if whole <= 0:
        return "-"
    return f"{100 * part / whole:.1f}%"


def parse_duration(text: str) -> float:
    """'1.5', '250ms', '2m', '1m30s' as seconds."""
    text = text.strip().lower()
    try:
        return float(text)
    except ValueError:
        pass
    total = 0.0
    num = ""
    i = 0
    while i < len(text):
        c = text[i]
        if c.isdigit() or c == ".":
            num += c
            i += 1
            continue
        unit = c
        if text[i:i + 2] == "ms":
            unit = "ms"
        if text[i:i + 2] == "us":
            unit = "us"
        i += len(unit)
        if not num:
            raise ValueError(f"bad duration {text!r}")
        v = float(num)
        num = ""
        total += {"h": 3600, "m": 60, "s": 1, "ms": 1e-3, "us": 1e-6}[unit] * v
    if num:
        total += float(num)
    return total
