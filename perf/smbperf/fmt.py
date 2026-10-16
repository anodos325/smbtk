"""Numbers as text, and text as numbers."""

from __future__ import annotations

import datetime
import re

from .perfdata import ns

US, MS, S = 1_000, 1_000_000, 1_000_000_000

UNITS = ("cycles", "instructions", "samples", "events", "calls", "ns")


def fmt_dur(ns: float | None) -> str:
    if ns is None:
        return "-"
    a = abs(ns)
    if a < US:
        return f"{ns:.0f}ns"
    if a < MS:
        return f"{ns / US:.1f}us"
    if a < S:
        return f"{ns / MS:.2f}ms"
    return f"{ns / S:.3f}s"


def fmt_bytes(n: float | None) -> str:
    """Bytes in binary units as zfs prints them: 512B, 1.50K, 29.0G,
    2.51T."""
    if n is None:
        return "-"
    a = abs(n)
    for div, suffix in ((1 << 50, "P"), (1 << 40, "T"), (1 << 30, "G"),
                        (1 << 20, "M"), (1 << 10, "K")):
        if a >= div:
            v = n / div
            if abs(v) >= 100:
                return f"{v:.0f}{suffix}"
            return f"{v:.1f}{suffix}" if abs(v) >= 10 else f"{v:.2f}{suffix}"
    return f"{n:.0f}B"


def fmt_si(v: float) -> str:
    a = abs(v)
    for div, suffix in ((1e12, "T"), (1e9, "G"), (1e6, "M"), (1e3, "K")):
        if a >= div:
            return f"{v / div:.2f}{suffix}"
    return f"{v:.0f}" if v == int(v) else f"{v:.3g}"


def fmt_val(v: float, unit: str) -> str:
    """A weight in its unit: time for ns, a count otherwise."""
    if unit == "ns":
        return fmt_dur(v)
    return fmt_si(v)


def unit_label(unit: str) -> str:
    return {"ns": "time", "calls": "calls"}.get(unit, unit)


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
    parts = re.findall(r"(\d+(?:\.\d*)?)\s*(h|ms|us|m|s)", text)
    if not parts or "".join(a + b for a, b in parts) != text.replace(" ", ""):
        raise ValueError(f"bad duration {text!r}")
    scale = {"h": 3600, "m": 60, "s": 1, "ms": 1e-3, "us": 1e-6}
    return sum(float(a) * scale[b] for a, b in parts)


def parse_per(text: str) -> tuple[float, str]:
    """'3000' or '3000:file' as (count, unit name)."""
    n, _, unit = text.partition(":")
    try:
        v = float(n)
    except ValueError:
        raise ValueError(f"bad count {text!r}") from None
    if v <= 0:
        raise ValueError(f"bad count {text!r}")
    return v, unit or "unit"


def _epoch_ns(d: datetime.datetime) -> int:
    delta = d - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    return ((delta.days * 86400 + delta.seconds) * S
            + delta.microseconds * US)


def parse_when(text: str, first_ns: int | None,
               tod_offset_ns: int | None) -> int:
    """A time in perf's clock: seconds into the recording ('12.5',
    '1m3s'), or wall clock: '@1791855038.5', ISO 8601
    ('2026-10-13T01:30:38.5', UTC unless it has an offset) or
    'HH:MM:SS[.f]' (UTC, on the recording's date)."""
    text = text.strip()
    wall_ns = None
    if text.startswith("@"):
        if not re.fullmatch(r"@\d+(\.\d*)?", text):
            raise ValueError(f"bad time {text!r}")
        wall_ns = ns(text[1:])
    elif re.match(r"^\d{4}-\d\d-\d\d[T ]", text):
        d = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=datetime.timezone.utc)
        wall_ns = _epoch_ns(d)
        m = re.search(r":\d\d\.(\d{7,9})", text)
        if m:
            wall_ns += int((m.group(1) + "000")[6:9])
    elif re.match(r"^\d{1,2}:\d\d:\d\d(\.\d+)?$", text):
        if first_ns is None or tod_offset_ns is None:
            raise ValueError("a time of day needs the recording's clock "
                             "reference (perf record -k)")
        day = datetime.datetime.fromtimestamp(
            (first_ns + tod_offset_ns) // S, datetime.timezone.utc).date()
        h, m, sec = text.split(":")
        midnight = datetime.datetime.combine(
            day, datetime.time(tzinfo=datetime.timezone.utc))
        wall_ns = _epoch_ns(midnight) + (int(h) * 3600 + int(m) * 60) * S \
            + ns(sec)
    if wall_ns is not None:
        if tod_offset_ns is None:
            raise ValueError("wall-clock times need the recording's clock "
                             "reference (perf record -k)")
        return wall_ns - tod_offset_ns
    if first_ns is None:
        raise ValueError("relative times need the time of the first sample")
    return first_ns + int(round(parse_duration(text) * S))


def wall(perf_ns: int, tod_offset_ns: int | None) -> str:
    if tod_offset_ns is None:
        return f"{perf_ns / S:.6f}"
    d = datetime.datetime.fromtimestamp((perf_ns + tod_offset_ns) / S,
                                        datetime.timezone.utc)
    return d.strftime("%Y-%m-%d %H:%M:%S.%f UTC")


def wrap_items(prefix: str, items, sep: str = ", ", indent: str = "    ",
               width: int = 100) -> str:
    """`prefix` and the items on lines of at most `width` columns with
    every item kept whole, where textwrap would break "tcp_rmem 4096
    131072 33554432" or "aio read size = 1" at any space."""
    lines: list[str] = []
    line = prefix
    first = True
    for item in items:
        if first:
            if len(prefix) + len(item) > width and prefix.strip():
                lines.append(prefix.rstrip())
                line = indent + item
            else:
                line = prefix + item
            first = False
        elif len(line) + len(sep) + len(item) <= width:
            line += sep + item
        else:
            lines.append(line + sep.rstrip())
            line = indent + item
    lines.append(line)
    return "\n".join(lines)
