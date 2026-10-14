"""Numbers as text, and text as numbers. Samba counts time in
microseconds."""

from __future__ import annotations

import datetime
import re


def fmt_us(us: float | None) -> str:
    if us is None:
        return "-"
    a = abs(us)
    if a < 1000:
        return f"{us:.0f}us" if a >= 10 or us == int(us) else f"{us:.1f}us"
    if a < 1_000_000:
        return f"{us / 1000:.2f}ms"
    return f"{us / 1_000_000:.2f}s"


def fmt_bytes(n: float) -> str:
    a = abs(n)
    for div, suffix in ((1 << 40, "TB"), (1 << 30, "GB"), (1 << 20, "MB"),
                        (1 << 10, "KB")):
        if a >= div:
            return f"{n / div:.1f}{suffix}"
    return f"{n:.0f}B"


def fmt_n(v: float) -> str:
    """A count: 1234, 12.3K, 4.56M."""
    a = abs(v)
    for limit, div, suffix in ((1e9, 1e9, "G"), (1e6, 1e6, "M"),
                               (1e4, 1e3, "K")):
        if a >= limit:
            x = v / div
            return f"{x:.3g}{suffix}" if abs(x) < 1000 else f"{x:.0f}{suffix}"
    return f"{v:.0f}" if v == int(v) else f"{v:.1f}"


def fmt_rate(v: float) -> str:
    if v == 0:
        return "0"
    if abs(v) < 10:
        return f"{v:.2f}".rstrip("0").rstrip(".")
    return fmt_n(round(v))


def fmt_pct(part: float, whole: float) -> str:
    if whole <= 0:
        return "-"
    return f"{100 * part / whole:.1f}%"


def fmt_change(new: float | None, old: float | None) -> str:
    if new is None or old is None:
        return "-"
    if old == 0:
        return "new" if new else "0"
    return f"{100 * (new - old) / old:+.1f}%"


def bar(value: float, maximum: float, width: int = 30) -> str:
    if maximum <= 0 or value <= 0:
        return ""
    n = value / maximum * width
    full = int(n)
    return "#" * full + ("+" if n - full >= 0.5 else "")


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


def parse_when(text: str, t0: float) -> float:
    """An epoch time: seconds into the recording ('90', '1m30s'), or wall
    clock: '@1791855038.5', ISO 8601 (UTC unless it has an offset) or
    'HH:MM:SS[.f]' (UTC, on the recording's first day)."""
    text = text.strip()
    if text.startswith("@"):
        return float(text[1:])
    utc = datetime.timezone.utc
    if re.match(r"^\d{4}-\d\d-\d\d[T ]", text):
        d = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=utc)
        return d.timestamp()
    if re.fullmatch(r"\d{1,2}:\d\d:\d\d(\.\d+)?", text):
        day = datetime.datetime.fromtimestamp(t0, utc).date()
        h, m, s = text.split(":")
        midnight = datetime.datetime.combine(day, datetime.time(tzinfo=utc))
        return midnight.timestamp() + int(h) * 3600 + int(m) * 60 + float(s)
    return t0 + parse_duration(text)


def wall(t: float, ms: bool = False) -> str:
    d = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    return d.strftime("%H:%M:%S.%f")[:-3] if ms else d.strftime("%H:%M:%S")


def wall_full(t: float) -> str:
    d = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    return d.strftime("%Y-%m-%d %H:%M:%S UTC")
