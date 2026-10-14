"""smb-perf-compare: runs of smb-perf-stat, side by side by label."""

from __future__ import annotations

import argparse
import json
import statistics
import sys

from . import cli
from .fmt import fmt_si

# name, header, a run's value (None when it has none)
METRICS = [
    ("elapsed", "elapsed s", lambda r: r.get("wall_s")),
    ("cpu", "CPU s", lambda r: r.get("cpu_s")),
    ("cycles", "cycles", lambda r: r["totals"].get("cycles")),
    ("instructions", "instructions",
     lambda r: r["totals"].get("instructions")),
    ("ipc", "IPC", lambda r: r.get("ipc")),
    ("ghz", "GHz", lambda r: r.get("ghz")),
    ("switches", "context switches",
     lambda r: r["totals"].get("context-switches")),
    ("migrations", "migrations", lambda r: r["totals"].get("cpu-migrations")),
]


def _fmt(name: str, v: float) -> str:
    if name in ("cycles", "instructions", "switches", "migrations"):
        return fmt_si(v)
    if name in ("ipc", "ghz"):
        return f"{v:.2f}"
    return f"{v:.3f}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Compare runs saved by smb-perf-stat -o: per label, "
                    "the median, the range and the change against the "
                    "first label. Interleave the runs (A B B A ...) so "
                    "drift falls on both sides.")
    ap.add_argument("runs", nargs="+", metavar="RUN.json")
    ap.add_argument("--base", metavar="LABEL",
                    help="label to compare against (default: the first)")
    ap.add_argument("--per", action="store_true",
                    help="divide by each run's --per count")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    groups: dict[str, list[dict]] = {}
    for path in args.runs:
        try:
            with open(path) as f:
                r = json.load(f)
        except (OSError, ValueError) as e:
            raise SystemExit(f"error: {path}: {e}")
        if r.get("tool") != "smb-perf-stat":
            raise SystemExit(f"error: {path}: not an smb-perf-stat run")
        groups.setdefault(r.get("label", "run"), []).append(r)
    labels = list(groups)
    base = args.base or labels[0]
    if base not in groups:
        raise SystemExit(f"error: no runs labelled {base}")
    labels.remove(base)
    labels.insert(0, base)
    out = {}
    rows = []
    for name, header, get in METRICS:
        per_label = {}
        for lb in labels:
            vals = []
            for r in groups[lb]:
                v = get(r)
                if v is None:
                    continue
                if args.per and name not in ("ipc", "ghz"):
                    if not r.get("per"):
                        raise SystemExit("error: --per needs runs saved "
                                         "with --per")
                    v /= r["per"]["n"]
                    if name in ("elapsed", "cpu"):
                        v *= 1000
                vals.append(v)
            if vals:
                per_label[lb] = vals
        if base not in per_label:
            continue
        out[name] = {lb: {"median": statistics.median(v), "min": min(v),
                          "max": max(v), "n": len(v)}
                     for lb, v in per_label.items()}
        if args.per and name not in ("ipc", "ghz"):
            unit = groups[base][0]["per"]["unit"]
            header = {"elapsed": "elapsed ms", "cpu": "CPU ms"}.get(
                name, header) + f" per {unit}"
        row = [header]
        b = per_label[base]
        mb = statistics.median(b)
        for lb in labels:
            v = per_label.get(lb)
            if not v:
                row += ["-", "", ""]
                continue
            m = statistics.median(v)
            row.append(_fmt(name, m))
            row.append(f"{_fmt(name, min(v))}..{_fmt(name, max(v))}"
                       if len(v) > 1 else "")
            if lb == base:
                row.append("")
            else:
                apart = len(v) > 1 and len(b) > 1 and (
                    max(v) < min(b) or min(v) > max(b))
                change = f"{100 * (m - mb) / mb:+.1f}%" if mb else "-"
                row.append(change + (" *" if apart else ""))
        rows.append(row)
    if args.json:
        json.dump({"base": base, "labels": labels, "metrics": out},
                  sys.stdout, indent=1)
        print()
        return 0
    headers = ["metric"]
    for lb in labels:
        headers += [f"{lb} ({len(groups[lb])})", "range",
                    "" if lb == base else "change"]
    print(cli.table(rows, headers, "l" + "rrr" * len(labels)))
    print("\nmedians; * the ranges do not overlap (two or more runs each)")
    return 0
