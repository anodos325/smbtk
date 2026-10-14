"""smb-perf-fold: perf samples as folded stacks."""

from __future__ import annotations

import argparse
import sys

from . import cli
from .fmt import fmt_val
from .stacks import write_folded

MEANING = {
    "cycles": "CPU cycles", "instructions": "instructions retired",
    "ns": "nanoseconds", "calls": "system calls", "samples": "samples",
    "events": "events",
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Fold perf samples into one line per call stack: "
                    "frames root first, separated by ';', then the weight. "
                    "flamegraph.pl, inferno and speedscope read it, and so "
                    "do smb-perf-flame and smb-perf-top.")
    cli.add_input_args(ap)
    cli.add_select_args(ap)
    cli.add_stack_args(ap)
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="write here (default: standard output)")
    args = ap.parse_args(argv)
    loaded = cli.load(args.input, args)
    st = loaded.stacks
    if args.output:
        with open(args.output, "w") as f:
            write_folded(st, f)
    else:
        write_folded(st, sys.stdout)
    what = MEANING.get(st.unit, st.unit)
    if st.what == "off-CPU":
        what = "nanoseconds off the CPU"
    cli.note(f"{len(st.weights)} stacks from {st.count_text()}, "
             f"{fmt_val(st.total(), st.unit)} in all; weights are {what}"
             + (f" (read it with --unit {st.unit})"
                if st.unit not in ("samples",) and args.output else ""))
    for n in st.notes:
        cli.note(n)
    return 0
