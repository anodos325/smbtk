"""smb-perf-flame: flame graphs and call trees of a perf recording."""

from __future__ import annotations

import argparse
import os
import sys

from . import cli, stacks
from .flame import Diff, render_svg, render_tree
from .fmt import fmt_val, parse_per, wall


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Flame graph of a perf recording: a box per function, "
                    "as wide as its share, callers below and callees above. "
                    "Self-contained SVG: click to zoom, Ctrl-F to search.")
    cli.add_input_args(ap)
    cli.add_select_args(ap)
    cli.add_stack_args(ap)
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="SVG to write (default: INPUT.svg; in a recording "
                    "directory flame.svg, or flame-N.svg if taken; - for "
                    "standard output)")
    d = ap.add_argument_group("comparing")
    d.add_argument("--diff", metavar="BASE",
                   help="a second input to compare INPUT against: frames as "
                   "wide as INPUT's, red where INPUT spends more, blue where "
                   "less (each function's own share)")
    d.add_argument("--widths", choices=("new", "base"), default="new",
                   help="with --diff: whose weights set the widths; base "
                   "shows what INPUT no longer does")
    d.add_argument("--absolute", action="store_true",
                   help="with --diff: compare weights as they are, not as "
                   "shares of each total")
    d.add_argument("--per", metavar="N[:UNIT]",
                   help="the work INPUT did, e.g. 3000:file: weights per "
                   "unit in the hover text and the tree")
    d.add_argument("--base-per", metavar="N[:UNIT]",
                   help="the work BASE did; with --per, --diff compares "
                   "weights per unit")
    cli.add_base_args(d)
    v = ap.add_argument_group("view")
    v.add_argument("--reverse", action="store_true",
                   help="merge stacks by their last function, its callers "
                   "above it (who calls the hottest functions)")
    v.add_argument("--icicle", action="store_true", help="roots at the top")
    v.add_argument("--title", help="title (default: from the recording)")
    v.add_argument("--subtitle", help="second line")
    v.add_argument("--width", type=int, default=1200, metavar="PX")
    v.add_argument("--min-width", type=float, default=0.1, metavar="PX",
                   help="leave out frames narrower than this (default 0.1)")
    t = ap.add_argument_group("text")
    t.add_argument("--tree", action="store_true",
                   help="print the call tree as text instead")
    t.add_argument("--min-pct", type=float, default=1.0, metavar="P",
                   help="tree: sum children under P%% of the total into "
                   "one line (default 1)")
    t.add_argument("--depth", type=int, default=0, metavar="N",
                   help="tree: stop N frames down")
    t.add_argument("--top", type=int, default=0, metavar="N",
                   help="tree: at most N children per function")
    args = ap.parse_args(argv)
    try:
        per = parse_per(args.per) if args.per else None
        base_per = parse_per(args.base_per) if args.base_per else None
    except ValueError as e:
        ap.error(str(e))
    if base_per and not per:
        ap.error("--base-per needs --per")
    if (args.absolute or base_per) and not args.diff:
        ap.error("--absolute and --base-per compare against --diff")

    new = cli.load(args.input, args)
    st = new.stacks
    if args.reverse:
        st = stacks.reverse(st)
    if not st.weights:
        raise SystemExit("error: no samples left after selection")
    diff = None
    if args.diff:
        base = cli.load(args.diff, cli.base_args(args))
        bst = stacks.reverse(base.stacks) if args.reverse else base.stacks
        if not bst.weights:
            raise SystemExit("error: no samples left in BASE")
        if bst.unit != st.unit:
            cli.note(f"warning: comparing {st.unit} with {bst.unit}")
        names = (_short(args.input), _short(args.diff))
        if base_per:
            scale = per[0] / base_per[0]
        elif args.absolute:
            scale = 1.0
        else:
            scale = st.total() / (bst.total() or 1)
        if args.widths == "base" and not args.tree:
            root = stacks.tree(bst, st, 1 / scale)
            diff = Diff(1 / scale, names[::-1], per[0] if per else 1,
                        flip=True)
            shown, shown_per = bst, base_per
        else:
            root = stacks.tree(st, bst, scale)
            diff = Diff(scale, names, base_per[0] if base_per else 1)
            shown, shown_per = st, per
    else:
        root = stacks.tree(st)
        shown, shown_per = st, per

    if args.tree:
        sys.stdout.write(render_tree(root, shown.unit, args.min_pct,
                                     args.depth, args.top, diff, shown_per))
        for n in st.notes:
            cli.note(n)
        return 0

    title = args.title or (f"{new.title()} vs {_short(args.diff)}"
                           if args.diff else new.title())
    subtitle = args.subtitle if args.subtitle is not None else \
        _subtitle(new, st, diff, args)
    svg = render_svg(root, shown, title, subtitle, args.width,
                     args.min_width, args.icicle, diff,
                     negate=args.widths == "base", per=shown_per)
    out = args.output or _default_output(args.input)
    if out == "-":
        sys.stdout.write(svg)
    else:
        with open(out, "w") as f:
            f.write(svg)
        cli.note(f"wrote {out}: {fmt_val(st.total(), st.unit)} in "
                 f"{st.count_text()}")
    for n in st.notes:
        cli.note(n)
    return 0


def _short(path: str) -> str:
    path = path.rstrip("/")
    name = os.path.basename(path)
    if name in ("perf.data", "perf.folded"):
        name = os.path.basename(os.path.dirname(os.path.abspath(path)))
    return name


def _default_output(path: str) -> str:
    """INPUT.svg; in a recording directory flame.svg, or flame-N.svg
    beside the ones already there."""
    if not os.path.isdir(path):
        return os.path.splitext(path)[0] + ".svg"
    out = os.path.join(path, "flame.svg")
    n = 2
    while os.path.exists(out):
        out = os.path.join(path, f"flame-{n}.svg")
        n += 1
    return out


def _subtitle(loaded: cli.Loaded, st: stacks.Stacks, diff: Diff | None,
              args: argparse.Namespace) -> str:
    parts = []
    what = {"off-CPU": "time off the CPU", "syscalls": "system calls",
            "on-CPU": f"{st.unit if st.unit != 'ns' else 'CPU time'}"}
    parts.append(what.get(st.what, st.unit))
    a, b = loaded.window
    off = loaded.header.get("tod_offset_ns")
    if a is not None or b is not None:
        parts.append(f"from {wall(a, off) if a is not None else 'start'} "
                     f"to {wall(b, off) if b is not None else 'end'}")
    sel = []
    for flag in ("client", "comm", "pid", "tid", "grep", "exclude"):
        for val in getattr(args, flag, []) or []:
            sel.append(f"{flag} {val}")
    if args.focus:
        sel.append(f"focus {args.focus}")
    if sel:
        parts.append(", ".join(sel))
    if diff:
        parts.append(f"widths: {diff.names[0]}; red: more than "
                     f"{diff.names[1]}, blue: less"
                     + ("" if args.absolute or args.base_per else
                        " (shares of each total)"))
    return "; ".join(parts)
