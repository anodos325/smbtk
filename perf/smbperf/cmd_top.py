"""smb-perf-top: where the weight of a perf recording goes, as tables."""

from __future__ import annotations

import argparse
import json
import sys

from . import cli, smbd, stacks
from .fmt import fmt_val, parse_per
from .perfdata import KERNEL, MODULE
from .stacks import PSEUDO, Stacks


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Tables of a perf recording: functions by their own "
                    "and total share (default), smbd's time by SMB2 "
                    "command, what runs under a function, who calls it, the "
                    "heaviest stacks, binaries, processes; or what changed "
                    "against another recording.")
    cli.add_input_args(ap)
    cli.add_select_args(ap)
    cli.add_stack_args(ap)
    view = ap.add_argument_group("view (one)")
    v = view.add_mutually_exclusive_group()
    v.add_argument("--ops", action="store_true",
                   help="smbd's weight by SMB2 command (the outermost "
                   "handler in each stack), io_uring workers by operation")
    v.add_argument("--below", metavar="FUNC",
                   help="functions under FUNC, by their total share of it; "
                   "with --depth, the call paths N frames down")
    v.add_argument("--callers", metavar="FUNC",
                   help="the call chains above FUNC, --depth frames (8)")
    v.add_argument("--stacks", nargs="?", type=int, const=8, metavar="N",
                   help="the heaviest stacks, by their last N frames (8): "
                   "with an off-CPU recording, what smbd waits in")
    v.add_argument("--dso", action="store_true",
                   help="own weight by binary: smbd's libraries, libc, the "
                   "kernel, its modules")
    v.add_argument("--process", action="store_true",
                   help="weight by process and thread")
    ap.add_argument("--depth", type=int, metavar="N",
                    help="frames per path for --below and --callers")
    ap.add_argument("--sort", choices=("self", "total"), default="self",
                    help="function table order (default self)")
    ap.add_argument("--top", type=int, default=30, metavar="N",
                    help="rows (default 30)")
    ap.add_argument("--per", metavar="N[:UNIT]",
                    help="the work done, e.g. 3000:file: adds weight per "
                    "unit")
    ap.add_argument("--requests", metavar="FILE",
                    help="with --ops: smb-latency --json output for the same "
                    "window (--by cmd), to add the weight per request")
    d = ap.add_argument_group("comparing")
    d.add_argument("--diff", metavar="BASE",
                   help="compare with a second input: the functions (or "
                   "with --ops, the commands) whose total moved most")
    d.add_argument("--base-per", metavar="N[:UNIT]",
                   help="the work BASE did; with --per, compares per unit")
    d.add_argument("--absolute", action="store_true",
                   help="compare weights as they are, not as shares")
    cli.add_base_args(d)
    ap.add_argument("--json", action="store_true", help="rows as JSON")
    args = ap.parse_args(argv)
    try:
        per = parse_per(args.per) if args.per else None
        base_per = parse_per(args.base_per) if args.base_per else None
    except ValueError as e:
        ap.error(str(e))
    if base_per and not per:
        ap.error("--base-per needs --per")
    if args.diff and (args.below or args.callers or args.stacks
                      or args.dso or args.process):
        ap.error("--diff compares functions or --ops")

    root = "process" if args.ops else None
    st = cli.load(args.input, args, root).stacks
    if not st.weights:
        raise SystemExit("error: no samples left after selection")
    if args.diff:
        base = cli.load(args.diff, cli.base_args(args), root).stacks
        if not base.weights:
            raise SystemExit("error: no samples left in BASE")
        if base_per:
            scale = per[0] / base_per[0]
        elif args.absolute:
            scale = 1.0
        else:
            scale = st.total() / (base.total() or 1)
        rows, headers, align, intro = _diff(st, base, scale, args, per)
    elif args.ops:
        rows, headers, align, intro = _ops(st, per, args.requests)
    elif args.below:
        rows, headers, align, intro = _below(st, args.below, args.depth,
                                             per, args.top)
    elif args.callers:
        rows, headers, align, intro = _callers(st, args.callers,
                                               args.depth or 8, args.top)
    elif args.stacks:
        rows, headers, align, intro = _stacks(st, args.stacks, args.top)
    elif args.dso:
        rows, headers, align, intro = _dso(st, per)
    elif args.process:
        rows, headers, align, intro = _process(st, per)
    else:
        rows, headers, align, intro = _functions(st, args.sort, args.top,
                                                 per)
    if args.json:
        json.dump({"unit": st.unit, "total": st.total(),
                   "samples": st.samples(), "columns": headers,
                   "rows": [[c.v if isinstance(c, W) else c for c in r]
                            for r in rows]},
                  sys.stdout, indent=1)
        print()
        return 0
    if intro:
        print(intro)
    print(cli.table([[_cell(c, st.unit) for c in r] for r in rows],
                    headers, align))
    for n in st.notes:
        cli.note(n)
    return 0


class W:
    """A weight cell: shown in the profile's unit."""
    __slots__ = ("v",)

    def __init__(self, v: float) -> None:
        self.v = v


def _cell(c: object, unit: str) -> str:
    if isinstance(c, W):
        return fmt_val(c.v, unit)
    if isinstance(c, float):
        return f"{c:.2f}"
    return str(c)


def _pct(part: float, whole: float) -> str:
    return f"{100 * part / whole:.2f}" if whole else "-"


def _summary(st: Stacks, per: tuple[float, str] | None) -> str:
    text = (f"{fmt_val(st.total(), st.unit)}"
            f"{'' if st.unit == 'ns' else ' ' + st.unit} in "
            f"{st.count_text()}")
    if per:
        text += (f", {fmt_val(st.total() / per[0], st.unit)} per {per[1]} "
                 f"over {per[0]:g}")
    return text


def _functions(st: Stacks, sort: str, top: int,
               per: tuple[float, str] | None):
    inc, own = stacks.inclusive(st)
    total = st.total()
    names = [n for n in inc if not st.kind(n) & PSEUDO]
    key = (lambda n: -own.get(n, 0)) if sort == "self" else \
        (lambda n: -inc[n])
    rows = []
    for n in sorted(names, key=key)[:top]:
        row = [_pct(own.get(n, 0), total), W(own.get(n, 0)),
               _pct(inc[n], total), W(inc[n])]
        if per:
            row += [W(own.get(n, 0) / per[0]), W(inc[n] / per[0])]
        rows.append(row + [n])
    headers = ["self %", "self", "total %", "total"]
    if per:
        headers += [f"self/{per[1]}", f"total/{per[1]}"]
    return (rows, headers + ["function"], "r" * (len(headers)) + "l",
            _summary(st, per))


def _ops(st: Stacks, per: tuple[float, str] | None, requests: str | None):
    acc: dict[str, float] = {}
    for s, w in st.weights.items():
        op = smbd.command(s)
        acc[op] = acc.get(op, 0) + w
    total = st.total()
    nreq: dict[str, int] = {}
    if requests:
        with open(requests) as f:
            d = json.load(f)
        if d.get("levels") != ["cmd"]:
            raise SystemExit(f"error: {requests}: needs smb-latency --json "
                             "--by cmd")
        nreq = {g["key"][0]: g["n"] for g in d.get("groups", [])}
    rows = []
    for op, w in sorted(acc.items(), key=lambda kv: -kv[1]):
        row = [op, _pct(w, total), W(w)]
        if per:
            row.append(W(w / per[0]))
        if requests:
            n = nreq.get(op)
            row += [n or "", W(w / n) if n else ""]
        rows.append(row)
    headers = ["work", "%", "weight"]
    if per:
        headers.append(f"per {per[1]}")
    if requests:
        headers += ["requests", "per request"]
    intro = _summary(st, per) + (
        "\ncommands: the outermost smbd frame named after an SMB2 command; "
        "a compound's members each count their own handler")
    return rows, headers, "l" + "r" * (len(headers) - 1), intro


def _below(st: Stacks, pattern: str, depth: int | None,
           per: tuple[float, str] | None, top: int):
    hit = stacks.matcher(pattern, stacks.frame_names(st))
    anchors: set[str] = set()
    tot = 0.0
    inc: dict[str, float] = {}
    own: dict[str, float] = {}
    paths: dict[str, float] = {}
    for s, w in st.weights.items():
        i = next((i for i, f in enumerate(s) if hit(f)), None)
        if i is None:
            continue
        anchors.add(s[i])
        tot += w
        under = s[i + 1:]
        if depth:
            key = " > ".join(under[:depth]) or "(self)"
            paths[key] = paths.get(key, 0) + w
        else:
            for f in set(under):
                inc[f] = inc.get(f, 0) + w
            leaf = under[-1] if under else "(self)"
            own[leaf] = own.get(leaf, 0) + w
    if not anchors:
        raise SystemExit(f"error: no frame matches {pattern!r}")
    intro = (f"{', '.join(sorted(anchors))}: {fmt_val(tot, st.unit)}, "
             f"{_pct(tot, st.total())}% of all"
             + (f", {fmt_val(tot / per[0], st.unit)} per {per[1]}"
                if per else ""))
    rows = []
    if depth:
        for p, w in sorted(paths.items(), key=lambda kv: -kv[1])[:top]:
            rows.append([_pct(w, tot), W(w)]
                        + ([W(w / per[0])] if per else []) + [p])
        headers = ["% of it", "weight"]
    else:
        if "(self)" in own:
            inc["(self)"] = own["(self)"]
        for f, w in sorted(inc.items(), key=lambda kv: -kv[1])[:top]:
            rows.append([_pct(w, tot), W(w), W(own.get(f, 0))]
                        + ([W(w / per[0])] if per else []) + [f])
        headers = ["% of it", "total", "self"]
    if per:
        headers.append(f"per {per[1]}")
    headers.append("path" if depth else "function")
    return rows, headers, "r" * (len(headers) - 1) + "l", intro


def _callers(st: Stacks, pattern: str, depth: int, top: int):
    hit = stacks.matcher(pattern, stacks.frame_names(st))
    tot = 0.0
    chains: dict[str, float] = {}
    for s, w in st.weights.items():
        idx = [i for i, f in enumerate(s) if hit(f)]
        if not idx:
            continue
        i = idx[-1]
        tot += w
        key = " <- ".join(s[max(0, i - depth):i + 1][::-1])
        chains[key] = chains.get(key, 0) + w
    if not tot:
        raise SystemExit(f"error: no frame matches {pattern!r}")
    rows = [[_pct(w, tot), W(w), c] for c, w in
            sorted(chains.items(), key=lambda kv: -kv[1])[:top]]
    intro = (f"{pattern}: {fmt_val(tot, st.unit)}, {_pct(tot, st.total())}% "
             "of all; callers from the innermost call")
    return rows, ["% of it", "weight", "chain"], "rrl", intro


def _stacks(st: Stacks, n: int, top: int):
    acc: dict[tuple[str, ...], float] = {}
    cnt: dict[tuple[str, ...], int] = {}
    for s, w in st.weights.items():
        k = s[-n:]
        acc[k] = acc.get(k, 0) + w
        cnt[k] = cnt.get(k, 0) + st.counts.get(s, 1)
    total = st.total()
    rows = []
    for k, w in sorted(acc.items(), key=lambda kv: -kv[1])[:top]:
        rows.append([_pct(w, total), W(w), cnt[k], W(w / cnt[k]),
                     " <- ".join(reversed(k))])
    each = "mean" if st.unit == "ns" else "per sample"
    return (rows, ["%", "weight", "samples", each, "stack, leaf first"],
            "rrrrl", _summary(st, None))


def _binary(st: Stacks, stack: tuple[str, ...]) -> str:
    """The binary the leaf runs in (an inlined leaf is in its caller's);
    for a system call, the first binary above the C library."""
    syscall = bool(stack) and stack[-1].endswith("()")
    for f in reversed(stack):
        kind = st.kind(f)
        dso = st.dsos.get(f, "")
        if kind & PSEUDO or dso == "inlined":
            continue
        if syscall and ("/libc." in dso or "/ld-linux" in dso
                        or "/libpthread" in dso):
            continue
        if kind & MODULE:
            return f"{dso[1:-1]} (kernel module)" if dso.startswith("[") \
                and dso not in ("[kernel.kallsyms]", "[unknown]") \
                else "kernel modules"
        if kind & KERNEL:
            return "kernel"
        if dso:
            return dso.rsplit("/", 1)[-1]
        return "(unknown binary)"
    return "(event loop)" if stacks.LOOP in stack else "(no frames)"


def _dso(st: Stacks, per: tuple[float, str] | None):
    acc: dict[str, float] = {}
    for s, w in st.weights.items():
        name = _binary(st, s)
        acc[name] = acc.get(name, 0) + w
    total = st.total()
    rows = [[_pct(w, total), W(w)] + ([W(w / per[0])] if per else [])
            + [d] for d, w in sorted(acc.items(), key=lambda kv: -kv[1])]
    headers = ["%", "self"] + ([f"per {per[1]}"] if per else []) + ["binary"]
    return rows, headers, "r" * (len(headers) - 1) + "l", _summary(st, per)


def _process(st: Stacks, per: tuple[float, str] | None):
    acc: dict[tuple[str, str], float] = {}
    for s, w in st.weights.items():
        proc = s[0] if s else ""
        thread = s[1] if len(s) > 1 and st.kind(s[1]) & PSEUDO and \
            not s[1].endswith("()") and not s[1].startswith("[") else ""
        acc[(proc, thread)] = acc.get((proc, thread), 0) + w
    total = st.total()
    rows = [[p, t, _pct(w, total), W(w)] + ([W(w / per[0])] if per else [])
            for (p, t), w in sorted(acc.items(), key=lambda kv: -kv[1])]
    headers = ["process", "thread", "%", "weight"] + (
        [f"per {per[1]}"] if per else [])
    return rows, headers, "ll" + "r" * (len(headers) - 2), _summary(st, per)


def _diff(st: Stacks, base: Stacks, scale: float, args: argparse.Namespace,
          per: tuple[float, str] | None):
    """Totals per function (or command) in both, base scaled; the largest
    rises then the largest falls."""
    if args.ops:
        def by(x: Stacks) -> dict[str, float]:
            acc: dict[str, float] = {}
            for s, w in x.weights.items():
                op = smbd.command(s)
                acc[op] = acc.get(op, 0) + w
            return acc
        a, b = by(base), by(st)
    else:
        a = {k: v for k, v in stacks.inclusive(base)[0].items()
             if not base.kind(k) & PSEUDO}
        b = {k: v for k, v in stacks.inclusive(st)[0].items()
             if not st.kind(k) & PSEUDO}
    total = st.total()
    unit_per = per if per and args.base_per else None
    div = unit_per[0] if unit_per else 1
    changes = []
    for k in set(a) | set(b):
        av = a.get(k, 0) * scale
        bv = b.get(k, 0)
        changes.append((bv - av, k, av, bv))
    changes.sort()
    n = args.top
    pick = sorted(changes, key=lambda c: -c[0])[:n] if args.ops else (
        [c for c in reversed(changes) if c[0] > 0][:n // 2 or 1]
        + [c for c in changes if c[0] < 0][:n // 2 or 1])
    rows = []
    for d, k, av, bv in pick:
        rows.append([_pct(av, total), _pct(bv, total),
                     f"{100 * d / total:+.2f}", W(av / div), W(bv / div),
                     f"{100 * d / av:+.1f}%" if av else "new", k])
    how = ("per " + per[1] if per and args.base_per else "absolute"
           if args.absolute else "as shares of each total")
    suffix = f"/{unit_per[1]}" if unit_per else ""
    intro = (f"{args.diff} -> {args.input}, {how}; points are of the new "
             "total")
    headers = ["base %", "new %", "points", "base" + suffix, "new" + suffix,
               "change", "command" if args.ops else "function"]
    return rows, headers, "rrrrrrl", intro
