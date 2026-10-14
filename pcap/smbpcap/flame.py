"""Collapsed stacks and a self-contained flame graph SVG."""

from __future__ import annotations

import html
import zlib
from typing import Iterable

from .stats import fmt_bytes, fmt_dur


# A sample: its stack, the weight that sets its width, its time in ns,
# its bytes and its client's idle time before it in ns. Every node holds
# the inclusive sums of what is under it.
Sample = tuple[tuple[str, ...], int, int, int, int]


class Node:
    __slots__ = ("name", "value", "count", "time", "nbytes", "idle",
                 "children")

    def __init__(self, name: str) -> None:
        self.name = name
        self.value = 0
        self.count = 0
        self.time = 0
        self.nbytes = 0
        self.idle = 0
        self.children: dict[str, Node] = {}

    def add(self, value: int, time: int, nbytes: int, idle: int) -> None:
        self.value += value
        self.count += 1
        self.time += time
        self.nbytes += nbytes
        self.idle += idle


def build(samples: Iterable[Sample], root_name: str = "all") -> Node:
    root = Node(root_name)
    for stack, *sums in samples:
        node = root
        node.add(*sums)
        for name in stack:
            child = node.children.get(name)
            if child is None:
                child = Node(name)
                node.children[name] = child
            node = child
            node.add(*sums)
    return root


def collapsed(samples: Iterable[Sample]) -> str:
    """The `folded` format flamegraph.pl and speedscope read."""
    totals: dict[tuple[str, ...], int] = {}
    for stack, value, *_ in samples:
        totals[stack] = totals.get(stack, 0) + value
    return "".join(
        ";".join(s.replace(";", ",") for s in stack) + f" {v}\n"
        for stack, v in sorted(totals.items())
    )


def to_dict(node: Node, idle: bool = False) -> dict:
    """The tree as nested objects (name, value, children: what
    d3-flame-graph reads), children largest first."""
    d = {"name": node.name, "value": node.value, "n": node.count,
         "time_ns": node.time, "bytes": node.nbytes}
    if idle:
        d["idle_ns"] = node.idle
    d["children"] = [to_dict(c, idle) for c in sorted(
        node.children.values(), key=lambda c: (-c.value, c.name))]
    return d


METRICS = ("n", "time", "each", "idle", "bytes")


def tree_columns(unit: str, idle: bool = False) -> list[str]:
    """The tree's columns: the weight, its share, then the rest."""
    first = "n" if unit == "count" else unit
    return [first, "%"] + [m for m in METRICS
                           if m != first and (idle or m != "idle")]


def _cell(node: Node, col: str, total: int) -> str:
    if col == "%":
        return f"{100 * node.value / total:.1f}%"
    if col == "n":
        return str(node.count)
    if col == "each":
        return fmt_dur(node.time // node.count) \
            if node.time and node.count else "-"
    if col == "bytes":
        return fmt_bytes(node.nbytes) if node.nbytes else "-"
    ns = node.time if col == "time" else node.idle
    return fmt_dur(ns) if ns else "-"


def render_tree(root: Node, unit: str, min_frac: float = 0.0,
                top: int = 0, name_width: int = 60,
                idle: bool = False) -> str:
    """The tree as indented text, children largest first; children past
    `top` or narrower than `min_frac` are summed into one row."""
    total = root.value or 1
    idle_total = root.idle or 1
    headers = tree_columns(unit, idle)
    rows: list[tuple[str, list[str]]] = []

    def walk(node: Node, indent: str, branch: str, last: bool) -> None:
        name = node.name
        if len(name) > name_width:
            name = name[:name_width - 2] + ".."
        rows.append((indent + branch + name,
                     [_cell(node, c, total) for c in headers]))
        kids = sorted(node.children.values(),
                      key=lambda c: (-c.value, c.name))
        shown = [c for c in kids if c.value / total >= min_frac or (
            idle and c.idle / idle_total >= min_frac)]
        if top:
            shown = shown[:top]
        hidden = kids[len(shown):]
        if hidden:
            rest = Node(f"({len(hidden)} more)")
            for c in hidden:
                rest.value += c.value
                rest.count += c.count
                rest.time += c.time
                rest.nbytes += c.nbytes
                rest.idle += c.idle
            shown.append(rest)
        sub = indent + ("   " if last else "│  ") if branch else indent
        for i, c in enumerate(shown):
            is_last = i == len(shown) - 1
            walk(c, sub, "└─ " if is_last else "├─ ", is_last)

    walk(root, "", "", True)
    w0 = max(len(r[0]) for r in rows)
    widths = [max(len(h), *(len(r[1][i]) for r in rows))
              for i, h in enumerate(headers)]
    lines = [" " * w0 + "  "
             + "  ".join(h.rjust(w) for h, w in zip(headers, widths))]
    for name, cols in rows:
        lines.append(name.ljust(w0) + "  "
                     + "  ".join(c.rjust(w) for c, w in zip(cols, widths)))
    return "\n".join(lines) + "\n"


def _fmt(value: int, unit: str) -> str:
    if unit == "time":
        return fmt_dur(value)
    if unit == "idle":
        return f"{fmt_dur(value)} idle"
    if unit == "bytes":
        return fmt_bytes(value)
    return f"{value} requests"


def label(node: Node, unit: str, total: int, idle: bool = False) -> str:
    parts = [f"{node.name}: {_fmt(node.value, unit)} "
             f"({100 * node.value / total:.2f}%)"]
    if unit != "count":
        parts.append(f"{node.count} requests")
    if node.time and unit != "time":
        parts.append(fmt_dur(node.time))
    if node.time and node.count:
        parts.append(f"{fmt_dur(node.time // node.count)} each")
    if node.nbytes and unit != "bytes":
        parts.append(fmt_bytes(node.nbytes))
    if idle and unit != "idle":
        parts.append(f"{fmt_dur(node.idle)} idle")
    return ", ".join(parts)


def fit(name: str, count: int, chars: int) -> str:
    """The text a frame `chars` wide shows: name and count, the name,
    or a truncated name (the JS below does the same on zoom)."""
    if chars < 3:
        return ""
    full = f"{name} ({count})"
    if len(full) <= chars:
        return full
    if len(name) <= chars:
        return name
    return name[:chars - 2] + ".."


def _color(name: str) -> str:
    h = zlib.crc32(name.encode("utf-8", "replace"))
    r = 205 + (h & 0xFF) * 50 // 255
    g = ((h >> 8) & 0xFF) * 230 // 255
    b = ((h >> 16) & 0xFF) * 55 // 255
    return f"rgb({r},{g},{b})"


_JS = r"""
var W=%(width)d, X0=%(x0)d, FH=%(fh)d;
var all=[].slice.call(document.querySelectorAll('g.f'));
function layout(x0,w){
  all.forEach(function(g){
    var gx=+g.dataset.x, gw=+g.dataset.w, gd=+g.dataset.d, cd=+g.dataset.cd;
    var r=g.querySelector('rect'), t=g.querySelector('text');
    var nx, nw;
    if (gx<=x0 && gx+gw>=x0+w && gd<=cd){ nx=0; nw=1; }
    else if (gx+gw<=x0 || gx>=x0+w){ g.style.display='none'; return; }
    else { nx=(Math.max(gx,x0)-x0)/w; nw=(Math.min(gx+gw,x0+w)-Math.max(gx,x0))/w; }
    g.style.display='';
    var px=X0+nx*W, pw=nw*W;
    r.setAttribute('x',px); r.setAttribute('width',Math.max(pw,0.5));
    t.setAttribute('x',px+3);
    var chars=Math.floor((pw-6)/7), name=g.dataset.n,
        full=name+' ('+g.dataset.c+')';
    t.textContent = chars<3 ? '' : full.length<=chars ? full
      : name.length<=chars ? name : name.substr(0,chars-2)+'..';
  });
}
all.forEach(function(g){
  g.addEventListener('click',function(){
    all.forEach(function(o){o.dataset.cd=+g.dataset.d;});
    layout(+g.dataset.x,+g.dataset.w);
  });
  g.addEventListener('mouseover',function(){
    document.getElementById('details').textContent=g.querySelector('title').textContent;
  });
});
document.getElementById('reset').addEventListener('click',function(){
  all.forEach(function(o){o.dataset.cd=0;}); layout(0,1);
});
"""


def render_svg(root: Node, title: str, unit: str = "time",
               width: int = 1200, min_frac: float = 0.0005,
               subtitle: str = "", idle: bool = False) -> str:
    total = root.value
    if total <= 0:
        total = 1
    fh = 16
    x0 = 10
    inner = width - 2 * x0
    depth = _depth(root)
    height = (depth + 1) * fh + 70
    out = [
        f'<?xml version="1.0" standalone="no"?>\n'
        f'<svg version="1.1" width="{width}" height="{height}" '
        f'xmlns="http://www.w3.org/2000/svg">\n'
        '<style>text{font-family:monospace;font-size:12px}'
        'g.f rect{stroke:#fff;stroke-width:0.5}g.f:hover rect{stroke:#000}'
        '#reset{cursor:pointer;fill:#00c}</style>\n'
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#f8f8f8"/>\n'
        f'<text x="{width // 2}" y="24" text-anchor="middle" '
        f'font-size="16">{html.escape(title)}</text>\n'
        f'<text x="{x0}" y="24" id="reset">Reset zoom</text>\n'
        f'<text x="{x0}" y="{height - 10}" id="details">'
        f'{html.escape(subtitle)}</text>\n'
    ]
    base_y = height - 40

    def walk(node: Node, x: float, d: int) -> None:
        frac = node.value / total
        if frac < min_frac:
            return
        w = frac * inner
        px = x0 + x * inner
        y = base_y - d * fh
        text = fit(node.name, node.count, int((w - 6) // 7))
        out.append(
            f'<g class="f" data-x="{x:.6f}" data-w="{frac:.6f}" data-d="{d}" '
            f'data-cd="0" data-n="{html.escape(node.name, quote=True)}" '
            f'data-c="{node.count}">'
            f'<title>{html.escape(label(node, unit, total, idle))}</title>'
            f'<rect x="{px:.1f}" y="{y}" width="{max(w, 0.5):.1f}" '
            f'height="{fh - 1}" fill="{_color(node.name)}"/>'
            f'<text x="{px + 3:.1f}" y="{y + 12}">{html.escape(text)}</text>'
            '</g>\n'
        )
        cx = x
        for child in sorted(node.children.values(), key=lambda c: c.name):
            walk(child, cx, d + 1)
            cx += child.value / total

    walk(root, 0.0, 0)
    out.append("<script><![CDATA[" + _JS % {
        "width": inner, "x0": x0, "fh": fh} + "]]></script>\n</svg>\n")
    return "".join(out)


def _depth(node: Node) -> int:
    if not node.children:
        return 0
    return 1 + max(_depth(c) for c in node.children.values())
