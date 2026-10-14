"""Flame graphs as self-contained SVG, and call trees as text."""

from __future__ import annotations

import html
import zlib

from .fmt import fmt_val
from .perfdata import INLINE, KERNEL, MODULE
from .stacks import PSEUDO, Node, Stacks

FH = 16
X0 = 10


def _hash(name: str) -> tuple[float, float, float]:
    h = zlib.crc32(name.encode("utf-8", "replace"))
    return (h & 0xFF) / 255, ((h >> 8) & 0xFF) / 255, ((h >> 16) & 0xFF) / 255


def color(name: str, kind: int) -> str:
    """User code red to yellow, the kernel orange, kernel modules (zfs,
    spl ...) teal, frames this toolkit adds lavender."""
    v1, v2, v3 = _hash(name)
    if kind & PSEUDO:
        r, g, b = 185 + 30 * v1, 185 + 30 * v1, 225 + 25 * v2
    elif kind & MODULE:
        r, g, b = 50 + 60 * v1, 165 + 55 * v1, 165 + 55 * v1
    elif kind & KERNEL:
        r, g, b = 190 + 65 * v1, 90 + 65 * v1, 0
    else:
        r, g, b = 205 + 50 * v3, 230 * v1, 55 * v2
    return f"rgb({int(r)},{int(g)},{int(b)})"


def diff_color(delta: float, top: float) -> str:
    """Red where the new profile spends more, blue where less."""
    if top <= 0 or delta == 0:
        return "rgb(255,255,255)"
    v = int(210 * (top - min(abs(delta), top)) / top)
    return f"rgb(255,{v},{v})" if delta > 0 else f"rgb({v},{v},255)"


class Diff:
    """How a base profile was laid against the new one: node.base holds
    base weights times `scale`; `base_per` is the base's work count;
    `names` label the shown side, then the other."""

    def __init__(self, scale: float = 1.0,
                 names: tuple[str, str] = ("new", "base"),
                 base_per: float = 1.0, flip: bool = False) -> None:
        self.scale = scale
        self.names = names
        self.base_per = base_per
        self.flip = flip    # the tree is the base's, node.base the new's


def own_delta(node: Node, total: float) -> float:
    """The change in what a function itself spends, in points of the new
    total (base scaled as the comparison asks)."""
    return 100 * (node.own - node.base_own) / (total or 1)


def _label(node: Node, st: Stacks, total: int, diff: Diff | None,
           base_total: float, per: tuple[float, str] | None) -> str:
    unit = st.unit
    text = (f"{node.name}: {fmt_val(node.total, unit)} "
            f"({100 * node.total / total:.2f}%)")
    if node.own and node.children:
        text += f", self {100 * node.own / total:.2f}%"
    if per:
        text += f", {fmt_val(node.total / per[0], unit)} per {per[1]}"
    if diff:
        raw = node.base / diff.scale
        sign = -1 if diff.flip else 1
        text += (f"; {diff.names[1]} {fmt_val(raw, unit)} "
                 f"({100 * node.base / (base_total or 1):.2f}%), change "
                 f"{sign * 100 * (node.total - node.base) / total:+.2f} "
                 f"points, self {sign * own_delta(node, total):+.2f}")
    dso = st.dsos.get(node.name, "")
    if dso and not dso.startswith("[kernel") and dso != "inlined":
        text += f" [{dso.rsplit('/', 1)[-1]}]"
    elif st.kind(node.name) & INLINE:
        text += " [inlined]"
    return text


_JS = r"""
var W=%(w)d, X0=%(x0)d;
var fr=[].slice.call(document.querySelectorAll('g.f'));
var orig=fr.map(function(g){return g.querySelector('rect').getAttribute('fill');});
var details=document.getElementById('details'), matched=document.getElementById('matched');
var base=details.textContent, re=null;
function fit(name,px){
  var c=Math.floor((px-6)/7);
  return c<3?'':name.length<=c?name:name.substr(0,c-2)+'..';
}
function layout(x0,w,d0){
  var e=1e-9;
  fr.forEach(function(g){
    var gx=+g.dataset.x, gw=+g.dataset.w, gd=+g.dataset.d, nx, nw;
    if(gd<d0){
      if(gx<=x0+e && gx+gw>=x0+w-e){nx=0;nw=1;} else {g.style.display='none';return;}
    } else if(gx>=x0-e && gx+gw<=x0+w+e){nx=(gx-x0)/w;nw=gw/w;}
    else {g.style.display='none';return;}
    g.style.display='';
    var r=g.querySelector('rect'), t=g.querySelector('text'), px=X0+nx*W, pw=nw*W;
    r.setAttribute('x',px.toFixed(1)); r.setAttribute('width',Math.max(pw,0.5).toFixed(1));
    t.setAttribute('x',(px+3).toFixed(1)); t.textContent=fit(g.dataset.n,pw);
  });
}
function search(text){
  re=text?new RegExp(text):null;
  var hits=[];
  fr.forEach(function(g,i){
    var m=re&&re.test(g.dataset.n);
    g.querySelector('rect').setAttribute('fill',m?'rgb(230,0,230)':orig[i]);
    if(m) hits.push([+g.dataset.x,+g.dataset.w]);
  });
  hits.sort(function(a,b){return a[0]-b[0];});
  var tot=0,end=0;
  hits.forEach(function(h){var s=Math.max(h[0],end),e=h[0]+h[1];if(e>s)tot+=e-s;if(e>end)end=e;});
  matched.textContent=re?'Matched: '+(100*tot).toFixed(2)+'%%':'';
}
function ask(){
  var t=prompt('Search for (regular expression):',re?re.source:'');
  if(t===null)return;
  try{search(t);}catch(err){alert(err);}
}
fr.forEach(function(g){
  g.addEventListener('click',function(){layout(+g.dataset.x,+g.dataset.w,+g.dataset.d);});
  g.addEventListener('mouseover',function(){details.textContent=g.querySelector('title').textContent;});
  g.addEventListener('mouseout',function(){details.textContent=base;});
});
document.getElementById('reset').addEventListener('click',function(){layout(0,1,0);});
document.getElementById('search').addEventListener('click',ask);
document.addEventListener('keydown',function(ev){
  if((ev.ctrlKey&&ev.key==='f')||ev.key==='/'){ev.preventDefault();ask();}
  else if(ev.key==='Escape'){search('');}
});
"""


def render_svg(root: Node, st: Stacks, title: str, subtitle: str = "",
               width: int = 1200, min_px: float = 0.1, icicle: bool = False,
               diff: Diff | None = None, negate: bool = False,
               per: tuple[float, str] | None = None) -> str:
    """Frames are as wide as their weight and, in a diff, colored by
    own_delta; `negate` flips the colors (widths from the base)."""
    total = root.total or 1
    inner = width - 2 * X0
    frames: list[tuple[Node, float, int]] = []

    def walk(node: Node, x: float, d: int) -> None:
        if node.total / total * inner < min_px:
            return
        frames.append((node, x, d))
        cx = x
        for c in sorted(node.children.values(), key=lambda c: c.name):
            walk(c, cx, d + 1)
            cx += c.total

    walk(root, 0, 0)
    top_delta = max((abs(own_delta(n, total)) for n, _, _ in frames),
                    default=0.0) if diff else 0.0
    depth = max(d for _, _, d in frames) if frames else 0
    head, foot = 50, 30
    height = head + (depth + 1) * FH + foot
    out = [
        '<?xml version="1.0" standalone="no"?>\n'
        f'<svg version="1.1" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" '
        'xmlns="http://www.w3.org/2000/svg">\n'
        '<style>text{font-family:monospace;font-size:12px}'
        'g.f text{pointer-events:none}'
        'g.f rect{stroke:#fff;stroke-width:0.5}g.f:hover rect{stroke:#000}'
        '.b{cursor:pointer;fill:#00c}</style>\n'
        f'<rect x="0" y="0" width="{width}" height="{height}" '
        'fill="#f8f8f8"/>\n'
        f'<text x="{width // 2}" y="20" text-anchor="middle" '
        f'style="font-size:15px">{html.escape(title)}</text>\n'
        f'<text x="{width // 2}" y="38" text-anchor="middle" fill="#555">'
        f'{html.escape(subtitle)}</text>\n'
        f'<text class="b" id="reset" x="{X0}" y="20">Reset zoom</text>\n'
        f'<text class="b" id="search" x="{width - X0}" y="20" '
        'text-anchor="end">Search</text>\n'
        f'<text id="matched" x="{width - X0}" y="{height - 10}" '
        'text-anchor="end"></text>\n'
        f'<text id="details" x="{X0}" y="{height - 10}">'
        f'{html.escape(_root_line(root, st, per))}</text>\n'
    ]
    for node, x, d in frames:
        frac = node.total / total
        w = frac * inner
        px = X0 + x / total * inner
        y = head + d * FH if icicle else head + (depth - d) * FH
        if diff:
            delta = own_delta(node, total)
            fill = diff_color(-delta if negate else delta, top_delta)
        else:
            fill = color(node.name, st.kind(node.name))
        label = _label(node, st, total, diff, root.base, per)
        out.append(
            f'<g class="f" data-n="{html.escape(node.name, quote=True)}" '
            f'data-x="{x / total:.7f}" data-w="{frac:.7f}" data-d="{d}">'
            f'<title>{html.escape(label)}</title>'
            f'<rect x="{px:.1f}" y="{y}" width="{max(w, 0.5):.1f}" '
            f'height="{FH - 1}" fill="{fill}"/>'
            f'<text x="{px + 3:.1f}" y="{y + 12}">'
            f'{html.escape(_fit(node.name, w))}</text></g>\n')
    out.append("<script><![CDATA[" + _JS % {"w": inner, "x0": X0}
               + "]]></script>\n</svg>\n")
    return "".join(out)


def _fit(name: str, px: float) -> str:
    chars = int((px - 6) // 7)
    if chars < 3:
        return ""
    return name if len(name) <= chars else name[:chars - 2] + ".."


def _root_line(root: Node, st: Stacks, per: tuple[float, str] | None) -> str:
    unit = "" if st.unit == "ns" else " " + st.unit
    text = f"{fmt_val(root.total, st.unit)}{unit} in {st.count_text()}"
    if per:
        text += f", {fmt_val(root.total / per[0], st.unit)} per {per[1]}"
    return text + "; click a frame to zoom, Ctrl-F to search"


# -- text ----------------------------------------------------------------------

def render_tree(root: Node, unit: str, min_pct: float = 1.0,
                depth: int = 0, top: int = 0, diff: Diff | None = None,
                per: tuple[float, str] | None = None) -> str:
    """The call tree, heaviest children first. Children under `min_pct`
    of the total or past `top` are summed into one line, shown when that
    sum reaches `min_pct`; a chain of single children is one line, with
    the last one's numbers."""
    total = root.total or 1
    base_total = root.base or 1
    div = per[0] if per else 1
    suffix = f" per {per[1]}" if per else ""
    if diff:
        headers = [f"{diff.names[1]} %", f"{diff.names[0]} %", "points",
                   f"{diff.names[1]}{suffix}", f"{diff.names[0]}{suffix}"]
    else:
        headers = ["total %", "self %", (unit if unit != "ns" else "time")
                   + suffix]

    def cells(node: Node) -> list[str]:
        if diff:
            return [f"{100 * node.base / base_total:.2f}",
                    f"{100 * node.total / total:.2f}",
                    f"{100 * (node.total - node.base) / total:+.2f}",
                    fmt_val(node.base / diff.scale / diff.base_per, unit),
                    fmt_val(node.total / div, unit)]
        return [f"{100 * node.total / total:.2f}",
                f"{100 * node.own / total:.2f}" if node.own else "",
                fmt_val(node.total / div, unit)]

    def size(n: Node) -> float:
        return max(n.total / total, n.base / base_total) if diff \
            else n.total / total

    rows: list[tuple[list[str], str]] = []

    def shown(node: Node) -> tuple[list[Node], list[Node]]:
        kids = sorted(node.children.values(), key=lambda c: -size(c))
        keep = [c for c in kids if 100 * size(c) >= min_pct]
        if top:
            keep = keep[:top]
        return keep, kids[len(keep):]

    def own(n: Node) -> float:
        return max(n.own / total, n.base_own / base_total) if diff \
            else n.own / total

    def walk(node: Node, indent: str, level: int) -> None:
        chain = [node.name]
        while node is not root and not (depth and level + len(chain) >= depth):
            keep, rest = shown(node)
            hidden = sum(size(c) for c in rest)
            if len(keep) != 1 or (rest and 100 * hidden >= min_pct) or (
                    own(node) and 100 * own(node) >= min_pct):
                break
            node = keep[0]
            chain.append(node.name)
        rows.append((cells(node), indent + " > ".join(chain)))
        level += len(chain)
        if depth and level >= depth:
            return
        keep, rest = shown(node)
        for c in keep:
            walk(c, indent + "  ", level)
        if rest and 100 * sum(size(c) for c in rest) >= min_pct:
            r = Node(f"({len(rest)} more)")
            for c in rest:
                r.total += c.total
                r.base += c.base
            rows.append((cells(r), indent + "  " + r.name))

    walk(root, "", 0)
    widths = [max(len(h), *(len(c[i]) for c, _ in rows))
              for i, h in enumerate(headers)]
    lines = ["  ".join(h.rjust(w) for h, w in zip(headers, widths))
             + "  function"]
    for c, name in rows:
        lines.append("  ".join(v.rjust(w) for v, w in zip(c, widths))
                     + "  " + name)
    return "\n".join(lines) + "\n"
