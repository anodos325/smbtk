"""Directory listings in a capture, and how often each was read again.

A scan is one pass over a directory through one handle. It starts with a
query that begins at the top: RESTART_SCANS, REOPEN, the first query on a
handle opened in the capture, or a reply that starts with "." on a handle
opened before it. It ends at the end of the directory, the handle's
CLOSE, the next restart, a failure, or the end of the capture. A query
without wildcards looks up one name; it is counted, not scanned.

A scan from the top returns entry i at position i, so the positions the
scans covered add up to the directory's entries, as long as it did not
change in between. A scan already running when the capture began is
placed by finding the first and last names of one of its replies the
same distance apart in a scan from the top.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .model import ALL_ONES_FID, Capture, Exchange
from .names import CLOSE, CREATE, QUERY_DIRECTORY, STATUS_NO_MORE_FILES

STATUS_NO_SUCH_FILE = 0xC000000F
RESTART, REOPEN = 0x01, 0x10
WILDCARDS = frozenset('*?<>"')


@dataclass(slots=True)
class Scan:
    how: str                # open, restart, reopen, top, joined
    fid: str
    t0: int
    t1: int
    queries: list[Exchange] = field(default_factory=list)
    # (offset in the scan, entries, first name, last name); the offset is
    # None after a reply whose entries are unknown
    replies: list[tuple[int | None, int, str | None, str | None]] = field(
        default_factory=list)
    entries: int = 0
    unknown: int = 0        # replies whose entries could not be counted
    end: str = "running"    # complete, closed, restarted, failed, running
    status: int | None = None
    pos0: int | None = None
    kind: str = ""          # first, rewind, repeat, overlap, joined
    new: int | None = None  # entries no earlier scan had returned
    time: int = 0           # summed latency of its queries, ns

    @property
    def reach(self) -> int | None:
        if self.pos0 is None or self.unknown:
            return None
        return self.pos0 + self.entries


@dataclass(slots=True)
class Directory:
    client: str
    share: str
    path: str
    pattern: str
    scans: list[Scan] = field(default_factory=list)
    lookups: int = 0
    names: dict[str, int] = field(default_factory=dict)
    moved: int = 0          # names found at another position than before
    distinct: int | None = None
    progress: list[tuple[int, int]] = field(default_factory=list)

    @property
    def returned(self) -> int:
        return sum(s.entries for s in self.scans)

    def sizes(self) -> list[int]:
        """The entries each complete listing from the top held."""
        return sorted({s.reach for s in self.scans
                       if s.end == "complete" and s.pos0 == 0
                       and s.reach is not None})

    @property
    def changed(self) -> bool:
        """Whether the directory changed between scans, which makes the
        entries counted by position approximate."""
        return self.moved > 0 or len(self.sizes()) > 1

    @property
    def ratio(self) -> float | None:
        if not self.distinct:
            return None
        return self.returned / self.distinct

    @property
    def wasted(self) -> int:
        return self.returned - (self.distinct or 0)

    @property
    def time(self) -> int:
        return sum(s.time for s in self.scans)

    def count(self, attr: str, value: str) -> int:
        return sum(1 for s in self.scans if getattr(s, attr) == value)

    def reread(self, min_scans: int, min_ratio: float) -> bool:
        """Whether the directory was listed again: enough scans, and
        enough entries returned for each one it holds."""
        if len(self.scans) < min_scans:
            return False
        r = self.ratio
        if r is None:
            return any(s.kind in ("rewind", "repeat", "overlap")
                       for s in self.scans)
        return r >= min_ratio

    def rate(self) -> tuple[int, int, int, int] | None:
        """(time, entries seen) after the first rewind, and at the end:
        how fast a directory that keeps being started over gets read."""
        first = next((s for s in self.scans if s.kind == "rewind"), None)
        if first is None or len(self.progress) < 2:
            return None
        start = next((p for p in self.progress if p[0] >= first.t1), None)
        end = self.progress[-1]
        if start is None or end[0] <= start[0]:
            return None
        return start[0], start[1], end[0], end[1]


@dataclass(slots=True)
class _Handle:
    opened: bool
    queries: int = 0
    scan: Scan | None = None


def _fid(x: Exchange, creates: dict) -> str | None:
    """The handle a request used; in a compound, the one its CREATE
    opened."""
    fid = x.req.get("fid")
    if fid != ALL_ONES_FID:
        return fid
    c = creates.get((x.fileidx, x.chain)) if x.chain is not None else None
    if c is None or c.resp is None or not c.ok:
        return None
    return c.resp.get("fid")


def _add(s: Scan, x: Exchange) -> None:
    s.queries.append(x)
    s.time += x.weight
    s.t1 = max(s.t1, x.t_resp or x.t_req)
    r = x.resp
    if r is None:
        return
    if x.status == 0:
        n = r.get("ents")
        if n is None:
            s.unknown += 1
            return
        s.replies.append((None if s.unknown else s.entries, n, r.get("e0"),
                          r.get("e1")))
        s.entries += n
    elif x.status in (STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE):
        if s.end == "running":
            s.end = "complete"
    elif s.end == "running":
        s.end = "failed"
        s.status = x.status


def _index(d: Directory) -> None:
    """Positions of the names that bound each reply of a scan from the
    top."""
    for s in d.scans:
        if s.how == "joined":
            continue
        s.pos0 = 0
        for off, n, e0, e1 in s.replies:
            if off is None or not n:
                continue
            for name, pos in ((e0, off), (e1, off + n - 1)):
                if d.names.setdefault(name, pos) != pos:
                    d.moved += 1


def _place(s: Scan, candidates: list[Directory]) -> Directory | None:
    """The directory a scan from before the capture belongs to, found by
    a reply whose first and last names sit as far apart in it."""
    for off, n, e0, e1 in s.replies:
        if off is None or not n:
            continue
        for d in candidates:
            p0, p1 = d.names.get(e0), d.names.get(e1)
            if p0 is not None and p1 is not None and p1 - p0 == n - 1 \
                    and p0 >= off:
                s.pos0 = p0 - off
                return d
    return None


def _cover(spans: list[list[int]], a: int, b: int) -> int:
    """Add [a, b) to the sorted disjoint spans; how much of it is new."""
    new = b - a
    merged = [a, b]
    keep = []
    for span in spans:
        if span[1] < merged[0] or span[0] > merged[1]:
            keep.append(span)
            continue
        new -= max(0, min(span[1], b) - max(span[0], a))
        merged = [min(merged[0], span[0]), max(merged[1], span[1])]
    keep.append(merged)
    keep.sort()
    spans[:] = keep
    return max(new, 0)


def _classify(d: Directory) -> None:
    d.scans.sort(key=lambda s: (s.t0, s.queries[0].frame))
    spans: list[list[int]] = []
    seen = 0
    prev: Scan | None = None
    open_until = 0          # the latest end of an earlier scan
    for s in d.scans:
        if s.how == "joined":
            s.kind = "joined"
        elif prev is None:
            s.kind = "first"
        elif open_until > s.t0:
            s.kind = "overlap"
        elif prev.end == "complete":
            s.kind = "repeat"
        else:
            s.kind = "rewind"
        prev = s
        # A scan still running at the end overlaps every later one.
        end = s.t1 if s.end != "running" else 1 << 63
        open_until = max(open_until, end)
        reach = s.reach
        if reach is None:
            continue
        s.new = _cover(spans, s.pos0, reach)
        if s.new:
            seen += s.new
            d.progress.append((s.t1, seen))
    d.distinct = seen if spans else None


def find(cap: Capture, wanted: Iterable[Exchange] | None = None
         ) -> list[Directory]:
    """Every directory listed or searched in the capture. `wanted`
    limits the QUERY_DIRECTORY requests looked at; handles are followed
    through all CREATE and CLOSE requests."""
    want = None if wanted is None else {
        id(x) for x in wanted if x.cmd == QUERY_DIRECTORY}
    creates: dict[tuple, Exchange] = {}
    handles: dict[tuple[int, str], _Handle] = {}
    dirs: dict[tuple, Directory] = {}

    def directory(x: Exchange, pattern: str) -> Directory:
        key = (x.client, x.share, x.file, pattern)
        d = dirs.get(key)
        if d is None:
            d = dirs[key] = Directory(x.client, x.share, x.file, pattern)
        return d

    for x in cap.exchanges:
        if x.proto != "smb2" or x.cmd not in (CREATE, CLOSE, QUERY_DIRECTORY):
            continue
        if x.cmd == CREATE:
            if x.chain is not None:
                creates[(x.fileidx, x.chain)] = x
            if x.resp is not None and x.ok and "fid" in x.resp:
                handles[(x.sesid, x.resp["fid"])] = _Handle(opened=True)
            continue
        fid = _fid(x, creates)
        if fid is None:
            continue
        key = (x.sesid, fid)
        h = handles.get(key)
        if x.cmd == CLOSE:
            if h is not None:
                if h.scan is not None and h.scan.end == "running":
                    h.scan.end = "closed"
                    h.scan.t1 = max(h.scan.t1, x.t_req)
                del handles[key]
            continue
        if want is not None and id(x) not in want:
            continue
        if h is None:
            h = handles[key] = _Handle(opened=False)
        pattern = x.req.get("pattern") or "*"
        if not WILDCARDS & set(pattern):
            directory(x, "*").lookups += 1
            continue
        flags = x.req.get("fflags") or 0
        how = None
        if flags & REOPEN:
            how = "reopen"
        elif flags & RESTART:
            how = "open" if h.opened and not h.queries else "restart"
        elif h.opened and not h.queries:
            how = "open"
        elif h.scan is None and x.resp is not None and x.resp.get("dots"):
            how = "top"
        elif h.scan is None:
            how = "joined"
        h.queries += 1
        if how is not None:
            if h.scan is not None and h.scan.end == "running":
                h.scan.end = "restarted"
                h.scan.t1 = x.t_req
            h.scan = Scan(how, fid, x.t_req, x.t_req)
            directory(x, pattern).scans.append(h.scan)
        _add(h.scan, x)

    out = list(dirs.values())
    for d in out:
        _index(d)
    named = [d for d in out if not d.path.startswith("fid:")]
    for d in out:
        for s in [s for s in d.scans if s.how == "joined"]:
            if not d.path.startswith("fid:"):
                _place(s, [d])
                continue
            home = _place(s, [o for o in named if o.client == d.client
                              and o.share == d.share
                              and o.pattern == d.pattern])
            if home is not None:
                d.scans.remove(s)
                home.scans.append(s)
    out = [d for d in out if d.scans or d.lookups]
    for d in out:
        if d.scans:
            _classify(d)
    return out


def entry_counts_missing(cap: Capture) -> bool:
    """Whether replies came from an extraction made before entries were
    counted."""
    ok = [x for x in cap.exchanges
          if x.cmd == QUERY_DIRECTORY and x.proto == "smb2" and x.ok]
    return bool(ok) and not any("ents" in x.resp for x in ok)
