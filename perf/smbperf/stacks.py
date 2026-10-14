"""Folded stacks: a weight per call stack, root first."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, TextIO

from .perfdata import INLINE, KERNEL, SWITCH, SYS_ENTER, Profile, unit_of
from .syscalls_gen import SYSCALLS

MARKS = ("_[k]", "_[i]", "_[j]")
PSEUDO = 4  # a frame this toolkit adds: process, thread, state, syscall

# Scheduler frames above what a task waits in.
_SCHED = {"__traceiter_sched_switch", "__schedule", "schedule",
          "preempt_schedule", "preempt_schedule_common",
          "preempt_schedule_irq", "preempt_schedule_notrace",
          "schedule_preempt_disabled", "__cond_resched"}


class Stacks:
    """Weights per stack, and what is known about each frame name: its
    binary and kind (KERNEL, INLINE, PSEUDO bits)."""

    def __init__(self, unit: str = "samples") -> None:
        self.weights: dict[tuple[str, ...], int] = {}
        self.counts: dict[tuple[str, ...], int] = {}
        self.dsos: dict[str, str] = {}
        self.kinds: dict[str, int] = {}
        self.unit = unit
        self.what = ""
        self.counted = True     # counts are samples, not folded lines
        self.notes: list[str] = []

    def add(self, stack: tuple[str, ...], w: int, n: int = 1) -> None:
        self.weights[stack] = self.weights.get(stack, 0) + w
        self.counts[stack] = self.counts.get(stack, 0) + n

    def total(self) -> int:
        return sum(self.weights.values())

    def samples(self) -> int:
        return sum(self.counts.values())

    def count_text(self) -> str:
        n = self.samples()
        return f"{n} samples" if self.counted else f"{n} stacks"

    def derive(self, weights: dict[tuple[str, ...], int],
               counts: dict[tuple[str, ...], int] | None = None) -> Stacks:
        out = Stacks(self.unit)
        out.weights = weights
        out.counts = counts if counts is not None else {
            s: self.counts.get(s, 1) for s in weights}
        out.dsos, out.kinds, out.notes = self.dsos, self.kinds, self.notes
        out.what = self.what
        out.counted = self.counted
        return out

    def kind(self, name: str) -> int:
        k = self.kinds.get(name)
        if k is not None:
            return k
        if name.endswith("_[k]"):
            return KERNEL
        if name.endswith("_[i]"):
            return INLINE
        return 0


def bare(name: str) -> str:
    """A frame name without its _[k]/_[i]/_[j] mark."""
    return name[:-4] if name.endswith(MARKS) else name


# -- from perf samples -------------------------------------------------------

@dataclass
class Selection:
    """Which samples to fold and how to name the root frames."""
    event: str | None = None
    t_from: int | None = None
    t_to: int | None = None
    comms: list[str] = field(default_factory=list)
    pids: list[int] = field(default_factory=list)
    tids: list[int] = field(default_factory=list)
    clients: list[str] = field(default_factory=list)
    root: str = "process"
    kernel_mark: bool = True
    inline: bool = True
    user_only: bool = False
    count_samples: bool = False
    # Process names from the recording (smbd[full client address]).
    names: dict[int, str] = field(default_factory=dict)
    clients_of: dict[int, list[str]] = field(default_factory=dict)


ROOTS = ("process", "role", "comm", "pid", "none")


def role(name: str) -> str:
    """A thread or process name without the parts that differ per
    instance: smbd[10.1.2.3] -> smbd[client], iou-wrk-123 -> iou-wrk,
    kworker/3:1H -> kworker."""
    if name.startswith("smbd[") or name.startswith("smbd: client"):
        return "smbd[client]"
    if "/" in name:
        name = name.split("/", 1)[0]
    return re.sub(r"[-_]\d+$", "", name) or name


def serves(name: str, client: str) -> bool:
    """Whether smbd's process name says it serves `client`; the kernel
    keeps 15 bytes of it, so a long address is matched on what is left."""
    full = f"smbd[{client}]"
    if name == full or (len(name) == 15 and len(full) > 15
                        and full.startswith(name)):
        return True
    return name.startswith("smbd[") and client in name[5:-1].split(",")


def pick_event(prof: Profile, wanted: str | None) -> str:
    if wanted:
        if wanted not in prof.events:
            raise ValueError(f"no {wanted} samples; the recording has "
                             f"{', '.join(prof.events) or 'none'}")
        return wanted
    for special in (SWITCH, SYS_ENTER):
        if special in prof.events:
            return special
    if not prof.events:
        raise ValueError("no samples")
    return prof.events[0]


def fold(prof: Profile, sel: Selection) -> Stacks:
    event = pick_event(prof, sel.event)
    ev = prof.events.index(event)
    off = event == SWITCH
    syscalls = event == SYS_ENTER
    st = Stacks("samples" if sel.count_samples and not off else
                unit_of(event))
    st.what = "off-CPU" if off else "syscalls" if syscalls else (
        "on-CPU" if unit_of(event) in ("cycles", "instructions", "ns")
        else event)
    leader: dict[int, str] = {}
    for s in prof.samples:
        if s[1] == s[2] and s[1] not in leader:
            leader[s[1]] = prof.comms[s[3]]

    def process_name(pid: int, comm: str) -> str:
        return sel.names.get(pid) or leader.get(pid) or comm

    want_pids = set(sel.pids)
    if sel.clients:
        for pid, addrs in sel.clients_of.items():
            if any(c in addrs for c in sel.clients):
                want_pids.add(pid)
        for pid, comm in leader.items():
            if any(serves(comm, c) for c in sel.clients):
                want_pids.add(pid)
        if not want_pids:
            raise ValueError("no samples from smbd serving "
                             + ", ".join(sel.clients))
    want_tids = set(sel.tids)
    marks: dict[int, str] = {}
    for fid, (name, dso, kind) in enumerate(prof.frames):
        shown = name + "_[k]" if kind & KERNEL and sel.kernel_mark else name
        if shown not in st.kinds:
            st.kinds[shown] = kind
            st.dsos[shown] = dso
        marks[fid] = shown
    drop = {fid for fid, (_, _, kind) in enumerate(prof.frames)
            if (kind & INLINE and not sel.inline)
            or (kind & KERNEL and (sel.user_only or syscalls))}
    sched = {fid for fid, (name, _, kind) in enumerate(prof.frames)
             if kind & KERNEL and name in _SCHED}
    roots: dict[tuple[int, int, int], tuple[str, ...]] = {}
    paths: dict[int, tuple[str, ...]] = {}
    unpaired = 0
    t_from, t_to = sel.t_from, sel.t_to
    for t, pid, tid, cid, e, w, sid, aux in prof.samples:
        if e != ev:
            continue
        if off:
            if w < 0:
                unpaired += 1
                continue
            a, b = t, t + w
            if t_from is not None:
                a = max(a, t_from)
            if t_to is not None:
                b = min(b, t_to)
            if b <= a:
                continue
            w = b - a
        else:
            if t_from is not None and t < t_from:
                continue
            if t_to is not None and t > t_to:
                continue
            if sel.count_samples:
                w = 1
        if want_pids and pid not in want_pids:
            continue
        if want_tids and tid not in want_tids:
            continue
        comm = prof.comms[cid]
        if sel.comms:
            pname = process_name(pid, comm)
            if not any(fnmatch.fnmatchcase(comm, g)
                       or fnmatch.fnmatchcase(pname, g) for g in sel.comms):
                continue
        rkey = (pid, tid, cid)
        root = roots.get(rkey)
        if root is None:
            root = roots[rkey] = _root(sel.root, pid, tid, comm,
                                       process_name(pid, comm))
        path = paths.get(sid)
        if path is None:
            frames = [f for f in prof.stacks[sid] if f not in drop]
            if off:
                while frames and frames[-1] in sched:
                    frames.pop()
            path = paths[sid] = tuple(marks[f] for f in frames)
        stack = root + path
        if off and aux:
            if aux.startswith("R"):
                stack += ("[preempted]",)
            elif "D" in aux:
                stack += ("[uninterruptible]",)
        elif syscalls:
            stack += (SYSCALLS.get(aux, f"syscall {aux}") + "()",)
        st.add(stack, w)
    for stack in st.weights:
        for name in stack:
            if name not in st.kinds:
                st.kinds[name] = PSEUDO
    if unpaired:
        st.notes.append(f"{unpaired} switches out had no switch back in "
                        "before the recording ended")
    return st


def _root(how: str, pid: int, tid: int, comm: str,
          pname: str) -> tuple[str, ...]:
    comm = comm.replace(" ", "_")
    pname = pname.replace(" ", "_")
    if how == "none":
        return ()
    if how == "comm":
        return (comm,)
    if how == "pid":
        return (f"{comm}-{pid}",)
    proc = role(pname) if how == "role" else pname
    if tid != pid and pid >= 0:
        return (proc, role(comm))
    return (proc,)


# -- folded text ---------------------------------------------------------------

def read_folded(lines: Iterable[str], unit: str = "weight") -> Stacks:
    st = Stacks(unit)
    st.counted = False
    for line in lines:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        stack, _, n = line.rpartition(" ")
        if not stack:
            continue
        try:
            w = int(n)
        except ValueError:
            try:
                w = int(round(float(n)))
            except ValueError:
                continue
        st.add(tuple(stack.split(";")), w)
    return st


def write_folded(st: Stacks, out: TextIO) -> None:
    for stack, w in sorted(st.weights.items(),
                           key=lambda kv: ";".join(kv[0])):
        if w > 0:
            out.write(";".join(f.replace(";", ":") for f in stack)
                      + f" {w}\n")


def looks_folded(lines: list[str]) -> bool:
    body = [ln for ln in lines if ln.strip() and not ln.startswith("#")]
    if not body or any(ln.startswith("\t") for ln in body):
        return False
    return all(re.match(r"^\S.* \d+(\.\d+)?$", ln.rstrip("\n"))
               for ln in body)


# -- transforms -------------------------------------------------------------

def matcher(pattern: str, names: Iterable[str] = ()) -> Callable[[str], bool]:
    """A frame matches when its name (without its mark) equals the
    pattern; if no frame does, when the pattern is found in it as a
    regular expression."""
    pool = {bare(n) for n in names}
    if pattern in pool:
        return lambda n: bare(n) == pattern
    rx = re.compile(pattern)
    return lambda n: rx.search(bare(n)) is not None


def frame_names(st: Stacks) -> set[str]:
    return {f for s in st.weights for f in s}


def grep(st: Stacks, pattern: str, keep: bool = True) -> Stacks:
    hit = matcher(pattern, frame_names(st))
    w = {s: v for s, v in st.weights.items()
         if any(hit(f) for f in s) == keep}
    return st.derive(w)


def focus(st: Stacks, pattern: str) -> Stacks:
    """Only stacks through a matching frame, cut above its outermost
    occurrence: that frame becomes the root."""
    hit = matcher(pattern, frame_names(st))
    w: dict[tuple[str, ...], int] = {}
    n: dict[tuple[str, ...], int] = {}
    for s, v in st.weights.items():
        for i, f in enumerate(s):
            if hit(f):
                k = s[i:]
                w[k] = w.get(k, 0) + v
                n[k] = n.get(k, 0) + st.counts.get(s, 1)
                break
    return st.derive(w, n)


_DISPATCH = {"tevent_common_invoke_fd_handler",
             "tevent_common_invoke_immediate_handler",
             "tevent_common_invoke_timer_handler",
             "tevent_common_invoke_signal_handler"}
_LOOP = {"std_event_loop_wait", "tevent_common_loop_wait", "_tevent_loop_once",
         "std_event_loop_once", "epoll_event_loop_once", "epoll_event_loop",
         "tevent_common_loop_immediate", "_tevent_loop_wait",
         "tevent_common_loop_timer_delay", "poll_event_loop_once"}
LOOP = "[event loop]"
_OUTER = _DISPATCH | _LOOP | {
    "_start", "__libc_start_main", "__libc_start_main_impl",
    "__libc_start_call_main", "main", "smbd_parent_loop",
    "smbd_accept_connection", "smbd_process"}


def cut_loop(st: Stacks) -> Stacks:
    """Stacks from the handler the event loop ran, under one [event loop]
    frame, so stacks perf cut short line up with whole ones. Loops
    nested in a handler (after smbd_process's) stay."""
    w: dict[tuple[str, ...], int] = {}
    n: dict[tuple[str, ...], int] = {}
    for s, v in st.weights.items():
        k = s
        lead = next((i for i, f in enumerate(s) if f in _OUTER), None)
        if lead is not None:
            first = s.index("smbd_process") + 1 if "smbd_process" in s \
                else lead
            cut = next((i for i in range(first, len(s))
                        if s[i] in _DISPATCH), None)
            if cut is None:
                loops = [i for i in range(lead, len(s)) if s[i] in _LOOP]
                cut = loops[-1] if loops else None
            if cut is not None:
                k = s[:lead] + (LOOP,) + s[cut + 1:]
        w[k] = w.get(k, 0) + v
        n[k] = n.get(k, 0) + st.counts.get(s, 1)
    out = st.derive(w, n)
    out.kinds = dict(st.kinds, **{LOOP: PSEUDO})
    return out


def reverse(st: Stacks) -> Stacks:
    w: dict[tuple[str, ...], int] = {}
    n: dict[tuple[str, ...], int] = {}
    for s, v in st.weights.items():
        k = s[::-1]
        w[k] = w.get(k, 0) + v
        n[k] = n.get(k, 0) + st.counts.get(s, 1)
    return st.derive(w, n)


def inclusive(st: Stacks) -> tuple[dict[str, int], dict[str, int]]:
    """Per frame name: weight of the stacks it is in (once per stack),
    and weight where it is the leaf."""
    inc: dict[str, int] = {}
    own: dict[str, int] = {}
    for s, v in st.weights.items():
        for f in set(s):
            inc[f] = inc.get(f, 0) + v
        if s:
            own[s[-1]] = own.get(s[-1], 0) + v
    return inc, own


# -- trees -------------------------------------------------------------------

class Node:
    __slots__ = ("name", "total", "own", "base", "base_own", "children")

    def __init__(self, name: str) -> None:
        self.name = name
        self.total = 0
        self.own = 0
        self.base = 0.0
        self.base_own = 0.0
        self.children: dict[str, Node] = {}

    def child(self, name: str) -> Node:
        c = self.children.get(name)
        if c is None:
            c = self.children[name] = Node(name)
        return c


def tree(st: Stacks, base: Stacks | None = None, scale: float = 1.0,
         root: str = "all") -> Node:
    """The call tree; with `base`, each node also holds the base
    profile's weights times `scale`."""
    top = Node(root)
    for s, v in st.weights.items():
        node = top
        node.total += v
        for f in s:
            node = node.child(f)
            node.total += v
        node.own += v
    if base is not None:
        for s, v in base.weights.items():
            bv = v * scale
            node = top
            node.base += bv
            for f in s:
                node = node.child(f)
                node.base += bv
            node.base_own += bv
    return top
