"""Pair requests with responses and resolve what each one acted on.

A `Capture` is built from the extractor's records. Every request becomes
an `Exchange` holding its response (or none), the interim STATUS_PENDING
response of an async request, a CANCEL aimed at it, and the names the
request's numbers resolve to: the share behind a tree id, the path
behind a file id, the user behind a session id.
"""

from __future__ import annotations

import fnmatch
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from . import names
from .names import (
    CANCEL, CHANGE_NOTIFY, CLOSE, CREATE, IOCTL, LOCK, NEGOTIATE,
    OPLOCK_BREAK, QUERY_DIRECTORY, QUERY_INFO, READ, SESSION_SETUP, SET_INFO,
    STATUS_PENDING, TREE_CONNECT, WRITE,
)

ALL_ONES_FID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
BREAK_MID = 0xFFFFFFFFFFFFFFFF
SMB1_NEGOTIATE = 0x72
SMB1_NT_CANCEL = 0xA4
SMB1_LOCKING_ANDX = 0x24
SMB1_NT_NOTIFY = 0x4  # NT_TRANSACT function
FSCTL_PIPE_WAIT = 0x00110018

# Commands whose response waits for an event rather than for the server's
# work: they are excluded from time-weighted views unless asked for.
WAIT_CMDS = {CHANGE_NOTIFY}


@dataclass(slots=True)
class Stream:
    id: int
    client: str = "?"
    server: str = "?"
    client_port: int = 0
    server_port: int = 0
    first: int | None = None
    last: int | None = None
    syn_rtt: int | None = None      # SYN -> SYN/ACK
    ack_rtt: int | None = None      # SYN/ACK -> ACK
    resets: int = 0
    fins: int = 0
    events: dict[str, int] = field(default_factory=dict)
    requests: int = 0
    min_latency: int | None = None
    min_turnaround: int | None = None  # response seen -> next request seen
    dialect: int | None = None
    encrypted: int = 0
    fast_acks: dict[str, tuple[int, int]] = field(default_factory=dict)


@dataclass(slots=True)
class Session:
    id: int
    user: str = "?"
    host: str = ""
    auth: str = ""
    client: str = "?"
    flags: int | None = None
    setup_status: int | None = None


@dataclass(slots=True)
class Tree:
    sesid: int
    tid: int
    path: str
    share: str
    type: int | None = None


class Exchange:
    """A request and what came back for it."""

    __slots__ = (
        "req", "resp", "interim", "cancel", "proto", "cmd", "stream",
        "client", "server", "sesid", "tid", "mid", "t_start", "t_req",
        "t_resp", "latency", "status", "share", "share_type", "file", "user",
        "sub", "chain", "chain_len", "chain_sig", "weight", "nbytes", "frame",
        "resp_frame", "fileidx", "resp_fileidx", "collateral", "idle",
    )

    def __init__(self, req: dict, proto: str, cmd: int) -> None:
        self.req = req
        self.resp: dict | None = None
        self.interim: dict | None = None
        self.cancel: dict | None = None
        self.proto = proto
        self.cmd = cmd
        self.stream = req["stream"]
        self.client = req["src"]
        self.server = req["dst"]
        self.sesid = req.get("sesid", 0)
        self.tid = req.get("tid")
        self.mid = req["mid"]
        self.t_start: int = req.get("thdr", req["t"])  # its first byte
        self.t_req: int = req["t"]
        self.t_resp: int | None = None
        self.latency: int | None = None
        self.status: int | None = None
        self.share = "?"
        self.share_type: int | None = None
        self.file = ""
        self.user = "?"
        self.sub = ""
        self.chain: tuple[int, int] | None = None
        self.chain_len = 1
        self.chain_sig = ""
        self.weight: int = 0
        self.nbytes = 0
        self.frame = req["frame"]
        self.resp_frame: int | None = None
        self.fileidx = req.get("fileidx", 0)
        self.resp_fileidx = self.fileidx
        self.collateral = False
        self.idle: int | None = None

    @property
    def cmd_name(self) -> str:
        return names.cmd_name(self.proto, self.cmd)

    @property
    def status_name(self) -> str:
        if self.resp is None:
            return "(no response)"
        return names.status_name(self.status)

    @property
    def status_class(self) -> str:
        """'ok', 'flow', 'probe', 'collateral', 'error' or 'unanswered'.

        A compound member that fails after an earlier member of its
        compound failed is collateral: the server did not try it."""
        if self.resp is None:
            return "unanswered"
        cls = names.status_class(self.cmd_name, self.status or 0)
        if self.collateral and cls in ("error", "probe"):
            return "collateral"
        return cls

    @property
    def ok(self) -> bool:
        return self.status == 0

    @property
    def answered(self) -> bool:
        return self.resp is not None

    @property
    def wait(self) -> bool:
        """Whether the server was waiting for an event, not working."""
        if self.proto == "smb2":
            if self.cmd in WAIT_CMDS:
                return True
            if self.cmd == IOCTL and self.req.get("fsctl") == FSCTL_PIPE_WAIT:
                return True
            return False
        return self.req.get("sub") == SMB1_NT_NOTIFY and self.cmd == 0xA0

    @property
    def target(self) -> str:
        """What the request acted on, for grouping and display."""
        if self.cmd == TREE_CONNECT and self.proto == "smb2":
            return self.req.get("tree", "?")
        if self.cmd == SESSION_SETUP and self.proto == "smb2":
            return self.user
        if self.file:
            return f"{self.share}:{self.file}"
        return self.share if self.share != "?" else ""

    @property
    def label(self) -> str:
        return f"{self.cmd_name} {self.sub}".rstrip()

    def pending_after(self) -> int | None:
        """Nanoseconds until the interim STATUS_PENDING, if any."""
        if self.interim is None:
            return None
        return self.interim["t"] - self.t_req

    def to_dict(self) -> dict:
        return {
            "frame": self.frame, "resp_frame": self.resp_frame,
            "t_req": self.t_req, "t_resp": self.t_resp,
            "latency_ns": self.latency, "proto": self.proto,
            "cmd": self.cmd_name, "sub": self.sub, "status": self.status,
            "status_name": self.status_name, "client": self.client,
            "server": self.server, "user": self.user, "share": self.share,
            "file": self.file, "bytes": self.nbytes, "chain": self.chain_sig,
            "async": self.interim is not None,
            "cancelled": self.cancel is not None,
        }


def size_bucket(n: int) -> str:
    """The power-of-two ceiling of a byte count, as a label."""
    if n <= 0:
        return "0"
    size = 512
    while size < n:
        size *= 2
    if size >= 1 << 20:
        return f"{size >> 20}M"
    if size >= 1024:
        return f"{size >> 10}K"
    return f"{size}B"


def short_info(cls: int | None, lvl: int | None) -> str:
    if cls is None or lvl is None:
        return "?"
    text = names.info_name(cls, lvl)
    cname, _, lname = text.partition("/")
    if cls == 1:
        lname = lname.removeprefix("FILE_").removesuffix("_INFO")
    elif cls == 2:
        lname = lname.removesuffix("Information")
    return f"{cname}/{lname}"


def short_find(level: int | None) -> str:
    text = names.find_level_name(level)
    return text.removesuffix("_INFO").removesuffix("_DIRECTORY")


def share_of(path: str) -> str:
    """The share name in a tree-connect path such as \\\\srv\\share."""
    parts = [p for p in path.replace("/", "\\").split("\\") if p]
    if len(parts) >= 2:
        return parts[1]
    return parts[0] if parts else path


def _sub_label(x: Exchange) -> str:
    r = x.req
    cmd = x.cmd
    if x.proto != "smb2":
        sub = r.get("sub")
        if sub is None:
            return ""
        if x.cmd == 0x32:
            return names.names_gen.TRANS2.get(sub, str(sub))
        if x.cmd == 0xA0:
            return names.names_gen.NT_TRANSACT.get(sub, str(sub))
        return ""
    if cmd == CREATE:
        disp = names.CREATE_DISPOSITION.get(r.get("disp", -1), "?")
        return disp + (" dir" if r.get("isdir") else "")
    if cmd in (READ, WRITE):
        return size_bucket(r.get("len", 0))
    if cmd in (QUERY_INFO, SET_INFO):
        label = short_info(r.get("cls"), r.get("lvl"))
        if cmd == SET_INFO and r.get("delete") is not None:
            label += " delete" if r["delete"] else " undelete"
        return label
    if cmd == QUERY_DIRECTORY:
        pat = r.get("pattern", "")
        kind = "*" if pat in ("*", "") else "name"
        flags = r.get("fflags", 0) or 0
        extra = ""
        if flags & 0x01:
            extra += "+restart"
        if flags & 0x02:
            extra += "+single"
        if flags & 0x10:
            extra += "+reopen"
        return f"{short_find(r.get('flvl'))} {kind}{extra}"
    if cmd == IOCTL:
        return names.fsctl_name(r.get("fsctl")).removeprefix("FSCTL_")
    if cmd == CHANGE_NOTIFY:
        return "tree" if r.get("watchtree") else "dir"
    if cmd == LOCK:
        flags = r.get("lockflags") or []
        if not flags:
            return ""
        if all(f & 0x4 for f in flags):
            kind = "unlock"
        elif any(f & 0x2 for f in flags):
            kind = "exclusive"
        else:
            kind = "shared"
        if kind != "unlock" and not all(f & 0x10 for f in flags):
            kind += "+wait"
        n = r.get("nlocks", len(flags))
        return f"{kind} x{n}" if n > 1 else kind
    if cmd == TREE_CONNECT:
        return share_of(r.get("tree", ""))
    if cmd == SESSION_SETUP:
        if "krb" in r:
            return "KRB5"
        t = r.get("ntlm")
        return names.NTLMSSP_TYPE.get(t, "") if t else ""
    if cmd == NEGOTIATE:
        if x.resp is not None and "dialect" in x.resp:
            return names.DIALECT.get(x.resp["dialect"], hex(x.resp["dialect"]))
        return "from SMB1" if r.get("proto") == "smb" else ""
    if cmd == OPLOCK_BREAK:
        return "lease ack" if r.get("bcode") == 36 else "oplock ack"
    return ""


class Capture:
    def __init__(self) -> None:
        self.exchanges: list[Exchange] = []
        self.orphans: list[dict] = []
        self.breaks: list[dict] = []
        self.tcp_events: list[dict] = []
        self.streams: dict[int, Stream] = {}
        self.sessions: dict[int, Session] = {}
        self.trees: dict[tuple[int, int], Tree] = {}
        self.encrypted_frames = 0
        self.encrypted_pdus = 0
        self.headers: list[dict] = []
        self.diag: dict = {}
        self.t0: int | None = None
        self.t1: int | None = None
        self.pdus = 0
        self.inputs: list[str] = []
        self._files: dict[tuple[int, str], str] = {}
        self._open: dict[tuple, Exchange] = {}
        self._smb1_open: dict[tuple, Exchange] = {}
        self._pending_user: dict[tuple[int, int], tuple[str, str, str]] = {}
        self._cur_frame: tuple[int, int] | None = None
        self._cur_start = 0
        self._cur_prev_next = False
        self._cur_name: str | None = None
        self._gids: dict[tuple[int, int], int] = {}
        self._by_ends: dict[frozenset, tuple[int, int]] = {}

    # -- building ---------------------------------------------------------

    def _global_stream(self, rec: dict, fileidx: int) -> int | None:
        """One id per TCP connection across input files: a connection
        that runs on into the next rotated file keeps its id, unless it
        starts over with a SYN."""
        local = (fileidx, rec["stream"])
        gid = self._gids.get(local)
        if gid is not None:
            return gid
        if "dst" not in rec:
            return None
        ends = frozenset(((rec["src"], rec["sport"]),
                          (rec["dst"], rec["dport"])))
        syn = rec.get("k") == "t" and rec.get("flags") == "S"
        prev = self._by_ends.get(ends)
        if prev is not None and not syn and prev[1] != fileidx:
            gid = prev[0]
        else:
            gid = fileidx * 1_000_000 + rec["stream"]
        self._by_ends[ends] = (gid, fileidx)
        self._gids[local] = gid
        return gid

    def add_records(self, records: Iterable[dict], fileidx: int = 0) -> None:
        """Feed one extraction's records; call once per input file, in
        capture order."""
        for rec in records:
            k = rec.get("k")
            if k == "h":
                self.headers.append(rec)
                continue
            if k == "d":
                for key, value in rec.items():
                    if key == "k":
                        continue
                    if isinstance(value, dict):
                        d = self.diag.setdefault(key, {})
                        for kk, vv in value.items():
                            d[kk] = d.get(kk, 0) + vv
                    elif isinstance(value, list):
                        lst = self.diag.setdefault(key, [])
                        lst.extend(v for v in value if v not in lst)
                    else:
                        self.diag[key] = self.diag.get(key, 0) + value
                continue
            gid = self._global_stream(rec, fileidx)
            if gid is None:
                continue
            rec["stream"] = gid
            rec["fileidx"] = fileidx
            if k == "a":
                st = self.streams.get(rec["stream"])
                if st is not None:
                    st.fast_acks[rec["src"]] = (rec["n"], rec["min"])
                continue
            t = rec["t"]
            if self.t0 is None or t < self.t0:
                self.t0 = t
            if self.t1 is None or t > self.t1:
                self.t1 = t
            if k == "t":
                self._tcp(rec)
            elif k == "e":
                self.encrypted_frames += 1
                self.encrypted_pdus += rec.get("n", 1)
                self._stream(rec).encrypted += rec.get("n", 1)
            elif k == "p":
                self.pdus += 1
                self._pdu(rec)

    def finish(self) -> None:
        """Close the books: unanswered requests, chain weights, ordering."""
        for x in list(self._open.values()) + list(self._smb1_open.values()):
            self.exchanges.append(x)
        self._open.clear()
        self._smb1_open.clear()
        self.exchanges.sort(key=lambda x: (x.t_req, x.frame, x.req["i"]))
        groups: dict[tuple, list[Exchange]] = defaultdict(list)
        for x in self.exchanges:
            if x.latency is None:
                continue
            if x.chain is None:
                x.weight = x.latency
                continue
            groups[(x.fileidx, x.chain, x.resp_frame)].append(x)
        for members in groups.values():
            for x in members:
                x.weight = x.latency // len(members)
        chains: dict[tuple, list[Exchange]] = defaultdict(list)
        for x in self.exchanges:
            if x.chain is not None:
                chains[(x.fileidx, x.chain)].append(x)
        for members in chains.values():
            members.sort(key=lambda x: x.req["i"])
            sig = "+".join(x.cmd_name for x in members)
            failed = False
            for x in members:
                x.chain_sig = sig
                x.chain_len = len(members)
                if failed and x.req.get("related"):
                    x.collateral = True
                if x.resp is not None and names.status_class(
                        x.cmd_name, x.status or 0) in ("error", "probe"):
                    failed = True
        last_resp: dict[int, int] = {}
        for x in self.exchanges:
            x.sub = _sub_label(x)
            st = self.streams.get(x.stream)
            if st is not None:
                st.requests += 1
                if x.latency is not None and (
                    st.min_latency is None or x.latency < st.min_latency
                ):
                    st.min_latency = x.latency
                prev = last_resp.get(x.stream)
                if prev is not None and x.t_req > prev and (
                    st.min_turnaround is None
                    or x.t_req - prev < st.min_turnaround
                ):
                    st.min_turnaround = x.t_req - prev
                if x.t_resp is not None and (
                    prev is None or x.t_resp > prev
                ):
                    last_resp[x.stream] = x.t_resp
        self._idle()

    def _idle(self) -> None:
        """Each request's `idle`: how long its client (by address) had
        nothing outstanding before the request's first byte. A request
        waiting for an event counts only as the moment it was sent; the
        first request a client sends in the capture has none."""
        busy: dict[str, int] = {}
        for x in sorted(self.exchanges, key=lambda x: x.t_start):
            last = busy.get(x.client)
            if last is not None:
                x.idle = max(0, x.t_start - last)
            end = x.t_req if x.t_resp is None or x.wait else x.t_resp
            if last is None or end > last:
                busy[x.client] = end

    def _stream(self, rec: dict) -> Stream:
        st = self.streams.get(rec["stream"])
        if st is None:
            st = Stream(rec["stream"])
            self.streams[st.id] = st
            if rec.get("k") == "t" and "S" in rec.get("flags", "") and \
                    "A" not in rec.get("flags", ""):
                st.client, st.server = rec["src"], rec["dst"]
                st.client_port, st.server_port = rec["sport"], rec["dport"]
            elif rec.get("k") == "p":
                if rec["resp"]:
                    st.client, st.server = rec["dst"], rec["src"]
                    st.client_port, st.server_port = rec["dport"], rec["sport"]
                else:
                    st.client, st.server = rec["src"], rec["dst"]
                    st.client_port, st.server_port = rec["sport"], rec["dport"]
            else:
                if rec["dport"] in (445, 139):
                    st.client, st.server = rec["src"], rec["dst"]
                    st.client_port, st.server_port = rec["sport"], rec["dport"]
                else:
                    st.client, st.server = rec["dst"], rec["src"]
                    st.client_port, st.server_port = rec["dport"], rec["sport"]
        t = rec["t"]
        if st.first is None or t < st.first:
            st.first = t
        if st.last is None or t > st.last:
            st.last = t
        return st

    def _tcp(self, rec: dict) -> None:
        st = self._stream(rec)
        flags = rec.get("flags", "")
        if flags == "SA" and "ackrtt" in rec:
            st.syn_rtt = rec["ackrtt"]
        elif flags == "A" and rec.get("seq") == 1 and rec.get("ackno") == 1 \
                and "ackrtt" in rec and st.ack_rtt is None:
            st.ack_rtt = rec["ackrtt"]
        if "R" in flags:
            st.resets += 1
        if "F" in flags:
            st.fins += 1
        for ev in rec.get("ev", []):
            st.events[ev] = st.events.get(ev, 0) + 1
        if rec.get("ev") or "R" in flags:
            self.tcp_events.append(rec)

    def _pdu(self, rec: dict) -> None:
        st = self._stream(rec)
        if rec["proto"] == "smb":
            self._smb1(rec, st)
        else:
            self._smb2(rec, st)

    def _smb2(self, rec: dict, st: Stream) -> None:
        cmd = rec["cmd"]
        key = (rec["stream"], rec["mid"])
        if rec["resp"]:
            if cmd == OPLOCK_BREAK and rec["mid"] == BREAK_MID:
                rec["kind"] = "lease" if rec.get("bcode") == 44 else "oplock"
                rec["file"] = self._file_name(rec)
                self.breaks.append(rec)
                return
            x = self._open.get(key)
            if x is None and cmd == NEGOTIATE:
                # A multi-protocol negotiate: an SMB1 request answered
                # with an SMB2 response.
                for k1, x1 in self._smb1_open.items():
                    if k1[0] == rec["stream"] and x1.cmd == SMB1_NEGOTIATE:
                        x = self._smb1_open.pop(k1)
                        x.proto, x.cmd = "smb2", NEGOTIATE
                        self._open[key] = x
                        break
            if x is None:
                rec["cmd_name"] = names.cmd_name("smb2", cmd)
                self.orphans.append(rec)
                return
            if rec.get("status") == STATUS_PENDING and rec["async"]:
                x.interim = rec
                return
            self._complete(x, rec)
            del self._open[key]
            self._after_response(x)
            return
        if cmd == CANCEL:
            x = self._open.get(key)
            if x is not None:
                x.cancel = rec
            return
        prev = self._open.pop(key, None)
        if prev is not None:
            self.exchanges.append(prev)
        x = Exchange(rec, "smb2", cmd)
        self._open[key] = x
        self._resolve(x, rec)
        if cmd == SESSION_SETUP and ("user" in rec or "krb" in rec):
            self._pending_user[key] = (
                rec.get("user", "?"), rec.get("host", ""),
                "kerberos" if "krb" in rec else "ntlmssp",
            )
        if cmd in (READ, WRITE):
            x.nbytes = rec.get("len", 0)

    def _complete(self, x: Exchange, rec: dict) -> None:
        x.resp = rec
        x.t_resp = rec["t"]
        x.latency = rec["t"] - x.t_req
        x.status = rec.get("status", 0)
        x.resp_frame = rec["frame"]
        x.resp_fileidx = rec.get("fileidx", x.fileidx)
        self.exchanges.append(x)

    def _chain(self, rec: dict) -> int | None:
        """The index of the chain this request PDU belongs to in its
        frame, or None for a PDU that stands alone.

        PDUs of a frame arrive in order. A chain starts at a PDU with a
        NextCommand and runs through the PDUs that follow one."""
        key = (rec["fileidx"], rec["frame"])
        i = rec["i"]
        if self._cur_frame != key or not self._cur_prev_next:
            self._cur_frame = key
            self._cur_start = i
            self._cur_name = None
        self._cur_prev_next = bool(rec.get("next"))
        if rec.get("next") or self._cur_start != i:
            return self._cur_start
        return None

    def _resolve(self, x: Exchange, rec: dict) -> None:
        """Share, user and file for a request, from state so far."""
        start = self._chain(rec)
        if start is not None:
            x.chain = (rec["frame"], start)
        ses = self.sessions.get(x.sesid)
        if ses is not None:
            x.user = ses.user
        tree = self.trees.get((x.sesid, x.tid)) if x.tid is not None else None
        if tree is not None:
            x.share = tree.share
            x.share_type = tree.type
        elif x.cmd == TREE_CONNECT:
            x.share = share_of(rec.get("tree", ""))
        elif x.tid:
            x.share = f"tid:{x.tid:#x}"
        if x.cmd == CREATE:
            x.file = rec.get("name", "")
            if x.file == "":
                x.file = "\\"
            self._cur_name = x.file
        elif "fid" in rec:
            fid = rec["fid"]
            if fid == ALL_ONES_FID and rec.get("related"):
                # The placeholder file id names what the chain's CREATE
                # opened.
                x.file = self._cur_name or "?"
            else:
                x.file = self._files.get((x.sesid, fid)) or f"fid:{fid[:8]}"
        if x.cmd == SET_INFO and "name" in rec:
            x.file = f"{x.file} -> {rec['name']}"

    def _after_response(self, x: Exchange) -> None:
        rec = x.resp
        assert rec is not None
        cmd = x.cmd
        if cmd == SESSION_SETUP:
            user, host, auth = self._pending_user.pop(
                (x.stream, x.mid), ("?", "", ""))
            if "user" in rec:
                user = rec["user"]
            if x.status in (0, names.STATUS_MORE_PROCESSING_REQUIRED) or \
                    x.sesid or rec.get("sesid"):
                sesid = rec.get("sesid", x.sesid)
                ses = self.sessions.get(sesid)
                if ses is None:
                    ses = Session(sesid)
                    self.sessions[sesid] = ses
                if user != "?":
                    ses.user = user
                if host:
                    ses.host = host
                if auth:
                    ses.auth = auth
                ses.client = x.client
                ses.setup_status = x.status
                if "sflags" in rec:
                    ses.flags = rec["sflags"]
                x.user = ses.user
        elif cmd == TREE_CONNECT and x.ok:
            path = x.req.get("tree", "")
            tid = rec.get("tid")
            if tid is not None:
                self.trees[(x.sesid, tid)] = Tree(
                    x.sesid, tid, path, share_of(path), rec.get("stype"))
        elif cmd == CREATE and x.ok and "fid" in rec:
            self._files[(x.sesid, rec["fid"])] = x.file
        elif cmd == CLOSE and x.ok:
            fid = x.req.get("fid")
            if fid and fid != ALL_ONES_FID:
                self._files.pop((x.sesid, fid), None)
        elif cmd == SET_INFO and x.ok and "name" in x.req and \
                x.req.get("lvl") == 10:
            fid = x.req.get("fid")
            if fid and fid != ALL_ONES_FID:
                self._files[(x.sesid, fid)] = x.req["name"]
        elif cmd == NEGOTIATE:
            st = self.streams.get(x.stream)
            if st is not None and "dialect" in rec:
                st.dialect = rec["dialect"]

    def _file_name(self, rec: dict) -> str:
        fid = rec.get("fid")
        if not fid:
            return ""
        for (sesid, f), name in self._files.items():
            if f == fid:
                return name
        return f"fid:{fid[:8]}"

    def _smb1(self, rec: dict, st: Stream) -> None:
        cmd = rec["cmd"]
        key = (rec["stream"], rec["mid"], rec.get("pid", 0))
        if rec["resp"]:
            x = self._smb1_open.pop(key, None)
            if x is None:
                rec["cmd_name"] = names.cmd_name("smb", cmd)
                self.orphans.append(rec)
                return
            self._complete(x, rec)
            return
        if cmd == SMB1_NT_CANCEL:
            x = self._smb1_open.get(key)
            if x is not None:
                x.cancel = rec
            return
        if cmd == SMB1_LOCKING_ANDX and rec["src"] == st.server:
            rec["kind"] = "oplock"
            rec["file"] = ""
            self.breaks.append(rec)
            return
        prev = self._smb1_open.pop(key, None)
        if prev is not None:
            self.exchanges.append(prev)
        x = Exchange(rec, "smb", cmd)
        self._smb1_open[key] = x
        x.file = rec.get("name", "")
        x.share = share_of(rec["tree"]) if "tree" in rec else (
            f"tid:{rec['tid']:#x}" if rec.get("tid") else "?")

    # -- queries ------------------------------------------------------------

    def rel(self, t: int) -> float:
        """Seconds since the capture's first record."""
        return (t - (self.t0 or 0)) / 1e9

    def duration(self) -> float:
        if self.t0 is None or self.t1 is None:
            return 0.0
        return (self.t1 - self.t0) / 1e9

    def servers(self) -> list[str]:
        return sorted({st.server for st in self.streams.values()})

    def clients(self) -> list[str]:
        return sorted({st.client for st in self.streams.values()})

    def vantage(self) -> tuple[str, str]:
        """Where the capture was taken, as ('server'|'client'|'path'|
        'unknown', explanation).

        Signals, strongest first: which half of the TCP handshake took
        no time (the capturing host answers at once); which side sends
        ACKs within microseconds of the data they acknowledge; whether
        the round trip shows up in the fastest response (server work
        plus the trip, seen from the client) or in the fastest
        turnaround from a response to the next request (client work
        plus the trip, seen from the server)."""
        syn = [st.syn_rtt for st in self.streams.values()
               if st.syn_rtt is not None and st.ack_rtt is not None]
        ack = [st.ack_rtt for st in self.streams.values()
               if st.syn_rtt is not None and st.ack_rtt is not None]
        lat = [st.min_latency for st in self.streams.values()
               if st.min_latency is not None]
        parts = []
        verdict = "unknown"
        if syn:
            s = sorted(syn)[len(syn) // 2]
            a = sorted(ack)[len(ack) // 2]
            parts.append(
                f"handshake: SYN->SYN/ACK {s / 1e3:.0f} us, "
                f"SYN/ACK->ACK {a / 1e3:.0f} us (median of {len(syn)})"
            )
            if s * 4 < a and s < 2_000_000:
                verdict = "server"
            elif a * 4 < s and a < 2_000_000:
                verdict = "client"
            else:
                verdict = "path"
        by_server = by_client = 0
        for st in self.streams.values():
            for src, (n, _) in st.fast_acks.items():
                if src == st.server:
                    by_server += n
                elif src == st.client:
                    by_client += n
        if by_server or by_client:
            parts.append(f"immediate ACKs: {by_server} by the server, "
                         f"{by_client} by the client")
            if verdict == "unknown":
                if by_server >= 3 and by_server > 3 * by_client:
                    verdict = "server"
                elif by_client >= 3 and by_client > 3 * by_server:
                    verdict = "client"
                elif by_server + by_client >= 6:
                    verdict = "path"
        turn = [st.min_turnaround for st in self.streams.values()
                if st.min_turnaround is not None]
        if lat:
            m = min(lat)
            parts.append(f"fastest response {m / 1e3:.0f} us")
            if turn:
                t = min(turn)
                parts.append(f"fastest turnaround {t / 1e3:.0f} us")
            if verdict == "unknown":
                if m < 60_000:
                    verdict = "server"
                elif turn:
                    t = min(turn)
                    if m < 300_000 and t > 2.5 * m:
                        verdict = "server"
                    elif t < 300_000 and m > 2.5 * t:
                        verdict = "client"
        return verdict, "; ".join(parts)


class Filter:
    """Which exchanges a tool looks at."""

    def __init__(
        self, *, clients: list[str] = (), servers: list[str] = (),
        shares: list[str] = (), users: list[str] = (), files: list[str] = (),
        cmds: list[tuple[str, int]] = (), statuses: list[int] = (),
        streams: list[int] = (), sessions: list[int] = (),
        t_from: float | None = None, t_to: float | None = None,
        errors_only: bool = False, answered_only: bool = False,
        waits: bool = True,
    ) -> None:
        self.clients = set(clients)
        self.servers = set(servers)
        self.shares = {s.lower() for s in shares}
        self.users = [u.lower() for u in users]
        self.files = [f.lower() for f in files]
        self.cmds = set(cmds)
        self.statuses = set(statuses)
        self.streams = set(streams)
        self.sessions = set(sessions)
        self.t_from = t_from
        self.t_to = t_to
        self.errors_only = errors_only
        self.answered_only = answered_only
        self.waits = waits

    def apply(self, cap: Capture, exchanges: Iterable[Exchange] | None = None
              ) -> Iterator[Exchange]:
        t0 = cap.t0 or 0
        for x in exchanges if exchanges is not None else cap.exchanges:
            if self.clients and x.client not in self.clients:
                continue
            if self.servers and x.server not in self.servers:
                continue
            if self.shares and x.share.lower() not in self.shares:
                continue
            if self.users and not any(u in x.user.lower() for u in self.users):
                continue
            if self.files:
                f = x.file.lower()
                if not any(fnmatch.fnmatchcase(f, pat) or pat in f
                           for pat in self.files):
                    continue
            if self.cmds and (x.proto, x.cmd) not in self.cmds:
                continue
            if self.statuses and x.status not in self.statuses:
                continue
            if self.streams and x.stream not in self.streams:
                continue
            if self.sessions and x.sesid not in self.sessions:
                continue
            if self.t_from is not None and (x.t_req - t0) / 1e9 < self.t_from:
                continue
            if self.t_to is not None and (x.t_req - t0) / 1e9 > self.t_to:
                continue
            if self.errors_only and x.status_class in ("ok", "flow",
                                                      "collateral"):
                continue
            if self.answered_only and x.resp is None:
                continue
            if not self.waits and x.wait:
                continue
            yield x
