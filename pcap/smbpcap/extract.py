"""Turn a capture into one record per SMB PDU, using tshark for dissection.

tshark's field output (`-T fields`) prints every occurrence of a field
in a frame, but a frame often carries several SMB2 PDUs (compounded
requests, pipelined messages, coalesced responses) and a field that
only some commands carry cannot be tied to its PDU by position alone.
The header fields are one per PDU, so they define the PDUs; each body
field is then handed to the PDUs that can carry it, using the exact
counts the dissector emits per command (`_SPEC`). A frame where the
counts do not add up keeps its header-level records and loses the body
field, and the summary reports how often that happened.

The tree output (`-T json`) would avoid the alignment problem but
hex-encodes every READ payload, which makes it unusable on a capture
of a file transfer.
"""

from __future__ import annotations

import gzip
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from typing import Callable, Iterator

from .names import (
    CHANGE_NOTIFY, CLOSE, CREATE, FLUSH, IOCTL, LOCK, NEGOTIATE,
    OPLOCK_BREAK, QUERY_DIRECTORY, QUERY_INFO, READ, SESSION_SETUP, SET_INFO,
    TREE_CONNECT, WRITE,
)

FORMAT_VERSION = 5
AGGREGATOR = "\x1f"

FRAME_FIELDS = [
    ("frame.number", "frame"), ("frame.time_epoch", "time"),
    ("frame.len", "flen"), ("tcp.stream", "stream"), ("ip.src", "ip4src"),
    ("ip.dst", "ip4dst"), ("ipv6.src", "ip6src"), ("ipv6.dst", "ip6dst"),
    ("tcp.srcport", "sport"), ("tcp.dstport", "dport"), ("tcp.len", "tlen"),
    ("tcp.flags.syn", "syn"), ("tcp.flags.ack", "ackf"),
    ("tcp.flags.fin", "fin"), ("tcp.flags.reset", "rst"), ("tcp.seq", "seq"),
    ("tcp.ack", "ackno"), ("tcp.analysis.retransmission", "retrans"),
    ("tcp.analysis.fast_retransmission", "fastretrans"),
    ("tcp.analysis.spurious_retransmission", "spurious"),
    ("tcp.analysis.out_of_order", "ooo"),
    ("tcp.analysis.duplicate_ack", "dupack"),
    ("tcp.analysis.zero_window", "zwin"),
    ("tcp.analysis.window_full", "winfull"),
    ("tcp.analysis.lost_segment", "lost"),
    ("tcp.analysis.keep_alive", "keepalive"),
    ("tcp.analysis.ack_rtt", "ackrtt"),
    ("smb2.header.transform.flags.encrypted", "enc"),
    ("frame.cap_len", "caplen"), ("nbss.length", "nbsslen"),
    ("nbss.type", "nbsstype"), ("tcp.segment", "segs"),
]
SMB2_HEADER_FIELDS = [
    ("smb2.cmd", "cmd"), ("smb2.flags.response", "resp"),
    ("smb2.flags.async", "async"), ("smb2.flags.chained", "related"),
    ("smb2.flags.signature", "signed"), ("smb2.msg_id", "mid"),
    ("smb2.sesid", "sesid"), ("smb2.tid", "tid"), ("smb2.aid", "aid"),
    ("smb2.nt_status", "status"), ("smb2.credit.charge", "charge"),
    ("smb2.credits.requested", "creq"), ("smb2.credits.granted", "cgrant"),
    ("smb2.chain_offset", "next"), ("smb2.buffer_code", "bcode"),
]
SMB2_BODY_FIELDS = [
    ("smb2.tag", "ctx"), ("smb2.class", "cls"), ("smb2.lock_count", "nlocks"),
    ("smb2.ioctl.function", "fsctl"), ("smb2.file_info.infolevel", "lvlfile"),
    ("smb2.fs_info.infolevel", "lvlfs"), ("smb2.sec_info.infolevel", "lvlsec"),
    ("smb2.infolevel", "lvl"), ("smb2.filename", "name"), ("smb2.fid", "fid"),
    ("smb2.create.disposition", "disp"), ("smb2.create.action", "action"),
    ("smb2.create.oplock", "oplock"),
    ("smb.nt.create_options.directory", "isdir"),
    ("smb.access_mask", "access"), ("smb2.lease.lease_state", "lease"),
    ("smb2.lease.lease_key", "leasekey"), ("smb2.file_offset", "off"),
    ("smb2.read_length", "rlen"), ("smb2.write_length", "wlen"),
    ("smb2.write.count", "wcount"), ("smb2.find.pattern", "pattern"),
    ("smb2.find.infolevel", "flvl"), ("smb2.find.flags", "fflags"),
    ("smb2.tree", "tree"), ("smb2.share_type", "stype"),
    ("smb2.dialect", "dialect"), ("smb2.sec_mode", "secmode"),
    ("smb2.capabilities", "caps"),
    ("smb2.negotiate_context.cipher_id", "cipher"),
    ("smb2.session_flags", "sflags"), ("smb2.acct", "acct"),
    ("smb2.domain", "domain"), ("smb2.host", "host"),
    ("ntlmssp.messagetype", "ntlm"), ("ntlmssp.auth.username", "ntuser"),
    ("ntlmssp.auth.domain", "ntdomain"), ("ntlmssp.auth.hostname", "nthost"),
    ("kerberos.SNameString", "krbsname"), ("kerberos.realm", "krbrealm"),
    ("smb2.lock_flags", "lockflags"), ("smb2.notify.watch_tree", "watchtree"),
    ("smb2.disposition.delete_on_close", "delete"),
    ("smb2.error.byte_count", "errbytes"),
]
SMB1_FIELDS = [
    ("smb.cmd", "cmd1"), ("smb.flags.response", "resp1"), ("smb.mid", "mid1"),
    ("smb.pid", "pid1"), ("smb.uid", "uid1"), ("smb.tid", "tid1"),
    ("smb.nt_status", "status1"), ("smb.flags2.nt_error", "nterr1"),
    ("smb.file", "file1"), ("smb.path", "path1"), ("smb.fid", "fid1"),
    ("smb.trans2.cmd", "trans2"), ("smb.nt.function", "ntfn"),
]
ALL_FIELDS = FRAME_FIELDS + SMB2_HEADER_FIELDS + SMB2_BODY_FIELDS + SMB1_FIELDS
KEYS = [k for _, k in ALL_FIELDS]

# Pure ACKs sent within FAST_ACK of the data they acknowledge come from
# the host the capture was taken on; they tell which side that was.
FAST_ACK_S = "0.0001"
DISPLAY_FILTER = (
    "smb2 || smb || tcp.flags.syn == 1 || tcp.flags.reset == 1"
    " || tcp.flags.fin == 1 || tcp.analysis.flags"
    " || (tcp.len == 0 && tcp.seq == 1 && tcp.ack == 1)"
    f" || (tcp.len == 0 && tcp.analysis.ack_rtt < {FAST_ACK_S})"
    # Frames holding the rest of a PDU tshark saw only the start of.
    " || (tcp.len > 0 && frame.cap_len < frame.len)"
    " || nbss.continuation_data"
    # Segments of a request reassembled later: when it began.
    " || (tcp.segment_data && tcp.dstport in {445, 139})"
)

# Fields kept as lists; everything else collapses to its single value.
LIST_KEYS = {"ctx", "dialect", "cipher", "lockflags", "off", "andx"}
STRING_KEYS = {
    "name", "pattern", "tree", "acct", "domain", "host", "ntuser", "ntdomain",
    "nthost", "krbsname", "krbrealm", "file1", "path1", "ctx", "fid",
    "leasekey",
}
INT_KEYS = set(KEYS) - STRING_KEYS - {
    "time", "ackrtt", "ip4src", "ip4dst", "ip6src", "ip6dst", "resp", "async",
    "related", "signed", "syn", "ackf", "fin", "rst", "isdir", "watchtree",
    "delete", "resp1", "nterr1", "retrans", "fastretrans", "spurious", "ooo",
    "dupack", "zwin", "winfull", "lost", "keepalive", "enc",
}
BOOL_KEYS = {
    "resp", "async", "related", "signed", "syn", "ackf", "fin", "rst", "isdir",
    "watchtree", "delete", "resp1", "nterr1",
}

# A lease break notification, its acknowledgement and the acknowledgement's
# response are told from the oplock forms by StructureSize.
BREAK_OPLOCK, BREAK_LEASE_ACK, BREAK_LEASE_NOTIFY = 24, 36, 44
ERROR_BODY = 9
FSCTL_QUERY_FILE_REGIONS = 0x00090284
FSCTL_QUERY_ALLOCATED_RANGES = 0x000940CF
FSCTL_DUPLICATE_EXTENTS = 0x00098344
DURABLE_FID_CONTEXTS = {"DHnQ", "DHnC", "DH2C"}
# Status values for which a response dissector reads a body even though
# the StructureSize is the error response's 9.
BODY_STATUS = {
    CHANGE_NOTIFY: {0, 0x10C}, IOCTL: {0, 0x80000005},
}


def unescape(text: str) -> str:
    """Undo tshark's field-output escaping of strings."""
    if "\\" not in text:
        return text
    out = []
    i = 0
    n = len(text)
    simple = {
        "\\": "\\", "t": "\t", "n": "\n", "r": "\r", "f": "\f", "v": "\v",
        "a": "\a", "b": "\b", '"': '"',
    }
    while i < n:
        c = text[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        d = text[i + 1]
        if d in simple:
            out.append(simple[d])
            i += 2
        elif d == "x" and i + 3 < n:
            try:
                out.append(chr(int(text[i + 2:i + 4], 16)))
                i += 4
            except ValueError:
                out.append(c)
                i += 1
        elif d == "u" and i + 5 < n:
            try:
                out.append(chr(int(text[i + 2:i + 6], 16)))
                i += 6
            except ValueError:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _ns(text: str) -> int:
    """Seconds with a fractional part, as integer nanoseconds."""
    sign = -1 if text.startswith("-") else 1
    text = text.lstrip("-")
    whole, _, frac = text.partition(".")
    frac = (frac + "000000000")[:9]
    return sign * (int(whole or 0) * 1_000_000_000 + int(frac))


def _int(text: str) -> int:
    return int(text, 0)


def _bool(text: str) -> bool:
    return text in ("True", "1")


def has_body(p: dict) -> bool:
    """Whether the dissector read a command body rather than an error one."""
    if not p["resp"]:
        return True
    cmd = p["cmd"]
    if cmd == SESSION_SETUP:
        return True
    status = p.get("status") or 0
    if status in BODY_STATUS.get(cmd, {0}):
        return True
    bcode = p.get("bcode")
    return bcode is not None and bcode != ERROR_BODY


def _lease_counts(p: dict) -> tuple[int, int]:
    """(lease states, lease keys) an OPLOCK_BREAK PDU carries."""
    b = p.get("bcode")
    if b == BREAK_LEASE_NOTIFY:
        return 2, 1
    if b == BREAK_LEASE_ACK:
        return 1, 1
    return 0, 0


Spec = Callable[[dict, "_Frame"], "int | None"]


def _req(cmds: set[int]) -> Spec:
    return lambda p, f: 1 if not p["resp"] and p["cmd"] in cmds else 0


def _resp_body(cmds: set[int]) -> Spec:
    return lambda p, f: (
        1 if p["resp"] and p["cmd"] in cmds and has_body(p) else 0
    )


def _either(*specs: Spec) -> Spec:
    def spec(p: dict, f: "_Frame") -> int | None:
        total = 0
        for s in specs:
            c = s(p, f)
            if c is None:
                return None
            total += c
        return total
    return spec


def _var(cmds: set[int], responses: bool = True) -> Spec:
    def spec(p: dict, f: "_Frame") -> int | None:
        if p["cmd"] not in cmds:
            return 0
        if p["resp"] and not (responses and has_body(p)):
            return 0
        return None
    return spec


def _fid(p: dict, f: "_Frame") -> int | None:
    cmd = p["cmd"]
    if cmd == OPLOCK_BREAK:
        return 1 if p.get("bcode") == BREAK_OPLOCK else 0
    if not p["resp"]:
        if cmd in (CLOSE, FLUSH, READ, WRITE, LOCK, QUERY_DIRECTORY,
                   CHANGE_NOTIFY, QUERY_INFO, SET_INFO):
            return 1
        if cmd == IOCTL:
            return 2 if p.get("fsctl") == FSCTL_DUPLICATE_EXTENTS else 1
        if cmd == CREATE:
            if "ctx" in p:
                return sum(1 for t in p["ctx"] if t in DURABLE_FID_CONTEXTS)
            if any(t in DURABLE_FID_CONTEXTS for t in f.tags):
                return None
            return 0
        return 0
    if cmd in (CREATE, IOCTL) and has_body(p):
        return 1
    return 0


def _info_level(cls: int | None) -> Spec:
    def spec(p: dict, f: "_Frame") -> int | None:
        if p["resp"] or p["cmd"] not in (QUERY_INFO, SET_INFO):
            return 0
        c = p.get("cls")
        if cls is None:
            return 1 if c not in (1, 2, 3) else 0
        return 1 if c == cls else 0
    return spec


def _file_level(p: dict) -> int | None:
    """The FILE-class info level of a QUERY_INFO or SET_INFO request."""
    if p.get("cls") != 1:
        return None
    return p.get("lvlfile", p.get("lvl"))


def _entries(p: dict, names: list[str]) -> None:
    """A QUERY_DIRECTORY reply's entry count, and its first and last
    names, which place it within the directory."""
    dots = sum(1 for n in names if n in (".", ".."))
    rest = [n for n in names if n not in (".", "..")]
    p["ents"] = len(rest)
    if dots:
        p["dots"] = dots
    if rest:
        p["e0"] = rest[0]
        p["e1"] = rest[-1]


def _name(p: dict, f: "_Frame") -> int | None:
    if p["resp"]:
        return 0
    if p["cmd"] == CREATE:
        return 1
    if p["cmd"] == SET_INFO:
        return 1 if _file_level(p) in (10, 11) else 0
    return 0


def _oplock(p: dict, f: "_Frame") -> int | None:
    if p["cmd"] == OPLOCK_BREAK:
        return 1 if p.get("bcode") == BREAK_OPLOCK else 0
    if p["cmd"] == CREATE:
        return 1 if has_body(p) else 0
    return 0


def _lease(p: dict, f: "_Frame") -> int | None:
    if p["cmd"] == OPLOCK_BREAK:
        return _lease_counts(p)[0]
    return _var({CREATE})(p, f)


def _leasekey(p: dict, f: "_Frame") -> int | None:
    if p["cmd"] == OPLOCK_BREAK:
        return _lease_counts(p)[1]
    return _var({CREATE})(p, f)


def _offset(p: dict, f: "_Frame") -> int | None:
    cmd = p["cmd"]
    if cmd == IOCTL:
        if not has_body(p):
            return 0
        if p.get("fsctl") in (FSCTL_QUERY_FILE_REGIONS,
                              FSCTL_QUERY_ALLOCATED_RANGES):
            return None
        return 0
    if p["resp"]:
        return 0
    if cmd in (READ, WRITE):
        return 1
    if cmd == LOCK:
        return p.get("nlocks")
    return 0


def _lockflags(p: dict, f: "_Frame") -> int | None:
    if p["resp"] or p["cmd"] != LOCK:
        return 0
    return p.get("nlocks")


def _delete(p: dict, f: "_Frame") -> int | None:
    if p["resp"] or p["cmd"] != SET_INFO:
        return 0
    return 1 if _file_level(p) == 13 else 0


def _errbytes(p: dict, f: "_Frame") -> int | None:
    return 1 if p["resp"] and not has_body(p) else 0


def _fsctl(p: dict, f: "_Frame") -> int | None:
    if p["cmd"] != IOCTL:
        return 0
    return 1 if has_body(p) else 0


_NEG_SS = {NEGOTIATE, SESSION_SETUP}
# Attribution order matters: later specs read earlier results.
_SPEC: list[tuple[str, Spec]] = [
    ("ctx", _var({CREATE})),
    ("cls", _req({QUERY_INFO, SET_INFO})),
    ("nlocks", _req({LOCK})),
    ("fsctl", _fsctl),
    ("lvlfile", _info_level(1)),
    ("lvlfs", _info_level(2)),
    ("lvlsec", _info_level(3)),
    ("lvl", _info_level(None)),
    ("name", _name),
    ("fid", _fid),
    ("disp", _req({CREATE})),
    ("action", _resp_body({CREATE})),
    ("oplock", _oplock),
    ("isdir", _req({CREATE})),
    ("access", _req({CREATE})),
    ("lease", _lease),
    ("leasekey", _leasekey),
    ("off", _offset),
    ("rlen", _req({READ})),
    ("wlen", _req({WRITE})),
    ("wcount", _resp_body({WRITE})),
    ("pattern", _req({QUERY_DIRECTORY})),
    ("flvl", _req({QUERY_DIRECTORY})),
    ("fflags", _req({QUERY_DIRECTORY})),
    ("tree", _req({TREE_CONNECT})),
    ("stype", _resp_body({TREE_CONNECT})),
    ("dialect", _either(_var({NEGOTIATE}, responses=False),
                        _resp_body({NEGOTIATE}))),
    ("secmode", _either(_req(_NEG_SS), _resp_body({NEGOTIATE}))),
    ("caps", _either(_req(_NEG_SS), _resp_body({NEGOTIATE}))),
    ("cipher", _var({NEGOTIATE})),
    ("sflags", lambda p, f: 1 if p["resp"] and p["cmd"] == SESSION_SETUP
     else 0),
    ("acct", _var({SESSION_SETUP})),
    ("domain", _var({SESSION_SETUP})),
    ("host", _var({SESSION_SETUP})),
    ("ntlm", _var({SESSION_SETUP})),
    ("ntuser", _var({SESSION_SETUP})),
    ("ntdomain", _var({SESSION_SETUP})),
    ("nthost", _var({SESSION_SETUP})),
    ("krbsname", _var({SESSION_SETUP})),
    ("krbrealm", _var({SESSION_SETUP})),
    ("lockflags", _lockflags),
    ("watchtree", _req({CHANGE_NOTIFY})),
    ("delete", _delete),
    ("errbytes", _errbytes),
]

ANDX_COMMANDS = {0x24, 0x2D, 0x2E, 0x2F, 0x73, 0x74, 0x75, 0xA2}


class _Frame:
    """One line of tshark output: the frame's fields, each a list."""

    __slots__ = ("vals", "tags")

    def __init__(self, vals: dict[str, list[str]]) -> None:
        self.vals = vals
        self.tags = vals.get("ctx", [])


class Diagnostics:
    def __init__(self) -> None:
        self.frames_broken = 0
        self.unattributed: Counter[str] = Counter()
        self.frames_unattributed = 0
        self.smb1_andx_guessed = 0
        self.fast_acks: dict[tuple[int, str], list[int]] = {}

    def as_dict(self) -> dict:
        return {
            "frames_broken": self.frames_broken,
            "frames_unattributed": self.frames_unattributed,
            "unattributed": dict(self.unattributed),
            "smb1_andx_guessed": self.smb1_andx_guessed,
        }

    def fast_ack(self, stream: int, src: str, rtt: int) -> None:
        entry = self.fast_acks.get((stream, src))
        if entry is None:
            self.fast_acks[(stream, src)] = [1, rtt]
        else:
            entry[0] += 1
            if rtt < entry[1]:
                entry[1] = rtt

    def ack_records(self) -> Iterator[dict]:
        for (stream, src), (n, rtt) in sorted(self.fast_acks.items()):
            yield {"k": "a", "stream": stream, "src": src, "n": n,
                   "min": rtt}


def _convert(key: str, text: str):
    if key in BOOL_KEYS:
        return _bool(text)
    if key in INT_KEYS:
        return _int(text)
    if key in STRING_KEYS:
        return unescape(text)
    return text


def _frame_base(vals: dict[str, list[str]]) -> dict | None:
    def one(key: str) -> str | None:
        v = vals.get(key)
        return v[0] if v else None

    frame = one("frame")
    stream = one("stream")
    if frame is None or stream is None:
        return None
    src = one("ip4src") or one("ip6src") or "?"
    dst = one("ip4dst") or one("ip6dst") or "?"
    return {
        "frame": int(frame), "t": _ns(one("time") or "0"),
        "stream": int(stream), "src": src, "dst": dst,
        "sport": int(one("sport") or 0), "dport": int(one("dport") or 0),
        "flen": int(one("flen") or 0), "tlen": int(one("tlen") or 0),
    }


def _tcp_record(base: dict, vals: dict[str, list[str]],
                diag: Diagnostics) -> dict | None:
    flags = ""
    for key, letter in (("syn", "S"), ("fin", "F"), ("rst", "R"),
                        ("ackf", "A")):
        v = vals.get(key)
        if v and _bool(v[0]):
            flags += letter
    events = [k for k in ("retrans", "fastretrans", "spurious", "ooo", "dupack",
                          "zwin", "winfull", "lost", "keepalive")
              if vals.get(k)]
    if not events and flags == "A":
        seq = vals.get("seq")
        ackno = vals.get("ackno")
        handshake = (seq and ackno and seq[0] == "1" and ackno[0] == "1"
                     and base["tlen"] == 0)
        if not handshake:
            if base["tlen"] == 0 and vals.get("ackrtt"):
                diag.fast_ack(base["stream"], base["src"],
                              _ns(vals["ackrtt"][0]))
            return None
    rec = dict(base)
    rec["k"] = "t"
    rec["flags"] = flags
    rec["ev"] = events
    rec["seq"] = int(vals["seq"][0]) if vals.get("seq") else 0
    rec["ackno"] = int(vals["ackno"][0]) if vals.get("ackno") else 0
    if vals.get("ackrtt"):
        rec["ackrtt"] = _ns(vals["ackrtt"][0])
    return rec


def _distribute(pdus: list[dict], key: str, vals: list[str],
                owners_flag: Callable[[dict], bool]) -> bool:
    """Give one value each to the PDUs `owners_flag` selects."""
    owners = [p for p in pdus if owners_flag(p)]
    if len(owners) != len(vals):
        return False
    for p, v in zip(owners, vals):
        p[key] = _convert(key, v)
    return True


def _smb2_pdus(base: dict, f: _Frame, diag: Diagnostics) -> list[dict]:
    vals = f.vals
    cmds = vals.get("cmd", [])
    n = len(cmds)
    if n == 0:
        return []
    resp = vals.get("resp", [])
    mids = vals.get("mid", [])
    sesids = vals.get("sesid", [])
    asyncs = vals.get("async", [])
    relateds = vals.get("related", [])
    signeds = vals.get("signed", [])
    nexts = vals.get("next", [])
    charges = vals.get("charge", [])
    if not (len(resp) == len(mids) == len(sesids) == len(asyncs)
            == len(relateds) == len(signeds) == len(nexts) == n):
        diag.frames_broken += 1
        return []
    pdus = []
    for i in range(n):
        p = dict(base)
        p["k"] = "p"
        p["proto"] = "smb2"
        p["n"] = n
        p["i"] = i
        p["cmd"] = _int(cmds[i])
        p["resp"] = _bool(resp[i])
        p["async"] = _bool(asyncs[i])
        p["related"] = _bool(relateds[i])
        p["signed"] = _bool(signeds[i])
        p["mid"] = _int(mids[i])
        p["sesid"] = _int(sesids[i])
        p["next"] = _int(nexts[i])
        if len(charges) == n:
            p["charge"] = _int(charges[i])
        pdus.append(p)
    ok = True
    ok &= _distribute(pdus, "status", vals.get("status", []),
                      lambda p: p["resp"])
    ok &= _distribute(pdus, "tid", vals.get("tid", []),
                      lambda p: not p["async"])
    ok &= _distribute(pdus, "aid", vals.get("aid", []), lambda p: p["async"])
    ok &= _distribute(pdus, "creq", vals.get("creq", []),
                      lambda p: not p["resp"])
    ok &= _distribute(pdus, "cgrant", vals.get("cgrant", []),
                      lambda p: p["resp"])
    if not ok:
        diag.frames_broken += 1
        return []
    for p in pdus:
        p["credits"] = p.pop("creq", None) if not p["resp"] else p.pop(
            "cgrant", None)
        p.pop("creq", None)
        p.pop("cgrant", None)
    bcodes = vals.get("bcode", [])
    if len(bcodes) == n:
        for p, b in zip(pdus, bcodes):
            p["bcode"] = _int(b)
    missed = False
    for key, spec in _SPEC:
        raw = vals.get(key)
        if not raw:
            continue
        owners: list[dict] = []
        counts: list[int | None] = []
        for p in pdus:
            c = spec(p, f)
            if c is None or c > 0:
                owners.append(p)
                counts.append(c)
        if not owners:
            continue
        if len(owners) == 1:
            p = owners[0]
            if key in LIST_KEYS:
                p[key] = [_convert(key, v) for v in raw]
            else:
                p[key] = _convert(key, raw[0])
            continue
        if any(c is None for c in counts) or sum(counts) != len(raw):
            diag.unattributed[key] += 1
            missed = True
            continue
        pos = 0
        for p, c in zip(owners, counts):
            chunk = raw[pos:pos + c]
            pos += c
            if key in LIST_KEYS:
                p[key] = [_convert(key, v) for v in chunk]
            elif chunk:
                p[key] = _convert(key, chunk[0])
    # A directory reply's entry names, unless another reply in the frame
    # may hold some: QUERY_INFO and CHANGE_NOTIFY replies carry names in
    # numbers the field output does not show.
    raw = vals.get("name")
    finds = [p for p in pdus if p["resp"] and p["cmd"] == QUERY_DIRECTORY
             and has_body(p)]
    if raw and finds:
        others = any(p["resp"] and p["cmd"] in (QUERY_INFO, CHANGE_NOTIFY)
                     and has_body(p) for p in pdus)
        if len(finds) == 1 and not others:
            _entries(finds[0], [unescape(v) for v in raw])
        else:
            diag.unattributed["entries"] += 1
            missed = True
    if missed:
        diag.frames_unattributed += 1
    for p in pdus:
        for lk in ("lvlfile", "lvlfs", "lvlsec"):
            if lk in p:
                p["lvl"] = p.pop(lk)
        if "rlen" in p:
            p["len"] = p.pop("rlen")
        if "wlen" in p:
            p["len"] = p.pop("wlen")
        if "off" in p and p["cmd"] != LOCK and isinstance(p["off"], list):
            p["off"] = p["off"][0]
        if p["cmd"] == NEGOTIATE:
            for key in ("dialect", "cipher"):
                if key in p:
                    if p["resp"]:
                        p[key] = p[key][0]
                    else:
                        p[key + "s"] = p.pop(key)
        user = p.pop("ntuser", None) or p.pop("acct", None)
        dom = p.pop("ntdomain", None) or p.pop("domain", None)
        p.pop("ntuser", None)
        p.pop("ntdomain", None)
        p.pop("acct", None)
        p.pop("domain", None)
        if user:
            p["user"] = f"{dom}\\{user}" if dom else user
        host = p.pop("nthost", None) or p.pop("host", None)
        p.pop("nthost", None)
        p.pop("host", None)
        if host:
            p["host"] = host
        if "krbsname" in p:
            p["krb"] = p.pop("krbsname") + (
                "@" + p.pop("krbrealm") if "krbrealm" in p else "")
        p.pop("krbrealm", None)
    return pdus


def _smb1_pdus(base: dict, f: _Frame, diag: Diagnostics) -> list[dict]:
    vals = f.vals
    mids = vals.get("mid1", [])
    n = len(mids)
    if n == 0:
        return []
    cmds = vals.get("cmd1", [])
    resp = vals.get("resp1", [])
    pids = vals.get("pid1", [])
    uids = vals.get("uid1", [])
    tids = vals.get("tid1", [])
    nterr = vals.get("nterr1", [])
    if not (len(resp) == len(pids) == len(uids) == len(tids) == n
            and len(cmds) >= n):
        diag.frames_broken += 1
        return []
    pdus = []
    for i in range(n):
        p = dict(base)
        p["k"] = "p"
        p["proto"] = "smb"
        p["n"] = n
        p["i"] = i
        p["resp"] = _bool(resp[i])
        p["mid"] = _int(mids[i])
        p["pid"] = _int(pids[i])
        p["sesid"] = _int(uids[i])
        p["tid"] = _int(tids[i])
        p["async"] = False
        p["related"] = False
        p["signed"] = False
        p["next"] = 0
        pdus.append(p)
    # Each PDU owns one command; the extra ones are AndX chain members,
    # given to the first PDU whose command can chain.
    extra = [_int(c) for c in cmds[n:]]
    if extra:
        diag.smb1_andx_guessed += 1
    for i, p in enumerate(pdus):
        p["cmd"] = _int(cmds[i])
        if extra and p["cmd"] in ANDX_COMMANDS:
            p["andx"] = extra
            extra = []
    statuses = vals.get("status1", [])
    if len(nterr) == n:
        _distribute(pdus, "status", statuses,
                    lambda p: p["resp"] and _bool(nterr[p["i"]]))
    elif len(statuses) == sum(1 for p in pdus if p["resp"]):
        _distribute(pdus, "status", statuses, lambda p: p["resp"])
    for p in pdus:
        if p["resp"] and "status" not in p:
            p["status"] = 0
    if n == 1:
        p = pdus[0]
        for key, out in (("file1", "name"), ("path1", "tree"),
                         ("fid1", "fid"), ("trans2", "sub"), ("ntfn", "sub")):
            raw = vals.get(key)
            if raw:
                p[out] = _convert(key, raw[0])
    return pdus


class Starts:
    """A request reassembled from several frames is seen in the last;
    its records get the first one's time as `thdr`, when the client
    began sending it."""

    def __init__(self) -> None:
        self.seen: dict[int, dict[int, int]] = {}  # stream: frame -> time

    def frame(self, base: dict, vals: dict[str, list[str]],
              out: list[dict]) -> None:
        if base["dport"] not in (445, 139) or not base["tlen"]:
            return
        seen = self.seen.setdefault(base["stream"], {})
        if any(r.get("k") == "p" for r in out):
            segs = vals.get("segs")
            t = seen.get(_int(segs[0])) if segs else None
            if t is not None:
                for r in _first_message(out):
                    r["thdr"] = t
            # Only this frame can hold the start of a PDU still to come.
            seen.clear()
        seen[base["frame"]] = base["t"]


class Ends:
    """PDUs cut short by the capture (a snapshot length, or smb-trim)
    are seen by tshark in the frame holding their start, not their last
    byte. Such a PDU is held back until the frame holding its last byte
    and given that frame's time, so its latency means what it means in
    a full capture: last byte to last byte."""

    def __init__(self) -> None:
        self.dirs: dict[tuple[int, str], list] = {}
        self.timed = 0
        self.unfinished = 0

    def frame(self, base: dict, vals: dict[str, list[str]],
              out: list[dict]) -> list[dict]:
        tlen = base["tlen"]
        seqv = vals.get("seq")
        if not tlen or not seqv:
            return out
        key = (base["stream"], base["src"])
        d = self.dirs.get(key)
        if d is None:
            # epoch, last raw seq, held records, their end, last time,
            # where the next PDU starts
            d = self.dirs[key] = [0, None, None, 0, 0, None]
        raw = _int(seqv[0])
        if d[1] is not None and raw < d[1] and d[1] - raw > 1 << 31:
            d[0] += 1 << 32
        d[1] = raw
        seq = raw + d[0]
        done: list[dict] = []
        if d[2] is not None and seq + tlen >= d[3]:
            if seq < d[3]:
                self._release(d, done, base["t"], base["frame"])
                self.timed += 1
            else:
                # The frame holding the end was not among those read.
                self._release(d, done, d[4], None)
                self.unfinished += 1
        for r in out:
            if r.get("k") == "p" and r["resp"]:
                od = self.dirs.get((base["stream"], r["dst"]))
                if od is not None and od[2] is not None and any(
                        not q["resp"] and q["mid"] == r["mid"] for q in od[2]):
                    # The response arrived first: the end was not captured.
                    self._release(od, done, od[4], None)
                    self.unfinished += 1
        d[4] = base["t"]
        caplen = vals.get("caplen")
        lens = vals.get("nbsslen", [])
        types = vals.get("nbsstype", [])
        if not (caplen and lens and len(lens) == len(types)
                and _int(caplen[0]) < base["flen"]):
            return done + out
        o0 = 0
        if d[5] is not None and seq < d[5] < seq + tlen:
            o0 = d[5] - seq
        end = seq + o0 + sum(4 + _int(n) for n in lens)
        if end <= seq + tlen or _int(types[-1]) != 0:
            return done + out
        d[5] = end
        held = _last_message(out, sum(1 for t in types if _int(t) == 0))
        if held:
            ids = {id(r) for r in held}
            out = [r for r in out if id(r) not in ids]
            d[2], d[3] = held, end
        return done + out

    def _release(self, d: list, done: list[dict], t: int,
                 frame: int | None) -> None:
        for r in d[2]:
            if t > r["t"]:
                r.setdefault("thdr", r["t"])
                r["t"] = t
            if frame is not None:
                r["endframe"] = frame
        done.extend(d[2])
        d[2] = None

    def flush(self) -> Iterator[dict]:
        """PDUs whose last byte the capture ended before: timed at the
        last frame seen of their direction."""
        for d in self.dirs.values():
            if d[2] is not None:
                done: list[dict] = []
                self._release(d, done, d[4], None)
                self.unfinished += 1
                yield from done


def _last_message(out: list[dict], messages: int) -> list[dict]:
    """The PDU records of a frame's last NBSS message, if the frame's
    session messages can be matched to its PDUs."""
    pdus = [r for r in out if r.get("k") == "p"]
    if not pdus or any(r.get("k") == "e" for r in out):
        return []
    if all(r["proto"] == "smb" for r in pdus):
        return pdus[-1:] if len(pdus) == messages else []
    if any(r["proto"] != "smb2" for r in pdus):
        return []
    groups: list[list[dict]] = []
    for r in pdus:
        if not groups or not groups[-1][-1].get("next"):
            groups.append([])
        groups[-1].append(r)
    return groups[-1] if len(groups) == messages else []


def _first_message(out: list[dict]) -> list[dict]:
    """The PDU records of a frame's first NBSS message: one SMB1 PDU, or
    an SMB2 PDU and the compound members after it."""
    first = []
    for r in out:
        if r.get("k") != "p":
            continue
        first.append(r)
        if r["proto"] != "smb2" or not r.get("next"):
            break
    return first


def parse_line(line: str, diag: Diagnostics,
               keys: list[str] = KEYS, ends: Ends | None = None,
               starts: Starts | None = None) -> list[dict]:
    cols = line.rstrip("\n").split("\t")
    if len(cols) != len(keys):
        diag.frames_broken += 1
        return []
    vals = {k: (c.split(AGGREGATOR) if c else []) for k, c in zip(keys, cols)}
    base = _frame_base(vals)
    if base is None:
        diag.frames_broken += 1
        return []
    out: list[dict] = []
    f = _Frame(vals)
    out.extend(_smb2_pdus(base, f, diag))
    out.extend(_smb1_pdus(base, f, diag))
    enc = vals.get("enc")
    if enc:
        rec = dict(base)
        rec["k"] = "e"
        rec["n"] = sum(1 for v in enc if _bool(v))
        out.append(rec)
    tcp = _tcp_record(base, vals, diag)
    if tcp is not None:
        out.append(tcp)
    if starts is not None:
        starts.frame(base, vals, out)
    if ends is not None:
        out = ends.frame(base, vals, out)
    return out


def tshark_command(
    pcap: str, tshark: str = "tshark", extra_filter: str | None = None,
    prefs: list[str] = (), skip: set[str] = frozenset(),
) -> tuple[list[str], list[str]]:
    """The tshark command line and the record key of each column."""
    filt = DISPLAY_FILTER
    if extra_filter:
        filt = f"({filt}) && ({extra_filter})"
    cmd = [tshark, "-r", pcap, "-n", "-Y", filt, "-T", "fields",
           "-E", "separator=/t", "-E", f"aggregator={AGGREGATOR}",
           "-E", "occurrence=a", "-E", "header=n"]
    for pref in prefs:
        cmd += ["-o", pref]
    keys = []
    for field, key in ALL_FIELDS:
        if field in skip:
            continue
        cmd += ["-e", field]
        keys.append(key)
    return cmd, keys


def invalid_fields(stderr: str) -> set[str]:
    """Field names tshark rejected, from its error output."""
    if "aren't valid" not in stderr:
        return set()
    names = set()
    for line in stderr.splitlines():
        if line.startswith(("\t", " ")):
            names.add(line.strip())
    return names


class ExtractError(Exception):
    pass


def tshark_version(tshark: str = "tshark") -> str:
    try:
        out = subprocess.run([tshark, "--version"], capture_output=True,
                             text=True).stdout
    except OSError as e:
        raise ExtractError(f"cannot run {tshark}: {e}") from None
    return out.splitlines()[0] if out else "?"


def extract(
    pcap: str, tshark: str = "tshark", extra_filter: str | None = None,
    prefs: list[str] = (), progress: Callable[[int], None] | None = None,
) -> Iterator[dict]:
    """Yield the header record, then one record per PDU, TCP event and
    encrypted frame, then the diagnostics record."""
    if shutil.which(tshark) is None:
        raise ExtractError(f"{tshark} not found")
    st = os.stat(pcap)
    yield {
        "k": "h", "v": FORMAT_VERSION, "tshark": tshark_version(tshark),
        "pcap": os.path.basename(pcap), "size": st.st_size,
        "mtime": int(st.st_mtime), "filter": extra_filter or "",
    }
    skip: set[str] = set()
    for attempt in range(2):
        cmd, keys = tshark_command(pcap, tshark, extra_filter, prefs, skip)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        diag = Diagnostics()
        ends = Ends()
        starts = Starts()
        assert proc.stdout is not None
        count = 0
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace")
            for rec in parse_line(line, diag, keys, ends, starts):
                yield rec
            count += 1
            if progress and count % 20000 == 0:
                progress(count)
        err = proc.stderr.read().decode("utf-8", errors="replace") \
            if proc.stderr else ""
        rc = proc.wait()
        if rc == 0:
            break
        bad = invalid_fields(err) - skip
        if attempt == 0 and bad and count == 0:
            # This tshark lacks some fields; go without them.
            skip |= bad
            continue
        err = "\n".join(
            l for l in err.splitlines() if "Running as user" not in l)
        raise ExtractError(f"tshark exited with {rc}: {err.strip()}")
    if skip:
        diag_skip = sorted(skip)
    else:
        diag_skip = []
    yield from ends.flush()
    yield from diag.ack_records()
    yield {"k": "d", "fields_unknown": diag_skip, "cut_timed": ends.timed,
           "cut_unfinished": ends.unfinished, **diag.as_dict()}


def write_records(records: Iterator[dict], path: str) -> int:
    """Write records as gzip JSON lines; returns the count written."""
    tmp = path + ".tmp"
    n = 0
    with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=5) as f:
        for rec in records:
            f.write(json.dumps(rec, separators=(",", ":"),
                               ensure_ascii=False))
            f.write("\n")
            n += 1
    os.replace(tmp, path)
    return n


def read_records(path: str) -> Iterator[dict]:
    opener = gzip.open if _is_gzip(path) else open
    with opener(path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def _is_gzip(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(2) == b"\x1f\x8b"


PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1", b"\x0a\x0d\x0d\x0a",
}


def is_capture(path: str) -> bool:
    """pcap or pcapng, gzipped or not (tshark reads both)."""
    opener = gzip.open if _is_gzip(path) else open
    try:
        with opener(path, "rb") as f:
            head = f.read(4)
    except (OSError, EOFError):
        return False
    return head in PCAP_MAGICS


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        description="Extract SMB PDU records from a capture (gzip JSON "
                    "lines, which the other tools read directly).")
    ap.add_argument("pcap")
    ap.add_argument("-o", "--output",
                    help="output path (default: <pcap>.smbx)")
    ap.add_argument("--tshark", default="tshark")
    ap.add_argument("--filter", help="extra tshark display filter, e.g. "
                    "'ip.addr == 10.0.0.5'")
    ap.add_argument("--pref", action="append", default=[],
                    help="tshark -o preference, e.g. "
                    "'tcp.desegment_tcp_streams:TRUE'; repeatable")
    args = ap.parse_args(argv)
    out = args.output or args.pcap + ".smbx"

    def progress(n: int) -> None:
        print(f"  {n} frames...", file=sys.stderr)

    try:
        n = write_records(
            extract(args.pcap, args.tshark, args.filter, args.pref, progress),
            out)
    except ExtractError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"{out}: {n - 2} records", file=sys.stderr)
    return 0
