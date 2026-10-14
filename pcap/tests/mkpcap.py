#!/usr/bin/env python3
"""Build a synthetic SMB2 capture with known contents.

The capture exercises what the extractor has to get right: compounded
requests, two PDUs in one segment, multi-segment READ and WRITE bodies,
async interim responses and a cancel, an oplock break, error bodies,
an unanswered request, SMB1-to-SMB2 negotiation, odd filenames, a TCP
retransmission and a reset. `build()` returns the expectations the
tests check against.

Run directly to write the capture somewhere:

    python3 mkpcap.py out.pcap
"""

from __future__ import annotations

import struct
import sys
import uuid

# --- pcap ---------------------------------------------------------------

LINKTYPE_ETHERNET = 1
PCAP_MAGIC_NS = 0xA1B23C4D


class Pcap:
    def __init__(self) -> None:
        self.frames: list[tuple[int, bytes, int]] = []  # ts, data, wire

    def add(self, ts_ns: int, data: bytes) -> int:
        self.frames.append((ts_ns, data, len(data)))
        return len(self.frames)

    def truncate(self, frame: int, caplen: int) -> None:
        """Keep a frame's first bytes, as a snapshot length does."""
        ts, data, wire = self.frames[frame - 1]
        self.frames[frame - 1] = (ts, data[:caplen], wire)

    def write(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(
                struct.pack(
                    "<IHHiIII", PCAP_MAGIC_NS, 2, 4, 0, 0, 262144,
                    LINKTYPE_ETHERNET,
                )
            )
            for ts, data, wire in self.frames:
                f.write(
                    struct.pack(
                        "<IIII", ts // 1_000_000_000, ts % 1_000_000_000,
                        len(data), wire,
                    )
                )
                f.write(data)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _ip(addr: str) -> bytes:
    return bytes(int(x) for x in addr.split("."))


def ethernet_ipv4_tcp(
    src_mac: bytes, dst_mac: bytes, src_ip: str, dst_ip: str,
    sport: int, dport: int, seq: int, ack: int, flags: int,
    payload: bytes, window: int = 65535,
) -> bytes:
    tcp_hdr = struct.pack(
        "!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        5 << 4, flags, window, 0, 0,
    )
    total = 20 + len(tcp_hdr) + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0, _ip(src_ip),
        _ip(dst_ip),
    )
    ip_hdr = ip_hdr[:10] + struct.pack("!H", _checksum(ip_hdr)) + ip_hdr[12:]
    return dst_mac + src_mac + b"\x08\x00" + ip_hdr + tcp_hdr + payload


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


class Conn:
    """One TCP connection; `send` emits segments with consistent numbers."""

    def __init__(
        self, pcap: Pcap, client_ip: str, server_ip: str, client_port: int,
        server_port: int = 445, mss: int = 1460,
    ) -> None:
        self.pcap = pcap
        self.c = (client_ip, client_port, b"\x02\x00\x00\x00\x00\x02")
        self.s = (server_ip, server_port, b"\x02\x00\x00\x00\x00\x01")
        self.mss = mss
        self.seq = {True: 1000, False: 5000}  # next seq, by from_client
        self.last: dict[bool, tuple[int, bytes]] = {}

    def _frame(self, from_client: bool, flags: int, payload: bytes,
               ts: int, seq: int | None = None) -> int:
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        if seq is None:
            seq = self.seq[from_client]
        data = ethernet_ipv4_tcp(
            src[2], dst[2], src[0], dst[0], src[1], dst[1], seq,
            self.seq[not from_client], flags, payload,
        )
        return self.pcap.add(ts, data)

    def handshake(self, t_syn: int, t_synack: int, t_ack: int) -> None:
        self.seq[False] = 0
        self._frame(True, SYN, b"", t_syn)
        self.seq[True] += 1
        self.seq[False] = 5000
        self._frame(False, SYN | ACK, b"", t_synack)
        self.seq[False] += 1
        self._frame(True, ACK, b"", t_ack)

    def send(self, from_client: bool, payload: bytes, ts: int) -> list[int]:
        """Send `payload` as one or more segments; returns frame numbers."""
        frames = []
        off = 0
        while off < len(payload) or (off == 0 and not payload):
            chunk = payload[off:off + self.mss]
            last = off + len(chunk) >= len(payload)
            flags = ACK | (PSH if last else 0)
            frames.append(self._frame(from_client, flags, chunk, ts))
            self.last[from_client] = (self.seq[from_client], chunk)
            self.seq[from_client] += len(chunk)
            off += len(chunk)
            ts += 1_000  # 1 µs between segments of one send
            if not payload:
                break
        return frames

    def retransmit_last(self, from_client: bool, ts: int) -> int:
        seq, chunk = self.last[from_client]
        return self._frame(from_client, ACK | PSH, chunk, ts, seq=seq)

    def reset(self, from_client: bool, ts: int) -> int:
        return self._frame(from_client, RST | ACK, b"", ts)

    def fin(self, from_client: bool, ts: int) -> int:
        n = self._frame(from_client, FIN | ACK, b"", ts)
        self.seq[from_client] += 1
        return n


# --- SMB2 ---------------------------------------------------------------

NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT, TREE_DISCONNECT = 0, 1, 2, 3, 4
CREATE, CLOSE, FLUSH, READ, WRITE, LOCK, IOCTL, CANCEL, ECHO = (
    5, 6, 7, 8, 9, 10, 11, 12, 13,
)
QUERY_DIRECTORY, CHANGE_NOTIFY, QUERY_INFO, SET_INFO, OPLOCK_BREAK = (
    14, 15, 16, 17, 18,
)

F_RESPONSE, F_ASYNC, F_RELATED, F_SIGNED = 0x1, 0x2, 0x4, 0x8

STATUS_SUCCESS = 0
STATUS_PENDING = 0x103
STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_FILE_CLOSED = 0xC0000128
STATUS_END_OF_FILE = 0xC0000011
STATUS_NO_MORE_FILES = 0x80000006
STATUS_CANCELLED = 0xC0000120
STATUS_LOCK_NOT_GRANTED = 0xC0000055
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_NOT_SUPPORTED = 0xC00000BB

FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204
FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC

ALL_ONES_FID = b"\xff" * 16


def u16(s: str) -> bytes:
    return s.encode("utf-16-le")


def header(
    cmd: int, msg_id: int, *, resp: bool = False, status: int = 0,
    sesid: int = 0, tid: int = 0, flags: int = 0, aid: int | None = None,
    charge: int = 1, credits: int = 1,
) -> bytes:
    if resp:
        flags |= F_RESPONSE
    if aid is not None:
        flags |= F_ASYNC
    if resp:
        mid = struct.pack("<I", status)
    else:
        mid = struct.pack("<HH", 0, 0)
    if aid is not None:
        tree = struct.pack("<Q", aid)
    else:
        tree = struct.pack("<II", 0, tid)
    return (
        b"\xfeSMB" + struct.pack("<HH", 64, charge) + mid
        + struct.pack("<HHII", cmd, credits, flags, 0)
        + struct.pack("<Q", msg_id & 0xFFFFFFFFFFFFFFFF) + tree
        + struct.pack("<Q", sesid) + b"\0" * 16
    )


def error_body(data: bytes = b"") -> bytes:
    return struct.pack("<HBBI", 9, 0, 0, len(data)) + (data or b"\0")


def negotiate_req(dialects: list[int]) -> bytes:
    return (
        struct.pack("<HHHHI", 36, len(dialects), 1, 0, 0x7F)
        + uuid.UUID(int=1).bytes_le + struct.pack("<Q", 0)
        + b"".join(struct.pack("<H", d) for d in dialects)
    )


def negotiate_resp(dialect: int) -> bytes:
    return (
        struct.pack("<HHHH", 65, 1, dialect, 0) + uuid.UUID(int=2).bytes_le
        + struct.pack("<IIII", 0x7F, 1 << 20, 1 << 20, 1 << 20)
        + struct.pack("<QQ", 0, 0) + struct.pack("<HHI", 128, 0, 0)
    )


def ntlmssp_negotiate() -> bytes:
    return b"NTLMSSP\0" + struct.pack("<I", 1) + struct.pack(
        "<I", 0xE2088297,
    ) + b"\0" * 16


def ntlmssp_auth(user: str, domain: str, host: str) -> bytes:
    fields = [b"", b"", u16(domain), u16(user), u16(host), b""]
    base = 8 + 4 + 8 * 6 + 4 + 8 + 16
    body = b""
    hdr = b""
    off = base
    for blob in fields:
        hdr += struct.pack("<HHI", len(blob), len(blob), off)
        body += blob
        off += len(blob)
    return (
        b"NTLMSSP\0" + struct.pack("<I", 3) + hdr
        + struct.pack("<I", 0xE2088215) + b"\0" * 8 + b"\0" * 16 + body
    )


def ntlmssp_challenge() -> bytes:
    return (
        b"NTLMSSP\0" + struct.pack("<I", 2) + struct.pack("<HHI", 0, 0, 56)
        + struct.pack("<I", 0xE2898215) + b"\x01" * 8 + b"\0" * 8
        + struct.pack("<HHI", 0, 0, 56) + b"\0" * 8
    )


def session_setup_req(blob: bytes) -> bytes:
    return struct.pack("<HBBIIHHQ", 25, 0, 1, 1, 0, 88, len(blob), 0) + blob


def session_setup_resp(blob: bytes, flags: int = 0) -> bytes:
    return struct.pack("<HHHH", 9, flags, 72, len(blob)) + blob


def tree_connect_req(path: str) -> bytes:
    p = u16(path)
    return struct.pack("<HHHH", 9, 0, 72, len(p)) + p


def tree_connect_resp(share_type: int) -> bytes:
    return struct.pack("<HBBIII", 16, share_type, 0, 0, 0, 0x1F01FF)


def create_context(tag: bytes, data: bytes) -> bytes:
    name_off = 16
    data_off = 16 + ((len(tag) + 7) & ~7) if data else 0
    body = struct.pack(
        "<IHHHHI", 0, name_off, len(tag), 0, data_off, len(data),
    ) + tag.ljust((len(tag) + 7) & ~7, b"\0") + data
    return body.ljust((len(body) + 7) & ~7, b"\0")


def create_req(
    name: str, disposition: int = 1, options: int = 0x40,
    access: int = 0x120089, oplock: int = 0, contexts: list[bytes] = (),
) -> bytes:
    n = u16(name)
    ctx = b""
    for i, c in enumerate(contexts):
        if i < len(contexts) - 1:
            c = struct.pack("<I", len(c)) + c[4:]
        ctx += c
    name_off = 64 + 56
    ctx_off = 0
    buf = n
    if ctx:
        pad = (-(name_off + len(n))) % 8
        buf = n + b"\0" * pad
        ctx_off = name_off + len(buf)
    return struct.pack(
        "<HBBIQQIIIIIHHII", 57, 0, oplock, 2, 0, 0, access, 0x80, 7,
        disposition, options, name_off, len(n), ctx_off, len(ctx),
    ) + (buf + ctx if (buf or ctx) else b"\0")


def create_resp(fid: bytes, action: int = 1, oplock: int = 0,
                attrs: int = 0x20) -> bytes:
    return (
        struct.pack("<HBBI", 89, oplock, 0, action)
        + struct.pack("<QQQQQQ", 0, 0, 0, 0, 0, 0)
        + struct.pack("<II", attrs, 0) + fid + struct.pack("<II", 0, 0)
    )


def close_req(fid: bytes) -> bytes:
    return struct.pack("<HHI", 24, 0, 0) + fid


def close_resp() -> bytes:
    return struct.pack("<HHI", 60, 0, 0) + b"\0" * 48 + struct.pack("<I", 0x20)


def flush_req(fid: bytes) -> bytes:
    return struct.pack("<HHI", 24, 0, 0) + fid


def read_req(fid: bytes, offset: int, length: int) -> bytes:
    return struct.pack(
        "<HBBIQ", 49, 0x50, 0, length, offset,
    ) + fid + struct.pack("<IIIHH", 0, 0, 0, 0, 0) + b"\0"


def read_resp(data: bytes) -> bytes:
    return struct.pack("<HBBIII", 17, 80, 0, len(data), 0, 0) + data


def write_req(fid: bytes, offset: int, data: bytes) -> bytes:
    return struct.pack(
        "<HHIQ", 49, 112, len(data), offset,
    ) + fid + struct.pack("<IIHHI", 0, 0, 0, 0, 0) + data


def write_resp(count: int) -> bytes:
    return struct.pack("<HHIIHH", 17, 0, count, 0, 0, 0)


def lock_req(fid: bytes, locks: list[tuple[int, int, int]]) -> bytes:
    body = struct.pack("<HHI", 48, len(locks), 0) + fid
    for off, length, flags in locks:
        body += struct.pack("<QQII", off, length, flags, 0)
    return body


def small_resp(size: int) -> bytes:
    return struct.pack("<HH", size, 0)


def ioctl_req(fid: bytes, code: int, data: bytes = b"") -> bytes:
    return struct.pack(
        "<HHI", 57, 0, code,
    ) + fid + struct.pack(
        "<IIIIIIII", 120 if data else 0, len(data), 0, 0, 0, 1024, 1, 0,
    ) + (data or b"\0")


def ioctl_resp(fid: bytes, code: int, data: bytes = b"") -> bytes:
    return struct.pack(
        "<HHI", 49, 0, code,
    ) + fid + struct.pack(
        "<IIIIII", 0, 0, 112 if data else 0, len(data), 0, 0,
    ) + (data or b"\0")


def find_req(fid: bytes, pattern: str, info_class: int = 1,
             flags: int = 0) -> bytes:
    p = u16(pattern)
    return struct.pack(
        "<HBBI", 33, info_class, flags, 0,
    ) + fid + struct.pack("<HHI", 96, len(p), 65536) + p


def dir_entries(names: list[str]) -> bytes:
    out = b""
    for i, name in enumerate(names):
        n = u16(name)
        entry = struct.pack(
            "<IIQQQQQQII", 0, 0, 0, 0, 0, 0, 10, 4096, 0x20, len(n),
        ) + n
        if i < len(names) - 1:
            entry = entry.ljust((len(entry) + 7) & ~7, b"\0")
            entry = struct.pack("<I", len(entry)) + entry[4:]
        out += entry
    return out


def buffer_resp(data: bytes) -> bytes:
    return struct.pack("<HHI", 9, 72, len(data)) + (data or b"\0")


def notify_req(fid: bytes, watch_tree: bool, filter_: int = 0xFFF) -> bytes:
    return struct.pack(
        "<HHI", 32, 1 if watch_tree else 0, 65536,
    ) + fid + struct.pack("<II", filter_, 0)


def query_info_req(fid: bytes, info_type: int, level: int) -> bytes:
    return struct.pack(
        "<HBBIHHIII", 41, info_type, level, 65536, 0, 0, 0, 0, 0,
    ) + fid + b"\0"


def set_info_req(fid: bytes, info_type: int, level: int,
                 data: bytes) -> bytes:
    return struct.pack(
        "<HBBIHHI", 33, info_type, level, len(data), 96, 0, 0,
    ) + fid + data


def rename_info(new_name: str) -> bytes:
    n = u16(new_name)
    return struct.pack("<B7sQI", 0, b"", 0, len(n)) + n


def oplock_break(fid: bytes, level: int) -> bytes:
    return struct.pack("<HBBI", 24, level, 0, 0) + fid


def nbss(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def compound(pdus: list[bytes]) -> bytes:
    """Chain PDUs: pad each but the last to 8 and set NextCommand."""
    out = b""
    for i, pdu in enumerate(pdus):
        if i < len(pdus) - 1:
            padded = pdu.ljust((len(pdu) + 7) & ~7, b"\0")
            pdu = padded[:20] + struct.pack("<I", len(padded)) + padded[24:]
        out += pdu
    return out


def smb1_negotiate(dialects: list[str]) -> bytes:
    buf = b"".join(b"\x02" + d.encode() + b"\0" for d in dialects)
    hdr = b"\xffSMB" + struct.pack(
        "<BIBHH8sHHHHH", 0x72, 0, 0x18, 0xC853, 0, b"", 0, 0, 0xFEFF, 0, 0,
    )
    return hdr + struct.pack("<BH", 0, len(buf)) + buf


# --- the scenario --------------------------------------------------------

MS = 1_000_000
US = 1_000

CLIENT1, CLIENT2, SERVER = "10.0.0.2", "10.0.0.3", "10.0.0.1"
WEIRD_NAME = "dir\\weïrd\tname,\"q\" 日本"


def build(path: str) -> dict:
    pcap = Pcap()
    exp: dict = {"latency_ms": {}, "frames": {}}
    t = 1_700_000_000 * 1_000_000_000  # epoch ns

    def at(ms: float) -> int:
        return t + int(ms * MS)

    c1 = Conn(pcap, CLIENT1, SERVER, 50000)
    c1.handshake(at(0), at(0.020), at(0.320))
    sesid, tid_share, tid_ipc = 0x11, 1, 2
    fid_a = uuid.UUID(int=0xA).bytes_le
    fid_b = uuid.UUID(int=0xB).bytes_le
    fid_d = uuid.UUID(int=0xD).bytes_le

    def xchg(conn: Conn, req: bytes, resp: bytes | None, t_req: float,
             latency_ms: float, label: str | None = None) -> None:
        fr = conn.send(True, nbss(req), at(t_req))
        if label:
            # tshark places a multi-segment PDU in the frame that
            # completes it.
            exp["frames"][label] = fr[-1]
        if resp is not None:
            conn.send(False, nbss(resp), at(t_req + latency_ms))
            if label:
                exp["latency_ms"][label] = latency_ms

    # SMB1 negotiate answered by an SMB2 wildcard response, then SMB2.
    xchg(c1, smb1_negotiate(["NT LM 0.12", "SMB 2.002", "SMB 2.???"]),
         header(NEGOTIATE, 0, resp=True) + negotiate_resp(0x2FF), 1.0, 0.2,
         "neg1")
    xchg(c1, header(NEGOTIATE, 1) + negotiate_req([0x202, 0x210, 0x300, 0x302]),
         header(NEGOTIATE, 1, resp=True) + negotiate_resp(0x302), 2.0, 0.3,
         "neg2")
    xchg(c1, header(SESSION_SETUP, 2) + session_setup_req(ntlmssp_negotiate()),
         header(SESSION_SETUP, 2, resp=True,
                status=STATUS_MORE_PROCESSING_REQUIRED, sesid=sesid)
         + session_setup_resp(ntlmssp_challenge()), 3.0, 0.5, "ss1")
    xchg(c1, header(SESSION_SETUP, 3, sesid=sesid)
         + session_setup_req(ntlmssp_auth("alice", "LAB", "PC1")),
         header(SESSION_SETUP, 3, resp=True, sesid=sesid)
         + session_setup_resp(b""), 4.0, 2.0, "ss2")
    xchg(c1, header(TREE_CONNECT, 4, sesid=sesid)
         + tree_connect_req("\\\\srv\\share"),
         header(TREE_CONNECT, 4, resp=True, sesid=sesid, tid=tid_share)
         + tree_connect_resp(1), 7.0, 0.4, "tc1")
    xchg(c1, header(TREE_CONNECT, 5, sesid=sesid)
         + tree_connect_req("\\\\srv\\IPC$"),
         header(TREE_CONNECT, 5, resp=True, sesid=sesid, tid=tid_ipc)
         + tree_connect_resp(2), 8.0, 0.2, "tc2")
    xchg(c1, header(IOCTL, 6, sesid=sesid, tid=tid_share)
         + ioctl_req(ALL_ONES_FID, FSCTL_VALIDATE_NEGOTIATE_INFO, b"\0" * 24),
         header(IOCTL, 6, resp=True, status=STATUS_NOT_SUPPORTED, sesid=sesid,
                tid=tid_share) + error_body(), 9.0, 0.1, "ioctl1")
    xchg(c1, header(CREATE, 7, sesid=sesid, tid=tid_share)
         + create_req("dir\\file.txt", disposition=3,
                      contexts=[create_context(b"MxAc", b""),
                                create_context(b"DHnQ", b"\0" * 16)]),
         header(CREATE, 7, resp=True, sesid=sesid, tid=tid_share)
         + create_resp(fid_a, action=2), 10.0, 1.5, "create_a")

    # A compound that succeeds and one whose CREATE fails.
    req = compound([
        header(CREATE, 8, sesid=sesid, tid=tid_share)
        + create_req("dir\\other.txt", disposition=1),
        header(QUERY_INFO, 9, sesid=sesid, tid=tid_share, flags=F_RELATED)
        + query_info_req(ALL_ONES_FID, 1, 18),
        header(CLOSE, 10, sesid=sesid, tid=tid_share, flags=F_RELATED)
        + close_req(ALL_ONES_FID),
    ])
    resp = compound([
        header(CREATE, 8, resp=True, sesid=sesid, tid=tid_share)
        + create_resp(fid_b),
        header(QUERY_INFO, 9, resp=True, sesid=sesid, tid=tid_share,
               flags=F_RELATED) + buffer_resp(b"\0" * 104),
        header(CLOSE, 10, resp=True, sesid=sesid, tid=tid_share,
               flags=F_RELATED) + close_resp(),
    ])
    xchg(c1, req, resp, 12.0, 2.0, "compound_ok")
    req = compound([
        header(CREATE, 11, sesid=sesid, tid=tid_share)
        + create_req("missing.txt", disposition=1),
        header(QUERY_INFO, 12, sesid=sesid, tid=tid_share, flags=F_RELATED)
        + query_info_req(ALL_ONES_FID, 1, 18),
        header(CLOSE, 13, sesid=sesid, tid=tid_share, flags=F_RELATED)
        + close_req(ALL_ONES_FID),
    ])
    resp = compound([
        header(CREATE, 11, resp=True, status=STATUS_OBJECT_NAME_NOT_FOUND,
               sesid=sesid, tid=tid_share) + error_body(),
        header(QUERY_INFO, 12, resp=True, status=STATUS_FILE_CLOSED,
               sesid=sesid, tid=tid_share, flags=F_RELATED) + error_body(),
        header(CLOSE, 13, resp=True, status=STATUS_FILE_CLOSED, sesid=sesid,
               tid=tid_share, flags=F_RELATED) + error_body(),
    ])
    xchg(c1, req, resp, 15.0, 0.3, "compound_fail")

    data = bytes(range(256)) * 256  # 64 KiB
    xchg(c1, header(WRITE, 14, sesid=sesid, tid=tid_share, charge=16)
         + write_req(fid_a, 0, data),
         header(WRITE, 14, resp=True, sesid=sesid, tid=tid_share, charge=16)
         + write_resp(len(data)), 20.0, 5.0, "write")
    xchg(c1, header(READ, 15, sesid=sesid, tid=tid_share, charge=16)
         + read_req(fid_a, 0, len(data)),
         header(READ, 15, resp=True, sesid=sesid, tid=tid_share, charge=16)
         + read_resp(data), 30.0, 3.0, "read")
    xchg(c1, header(READ, 16, sesid=sesid, tid=tid_share)
         + read_req(fid_a, len(data), 4096),
         header(READ, 16, resp=True, status=STATUS_END_OF_FILE, sesid=sesid,
                tid=tid_share) + error_body(), 35.0, 0.2, "read_eof")

    # Two independent PDUs in one segment, answered the same way.
    two = (nbss(header(READ, 17, sesid=sesid, tid=tid_share)
                + read_req(fid_a, 0, 4096))
           + nbss(header(READ, 18, sesid=sesid, tid=tid_share)
                  + read_req(fid_a, 4096, 4096)))
    exp["frames"]["pipelined"] = c1.send(True, two, at(36.0))[0]
    two = (nbss(header(READ, 17, resp=True, sesid=sesid, tid=tid_share)
                + read_resp(data[:4096]))
           + nbss(header(READ, 18, resp=True, sesid=sesid, tid=tid_share)
                  + read_resp(data[4096:8192])))
    c1.send(False, two, at(36.4))
    exp["latency_ms"]["pipelined"] = 0.4

    xchg(c1, header(CREATE, 19, sesid=sesid, tid=tid_share)
         + create_req("dir", disposition=1, options=0x21, access=0x100081),
         header(CREATE, 19, resp=True, sesid=sesid, tid=tid_share)
         + create_resp(fid_d, attrs=0x10), 40.0, 0.5, "create_dir")
    xchg(c1, header(QUERY_DIRECTORY, 20, sesid=sesid, tid=tid_share)
         + find_req(fid_d, "*"),
         header(QUERY_DIRECTORY, 20, resp=True, sesid=sesid, tid=tid_share)
         + buffer_resp(dir_entries(["a.txt", "b.txt"])), 41.0, 0.8, "find1")
    xchg(c1, header(QUERY_DIRECTORY, 21, sesid=sesid, tid=tid_share)
         + find_req(fid_d, "*"),
         header(QUERY_DIRECTORY, 21, resp=True, status=STATUS_NO_MORE_FILES,
                sesid=sesid, tid=tid_share) + error_body(), 42.0, 0.1,
         "find2")

    # Change notify: interim pending, then cancelled by the client.
    xchg(c1, header(CHANGE_NOTIFY, 22, sesid=sesid, tid=tid_share)
         + notify_req(fid_d, True),
         header(CHANGE_NOTIFY, 22, resp=True, status=STATUS_PENDING,
                sesid=sesid, aid=0x99) + error_body(), 43.0, 0.1, "notify")
    c1.send(True, nbss(header(CANCEL, 22, sesid=sesid, aid=0x99)
                       + small_resp(4)), at(543.0))
    c1.send(False, nbss(header(CHANGE_NOTIFY, 22, resp=True,
                               status=STATUS_CANCELLED, sesid=sesid, aid=0x99)
                        + error_body()), at(543.05))
    exp["latency_ms"]["notify"] = 500.05

    xchg(c1, header(SET_INFO, 23, sesid=sesid, tid=tid_share)
         + set_info_req(fid_a, 1, 10, rename_info("dir\\renamed.txt")),
         header(SET_INFO, 23, resp=True, sesid=sesid, tid=tid_share)
         + small_resp(2), 550.0, 1.0, "rename")
    xchg(c1, header(SET_INFO, 24, sesid=sesid, tid=tid_share)
         + set_info_req(fid_a, 1, 13, b"\x01"),
         header(SET_INFO, 24, resp=True, sesid=sesid, tid=tid_share)
         + small_resp(2), 552.0, 0.3, "delete")
    xchg(c1, header(LOCK, 25, sesid=sesid, tid=tid_share)
         + lock_req(fid_a, [(0, 100, 0x12), (100, 100, 0x12)]),
         header(LOCK, 25, resp=True, sesid=sesid, tid=tid_share)
         + small_resp(4), 553.0, 0.2, "lock1")
    xchg(c1, header(LOCK, 26, sesid=sesid, tid=tid_share)
         + lock_req(fid_a, [(0, 100, 0x12)]),
         header(LOCK, 26, resp=True, status=STATUS_LOCK_NOT_GRANTED,
                sesid=sesid, tid=tid_share) + error_body(), 554.0, 0.1,
         "lock2")

    # Oplock break notification and its acknowledgement.
    c1.send(False, nbss(header(OPLOCK_BREAK, -1, resp=True)
                        + oplock_break(fid_a, 1)), at(560.0))
    xchg(c1, header(OPLOCK_BREAK, 27, sesid=sesid, tid=tid_share)
         + oplock_break(fid_a, 1),
         header(OPLOCK_BREAK, 27, resp=True, sesid=sesid, tid=tid_share)
         + oplock_break(fid_a, 1), 561.0, 0.2, "break_ack")
    xchg(c1, header(ECHO, 28, sesid=sesid) + small_resp(4),
         header(ECHO, 28, resp=True, sesid=sesid) + small_resp(4), 562.0,
         0.05, "echo")
    xchg(c1, header(CREATE, 29, sesid=sesid, tid=tid_share)
         + create_req(WEIRD_NAME, disposition=1),
         header(CREATE, 29, resp=True, status=STATUS_OBJECT_NAME_NOT_FOUND,
                sesid=sesid, tid=tid_share) + error_body(), 563.0, 0.2,
         "weird")
    xchg(c1, header(CLOSE, 30, sesid=sesid, tid=tid_share) + close_req(fid_d),
         header(CLOSE, 30, resp=True, sesid=sesid, tid=tid_share)
         + close_resp(), 564.0, 0.1, "close_d")
    # Unanswered, and retransmitted while waiting.
    xchg(c1, header(FLUSH, 31, sesid=sesid, tid=tid_share) + flush_req(fid_a),
         None, 565.0, 0, "flush")
    c1.retransmit_last(True, at(765.0))

    # A second client whose CREATE is refused, then reset by the server.
    c2 = Conn(pcap, CLIENT2, SERVER, 50001)
    c2.handshake(at(100.0), at(100.015), at(100.300))
    sesid2, tid2 = 0x22, 7
    xchg(c2, header(NEGOTIATE, 0) + negotiate_req([0x202, 0x210]),
         header(NEGOTIATE, 0, resp=True) + negotiate_resp(0x210), 101.0, 0.3)
    xchg(c2, header(SESSION_SETUP, 1)
         + session_setup_req(ntlmssp_auth("bob", "LAB", "PC2")),
         header(SESSION_SETUP, 1, resp=True, sesid=sesid2)
         + session_setup_resp(b""), 102.0, 1.0)
    xchg(c2, header(TREE_CONNECT, 2, sesid=sesid2)
         + tree_connect_req("\\\\srv\\share"),
         header(TREE_CONNECT, 2, resp=True, sesid=sesid2, tid=tid2)
         + tree_connect_resp(1), 104.0, 0.4)
    xchg(c2, header(CREATE, 3, sesid=sesid2, tid=tid2)
         + create_req("secret.txt", disposition=1),
         header(CREATE, 3, resp=True, status=STATUS_ACCESS_DENIED,
                sesid=sesid2, tid=tid2) + error_body(), 105.0, 0.4,
         "denied")
    c2.reset(False, at(106.0))

    pcap.write(path)
    exp["sessions"] = {sesid: ("LAB", "alice"), sesid2: ("LAB", "bob")}
    exp["clients"] = [CLIENT1, CLIENT2]
    exp["server"] = SERVER
    exp["fid_a"] = str(uuid.UUID(bytes_le=fid_a))
    exp["weird_name"] = WEIRD_NAME
    return exp


RESTART_SCANS, RETURN_SINGLE_ENTRY = 0x01, 0x02


def build_dirscans(path: str) -> dict:
    """Directories listed again: a scan already running when the capture
    begins, scans started over before the end, complete listings
    repeated, a restart on one handle, two scans at once and a lookup."""
    pcap = Pcap()
    t = 1_700_000_000 * 1_000_000_000

    def at(ms: float) -> int:
        return t + int(ms * MS)

    c = Conn(pcap, CLIENT1, SERVER, 50010)
    c.handshake(at(0), at(0.020), at(0.320))
    sesid, tid = 0x31, 1
    mids = iter(range(1, 10_000))

    def hdr(cmd: int, mid: int, resp: bool = False, status: int = 0,
            related: bool = False) -> bytes:
        return header(cmd, mid, resp=resp, status=status, sesid=sesid,
                      tid=tid, flags=F_RELATED if related else 0)

    def xchg(reqs: list[bytes], resps: list[bytes], ms: float) -> None:
        c.send(True, nbss(compound(reqs)), at(ms))
        c.send(False, nbss(compound(resps)), at(ms + 0.2))

    def reply(mid: int, names: list[str] | None,
              related: bool = False) -> bytes:
        if names is None:
            return hdr(QUERY_DIRECTORY, mid, resp=True,
                       status=STATUS_NO_MORE_FILES, related=related) \
                + error_body()
        return hdr(QUERY_DIRECTORY, mid, resp=True, related=related) \
            + buffer_resp(dir_entries(names))

    def open_dir(name: str, fid: bytes, first: list[str], ms: float) -> None:
        """CREATE and the first QUERY_DIRECTORY, compounded."""
        m1, m2 = next(mids), next(mids)
        xchg([hdr(CREATE, m1) + create_req(name, options=0x21,
                                           access=0x100081),
              hdr(QUERY_DIRECTORY, m2, related=True)
              + find_req(ALL_ONES_FID, "*", flags=RESTART_SCANS)],
             [hdr(CREATE, m1, resp=True) + create_resp(fid, attrs=0x10),
              reply(m2, first, related=True)], ms)

    def create(name: str, fid: bytes, ms: float) -> None:
        m = next(mids)
        xchg([hdr(CREATE, m) + create_req(name, options=0x21,
                                          access=0x100081)],
             [hdr(CREATE, m, resp=True) + create_resp(fid, attrs=0x10)], ms)

    def find(fid: bytes, names: list[str] | None, ms: float,
             flags: int = 0) -> None:
        m = next(mids)
        xchg([hdr(QUERY_DIRECTORY, m) + find_req(fid, "*", flags=flags)],
             [reply(m, names)], ms)

    def close(fid: bytes, ms: float) -> None:
        m = next(mids)
        xchg([hdr(CLOSE, m) + close_req(fid)],
             [hdr(CLOSE, m, resp=True) + close_resp()], ms)

    def lookup(dirname: str, fid: bytes, name: str, ms: float) -> None:
        m1, m2, m3 = next(mids), next(mids), next(mids)
        xchg([hdr(CREATE, m1) + create_req(dirname, options=0x21,
                                           access=0x100081),
              hdr(QUERY_DIRECTORY, m2, related=True)
              + find_req(ALL_ONES_FID, name,
                         flags=RESTART_SCANS | RETURN_SINGLE_ENTRY),
              hdr(CLOSE, m3, related=True) + close_req(ALL_ONES_FID)],
             [hdr(CREATE, m1, resp=True) + create_resp(fid, attrs=0x10),
              reply(m2, [name], related=True),
              hdr(CLOSE, m3, resp=True, related=True) + close_resp()], ms)

    def fid(n: int) -> bytes:
        return uuid.UUID(int=0x100 + n).bytes_le

    m = next(mids)
    xchg([hdr(SESSION_SETUP, m)
          + session_setup_req(ntlmssp_auth("carol", "LAB", "PC3"))],
         [hdr(SESSION_SETUP, m, resp=True) + session_setup_resp(b"")], 1.0)
    m = next(mids)
    xchg([hdr(TREE_CONNECT, m) + tree_connect_req("\\\\srv\\share")],
         [hdr(TREE_CONNECT, m, resp=True) + tree_connect_resp(1)], 2.0)

    big = [f"f{i:02d}" for i in range(30)]
    r1, r2, r3 = [".", ".."] + big[:10], big[10:20], big[20:]
    # Opened before the capture: placed in "big" by its reply's names.
    find(fid(0), r2, 10.0)
    close(fid(0), 11.0)
    # Started over twice before the end, then read to the end.
    open_dir("big", fid(1), r1, 20.0)
    find(fid(1), r2, 22.0)
    close(fid(1), 24.0)
    open_dir("big", fid(2), r1, 30.0)
    find(fid(2), r2, 32.0)
    find(fid(2), r3, 34.0)
    close(fid(2), 36.0)
    open_dir("big", fid(3), r1, 40.0)
    find(fid(3), r2, 42.0)
    find(fid(3), r3, 44.0)
    find(fid(3), None, 46.0)
    close(fid(3), 48.0)
    lookup("big", fid(4), "f05", 50.0)
    # Listed in full twice.
    for i, ms in enumerate((60.0, 70.0)):
        open_dir("small", fid(5 + i), [".", "..", "s1", "s2"], ms)
        find(fid(5 + i), None, ms + 1)
        close(fid(5 + i), ms + 2)
    # Restarted on one handle.
    again = [".", ".."] + [f"g{i}" for i in range(5)]
    create("again", fid(7), 80.0)
    find(fid(7), again, 81.0)
    find(fid(7), [f"g{i}" for i in range(5, 10)], 82.0)
    find(fid(7), again, 83.0, flags=RESTART_SCANS)
    find(fid(7), [f"g{i}" for i in range(5, 10)], 84.0)
    find(fid(7), None, 85.0)
    close(fid(7), 86.0)
    # Two scans of one directory at once.
    create("two", fid(8), 90.0)
    create("two", fid(9), 91.0)
    find(fid(8), [".", "..", "t1"], 92.0)
    find(fid(9), [".", "..", "t1"], 93.0)
    find(fid(8), None, 94.0)
    find(fid(9), None, 95.0)
    close(fid(8), 96.0)
    close(fid(9), 97.0)

    pcap.write(path)
    return {
        # scans, complete, rewinds, repeats, overlaps, returned, distinct
        "big": (4, 1, 3, 0, 0, 90, 30),
        "small": (2, 2, 0, 1, 0, 4, 2),
        "again": (2, 1, 1, 0, 0, 20, 10),
        "two": (2, 2, 0, 0, 1, 2, 1),
        "lookups": {"big": 1},
        "user": "LAB\\carol",
    }


if __name__ == "__main__":
    print(build(sys.argv[1]))
