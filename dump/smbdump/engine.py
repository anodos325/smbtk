"""Follow each TCP direction, cut it into SMB PDUs, and let the handlers
rewrite them.

A PDU that may need rewriting is buffered until complete (or until the
capture loses it), so names split across segments are still found; the
frames holding it wait in the output queue meanwhile. Bulk data is
handled as it streams by.

When cutting, a cut frame is split at every PDU start in it, and the
piece holding a cut PDU's start carries the PDU's whole kept prefix:
tshark cannot reassemble across a truncated frame, so each header has
to be readable where its PDU starts.
"""

from __future__ import annotations

from collections import deque
from typing import Iterable

from . import pcapio
from .packet import Packet, _merge

HEAD_NEED = 4 + 64 + 48
MAX_PDU = 16 << 20
MASK = 0xFFFFFFFF
SMB_FIRST = (0xFE, 0xFF, 0xFD, 0xFC)
BUFFERING = ("pending", "prefix", "buffer")


def seq_lt(a: int, b: int) -> bool:
    return ((a - b) & MASK) >= 0x80000000


class Edit:
    """What a handler produces for one PDU: `out` starts zeroed (deny) or
    as a copy (allow); `drops` are ranges to cut from the frames."""

    def __init__(self, buf: bytes, deny: bool):
        self.buf = buf
        self.out = bytearray(len(buf)) if deny else bytearray(buf)
        self.drops: list[tuple[int, int]] = []

    def keep(self, a: int, b: int) -> None:
        a, b = max(a, 0), min(b, len(self.buf))
        if b > a:
            self.out[a:b] = self.buf[a:b]

    def put(self, a: int, data: bytes) -> None:
        if a < 0 or a >= len(self.buf):
            return
        data = data[:len(self.buf) - a]
        self.out[a:a + len(data)] = data

    def zero(self, a: int, b: int) -> None:
        a, b = max(a, 0), min(b, len(self.buf))
        if b > a:
            self.out[a:b] = bytes(b - a)

    def drop(self, a: int, b: int) -> None:
        a, b = max(a, 0), min(b, len(self.buf))
        if b > a:
            self.zero(a, b)
            self.drops.append((a, b))


class Pdu:
    __slots__ = ("total", "got", "buf", "parts", "mode", "data_from",
                 "need", "hole")

    def __init__(self, total: int):
        self.total = total
        self.got = 0
        self.buf = bytearray()
        # (packet, offset in its data, position in the PDU, length)
        self.parts: list[tuple[Packet, int, int, int]] = []
        self.mode = "pending"
        self.data_from = total
        self.need = min(HEAD_NEED, total)
        self.hole = False


class Dir:
    __slots__ = ("next_seq", "pdu", "carry", "carry_parts", "synced")

    def __init__(self) -> None:
        self.next_seq: int | None = None
        self.pdu: Pdu | None = None
        self.carry = bytearray()  # an NBSS header split across segments
        self.carry_parts: list[tuple[Packet, int, int]] = []
        self.synced = False


class Conn:
    __slots__ = ("dirs", "reqs")

    def __init__(self) -> None:
        self.dirs: dict[tuple[bytes, int], Dir] = {}
        self.reqs: dict[int, tuple] = {}


class Stats:
    def __init__(self) -> None:
        self.frames = 0
        self.frames_out = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.dropped = 0
        self.split = 0
        self.pdus = 0
        self.buffered = 0
        self.partial = 0
        self.gaps = 0
        self.unknown = 0

    def add(self, other: "Stats") -> None:
        for k, v in vars(other).items():
            setattr(self, k, getattr(self, k) + v)


class Engine:
    def __init__(self, handlers, ports: Iterable[int], strip: bool,
                 anon: bool, keep_other: bool = False):
        self.h = handlers
        self.ports = set(ports)
        self.strip = strip
        self.anon = anon
        self.keep_other = keep_other
        self.conns: dict[tuple, Conn] = {}
        self.stats = Stats()

    # -- driving ----------------------------------------------------------------

    def run(self, records: Iterable[pcapio.Record], writer) -> Stats:
        queue: deque[Packet] = deque()
        st = self.stats
        for rec in records:
            pkt = Packet(rec)
            st.frames += 1
            st.bytes_in += len(rec.data)
            smb = pkt.is_tcp and (pkt.sport in self.ports
                                  or pkt.dport in self.ports)
            if not self._lower(pkt, smb):
                st.dropped += 1
                continue
            queue.append(pkt)
            if smb and pkt.l4_wire:
                self._segment(pkt)
            while queue and queue[0].pending == 0:
                self._emit(queue.popleft(), writer)
        # Every frame of this file is written below, so nothing may stay
        # buffered; a PDU being streamed carries on into a next file.
        for conn in self.conns.values():
            for d in conn.dirs.values():
                if d.pdu is not None and d.pdu.mode in BUFFERING:
                    self._close(d.pdu, conn)
                if d.carry:
                    self._drop_carry(d)
                    d.synced = False
        while queue:
            self._emit(queue.popleft(), writer)
        return st

    def _emit(self, pkt: Packet, writer) -> None:
        if self.strip and pkt.reshaped:
            recs = pkt.pieces()
            if len(recs) > 1:
                self.stats.split += 1
        else:
            pkt.finish()
            recs = [pkt.rec]
        for r in recs:
            writer.write(r)
            self.stats.frames_out += 1
            self.stats.bytes_out += len(r.data)

    def _lower(self, pkt: Packet, smb: bool) -> bool:
        """Layers 2 to 4. False drops the frame."""
        if not self.anon:
            return True
        if (not smb and not self.keep_other) or pkt.ip_off < 0:
            return False  # ARP, LLDP and the like carry names and addresses
        m = self.h.m
        for off, n in pkt.macs:
            if n == 6:
                pkt.edit(off, m.mac(bytes(pkt.data[off:off + 6])))
        pkt.set_addrs(m.ip(pkt.src), m.ip(pkt.dst))
        if not smb and pkt.payload_off >= 0:
            if self.strip:
                pkt.truncate(pkt.payload_off)
            else:
                pkt.zero(pkt.payload_off, len(pkt.data))
        return True

    # -- TCP directions -----------------------------------------------------------

    def _conn(self, pkt: Packet) -> Conn:
        a, b = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
        key = (a, b) if a <= b else (b, a)
        conn = self.conns.get(key)
        if conn is None:
            conn = self.conns[key] = Conn()
        return conn

    def _segment(self, pkt: Packet) -> None:
        conn = self._conn(pkt)
        key = (pkt.src, pkt.sport)
        d = conn.dirs.get(key)
        if d is None:
            d = conn.dirs[key] = Dir()
        seq, wire = pkt.seq, pkt.l4_wire
        if d.next_seq is None or seq == d.next_seq:
            self._walk(d, pkt, conn)
        elif seq_lt(seq, d.next_seq):
            # A retransmission: handled on its own, the direction's state
            # left alone unless it also carries new bytes.
            tmp = Dir()
            self._walk(tmp, pkt, conn, update=False)
            self._abandon(tmp, conn)
            if seq_lt(d.next_seq, (seq + wire) & MASK):
                self._abandon(d, conn)
                d.synced = False
                d.next_seq = (seq + wire) & MASK
        else:
            self.stats.gaps += 1
            self._abandon(d, conn)
            d.synced = False
            self._walk(d, pkt, conn)

    def _walk(self, d: Dir, pkt: Packet, conn: Conn,
              update: bool = True) -> None:
        o, end = pkt.payload_off, pkt.payload_end
        if not d.synced and o < end:
            k = self._find_start(pkt)
            if k < 0:
                self._unknown(pkt, o, end)
                o = end
            else:
                self._unknown(pkt, o, k)
                o = k
                d.synced = True
        if o < end:
            self._consume(d, pkt, o, conn)
        missing = pkt.l4_wire - pkt.captured
        if missing > 0:
            self._skip(d, conn, missing)
        if update:
            d.next_seq = (pkt.seq + pkt.l4_wire) & MASK

    def _find_start(self, pkt: Packet) -> int:
        """Offset of a plausible PDU start in the payload, or -1."""
        data = pkt.data
        o, end = pkt.payload_off, pkt.payload_end
        i = data.find(b"SMB", o + 5, end)
        while i >= 0:
            s = i - 5
            if data[s] == 0 and data[i - 1] in SMB_FIRST:
                n = int.from_bytes(data[s + 1:s + 4], "big")
                if 32 <= n <= MAX_PDU and _plausible(data, s + 4, end):
                    return s
            i = data.find(b"SMB", i + 1, end)
        return -1

    def _unknown(self, pkt: Packet, a: int, b: int) -> None:
        if b > a:
            self.stats.unknown += b - a
            if self.strip or self.anon:
                self._cut(pkt, a, b)

    def _cut(self, pkt: Packet, a: int, b: int) -> None:
        if self.strip:
            pkt.drop(a, b)
        else:
            pkt.zero(a, b)

    def _skip(self, d: Dir, conn: Conn, n: int) -> None:
        """Wire bytes the capture does not hold."""
        if d.carry:
            self._drop_carry(d)
            d.synced = False
        while n > 0 and d.pdu is not None:
            pdu = d.pdu
            take = min(n, pdu.total - pdu.got)
            if pdu.mode in BUFFERING:
                pdu.hole = True
                self._close(pdu, conn)
            pdu.got += take
            n -= take
            if pdu.got >= pdu.total:
                d.pdu = None
        if n > 0:
            d.synced = False

    def _consume(self, d: Dir, pkt: Packet, o: int, conn: Conn) -> None:
        data = pkt.data
        end = pkt.payload_end
        while o < end:
            pdu = d.pdu
            if pdu is None:
                if not d.carry:
                    pkt.starts.append(o)
                take = min(4 - len(d.carry), end - o)
                d.carry += data[o:o + take]
                d.carry_parts.append((pkt, o, take))
                pkt.pending += 1
                o += take
                if len(d.carry) < 4:
                    return
                pdu = self._start(d)
                if pdu.got < pdu.total:
                    d.pdu = pdu
                continue
            avail = min(end - o, pdu.total - pdu.got)
            if pdu.mode in BUFFERING:
                take = min(avail, pdu.need - pdu.got)
                pdu.buf += data[o:o + take]
                pdu.parts.append((pkt, o, pdu.got, take))
                pkt.pending += 1
                pdu.got += take
                o += take
                if pdu.got >= pdu.need:
                    self._advance(pdu, conn)
                if pdu.got >= pdu.total:
                    d.pdu = None
                continue
            if pdu.mode == "data":
                a = max(pdu.got, pdu.data_from)
                if pdu.got + avail > a:
                    self._cut(pkt, o + (a - pdu.got), o + avail)
            elif pdu.mode == "zero":
                self._cut(pkt, o, o + avail)
            pdu.got += avail
            o += avail
            if pdu.got >= pdu.total:
                d.pdu = None

    def _drop_carry(self, d: Dir) -> None:
        for p, _, _ in d.carry_parts:
            p.pending -= 1
        d.carry = bytearray()
        d.carry_parts = []

    def _abandon(self, d: Dir, conn: Conn) -> None:
        if d.pdu is not None:
            self._close(d.pdu, conn)
            d.pdu = None
        if d.carry:
            self._drop_carry(d)

    # -- PDU lifecycle ---------------------------------------------------------------

    def _start(self, d: Dir) -> Pdu:
        ntype = d.carry[0]
        length = int.from_bytes(d.carry[1:4], "big")
        pdu = Pdu(4 + length)
        pdu.buf = bytearray(d.carry)
        pos = 0
        for p, off, n in d.carry_parts:
            pdu.parts.append((p, off, pos, n))
            pos += n
        pdu.got = 4
        d.carry = bytearray()
        d.carry_parts = []
        self.stats.pdus += 1
        if ntype != 0 or length == 0:
            # Keepalives, and session requests that carry NetBIOS names.
            self._settle(pdu, "zero" if ntype and self.anon else "keep")
        return pdu

    def _advance(self, pdu: Pdu, conn: Conn) -> None:
        if pdu.mode == "pending":
            if not self._classify(pdu):
                return
        if pdu.got < pdu.need and not pdu.hole:
            return
        if pdu.mode == "prefix":
            self._settle_data(pdu)
        elif pdu.mode == "buffer":
            self._resolve(pdu, conn)

    def _classify(self, pdu: Pdu) -> bool:
        """Decide what to do with a PDU from its first bytes; False once
        it is settled."""
        mode, data_from = self.h.classify(bytes(pdu.buf), pdu.total)
        if mode == "buffer":
            pdu.mode = "buffer"
            pdu.need = pdu.total
            self.stats.buffered += 1
        elif mode == "data":
            pdu.mode = "prefix"
            pdu.data_from = min(data_from, pdu.total)
            # The piece starting the PDU must reach past its kept prefix.
            pdu.need = min(pdu.total, pdu.data_from + 1) if self.strip \
                else pdu.got
        else:
            self._settle(pdu, mode)
            return False
        return True

    def _close(self, pdu: Pdu, conn: Conn) -> None:
        """Settle a PDU that will not be buffered any further."""
        if pdu.mode == "pending" and not self._classify(pdu):
            return
        if pdu.mode == "prefix":
            self._settle_data(pdu)
        elif pdu.mode == "buffer":
            self._resolve(pdu, conn)

    def _settle(self, pdu: Pdu, mode: str) -> None:
        pdu.mode = mode
        if mode == "zero":
            for p, off, pos, n in pdu.parts:
                a = max(pos, 4)
                if pos + n > a:
                    self._cut(p, off + (a - pos), off + n)
            if self.strip and pdu.total > 4:
                self._borrow(pdu, 4, bytes(pdu.buf))
        self._release(pdu)

    def _settle_data(self, pdu: Pdu) -> None:
        k = pdu.data_from
        for p, off, pos, n in pdu.parts:
            a = max(pos, k)
            if pos + n > a:
                self._cut(p, off + (a - pos), off + n)
        if self.strip and k < pdu.total:
            self._borrow(pdu, k, bytes(pdu.buf))
        pdu.mode = "data"
        self._release(pdu)

    def _resolve(self, pdu: Pdu, conn: Conn) -> None:
        if pdu.got < pdu.total or pdu.hole:
            self.stats.partial += 1
        edit = Edit(bytes(pdu.buf), deny=self.anon)
        self.h.handle(edit, conn)
        out = edit.out
        for p, off, pos, n in pdu.parts:
            new = out[pos:pos + n]
            if new != pdu.buf[pos:pos + n]:
                p.edit(off, bytes(new))
        # tshark reads a cut PDU only up to the cut, so only a drop running
        # to the end is cut; one with kept bytes after it (a compound
        # member's data) stays, zeroed.
        keep_end = pdu.total
        drops = _merge(edit.drops)
        if drops and drops[-1][1] >= len(pdu.buf):
            keep_end = drops[-1][0]
            for p, off, pos, n in pdu.parts:
                lo = max(keep_end, pos)
                if pos + n > lo:
                    self._cut(p, off + (lo - pos), off + n)
        if self.strip and keep_end < pdu.total:
            self._borrow(pdu, keep_end, bytes(out))
        # Bytes still to come (past a hole) were never seen by a handler.
        pdu.mode = "zero" if self.anon or keep_end < pdu.total else "keep"
        self._release(pdu)

    def _borrow(self, pdu: Pdu, k: int, content: bytes) -> None:
        """Make the frame holding the PDU's start also hold its first k
        bytes and reach one byte past them, moving bytes there from the
        frames that follow, so that frame is cut right after them."""
        if not pdu.parts or k + 1 > pdu.got:
            return
        p0, off0 = pdu.parts[0][0], pdu.parts[0][1]
        have = p0.payload_end - off0
        if have >= k + 1:
            return
        pos = have
        for p, _, ppos, n in pdu.parts:
            if p is p0:
                continue
            lo, hi = max(ppos, pos), min(ppos + n, k + 1)
            if hi > lo:
                p.front += hi - lo
                pos = hi
            if pos >= k + 1:
                break
        p0.extra += content[have:k]
        p0.extra_wire += k + 1 - have

    def _release(self, pdu: Pdu) -> None:
        for p, _, _, _ in pdu.parts:
            p.pending -= 1
        pdu.parts = []
        pdu.buf = bytearray()


def _plausible(data: bytearray, h: int, end: int) -> bool:
    """An SMB2 header at h: StructureSize 64 and a known command."""
    if data[h] != 0xFE or h + 14 > end:
        return True
    return data[h + 4] == 64 and data[h + 5] == 0 and data[h + 13] == 0 \
        and data[h + 12] < 19
