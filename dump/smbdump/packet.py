"""One captured frame: where its headers are, edits that keep the
checksums consistent, and the frames it becomes once payload is cut."""

from __future__ import annotations

import struct

from . import pcapio

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_VLAN = (0x8100, 0x88A8, 0x9100)
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1
PROTO_ICMPV6 = 58
IPV6_EXT = {0, 43, 60, 51}  # hop-by-hop, routing, destination, AH
FIN, SYN, RST, PSH = 0x01, 0x02, 0x04, 0x08


class Packet:
    __slots__ = (
        "rec", "data", "wire", "pending", "link_len", "macs", "ip_off",
        "ipver", "src", "dst", "proto", "l4_off", "payload_off", "l4_wire",
        "csum_off", "csum_delta", "sport", "dport", "seq", "flags",
        "starts", "drops", "front", "extra", "extra_wire",
        "csum_off_partial",
    )

    def __init__(self, rec: pcapio.Record):
        self.rec = rec
        self.data = rec.data
        self.wire = rec.wire
        self.pending = 0
        self.link_len = 0
        self.macs: list[tuple[int, int]] = []  # (offset, length)
        self.ip_off = -1
        self.ipver = 0
        self.src = b""
        self.dst = b""
        self.proto = -1
        self.l4_off = -1
        self.payload_off = -1
        self.l4_wire = 0  # transport payload bytes on the wire
        self.csum_off = -1
        self.csum_delta = 0
        self.csum_off_partial = False
        self.sport = self.dport = 0
        self.seq = 0
        self.flags = 0
        self.starts: list[int] = []  # PDU starts in the payload
        self.drops: list[tuple[int, int]] = []  # payload ranges to cut
        self.front = 0  # leading payload bytes moved to an earlier frame
        self.extra = bytearray()  # bytes moved here from later frames
        self.extra_wire = 0  # wire bytes moved here, captured or not
        self._parse()

    # -- parsing ---------------------------------------------------------------

    def _parse(self) -> None:
        d = self.data
        link = self.rec.link
        off = 0
        if link == pcapio.LINK_ETHERNET:
            if len(d) < 14:
                return
            self.macs = [(0, 6), (6, 6)]
            etype = struct.unpack_from(">H", d, 12)[0]
            off = 14
            while etype in ETH_VLAN and off + 4 <= len(d):
                etype = struct.unpack_from(">H", d, off + 2)[0]
                off += 4
        elif link == pcapio.LINK_SLL:
            if len(d) < 16:
                return
            alen = struct.unpack_from(">H", d, 4)[0]
            self.macs = [(6, min(alen, 8))]
            etype = struct.unpack_from(">H", d, 14)[0]
            off = 16
        elif link == pcapio.LINK_SLL2:
            if len(d) < 20:
                return
            etype = struct.unpack_from(">H", d, 0)[0]
            self.macs = [(12, min(d[11], 8))]
            off = 20
        elif link in (pcapio.LINK_RAW, pcapio.LINK_IPV4, pcapio.LINK_IPV6):
            etype = ETH_IPV4 if d and d[0] >> 4 == 4 else ETH_IPV6
        else:
            return
        self.link_len = off
        if etype == ETH_IPV4:
            self._ipv4(off)
        elif etype == ETH_IPV6:
            self._ipv6(off)

    def _ipv4(self, off: int) -> None:
        d = self.data
        if off + 20 > len(d) or d[off] >> 4 != 4:
            return
        ihl = (d[off] & 0xF) * 4
        total = struct.unpack_from(">H", d, off + 2)[0]
        if total == 0:  # segmentation offload: the length is the frame's
            total = self.wire - off
        frag = struct.unpack_from(">H", d, off + 6)[0]
        self.ip_off = off
        self.ipver = 4
        self.src = bytes(d[off + 12:off + 16])
        self.dst = bytes(d[off + 16:off + 20])
        if ihl < 20 or off + ihl > len(d):
            return
        if frag & 0x3FFF:  # a fragment: payload unknown
            self.payload_off = off + ihl
            self.l4_wire = max(0, total - ihl)
            return
        self.proto = d[off + 9]
        self._l4(off + ihl, max(0, total - ihl))

    def _ipv6(self, off: int) -> None:
        d = self.data
        if off + 40 > len(d) or d[off] >> 4 != 6:
            return
        plen = struct.unpack_from(">H", d, off + 4)[0]
        nxt = d[off + 6]
        if plen == 0 and nxt == 0:  # jumbogram
            plen = self.wire - off - 40
        self.ip_off = off
        self.ipver = 6
        self.src = bytes(d[off + 8:off + 24])
        self.dst = bytes(d[off + 24:off + 40])
        pos = off + 40
        end = pos + plen
        while nxt in IPV6_EXT:
            if pos + 2 > len(d):
                return
            elen = (d[pos + 1] + 2) * 4 if nxt == 51 else (d[pos + 1] + 1) * 8
            nxt = d[pos]
            pos += elen
        if nxt == 44:  # fragment
            self.payload_off = pos
            self.l4_wire = max(0, end - pos)
            return
        self.proto = nxt
        self._l4(pos, max(0, end - pos))

    def _l4(self, off: int, wire_len: int) -> None:
        d = self.data
        self.l4_off = off
        if self.proto == PROTO_TCP:
            if off + 20 > len(d):
                return
            self.sport, self.dport, self.seq = struct.unpack_from(">HHI", d,
                                                                  off)
            doff = (d[off + 12] >> 4) * 4
            self.flags = d[off + 13]
            self.csum_off = off + 16
            if doff < 20 or off + doff > len(d):
                return
            self.payload_off = off + doff
            self.l4_wire = max(0, wire_len - doff)
        elif self.proto == PROTO_UDP:
            if off + 8 > len(d):
                return
            self.sport, self.dport = struct.unpack_from(">HH", d, off)
            self.csum_off = off + 6
            self.payload_off = off + 8
            self.l4_wire = max(0, wire_len - 8)
        elif self.proto in (PROTO_ICMP, PROTO_ICMPV6):
            self.csum_off = off + 2
            self.payload_off = off + 4
            self.l4_wire = max(0, wire_len - 4)
        else:
            self.payload_off = off
            self.l4_wire = wire_len

    # -- what is captured ------------------------------------------------------

    @property
    def payload_end(self) -> int:
        """End of the captured transport payload, link padding excluded."""
        if self.payload_off < 0:
            return 0
        return min(len(self.data), self.payload_off + self.l4_wire)

    @property
    def captured(self) -> int:
        if self.payload_off < 0:
            return 0
        return max(0, self.payload_end - self.payload_off)

    @property
    def is_tcp(self) -> bool:
        return self.proto == PROTO_TCP and self.payload_off >= 0

    # -- edits -----------------------------------------------------------------

    def edit(self, off: int, new: bytes) -> None:
        d = self.data
        end = min(off + len(new), len(d))
        if end <= off:
            return
        new = new[:end - off]
        old = d[off:end]
        if old == new:
            return
        if self.csum_off >= 0 and off >= self.l4_off:
            self.csum_delta += _sum16(new, off - self.l4_off) - _sum16(
                old, off - self.l4_off)
        d[off:end] = new

    def zero(self, off: int, end: int) -> None:
        end = min(end, len(self.data))
        if end > off:
            self.edit(off, bytes(end - off))

    def drop(self, off: int, end: int) -> None:
        """Cut payload bytes when the frame is written."""
        if end > off:
            self.drops.append((off, end))

    def truncate(self, off: int) -> None:
        if off < len(self.data):
            del self.data[off:]

    def set_addrs(self, src: bytes, dst: bytes) -> None:
        d = self.data
        off = self.ip_off
        if self.ipver == 4:
            so, do, n = off + 12, off + 16, 4
        else:
            so, do, n = off + 8, off + 24, 16
        if do + n > len(d):
            return
        old = bytes(d[so:so + n]) + bytes(d[do:do + n])
        if old == src + dst:
            return
        partial = self._partial()
        d[so:so + n] = src
        d[do:do + n] = dst
        osrc, odst = self.src, self.dst
        self.src, self.dst = src, dst
        if partial is not None:
            # Offloaded: the field holds the pseudo-header sum alone.
            struct.pack_into(">H", d, self.csum_off, self._pseudo(partial))
            self.csum_off_partial = True
        elif self.csum_off >= 0 and self.proto in (PROTO_TCP, PROTO_UDP,
                                                    PROTO_ICMPV6):
            # The pseudo-header puts the addresses under the checksum.
            self.csum_delta += _sum16(src + dst, 0) - _sum16(osrc + odst, 0)
        if self.ipver == 4:
            _ipv4_checksum(d, off)

    def _pseudo(self, with_len: bool) -> int:
        """Folded pseudo-header sum, the value a checksum offloaded to
        the NIC holds when captured on the sending host."""
        n = self.payload_off - self.l4_off + self.l4_wire if with_len else 0
        if self.ipver == 4:
            b = self.src + self.dst + bytes([0, self.proto]) + \
                n.to_bytes(2, "big")
        else:
            b = self.src + self.dst + n.to_bytes(4, "big") + \
                bytes([0, 0, 0, self.proto])
        return _fold(_sum16(b, 0))

    def _partial(self) -> bool | None:
        """True or False (with or without the length) if the checksum
        is an offloaded partial one, else None."""
        if self.proto not in (PROTO_TCP, PROTO_UDP) or self.payload_off < 0 \
                or self.csum_off + 2 > len(self.data):
            return None
        cur = struct.unpack_from(">H", self.data, self.csum_off)[0]
        for with_len in (True, False):
            if cur == self._pseudo(with_len):
                # A full checksum can equal the pseudo-header sum by chance.
                if self.captured == self.l4_wire and _fold(
                        self._pseudo(True) + _sum16(bytes(
                            self.data[self.l4_off:self.payload_end]), 0)) \
                        == 0xFFFF:
                    return None
                return with_len
        return None

    def finish(self) -> None:
        """Fold the accumulated delta into the transport checksum."""
        if not self.csum_delta or self.csum_off < 0 or self.csum_off_partial:
            return
        d = self.data
        if self.csum_off + 2 > len(d):
            return
        old = struct.unpack_from(">H", d, self.csum_off)[0]
        if old == 0 and self.proto == PROTO_UDP:
            return
        s = ((~old) & 0xFFFF) + self.csum_delta % 0xFFFF
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        struct.pack_into(">H", d, self.csum_off, (~s) & 0xFFFF)
        self.csum_delta = 0

    # -- cutting ------------------------------------------------------------------

    @property
    def reshaped(self) -> bool:
        return bool(self.drops or self.front or self.extra_wire)

    def pieces(self) -> list[pcapio.Record]:
        """The frames this one becomes once its drops are cut: split at
        every PDU start, so that each piece holds one PDU's bytes and a
        cut piece starts where its PDU does."""
        if not self.is_tcp:
            self.finish()
            return [self.rec]
        start = self.payload_off + self.front
        end = self.payload_end
        wire_end = self.payload_off + self.l4_wire
        drops = _merge(self.drops)
        cuts = [] if self.flags & RST else sorted(
            {s for s in self.starts if start < s < end})
        bounds = [start, *cuts, end]
        out = []
        n = len(bounds) - 1
        for i in range(n):
            s, e = bounds[i], bounds[i + 1]
            last = i == n - 1
            cap = e
            for a, b in drops:
                if a < e and b >= e:
                    cap = max(a, s)
                    break
            body = bytearray(self.data[s:cap])
            for a, b in drops:
                lo, hi = max(a, s), min(b, cap)
                if hi > lo:
                    body[lo - s:hi - s] = bytes(hi - lo)
            wire = e - s
            if last:
                wire = wire_end - s + self.extra_wire
                if cap == e == wire_end:
                    body += self.extra
            if wire <= 0 and not (last and self.flags & (FIN | SYN | RST)):
                continue
            out.append(self._piece(s, body, max(wire, 0), last))
        return out

    def _piece(self, s: int, body: bytearray, wire: int,
               last: bool) -> pcapio.Record:
        hdr = bytearray(self.data[:self.payload_off])
        lo = self.l4_off
        seq = (self.seq + (s - self.payload_off)) & 0xFFFFFFFF
        struct.pack_into(">I", hdr, lo + 4, seq)
        if not last:
            hdr[lo + 13] = self.flags & ~(FIN | PSH)
        iplen = self.payload_off - self.ip_off + wire
        if self.ipver == 4:
            struct.pack_into(">H", hdr, self.ip_off + 2,
                             iplen if iplen <= 0xFFFF else 0)
            _ipv4_checksum(hdr, self.ip_off)
        else:
            plen = iplen - 40
            struct.pack_into(">H", hdr, self.ip_off + 4,
                             plen if plen <= 0xFFFF else 0)
        struct.pack_into(">H", hdr, lo + 16, 0)
        if len(body) == wire:
            struct.pack_into(">H", hdr, lo + 16, self._tcp_sum(hdr, body))
        return pcapio.Record(self.rec.ts, hdr + body, self.payload_off + wire,
                             self.rec.link)

    def _tcp_sum(self, hdr: bytearray, body: bytes) -> int:
        seg = bytes(hdr[self.l4_off:]) + bytes(body)
        n = len(seg)
        if self.ipver == 4:
            pseudo = self.src + self.dst + bytes([0, PROTO_TCP]) + \
                n.to_bytes(2, "big")
        else:
            pseudo = self.src + self.dst + n.to_bytes(4, "big") + \
                bytes([0, 0, 0, PROTO_TCP])
        return (~_fold(_sum16(pseudo, 0) + _sum16(seg, 0))) & 0xFFFF


def _fold(s: int) -> int:
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def _merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for a, b in sorted(ranges):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]


def _ipv4_checksum(d: bytearray, off: int) -> None:
    ihl = (d[off] & 0xF) * 4
    if off + ihl > len(d):
        return
    d[off + 10:off + 12] = b"\0\0"
    s = sum(struct.unpack_from(f">{ihl // 2}H", d, off))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    struct.pack_into(">H", d, off + 10, (~s) & 0xFFFF)


def _sum16(b: bytes, pos: int) -> int:
    """Word sum of `b` placed at offset `pos` of the summed area (odd
    offsets start in the low byte of a word)."""
    if pos & 1:
        b = b"\0" + bytes(b)
    if len(b) & 1:
        b = bytes(b) + b"\0"
    return sum(struct.unpack(f">{len(b) // 2}H", b))
