"""Read pcap and pcapng (gzipped or not), write pcap with nanosecond
timestamps."""

from __future__ import annotations

import gzip
import os
import struct
from typing import BinaryIO, Iterator

LINK_ETHERNET = 1
LINK_RAW = 101
LINK_SLL = 113
LINK_IPV4 = 228
LINK_IPV6 = 229
LINK_SLL2 = 276

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
    b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class FormatError(Exception):
    pass


class Record:
    __slots__ = ("ts", "data", "wire", "link")

    def __init__(self, ts: int, data: bytearray, wire: int, link: int):
        self.ts = ts
        self.data = data
        self.wire = wire
        self.link = link


def open_capture(path: str) -> BinaryIO:
    f = open(path, "rb")
    if f.read(2) == b"\x1f\x8b":
        f.close()
        return gzip.open(path, "rb")
    f.seek(0)
    return f


class _GzipOut(gzip.GzipFile):
    """A gzip file whose header names `name`, not the path written."""

    def __init__(self, path: str, name: str):
        self._raw = open(path, "wb")
        super().__init__(filename=name, mode="wb", fileobj=self._raw,
                         compresslevel=6)

    def close(self) -> None:
        try:
            super().close()
        finally:
            self._raw.close()


def create(path: str, final: str | None = None) -> BinaryIO:
    """Open `path` for writing, gzipped if the file it will become ends
    in .gz."""
    final = final or path
    if final.endswith(".gz"):
        return _GzipOut(path, os.path.basename(final[:-3]))
    return open(path, "wb")


def is_capture(path: str) -> bool:
    with open_capture(path) as f:
        head = f.read(4)
    return head in PCAP_MAGICS or head == PCAPNG_MAGIC


def read(f: BinaryIO) -> Iterator[Record]:
    head = f.read(4)
    if head == PCAPNG_MAGIC:
        yield from _read_pcapng(f, head)
    elif head in PCAP_MAGICS:
        yield from _read_pcap(f, head)
    else:
        raise FormatError("not a pcap or pcapng file")


def _read_pcap(f: BinaryIO, head: bytes) -> Iterator[Record]:
    endian, mul = PCAP_MAGICS[head]
    rest = f.read(20)
    if len(rest) < 20:
        raise FormatError("short pcap header")
    link = struct.unpack(endian + "I", rest[16:20])[0]
    rec = struct.Struct(endian + "IIII")
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        sec, frac, caplen, wire = rec.unpack(h)
        data = f.read(caplen)
        if len(data) < caplen:
            return
        yield Record(sec * 1_000_000_000 + frac * mul, bytearray(data),
                     wire, link)


def _read_pcapng(f: BinaryIO, head: bytes) -> Iterator[Record]:
    endian = "<"
    ifaces: list[tuple[int, int, int]] = []  # link, snaplen, ns per tick
    block_head = head
    while True:
        if block_head is None:
            block_head = f.read(4)
            if len(block_head) < 4:
                return
        if block_head == PCAPNG_MAGIC:
            raw = f.read(8)
            if len(raw) < 8:
                return
            bom = raw[4:8]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            total = struct.unpack(endian + "I", raw[:4])[0]
            body = f.read(total - 12)
            ifaces = []
            block_head = None
            continue
        btype = struct.unpack(endian + "I", block_head)[0]
        raw = f.read(4)
        if len(raw) < 4:
            return
        total = struct.unpack(endian + "I", raw)[0]
        if total < 12:
            raise FormatError("bad pcapng block length")
        body = f.read(total - 12)
        f.read(4)
        block_head = None
        if len(body) < total - 12:
            return
        if btype == 1:  # interface description
            link, _, snap = struct.unpack(endian + "HHI", body[:8])
            ifaces.append((link, snap, _tsresol(body[8:], endian)))
        elif btype == 6:  # enhanced packet
            iid, th, tl, caplen, wire = struct.unpack(endian + "IIIII",
                                                      body[:20])
            link, _, tick = ifaces[iid] if iid < len(ifaces) else (1, 0, 1000)
            data = body[20:20 + caplen]
            yield Record(((th << 32) | tl) * tick, bytearray(data), wire,
                         link)
        elif btype == 3:  # simple packet
            wire = struct.unpack(endian + "I", body[:4])[0]
            link, snap, _ = ifaces[0] if ifaces else (1, 0, 1000)
            caplen = min(wire, snap) if snap else wire
            yield Record(0, bytearray(body[4:4 + caplen]), wire, link)
        elif btype == 2:  # obsolete packet block
            iid, _, th, tl, caplen, wire = struct.unpack(endian + "HHIIII",
                                                         body[:20])
            link, _, tick = ifaces[iid] if iid < len(ifaces) else (1, 0, 1000)
            yield Record(((th << 32) | tl) * tick,
                         bytearray(body[20:20 + caplen]), wire, link)


def _tsresol(opts: bytes, endian: str) -> int:
    """Nanoseconds per timestamp unit from the if_tsresol option."""
    off = 0
    while off + 4 <= len(opts):
        code, length = struct.unpack(endian + "HH", opts[off:off + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = opts[off + 4]
            if v & 0x80:
                return max(1, round(1e9 / (1 << (v & 0x7F))))
            return max(1, 10 ** (9 - v)) if v <= 9 else 1
        off += 4 + ((length + 3) & ~3)
    return 1000


class Writer:
    """pcap with nanosecond timestamps and one link type."""

    def __init__(self, f: BinaryIO, link: int, snaplen: int = 262144):
        self.f = f
        self.link = link
        self.count = 0
        self.nbytes = 0
        f.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, snaplen,
                            link))

    def write(self, rec: Record) -> None:
        if rec.link != self.link:
            raise FormatError(
                f"mixed link types ({self.link} and {rec.link})")
        sec, ns = divmod(rec.ts, 1_000_000_000)
        self.f.write(struct.pack("<IIII", sec, ns, len(rec.data), rec.wire))
        self.f.write(rec.data)
        self.count += 1
        self.nbytes += len(rec.data)
