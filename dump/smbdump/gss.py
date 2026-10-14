"""Authentication blobs: SPNEGO and Kerberos (DER), and NTLMSSP.

Names are replaced; everything encrypted or keyed (tickets,
authenticators, challenge responses, session keys, MICs) is zeroed, and
so is anything not understood.
"""

from __future__ import annotations

import struct

from .mapping import Mapper

NTLM_SIG = b"NTLMSSP\0"
KRB_TOK_IDS = (b"\x01\x00", b"\x02\x00", b"\x03\x00", b"\x04\x00")
TAG_OCTET = 0x04
TAG_OID = 0x06
TAG_STRINGS = {0x0C, 0x13, 0x16, 0x1A, 0x1B, 0x1E}
TAG_KEEP = {0x01, 0x02, 0x03, 0x05, 0x0A, 0x17, 0x18}


def sanitize_blob(blob: bytes, m: Mapper) -> bytes:
    out = bytearray(len(blob))
    if blob.startswith(NTLM_SIG):
        _ntlm(blob, _View(out, 0, len(blob)), m)
    else:
        _der(blob, 0, len(blob), out, m)
    return bytes(out)


# -- DER ---------------------------------------------------------------------

def _tlv(b: bytes, off: int, end: int):
    """(tag, content start, content end) or None."""
    if off + 2 > end:
        return None
    tag = b[off]
    if tag & 0x1F == 0x1F:
        return None
    n = b[off + 1]
    pos = off + 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or pos + k > end:
            return None
        n = int.from_bytes(b[pos:pos + k], "big")
        pos += k
    if pos + n > end:
        return None
    return tag, pos, pos + n


def _der(b: bytes, off: int, end: int, out: bytearray, m: Mapper) -> bool:
    """Copy what is safe of the DER elements in b[off:end] into out;
    True if they parsed completely."""
    while off < end:
        t = _tlv(b, off, end)
        if t is None:
            return False
        tag, c0, c1 = t
        out[off:c0] = b[off:c0]
        if tag & 0x20:
            if not _der(b, c0, c1, out, m):
                return False
        elif tag == TAG_OCTET:
            content = b[c0:c1]
            if content.startswith(NTLM_SIG):
                _ntlm(content, _View(out, c0, c1), m)
            elif content[:1] in (b"\x60", b"\xa0", b"\xa1"):
                # A nested GSS or SPNEGO token; ciphertext that happens
                # to start the same way fails to parse and stays zeroed.
                tmp = bytearray(out)
                if _der(b, c0, c1, tmp, m):
                    out[:] = tmp
        elif tag in TAG_STRINGS:
            text = b[c0:c1].decode("latin-1")
            out[c0:c1] = m.name(text).encode("latin-1")
        elif tag == TAG_OID or tag in TAG_KEEP:
            out[c0:c1] = b[c0:c1]
            if tag == TAG_OID and b[c1:c1 + 2] in KRB_TOK_IDS:
                out[c1:c1 + 2] = b[c1:c1 + 2]
                c1 += 2
        off = c1
    return True


class _View:
    """Write-through window on part of a bytearray."""

    def __init__(self, buf: bytearray, start: int, end: int):
        self.buf, self.start, self.end = buf, start, end

    def __setitem__(self, sl: slice, value) -> None:
        a = self.start + (sl.start or 0)
        z = min(self.start + sl.stop, self.end)
        if z > a:
            self.buf[a:z] = bytes(value)[:z - a]


# -- NTLMSSP -----------------------------------------------------------------

def _field(b: bytes, off: int) -> tuple[int, int]:
    """(length, offset) of an NTLM (len, maxlen, offset) field."""
    if off + 8 > len(b):
        return 0, 0
    n, _, pos = struct.unpack_from("<HHI", b, off)
    if pos + n > len(b):
        return 0, 0
    return n, pos


def _ntlm(b: bytes, out: _View, m: Mapper) -> None:
    if len(b) < 12:
        return
    out[0:12] = b[0:12]
    mtype = struct.unpack_from("<I", b, 8)[0]
    if mtype == 1 and len(b) >= 16:
        _fixed(b, out, 12, 40, (16, 24))  # flags, descriptors, version
        _name(b, out, 16, m.name, False)
        _name(b, out, 24, m.name, False)
    elif mtype == 2 and len(b) >= 24:
        _fixed(b, out, 12, 24, (12, 40))  # target name descriptor, flags
        _fixed(b, out, 32, 56, (12, 40))  # target info descriptor, version
        unicode = bool(struct.unpack_from("<I", b, 20)[0] & 1)
        _name(b, out, 12, m.name, unicode)
        n, pos = _field(b, 40)
        _av_pairs(b, out, pos, pos + n, m)
    elif mtype == 3 and len(b) >= 64:
        # Descriptors, flags and version; the MIC after them is zeroed.
        _fixed(b, out, 12, 72, (12, 20, 28, 36, 44, 52))
        unicode = bool(struct.unpack_from("<I", b, 60)[0] & 1)
        _name(b, out, 28, m.name, unicode)
        _name(b, out, 36, m.user, unicode)
        _name(b, out, 44, m.name, unicode)


def _fixed(b: bytes, out: _View, start: int, end: int, descs) -> None:
    """Copy fixed fields, stopping where the payload starts (messages
    without the optional version have it earlier)."""
    for d in descs:
        n, pos = _field(b, d)
        if n and pos < end:
            end = pos
    if end > start:
        out[start:end] = b[start:end]


def _name(b: bytes, out: _View, desc: int, fn, unicode: bool) -> None:
    n, pos = _field(b, desc)
    if not n:
        return
    raw = bytes(b[pos:pos + n])
    if unicode and n % 2 == 0:
        text = raw.decode("utf-16-le", "surrogatepass")
        out[pos:pos + n] = fn(text).encode("utf-16-le", "surrogatepass")
    else:
        out[pos:pos + n] = fn(raw.decode("latin-1")).encode("latin-1")


def _av_pairs(b: bytes, out: _View, off: int, end: int, m: Mapper) -> None:
    """MsvAv pairs: names replaced, flags and timestamp kept, the rest
    (channel bindings, single-host data) zeroed."""
    while off + 4 <= end:
        aid, n = struct.unpack_from("<HH", b, off)
        out[off:off + 4] = b[off:off + 4]
        v0, v1 = off + 4, min(off + 4 + n, end)
        if aid == 0:
            return
        if aid in (1, 2, 3, 4, 5, 9) and n % 2 == 0:
            text = bytes(b[v0:v1]).decode("utf-16-le", "surrogatepass")
            out[v0:v1] = m.name(text).encode("utf-16-le", "surrogatepass")
        elif aid in (6, 7):
            out[v0:v1] = b[v0:v1]
        off = v1
