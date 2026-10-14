"""What to do with each SMB PDU: which to buffer, and how to rewrite
the bodies that carry names, credentials or bulk data.

Anonymizing starts every buffered PDU zeroed and copies back only what
a handler knows to be safe (deny by default); trimming starts from a
copy and only cuts.
"""

from __future__ import annotations

import struct

from . import gss
from .engine import Conn, Edit
from .mapping import Mapper

MAGIC2, MAGIC1, MAGIC_TF, MAGIC_CMP = (b"\xfeSMB", b"\xffSMB", b"\xfdSMB",
                                       b"\xfcSMB")
(NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT, TREE_DISCONNECT, CREATE,
 CLOSE, FLUSH, READ, WRITE, LOCK, IOCTL, CANCEL, ECHO, QUERY_DIRECTORY,
 CHANGE_NOTIFY, QUERY_INFO, SET_INFO, OPLOCK_BREAK) = range(19)

STATUS_NOTIFY_ENUM_DIR = 0x10C
STATUS_BUFFER_OVERFLOW = 0x80000005
STATUS_STOPPED_ON_SYMLINK = 0x8000002D
STATUS_BUFFER_TOO_SMALL = 0xC0000023
TRANSFORM_HEADER = 52

FSCTL_DFS_GET_REFERRALS = 0x00060194
FSCTL_PIPE_PEEK = 0x0011400C
FSCTL_PIPE_TRANSCEIVE = 0x0011C017
FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC
FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204
# Buffers that hold only sizes, offsets, flags, times and opaque tokens.
IOCTL_KEEP = {
    0x00144064, 0x00140078, 0x001440F2, 0x001480F2, 0x000940CF, 0x000980C8,
    0x00098208, 0x001401D4, 0x000900C4, 0x0009C040, 0x0009003C, 0x00098344,
    0x00090284, 0x00094264, 0x00098268,
}
IOCTL_BULK = {FSCTL_PIPE_TRANSCEIVE, FSCTL_PIPE_PEEK}
POSIX_CONTEXT = bytes.fromhex("93AD25509CB411E7B42383DE968BCD7C")

# Directory entry layouts: (name length offset, name offset,
# short name length offset, short name offset).
FIND_LAYOUT = {
    1: (60, 64, None, None), 2: (60, 68, None, None), 3: (60, 94, 68, 70),
    12: (8, 12, None, None), 37: (60, 104, 68, 70), 38: (60, 80, None, None),
    60: (60, 88, None, None),
}
FILE_NUMERIC = {4, 5, 6, 7, 8, 13, 14, 16, 17, 19, 20, 23, 24, 28, 29, 34,
                35, 39, 55, 59, 64, 68, 70, 71}
FILE_NAMED = {9, 21, 40, 48, 49, 58}
FILE_RENAME = {10, 11, 65, 66, 72, 73}
FILE_POSIX = 100
FS_NUMERIC = {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}

# Bodies with nothing to rewrite.
KEEP_RESP = {LOGOFF, TREE_CONNECT, TREE_DISCONNECT, CLOSE, FLUSH, WRITE,
             LOCK, ECHO, SET_INFO, OPLOCK_BREAK, CANCEL}
KEEP_REQ = {LOGOFF, TREE_DISCONNECT, CLOSE, FLUSH, READ, LOCK, CANCEL, ECHO,
            CHANGE_NOTIFY, OPLOCK_BREAK}


class Short(Exception):
    pass


def u8(b, o):
    if o < 0 or o + 1 > len(b):
        raise Short
    return b[o]


def u16(b, o):
    if o < 0 or o + 2 > len(b):
        raise Short
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    if o < 0 or o + 4 > len(b):
        raise Short
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    if o < 0 or o + 8 > len(b):
        raise Short
    return struct.unpack_from("<Q", b, o)[0]


def is_error(cmd: int, status: int, ssize: int) -> bool:
    """An error response body, as tshark decides it."""
    if not status or ssize != 9 or cmd == SESSION_SETUP:
        return False
    if cmd == CHANGE_NOTIFY and status == STATUS_NOTIFY_ENUM_DIR:
        return False
    return not (cmd == IOCTL and status == STATUS_BUFFER_OVERFLOW)


def drop_buffer(e: Edit, a: int, z: int, end: int) -> None:
    """Drop a message's buffer, and the padding after it when it is the
    message's last field."""
    e.drop(a, end if end - z < 8 else z)


class Handlers:
    def __init__(self, mapper: Mapper | None, full: bool = False):
        self.m = mapper
        self.anon = mapper is not None
        self.full = full
        self.encrypted = 0
        bulk = {
            (READ, True): self._read_resp,
            (WRITE, False): self._write_req,
            (IOCTL, False): self._ioctl_req,
            (IOCTL, True): self._ioctl_resp,
            (QUERY_DIRECTORY, True): self._find_resp,
            (CHANGE_NOTIFY, True): self._notify_resp,
        }
        self.table = dict(bulk)
        if self.anon:
            self.table.update({
                (NEGOTIATE, False): self._negotiate_req,
                (NEGOTIATE, True): self._negotiate_resp,
                (SESSION_SETUP, False): self._session_setup_req,
                (SESSION_SETUP, True): self._session_setup_resp,
                (TREE_CONNECT, False): self._tree_connect_req,
                (CREATE, False): self._create_req,
                (CREATE, True): self._create_resp,
                (QUERY_DIRECTORY, False): self._find_req,
                (QUERY_INFO, False): self._query_info_req,
                (QUERY_INFO, True): self._query_info_resp,
                (SET_INFO, False): self._set_info_req,
            })

    # -- classification ----------------------------------------------------------

    def classify(self, head: bytes, total: int) -> tuple[str, int]:
        """('data', offset) to cut everything from offset on as it
        streams by, 'buffer' for PDUs a handler must see whole, 'keep'
        or 'zero'."""
        magic = head[4:8]
        deny = "zero" if self.anon else "keep"
        try:
            if magic == MAGIC2:
                return self._classify2(head, total)
            if magic == MAGIC1:
                if not self.anon or (u8(head, 8) == 0x72
                                     and not u8(head, 13) & 0x80):
                    return "keep", 0
                return "buffer", 0
            if magic == MAGIC_TF:
                self.encrypted += 1
                return "data", 4 + TRANSFORM_HEADER
            if magic == MAGIC_CMP:
                return ("data", 4 + 16) if self.anon else ("keep", 0)
        except Short:
            pass
        return deny, 0

    def _classify2(self, head: bytes, total: int) -> tuple[str, int]:
        h, body = 4, 68
        status, cmd = u32(head, h + 8), u16(head, h + 12)
        resp = bool(u32(head, h + 16) & 1)
        nxt = u32(head, h + 20)
        ssize = u16(head, body)
        if nxt:
            return "buffer", 0
        if resp and is_error(cmd, status, ssize):
            return ("buffer", 0) if self.anon else ("keep", 0)
        start = self._bulk_start(head, cmd, resp, ssize)
        if start is not None:
            return "data", start
        if (cmd, resp) in self.table:
            return "buffer", 0
        if not self.anon:
            return "keep", 0
        if (resp and cmd in KEEP_RESP) or (not resp and cmd in KEEP_REQ):
            return "keep", 0
        return "buffer", 0

    def _bulk_start(self, head: bytes, cmd: int, resp: bool,
                    ssize: int) -> int | None:
        """Where a lone PDU's bulk payload starts, if it has one."""
        body = 68
        if cmd == READ and resp and ssize == 17:
            return 4 + max(u8(head, body + 2), 80)
        if cmd == WRITE and not resp and ssize == 49:
            return 4 + max(u16(head, body + 2), 112)
        if cmd in (QUERY_DIRECTORY, CHANGE_NOTIFY) and resp and ssize == 9 \
                and not self.full and u32(head, body + 4):
            return 4 + max(u16(head, body + 2), 72)
        if cmd == IOCTL and u32(head, body + 4) in IOCTL_BULK:
            if not resp and ssize == 57:
                off, n = u32(head, body + 24), u32(head, body + 28)
                if n and not u32(head, body + 40):
                    return 4 + max(off, 120)
            if resp and ssize == 49:
                ins = u32(head, body + 28)
                off, n = u32(head, body + 32), u32(head, body + 36)
                if n and not ins:
                    return 4 + max(off, 112)
        return None

    # -- a whole PDU ---------------------------------------------------------------

    def handle(self, e: Edit, conn: Conn) -> None:
        b = e.buf
        e.keep(0, 4)
        magic = b[4:8]
        try:
            if magic == MAGIC2:
                off = 4
                while off + 64 <= len(b):
                    nxt = u32(b, off + 20)
                    end = off + nxt if nxt else len(b)
                    self._message(e, off, min(end, len(b)), conn)
                    if not nxt:
                        break
                    off = end
            elif magic == MAGIC1:
                self._smb1(e)
            elif magic == MAGIC_CMP:
                e.keep(4, 20)
            elif not self.anon:
                e.keep(4, len(b))
        except Short:
            pass

    def _message(self, e: Edit, hdr: int, end: int, conn: Conn) -> None:
        b = e.buf
        e.keep(hdr, hdr + 64)
        status, cmd = u32(b, hdr + 8), u16(b, hdr + 12)
        resp = bool(u32(b, hdr + 16) & 1)
        mid = u64(b, hdr + 24)
        body = hdr + 64
        ssize = u16(b, body)
        if resp and is_error(cmd, status, ssize):
            if self.anon:
                self._error(e, body, end, status)
            return
        fn = self.table.get((cmd, resp))
        if fn is not None:
            try:
                fn(e, hdr, body, end, conn, mid)
            except Short:
                pass
        elif not self.anon or (resp and cmd in KEEP_RESP) or (
                not resp and cmd in KEEP_REQ):
            e.keep(hdr, end)

    # -- helpers -----------------------------------------------------------------------

    def _utf16(self, e: Edit, a: int, z: int, fn) -> None:
        raw = bytes(e.buf[max(a, 0):z])
        n = len(raw) & ~1
        if not n:
            return
        text = raw[:n].decode("utf-16-le", "surrogatepass")
        e.put(a, fn(text).encode("utf-16-le", "surrogatepass"))

    def _blob(self, e: Edit, a: int, z: int) -> None:
        raw = bytes(e.buf[max(a, 0):z])
        if raw:
            e.put(a, gss.sanitize_blob(raw, self.m))

    def _guid(self, e: Edit, a: int) -> None:
        e.put(a, self.m.guid(bytes(e.buf[a:a + 16])))

    def _sid(self, e: Edit, a: int) -> int:
        count = u8(e.buf, a + 1)
        n = 8 + 4 * count
        e.put(a, self.m.sid(bytes(e.buf[a:a + n])))
        return n

    def _sd(self, e: Edit, a: int) -> None:
        b = e.buf
        e.keep(a, a + 20)
        owner, group, sacl, dacl = (u32(b, a + 4), u32(b, a + 8),
                                    u32(b, a + 12), u32(b, a + 16))
        for off in (owner, group):
            if off:
                self._sid(e, a + off)
        for off in (sacl, dacl):
            if off:
                self._acl(e, a + off)

    def _acl(self, e: Edit, a: int) -> None:
        b = e.buf
        e.keep(a, a + 8)
        off = a + 8
        for _ in range(u16(b, a + 4)):
            atype, asize = u8(b, off), u16(b, off + 2)
            e.keep(off, off + 8)
            p = off + 8
            if atype in (5, 6, 7, 8, 11, 12, 15, 16):  # object ACEs
                fl = u32(b, p)
                e.keep(p, p + 4)
                p += 4
                for bit in (1, 2):
                    if fl & bit:
                        e.keep(p, p + 16)
                        p += 16
            n = self._sid(e, p)
            if atype not in (9, 10, 11, 12, 13):  # callback ACEs: zeroed
                e.keep(p + n, off + asize)
            if asize < 8:
                return
            off += asize

    def _contexts(self, e: Edit, start: int, length: int, end: int,
                  fn) -> None:
        """Create contexts: name and framing kept, data passed to fn."""
        b = e.buf
        off = start
        stop = min(start + length, end)
        while off + 16 <= stop:
            nxt, toff, tlen = u32(b, off), u16(b, off + 4), u16(b, off + 6)
            doff, dlen = u16(b, off + 10), u32(b, off + 12)
            e.keep(off, off + 16)
            e.keep(off + toff, off + toff + tlen)
            fn(bytes(b[off + toff:off + toff + tlen]), off + doff,
               off + doff + dlen)
            if not nxt:
                break
            off += nxt

    # -- requests and responses ----------------------------------------------------------

    def _negotiate_req(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 36)
        self._guid(e, body + 12)
        count = u16(b, body + 2)
        e.keep(body + 36, body + 36 + 2 * count)
        ctx_off, ctx_count = u32(b, body + 28), u16(b, body + 32)
        if 0x311 in struct.unpack_from(f"<{count}H", b, body + 36):
            self._negotiate_contexts(e, hdr + ctx_off, ctx_count, end)

    def _negotiate_resp(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 64)
        self._guid(e, body + 8)
        off, n = u16(b, body + 56), u16(b, body + 58)
        self._blob(e, hdr + off, hdr + off + n)
        if u16(b, body + 4) == 0x311:
            self._negotiate_contexts(e, hdr + u32(b, body + 60),
                                     u16(b, body + 6), end)

    def _negotiate_contexts(self, e, off, count, end):
        b = e.buf
        for _ in range(count):
            if off + 8 > end:
                return
            ctype, clen = u16(b, off), u16(b, off + 2)
            e.keep(off, off + 8)
            if ctype == 5:  # NETNAME
                self._utf16(e, off + 8, off + 8 + clen, self.m.name)
            else:
                e.keep(off + 8, off + 8 + clen)
            off += 8 + ((clen + 7) & ~7)

    def _session_setup_req(self, e, hdr, body, end, conn, mid):
        e.keep(body, body + 24)
        off, n = u16(e.buf, body + 12), u16(e.buf, body + 14)
        self._blob(e, hdr + off, hdr + off + n)

    def _session_setup_resp(self, e, hdr, body, end, conn, mid):
        e.keep(body, body + 8)
        off, n = u16(e.buf, body + 4), u16(e.buf, body + 6)
        self._blob(e, hdr + off, hdr + off + n)

    def _tree_connect_req(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 8)
        flags, off, n = u16(b, body + 2), u16(b, body + 4), u16(b, body + 6)
        a = hdr + off
        if flags & 4:  # extension header, path, contexts (left zeroed)
            e.keep(a, a + 16)
            a += 16
        self._utf16(e, a, a + n, self.m.unc)

    def _create_req(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 56)
        noff, nlen = u16(b, body + 44), u16(b, body + 46)
        coff, clen = u32(b, body + 48), u32(b, body + 52)
        self._utf16(e, hdr + noff, hdr + noff + nlen, self.m.path)

        def ctx(tag, a, z):
            if tag == b"SecD":
                self._sd(e, a)
            elif tag != b"ExtA":  # EA names and values stay zeroed
                e.keep(a, z)

        if coff:
            self._contexts(e, hdr + coff, clen, end, ctx)

    def _create_resp(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 88)
        coff, clen = u32(b, body + 80), u32(b, body + 84)

        def ctx(tag, a, z):
            if tag == POSIX_CONTEXT:  # links, reparse tag, mode, two SIDs
                e.keep(a, a + 12)
                n = self._sid(e, a + 12)
                self._sid(e, a + 12 + n)
            else:
                e.keep(a, z)

        if coff:
            self._contexts(e, hdr + coff, clen, end, ctx)

    def _read_resp(self, e, hdr, body, end, conn, mid):
        e.keep(body, body + 16)
        e.drop(max(hdr + u8(e.buf, body + 2), body + 16), end)

    def _write_req(self, e, hdr, body, end, conn, mid):
        e.keep(body, body + 48)
        off, n = u16(e.buf, body + 2), u32(e.buf, body + 4)
        drop_buffer(e, max(hdr + off, body + 48), min(hdr + off + n, end),
                    end)

    def _ioctl_req(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 56)
        code = u32(b, body + 4)
        self._ioctl_buf(e, hdr, code, u32(b, body + 24), u32(b, body + 28),
                        False, end)

    def _ioctl_resp(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 48)
        code = u32(b, body + 4)
        self._ioctl_buf(e, hdr, code, u32(b, body + 24), u32(b, body + 28),
                        False, end)
        self._ioctl_buf(e, hdr, code, u32(b, body + 32), u32(b, body + 36),
                        True, end)

    def _ioctl_buf(self, e, hdr, code, off, n, output, end):
        if not n or not off:
            return
        a, z = hdr + off, min(hdr + off + n, end)
        if code in IOCTL_BULK:
            drop_buffer(e, a, z, end)
        elif not self.anon:
            return
        elif code in IOCTL_KEEP:
            e.keep(a, z)
        elif code == FSCTL_VALIDATE_NEGOTIATE_INFO:
            e.keep(a, z)
            self._guid(e, a + 4)
        elif code == FSCTL_QUERY_NETWORK_INTERFACE_INFO and output:
            self._netif(e, a, z)
        elif code == FSCTL_DFS_GET_REFERRALS and not output:
            e.keep(a, a + 2)
            self._utf16(e, a + 2, z, self.m.unc)

    def _netif(self, e, a, z):
        b = e.buf
        off = a
        while off + 152 <= z:
            nxt, fam = u32(b, off), u16(b, off + 24)
            e.keep(off, off + 152)
            if fam == 2:
                e.put(off + 28, self.m.ipv4(bytes(b[off + 28:off + 32])))
            elif fam == 0x17:
                e.put(off + 32, self.m.ipv6(bytes(b[off + 32:off + 48])))
            if not nxt:
                break
            off += nxt

    def _find_req(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 32)
        off, n = u16(b, body + 24), u16(b, body + 26)
        self._utf16(e, hdr + off, hdr + off + n, self.m.path)
        conn.reqs[mid] = ("find", u8(b, body + 2))

    def _find_resp(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 8)
        off, n = u16(b, body + 2), u32(b, body + 4)
        info = conn.reqs.pop(mid, None)
        a, z = max(hdr + off, body + 8), min(hdr + off + n, end)
        if not self.full or not self.anon:
            drop_buffer(e, a, z, end)
            return
        layout = FIND_LAYOUT.get(info[1]) if info and info[0] == "find" \
            else None
        if layout is None:
            return
        len_off, name_off, slen_off, sname_off = layout
        while a + name_off <= z:
            nxt, nlen = u32(b, a), u32(b, a + len_off)
            e.keep(a, a + name_off)
            self._utf16(e, a + name_off, a + name_off + nlen, self.m.path)
            if slen_off is not None:
                slen = u8(b, a + slen_off)
                self._utf16(e, a + sname_off, a + sname_off + slen,
                            self.m.path)
            if not nxt:
                break
            a += nxt

    def _notify_resp(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 8)
        off, n = u16(b, body + 2), u32(b, body + 4)
        a, z = max(hdr + off, body + 8), min(hdr + off + n, end)
        if not self.full or not self.anon:
            drop_buffer(e, a, z, end)
            return
        while a + 12 <= z:
            nxt, nlen = u32(b, a), u32(b, a + 8)
            e.keep(a, a + 12)
            self._utf16(e, a + 12, a + 12 + nlen, self.m.path)
            if not nxt:
                break
            a += nxt

    def _query_info_req(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 40)
        conn.reqs[mid] = ("info", u8(b, body + 2), u8(b, body + 3))

    def _query_info_resp(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 8)
        off, n = u16(b, body + 2), u32(b, body + 4)
        info = conn.reqs.pop(mid, None)
        if info and info[0] == "info":
            self._info(e, hdr + off, min(hdr + off + n, end), info[1],
                       info[2], True)

    def _set_info_req(self, e, hdr, body, end, conn, mid):
        b = e.buf
        e.keep(body, body + 32)
        n, off = u32(b, body + 4), u16(b, body + 8)
        self._info(e, hdr + off, min(hdr + off + n, end), u8(b, body + 2),
                   u8(b, body + 3), False)

    def _info(self, e, a, z, typ, cls, response):
        b = e.buf
        if typ == 1:
            if cls in FILE_NUMERIC:
                e.keep(a, z)
            elif cls == 18:  # FileAllInformation ends with the name
                e.keep(a, a + 100)
                self._utf16(e, a + 100, a + 100 + u32(b, a + 96), self.m.path)
            elif cls in FILE_NAMED:
                e.keep(a, a + 4)
                self._utf16(e, a + 4, a + 4 + u32(b, a), self.m.path)
            elif cls in FILE_RENAME and not response:
                e.keep(a, a + 20)
                self._utf16(e, a + 20, a + 20 + u32(b, a + 16), self.m.path)
            elif cls == 22:  # streams
                while a + 24 <= z:
                    nxt, nlen = u32(b, a), u32(b, a + 4)
                    e.keep(a, a + 24)
                    self._utf16(e, a + 24, a + 24 + nlen, self.m.path)
                    if not nxt:
                        break
                    a += nxt
            elif cls == 46:  # hard links
                e.keep(a, a + 8)
                p = a + 8
                while p + 16 <= z:
                    nxt, nlen = u32(b, p), u32(b, p + 12)
                    e.keep(p, p + 16)
                    self._utf16(e, p + 16, p + 16 + nlen, self.m.path)
                    if not nxt:
                        break
                    p += nxt
            elif cls == FILE_POSIX:  # SMB3 POSIX extensions: two SIDs last
                e.keep(a, a + 80)
                n = self._sid(e, a + 80)
                self._sid(e, a + 80 + n)
        elif typ == 2:
            if cls in FS_NUMERIC:
                e.keep(a, z)
            elif cls == 1:  # volume label
                e.keep(a, a + 18)
                self._utf16(e, a + 18, a + 18 + u32(b, a + 12), self.m.share)
        elif typ == 3:
            self._sd(e, a)
        elif typ == 4:  # quota entries
            while a + 40 <= z:
                nxt = u32(b, a)
                e.keep(a, a + 40)
                self._sid(e, a + 40)
                if not nxt:
                    break
                a += nxt

    def _error(self, e, body, end, status):
        b = e.buf
        e.keep(body, body + 8)
        count, bc = u8(b, body + 2), u32(b, body + 4)
        a = body + 8
        if status == STATUS_STOPPED_ON_SYMLINK:
            if not count:
                self._symlink(e, a)
                return
            for _ in range(count):
                dl, eid = u32(b, a), u32(b, a + 4)
                e.keep(a, a + 8)
                if eid == 0:
                    self._symlink(e, a + 8)
                a += (8 + dl + 7) & ~7
        elif status == STATUS_BUFFER_TOO_SMALL and bc == 4:
            e.keep(a, a + 4)

    def _symlink(self, e, a):
        b = e.buf
        e.keep(a, a + 28)
        pb = a + 28
        for off, n in ((u16(b, a + 16), u16(b, a + 18)),
                       (u16(b, a + 20), u16(b, a + 22))):
            self._utf16(e, pb + off, pb + off + n, self.m.path)

    # -- SMB1 ----------------------------------------------------------------------------------

    def _smb1(self, e: Edit) -> None:
        """Header and parameter words stay; the data block is zeroed
        except a session setup's or negotiate's security blob."""
        b = e.buf
        h = 4
        e.keep(h, h + 32)
        cmd, resp = u8(b, h + 4), u8(b, h + 9) & 0x80
        flags2 = u16(b, h + 10)
        wct = u8(b, h + 32)
        words = h + 33
        data = words + 2 * wct + 2
        e.keep(h + 32, data)
        if cmd == 0x72 and resp and wct == 17 and flags2 & 0x0800:
            self._guid(e, data)
            self._blob(e, data + 16, data + u16(b, data - 2))
        elif cmd == 0x73:
            if not resp and wct == 12:
                self._blob(e, data, data + u16(b, words + 14))
            elif resp and wct == 4:
                self._blob(e, data, data + u16(b, words + 6))
