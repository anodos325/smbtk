"""Keyed, consistent replacements: names, addresses, SIDs, GUIDs.

Every replacement is a function of a secret key and the original value:
the same value maps to the same replacement throughout a capture, and
across captures anonymized with the same key; nothing maps back without
the key and the original. Replacements keep their length (in UTF-16 code
units for names), since the protocol states lengths elsewhere.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import struct

ALNUM = ("abcdefghijklmnopqrstuvwxyz"
         "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
# Characters that shape a name and say nothing about it.
PUNCT = set(" .,;:'\"!#$%&()[]{}+-=@^_`~|<>?*\\/")
KEEP_NAMES = {
    "", ".", "..", "*", "*.*", ".ds_store", "desktop.ini", "thumbs.db",
    ".localized", ".trashes", ".fseventsd", ".spotlight-v100",
    ".temporaryitems", ".apdisk", ".hidden", "autorun.inf", "ipc$", "c$",
    "admin$", "print$", "srvsvc", "wkssvc", "lsarpc", "samr", "netlogon",
    "spoolss", "winreg", "netdfs", "mdssvc", "cifs", "host", "krbtgt",
    "workgroup", "nt authority", "builtin", "localhost", "anonymous",
    "guest", "administrator", "root", "nobody", "$data", "$extend", "$i30",
    "afp_afpinfo", "afp_resource", "com.apple.resourcefork",
    "com.apple.finderinfo", "com.apple.quarantine", "zone.identifier",
    "not_defined_in_rfc4178@please_ignore",
}
IPV4_TEXT = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
# (prefix, prefix length): addresses keep these bits, so private stays
# private and link-local stays link-local.
V4_KEEP = [
    (0x0A000000, 8), (0xAC100000, 12), (0xC0A80000, 16), (0xA9FE0000, 16),
    (0x64400000, 10), (0x7F000000, 8), (0x00000000, 8),
]


def new_key() -> bytes:
    return secrets.token_bytes(32)


def load_key(path: str) -> bytes:
    """A 32-byte key kept in `path` as hex; created there if missing."""
    try:
        with open(path, "rb") as f:
            key = bytes.fromhex(f.read().decode("ascii").strip())
    except FileNotFoundError:
        key = new_key()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key.hex() + "\n")
    if len(key) != 32:
        raise ValueError(f"{path}: key must be 32 bytes (64 hex digits)")
    return key


class Mapper:
    def __init__(self, key: bytes, keep_ext: bool = True):
        self.key = key
        self.keep_ext = keep_ext
        self.streams: dict[tuple[str, str], bytes] = {}
        self.seen: dict[tuple[str, str], str] = {}
        self.v4: dict[bytes, bytes] = {}
        self.v6: dict[bytes, bytes] = {}
        self.macs: dict[bytes, bytes] = {}
        self.sids: dict[bytes, bytes] = {}
        self.guids: dict[bytes, bytes] = {}

    def _prf(self, *parts: bytes) -> bytes:
        return hmac.new(self.key, b"\0".join(parts), hashlib.sha256).digest()

    # -- permutations -------------------------------------------------------

    def _feistel(self, value: int, bits: int, ctx: bytes) -> int:
        """A keyed permutation of `bits`-bit values (bits even)."""
        half = bits // 2
        mask = (1 << half) - 1
        left, right = value >> half, value & mask
        for r in range(6):
            f = self._prf(b"f", ctx, bytes([r]), right.to_bytes(4, "big"))
            left, right = right, left ^ (int.from_bytes(f[:4], "big") & mask)
        return (left << half) | right

    def _permute_in(self, value: int, bits: int, ctx: bytes, allowed) -> int:
        """Permute within the set `value` belongs to (cycle walking)."""
        if not allowed(value):
            return value
        x = value
        while True:
            x = self._feistel(x, bits, ctx)
            if allowed(x):
                return x

    # -- addresses ----------------------------------------------------------

    def ipv4(self, b: bytes) -> bytes:
        hit = self.v4.get(b)
        if hit is not None:
            return hit
        v = int.from_bytes(b, "big")
        if v >> 28 >= 0xE or v == 0xFFFFFFFF:  # multicast, broadcast
            out = b
        else:
            keep = 0
            for prefix, plen in V4_KEEP:
                if v >> (32 - plen) == prefix >> (32 - plen):
                    keep = plen
                    break
            if keep == 8 and b[0] in (0, 127):
                out = b
            else:
                out = bytearray(b)
                for i in range(4):
                    lo_bit = 8 * (i + 1)
                    if lo_bit <= keep:
                        continue
                    fixed = max(0, keep - 8 * i)  # leading bits kept
                    lo, hi = _digit_class(b[i])
                    if i == 0:
                        hi = min(hi, 223)
                    top = b[i] >> (8 - fixed) if fixed else 0

                    def allowed(x, lo=lo, hi=hi, fixed=fixed, top=top, i=i):
                        if not lo <= x <= hi:
                            return False
                        if fixed and x >> (8 - fixed) != top:
                            return False
                        return not (i == 0 and x in (0, 10, 127))

                    out[i] = self._permute_in(b[i], 8, b"v4" + bytes([i])
                                              + bytes(out[:i]), allowed)
                out = bytes(out)
        self.v4[b] = out
        return out

    def ipv6(self, b: bytes) -> bytes:
        hit = self.v6.get(b)
        if hit is not None:
            return hit
        groups = list(struct.unpack(">8H", b))
        if groups[:5] == [0] * 5 and groups[5] == 0xFFFF:  # v4-mapped
            out = b[:12] + self.ipv4(b[12:])
        elif b[0] == 0xFF or groups[:7] == [0] * 7:  # multicast, ::, ::1
            out = b
        else:
            res = []
            for i, g in enumerate(groups):
                if i == 0:
                    if g == 0xFE80:
                        res.append(g)
                        continue
                    if 0xFC00 <= g <= 0xFDFF:
                        lo, hi = 0xFC00, 0xFDFF
                    elif 0x2000 <= g <= 0x3FFF:
                        lo, hi = 0x2000, 0x3FFF
                    else:
                        res.append(g)
                        continue
                elif g == 0:
                    res.append(0)
                    continue
                else:
                    lo, hi = 1, 0xFFFF
                ctx = b"v6" + bytes([i]) + struct.pack(f">{i}H", *res)
                res.append(self._permute_in(
                    g, 16, ctx, lambda x, lo=lo, hi=hi: lo <= x <= hi))
            out = struct.pack(">8H", *res)
        self.v6[b] = out
        return out

    def ip(self, b: bytes) -> bytes:
        return self.ipv4(b) if len(b) == 4 else self.ipv6(b)

    def ipv4_text(self, text: str) -> str | None:
        m = IPV4_TEXT.match(text)
        if not m or any(int(g) > 255 for g in m.groups()):
            return None
        groups = [int(g) for g in m.groups()]
        if any(len(g) != len(str(int(g))) for g in m.groups()):
            return None  # leading zeros: leave to the name mapping
        out = self.ipv4(bytes(groups))
        return ".".join(str(x) for x in out)

    def mac(self, b: bytes) -> bytes:
        """Unicast MACs keep their vendor prefix."""
        if len(b) != 6 or b[0] & 1 or not any(b):
            return b
        hit = self.macs.get(b)
        if hit is None:
            hit = b[:3] + self._prf(b"mac", b)[:3]
            self.macs[b] = hit
        return hit

    def guid(self, b: bytes) -> bytes:
        if len(b) != 16 or not any(b):
            return b
        hit = self.guids.get(b)
        if hit is None:
            hit = self._prf(b"guid", b)[:16]
            self.guids[b] = hit
        return hit

    # -- names --------------------------------------------------------------

    def token(self, kind: str, text: str) -> str:
        """Same length and punctuation as `text`, letters and digits
        replaced; the same name in any case maps the same way."""
        low = text.casefold()
        if low in KEEP_NAMES:
            return text
        key = (kind, low)
        stream = self.streams.get(key)
        if stream is None:
            stream = self._prf(b"n", kind.encode(),
                               low.encode("utf-8", "surrogatepass"))
            self.streams[key] = stream
        keep = [c in PUNCT for c in text]
        if kind == "file" and self.keep_ext:
            dot = text.rfind(".")
            ext = text[dot + 1:]
            if 0 < dot and 1 <= len(ext) <= 5 and ext.isalnum():
                for i in range(dot + 1, len(text)):
                    keep[i] = True
        out = []
        pos = 0
        for i, c in enumerate(text):
            if keep[i]:
                out.append(c)
                continue
            for _ in range(2 if ord(c) > 0xFFFF else 1):
                if pos >= len(stream):
                    stream = self._prf(b"n+", stream)
                    pos = 0
                out.append(ALNUM[stream[pos] % len(ALNUM)])
                pos += 1
        res = "".join(out)
        self.seen.setdefault(key, f"{text} -> {res}")
        return res

    def name(self, text: str) -> str:
        """A host, domain or realm: NetBIOS, DNS (label by label, so
        TRUENAS and truenas.example.com agree), SPN or address."""
        if "/" in text:  # service/host[:port]
            svc, _, rest = text.partition("/")
            host, colon, port = rest.partition(":")
            return svc + "/" + self.name(host) + colon + port
        mapped = self.ipv4_text(text)
        if mapped:
            return mapped
        return ".".join(self.token("name", label)
                        for label in text.split("."))

    def user(self, text: str) -> str:
        """DOMAIN\\user, user@realm or a bare account name."""
        if "\\" in text:
            dom, _, acct = text.partition("\\")
            return self.name(dom) + "\\" + self.token("user", acct)
        acct, at, realm = text.partition("@")
        return self.token("user", acct) + at + (self.name(realm) if at
                                                 else "")

    def share(self, text: str) -> str:
        return self.token("share", text)

    def path(self, text: str) -> str:
        """Every component of a path; separators, wildcards and stream
        suffixes stay."""
        parts = re.split(r"([\\/])", text)
        for i, p in enumerate(parts):
            if p in ("\\", "/") or not p:
                continue
            if p.startswith("._"):  # AppleDouble file of the same name
                parts[i] = "._" + self.path(p[2:])
                continue
            base, colon, stream = p.partition(":")
            if colon:
                sname, c2, stype = stream.partition(":")
                stream = self.token("stream", sname) + c2 + stype
            parts[i] = self.token("file", base) + colon + stream
        return "".join(parts)

    def unc(self, text: str) -> str:
        """\\\\server\\share\\path."""
        if text.startswith("\\\\") or text.startswith("//"):
            sep = text[0]
            rest = text[2:].split(sep, 2)
            out = [self.name(rest[0])]
            if len(rest) > 1:
                out.append(self.share(rest[1]))
            if len(rest) > 2:
                out.append(self.path(rest[2]))
            return sep * 2 + sep.join(out)
        return self.path(text)

    # -- SIDs ---------------------------------------------------------------

    def sid(self, b: bytes) -> bytes:
        """Domain SIDs keep their shape (the domain part and RIDs from
        1000 up are permuted); Unix-id SIDs (S-1-22) are permuted;
        well-known SIDs stay."""
        if len(b) < 8 or len(b) < 8 + 4 * b[1]:
            return b
        hit = self.sids.get(b)
        if hit is not None:
            return hit
        count = b[1]
        auth = int.from_bytes(b[2:8], "big")
        subs = list(struct.unpack_from(f"<{count}I", b, 8))
        if auth == 5 and count >= 4 and subs[0] == 21:
            for i in (1, 2, 3):
                subs[i] = self._feistel(subs[i], 32, b"sid" + bytes([i]))
            if count >= 5 and subs[4] >= 1000:
                subs[4] = self._permute_in(subs[4], 32, b"rid",
                                           lambda x: x >= 1000)
        elif auth == 22 and count == 2:
            subs[1] = self._feistel(subs[1], 32, b"unix" + bytes([subs[0]]))
        else:
            self.sids[b] = b
            return b
        out = b[:8] + struct.pack(f"<{count}I", *subs)
        self.sids[b] = out
        return out

    # -- the table for the owner --------------------------------------------

    def table(self) -> dict:
        names: dict[str, list[str]] = {}
        for (kind, _), pair in sorted(self.seen.items()):
            names.setdefault(kind, []).append(pair)

        def ip_text(a: bytes) -> str:
            return str(ipaddress.ip_address(a))

        return {
            "names": names,
            "ipv4": {ip_text(k): ip_text(v) for k, v in sorted(self.v4.items())
                     if k != v},
            "ipv6": {ip_text(k): ip_text(v) for k, v in sorted(self.v6.items())
                     if k != v},
            "mac": {k.hex(":"): v.hex(":")
                    for k, v in sorted(self.macs.items())},
            "sid": {sid_text(k): sid_text(v)
                    for k, v in sorted(self.sids.items()) if k != v},
            "guid": {k.hex(): v.hex() for k, v in sorted(self.guids.items())},
        }

    def counts(self) -> dict[str, int]:
        kinds: dict[str, int] = {}
        for kind, _ in self.seen:
            kinds[kind] = kinds.get(kind, 0) + 1
        t = self.table()
        kinds["address"] = len(t["ipv4"]) + len(t["ipv6"])
        kinds["mac"] = len(t["mac"])
        kinds["sid"] = len(t["sid"])
        kinds["guid"] = len(t["guid"])
        return {k: v for k, v in kinds.items() if v}


def _digit_class(v: int) -> tuple[int, int]:
    if v < 10:
        return 0, 9
    if v < 100:
        return 10, 99
    return 100, 255


def sid_text(b: bytes) -> str:
    count = b[1]
    auth = int.from_bytes(b[2:8], "big")
    subs = struct.unpack_from(f"<{count}I", b, 8)
    return "S-%d-%d" % (b[0], auth) + "".join(f"-{s}" for s in subs)
