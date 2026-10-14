"""Samba's struct profile_stats: its counters in order, learned from
`smbstatus --profile`, checked against the magic smbd stamps on each
record, and the words of a record."""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass

# smbprofile.h: SMBPROFILE_STATS_SECTION_START(name, display)
SECTION_IDS = {
    "SMBD loop": "global", "Authentication": "global",
    "System Calls": "syscall", "ACL Calls": "acl", "Stat Cache": "statcache",
    "SMB Calls": "SMB", "Trans2 Calls": "Trans2",
    "NT Transact Calls": "NT_transact", "SMB2 Calls": "smb2",
}

# Field orders of the counter kinds, longest first.
KINDS = (
    ("iobytes", ("count", "failed_count", "time", "buckets", "idle",
                 "inbytes", "outbytes")),
    ("iobytes", ("count", "time", "idle", "inbytes", "outbytes")),
    ("bytes", ("count", "time", "idle", "bytes")),
    ("basic", ("count", "time")),
    ("count", ("count",)),
    ("time", ("time",)),
)
NBUCKETS = 10
BUCKET_MS = (1, 2, 4, 8, 16, 32, 64, 128, 256, None)  # below; None: all
GAUGES = ("num_sessions", "num_tcons", "num_files")
CPU = ("cpu_user", "cpu_system")


class LayoutError(Exception):
    pass


@dataclass
class Counter:
    name: str
    section: str
    kind: str
    fields: tuple[str, ...]
    offset: int = 0

    @property
    def width(self) -> int:
        return sum(NBUCKETS if f == "buckets" else 1 for f in self.fields)

    def slots(self):
        """(field, first word, words) for each field."""
        i = self.offset
        for f in self.fields:
            n = NBUCKETS if f == "buckets" else 1
            yield f, i, n
            i += n


class Layout:
    def __init__(self, counters: list[Counter]) -> None:
        self.counters = counters
        i = 0
        for c in counters:
            c.offset = i
            i += c.width
        self.words = i
        self.by_name = {c.name: c for c in counters}
        self.sections = list(dict.fromkeys(c.section for c in counters))
        self.gauge_words = [self.by_name[g].offset for g in GAUGES
                            if g in self.by_name]
        self.cpu_words = [self.by_name[c].offset for c in CPU
                          if c in self.by_name]
        self._unpack = struct.Struct(f"<{self.words}Q")

    @classmethod
    def from_profile_text(cls, text: str) -> "Layout":
        items: list[tuple[str, str]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.fullmatch(r"\*+ (.*?) \*+", line)
            if m:
                items.append(("section", m.group(1)))
            elif ":" in line:
                items.append(("key", line.split(":", 1)[0].strip()))
        counters: list[Counter] = []
        section = ""
        i = 0
        while i < len(items):
            kind, v = items[i]
            if kind == "section":
                section = v
                i += 1
                continue
            for k, fields in KINDS:
                if not v.endswith("_" + fields[0]):
                    continue
                name = v[:-len(fields[0]) - 1]
                if items[i:i + len(fields)] == [
                        ("key", f"{name}_{f}") for f in fields]:
                    counters.append(Counter(name, section, k, fields))
                    i += len(fields)
                    break
            else:
                raise LayoutError(f"cannot place {v!r}")
        if not counters:
            raise LayoutError("no counters in smbstatus --profile output")
        return cls(counters)

    def to_json(self) -> list:
        return [[c.section, c.name, c.kind, list(c.fields)]
                for c in self.counters]

    @classmethod
    def from_json(cls, obj: list) -> "Layout":
        return cls([Counter(n, s, k, tuple(f)) for s, n, k, f in obj])

    def record_sizes(self) -> dict[int, int]:
        """Record size -> header size: magic and summary_record (4.22+),
        or magic alone."""
        return {16 + 8 * self.words: 16, 8 + 8 * self.words: 8}

    def magic(self, header: int = 16) -> int | None:
        """smbprofile_magic(): SHA1 over the zeroed struct and the
        counter names; None when a section is unknown."""
        h = hashlib.sha1(bytes(header + 8 * self.words))
        section = None
        for c in self.counters:
            if c.section != section:
                section = c.section
                if section not in SECTION_IDS:
                    return None
                h.update(f'{SECTION_IDS[section]}+"{section}"'.encode())
            for f in c.fields:
                if f not in ("failed_count", "buckets"):
                    h.update(f"{c.name}+{f}".encode())
        return int.from_bytes(h.digest()[:8], "little")

    def unpack(self, blob: bytes) -> tuple[int, bool, tuple[int, ...]]:
        """(magic, summary_record, words) of a record."""
        header = self.record_sizes().get(len(blob))
        if header is None:
            raise LayoutError(f"record of {len(blob)} bytes, layout needs "
                              f"{16 + 8 * self.words}")
        magic = int.from_bytes(blob[:8], "little")
        summary = header == 16 and blob[8] != 0
        return magic, summary, self._unpack.unpack_from(blob, header)

    def sparse(self, words) -> dict:
        """The nonzero fields of each counter: {name: {field: value}};
        buckets stay a list."""
        out = {}
        for c in self.counters:
            if not any(words[c.offset:c.offset + c.width]):
                continue
            d = {}
            for f, i, n in c.slots():
                if n == 1:
                    if words[i]:
                        d[f] = words[i]
                elif any(words[i:i + n]):
                    d[f] = list(words[i:i + n])
            out[c.name] = d
        return out
