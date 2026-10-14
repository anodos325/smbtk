"""The records of a tdb file: through Samba's tdb bindings when they
import (locked reads), else read here, lock-free, from the hash chains."""

from __future__ import annotations

import glob
import os
import struct
import sys
import time

VERSION = 0x26011967 + 6
REC_MAGIC = 0x26011999
DEAD_MAGIC = 0xFEE1DEAD
FEATURE_FLAG_MAGIC = 0x0BAD1A52
FEATURE_MUTEX = 1
HEADER_SIZE = 168


class TdbError(Exception):
    pass


def parse(buf: bytes) -> dict[bytes, bytes]:
    """Live records of a tdb image. A mutex tdb keeps its data behind the
    mutex area, at the offset its first header gives."""
    if not buf.startswith(b"TDB file\n") or len(buf) < HEADER_SIZE:
        raise TdbError("not a tdb file")
    for e in "<>":
        if struct.unpack_from(e + "I", buf, 32)[0] == VERSION:
            break
    else:
        raise TdbError("unknown tdb version")
    _, rwlocks, _, _, _, _, features, mutex_size = struct.unpack_from(
        e + "8I", buf, 36)
    base = 0
    if rwlocks == FEATURE_FLAG_MAGIC and features & FEATURE_MUTEX:
        base = mutex_size
        if buf[base:base + 9] != b"TDB file\n":
            raise TdbError("no header behind the mutex area")
    hash_size = struct.unpack_from(e + "I", buf, base + 36)[0]
    if hash_size == 0 or base + HEADER_SIZE + 4 * (hash_size + 1) > len(buf):
        raise TdbError("bad hash size")
    rec = struct.Struct(e + "6I")
    heads = struct.unpack_from(f"{e}{hash_size}I", buf, base + HEADER_SIZE + 4)
    out: dict[bytes, bytes] = {}
    seen: set[int] = set()
    for off in heads:
        while off:
            if off in seen:
                raise TdbError("hash chain loops")
            seen.add(off)
            p = base + off
            if p + rec.size > len(buf):
                raise TdbError("record past the end")
            nxt, rec_len, key_len, data_len, _, magic = rec.unpack_from(buf, p)
            if magic == REC_MAGIC:
                k = p + rec.size
                if key_len + data_len > rec_len or k + rec_len > len(buf):
                    raise TdbError("bad record length")
                v = k + key_len
                out[buf[k:v]] = buf[v:v + data_len]
            elif magic != DEAD_MAGIC:
                raise TdbError(f"bad record magic {magic:#x}")
            off = nxt
    return out


def _bindings(prefix: str | None):
    """Samba's tdb module, from `prefix`'s site-packages first."""
    if prefix:
        v = f"python{sys.version_info.major}.{sys.version_info.minor}"
        for d in glob.glob(os.path.join(prefix, "lib*", v, "*-packages")):
            if d not in sys.path:
                sys.path.insert(0, d)
    try:
        import tdb
    except ImportError:
        return None
    return tdb


def wipe(path: str, prefix: str | None = None) -> None:
    """Delete every record, through a handle opened just now.

    Not `smbcontrol PID profile flush`: smbd wipes through a handle whose
    idea of the file size dates from when it opened the file. Records
    past that size stay behind unlisted, the next growth is merged into
    them and lost, and the file grows to 4 GB while every store fails.
    A fresh handle sees the whole file."""
    mod = _bindings(prefix)
    if mod is None:
        raise TdbError("resetting needs Samba's tdb Python module")
    with open(path, "rb") as f:
        head = f.read(HEADER_SIZE)
    flags = 0
    if len(head) == HEADER_SIZE:
        rwlocks, features = struct.unpack_from("=I", head, 40)[0], \
            struct.unpack_from("=I", head, 60)[0]
        if rwlocks == FEATURE_FLAG_MAGIC and features & FEATURE_MUTEX:
            flags = mod.MUTEX_LOCKING
    db = mod.Tdb(path, 0, flags, os.O_RDWR)
    try:
        db.clear()
    finally:
        db.close()


class Reader:
    """Snapshots of one tdb file. Opened per read: smbd truncates the
    file when it restarts, under a long-lived mapping."""

    def __init__(self, path: str, prefix: str | None = None,
                 bindings: bool = True) -> None:
        self.path = path
        self.mod = _bindings(prefix) if bindings else None

    @property
    def how(self) -> str:
        return "tdb bindings" if self.mod else "built-in reader"

    def _locked(self) -> dict[bytes, bytes]:
        db = self.mod.Tdb(self.path, 0, self.mod.DEFAULT, os.O_RDONLY)
        try:
            out = {}
            for k in db.keys():
                v = db.get(k)
                if v is not None:
                    out[k] = v
            return out
        finally:
            db.close()

    def read(self, tries: int = 5) -> dict[bytes, bytes]:
        last: Exception | None = None
        for _ in range(tries):
            try:
                if self.mod:
                    return self._locked()
                with open(self.path, "rb") as f:
                    return parse(f.read())
            except (TdbError, RuntimeError) as e:
                last = e
                time.sleep(0.002)
        raise TdbError(f"{self.path}: {last}")
