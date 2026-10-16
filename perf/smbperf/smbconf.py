"""Samba's configuration: which shares there are, where they point, and
the settings that shape their I/O."""

from __future__ import annotations

import os
import re
import shutil
import subprocess

CANDIDATES = ("/etc/smb4.conf", "/etc/samba/smb.conf",
              "/usr/local/etc/smb4.conf", "/usr/local/etc/smb.conf")
# Settings of a share (or of [global]) that change how smbd reads and
# writes, in the order they are shown.
IO_PARAMS = (
    "vfs objects", "strict sync", "sync always", "strict allocate",
    "aio read size", "aio write size", "aio write behind", "use sendfile",
    "min receivefile size", "case sensitive", "ea support",
    "store dos attributes", "smbd max xattr size", "posix locking",
    "strict locking", "kernel oplocks", "oplocks", "level2 oplocks",
    "kernel share modes", "smb3 unix extensions", "read only",
    "fruit:metadata", "fruit:resource", "fruit:time machine",
    "shadow:snapdir", "zfs_core:zfs_block_cloning",
    "zfs_core:zfs_integrity_streams", "ixnas:dosattrib_xattr",
    "streams_xattr:prefix", "streams_xattr:store_stream_type",
    "io_uring:num_entries", "io_uring:sqpoll", "aio_pthread:aio open",
)
# Global settings that set the pace for every share: dialects,
# channels, encryption and signing, asynchronous I/O, sizes and credits,
# sockets, logging, locking and caching.
PERF_PARAMS = (
    "server min protocol", "server max protocol",
    "server multi channel support", "server smb encrypt", "server signing",
    "server smb3 encryption algorithms", "server smb3 signing algorithms",
    "aio max threads", "aio read size", "aio write size", "aio write behind",
    "smb2 max read", "smb2 max write", "smb2 max trans", "smb2 max credits",
    "socket options", "use sendfile", "min receivefile size",
    "large readwrite", "max connections", "deadtime", "log level",
    "max log size", "smbd profiling level", "durable handles",
    "smb2 leases", "kernel oplocks", "oplocks", "level2 oplocks",
    "strict locking", "posix locking", "kernel share modes",
    "change notify", "kernel change notify", "stat cache", "getwd cache",
    "ea support", "store dos attributes", "map archive", "map hidden",
    "map system", "map readonly", "dos filemode", "inherit acls",
    "nt acl support", "strict allocate", "allocation roundup size",
    "strict sync", "sync always", "unix extensions", "smb3 unix extensions",
    "winbind cache time", "idmap cache time", "name resolve order",
    "disable netbios", "smb ports")
SYNONYMS = {"readonly": ("read only", None), "writable": ("read only", "!"),
            "writeable": ("read only", "!"), "write ok": ("read only", "!"),
            "casesignames": ("case sensitive", None)}
TRUE = ("yes", "true", "1")
FALSE = ("no", "false", "0")


def parse(text: str) -> dict[str, dict[str, str]]:
    """Sections of an smb.conf, or of testparm's output: {section:
    {parameter: value}}; parameter names lowercased with single spaces,
    a few synonyms folded into the names testparm prints."""
    sections: dict[str, dict[str, str]] = {}
    cur: dict[str, str] | None = None
    pending = ""
    for raw in text.splitlines():
        line = pending + raw.rstrip("\r")
        pending = ""
        if line.rstrip().endswith("\\"):
            pending = line.rstrip()[:-1]
            continue
        s = line.strip()
        if not s or s[0] in ";#":
            continue
        m = re.match(r"^\[(.*)\]$", s)
        if m:
            name = m.group(1).strip()
            if name.lower() == "global":
                name = "global"
            cur = sections.setdefault(name, {})
            continue
        if cur is None or "=" not in s:
            continue
        k, _, v = s.partition("=")
        key = " ".join(k.lower().split())
        v = v.strip()
        if key in SYNONYMS:
            key, invert = SYNONYMS[key]
            if invert:
                v = "no" if v.lower() in TRUE else "yes" \
                    if v.lower() in FALSE else v
        cur[key] = v
    return sections


def config_file(smbd: str = "smbd") -> str | None:
    """The configuration file smbd was built to read, if it exists,
    else the usual places."""
    exe = shutil.which(smbd)
    if exe:
        try:
            out = subprocess.run([exe, "-b"], capture_output=True,
                                 text=True, timeout=10).stdout
        except (OSError, subprocess.TimeoutExpired):
            out = ""
        m = re.search(r"CONFIGFILE:\s*(\S+)", out)
        if m and os.path.exists(m.group(1)):
            return m.group(1)
    for c in CANDIDATES:
        if os.path.exists(c):
            return c
    return None


def load(testparm: str = "testparm", smbd: str = "smbd") -> dict:
    """The configuration as smbd sees it, from testparm (which also
    reads shares kept in the registry); the file as written when
    testparm cannot run, as it cannot for a user without access to
    the registry."""
    out: dict = {"source": None, "file": config_file(smbd), "sections": {},
                 "error": None}
    exe = shutil.which(testparm)
    if exe:
        try:
            p = subprocess.run([exe, "-s", "--suppress-prompt"],
                               capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            p = None
            out["error"] = f"testparm: {e}"
        if p is not None:
            secs = parse(p.stdout)
            if p.returncode == 0 and secs:
                out["source"] = "testparm"
                out["sections"] = secs
                return out
            err = [ln.strip() for ln in p.stderr.splitlines() if ln.strip()
                   and not ln.startswith(("Load smb config",
                                          "Loaded services"))]
            # The first line says why; the last only that it failed.
            out["error"] = "testparm: " + (
                err[0] if err else f"exit {p.returncode}")
    else:
        out["error"] = "testparm not found"
    if out["file"]:
        try:
            with open(out["file"]) as f:
                text = f.read()
        except OSError as e:
            out["error"] = f"{out['error']}; {out['file']}: {e.strerror}"
        else:
            out["sections"] = parse(text)
            out["source"] = out["file"]
    return out


def shares(sections: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    return {k: v for k, v in sections.items() if k != "global"}


def share_path(params: dict[str, str]) -> str | None:
    """The share's path, cut at the first %-variable, which only a
    session can expand."""
    path = params.get("path") or params.get("directory")
    if not path:
        return None
    if "%" in path:
        path = path.split("%", 1)[0]
        path = path[:path.rfind("/")] if "/" in path else ""
    return path.rstrip("/") or "/" if path else None


def io_settings(params: dict[str, str],
                global_params: dict[str, str] | None = None) -> dict[str, str]:
    """The I/O settings in force for a share: its own, else global
    ones; `vfs objects` only where set on the share itself."""
    out = {}
    g = global_params or {}
    for k in IO_PARAMS:
        if k in params:
            out[k] = params[k]
        elif k in g and k != "vfs objects":
            out[k] = g[k]
    return out


def has_vfs(params: dict[str, str], module: str) -> bool:
    return module in (params.get("vfs objects") or "").split()


def effective_globals(names=PERF_PARAMS,
                      testparm: str = "testparm") -> tuple[dict[str, str],
                                                           str | None]:
    """Global settings as smbd resolves them, defaults included, from
    testparm -v; ({}, why) when testparm cannot run."""
    exe = shutil.which(testparm)
    if not exe:
        return {}, "testparm not found"
    try:
        p = subprocess.run([exe, "-s", "-v", "--suppress-prompt"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {}, f"testparm: {e}"
    if p.returncode != 0:
        err = [ln.strip() for ln in p.stderr.splitlines() if ln.strip()
               and not ln.startswith(("Load smb config", "Loaded services"))]
        return {}, "testparm: " + (err[0] if err else f"exit {p.returncode}")
    g = parse(p.stdout).get("global", {})
    return {k: g[k] for k in names if k in g}, None
