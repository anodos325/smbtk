"""Grouping keys an exchange can be split by, shared by the tools."""

from __future__ import annotations

import ntpath

from .model import Capture, Exchange

LEVELS = {
    "client": "client address",
    "server": "server address",
    "user": "DOMAIN\\user of the session",
    "session": "session id",
    "stream": "tcp stream",
    "share": "share name",
    "cmd": "command",
    "sub": "sub-command: info level, FSCTL, disposition, size bucket ...",
    "op": "command and sub-command together",
    "status": "NT status of the response",
    "class": "ok / flow / probe / error / unanswered",
    "file": "path the request acted on",
    "path": "that path split into one level per component",
    "dir": "directory of that path",
    "ext": "extension of that path",
    "chain": "shape of the compound the request was part of",
    "async": "sync / async (interim STATUS_PENDING seen)",
}


def level_value(cap: Capture, x: Exchange, level: str) -> str:
    if level == "client":
        return x.client
    if level == "server":
        return x.server
    if level == "user":
        return x.user
    if level == "session":
        return f"{x.sesid:#x}"
    if level == "stream":
        return str(x.stream)
    if level == "share":
        return x.share
    if level == "cmd":
        return x.cmd_name
    if level == "sub":
        return x.sub or "-"
    if level == "op":
        return x.label
    if level == "status":
        return x.status_name
    if level == "class":
        return x.status_class
    if level in ("file", "path"):
        return x.file or "-"
    if level == "dir":
        return ntpath.dirname(x.file.replace("/", "\\")) or "\\"
    if level == "ext":
        _, ext = ntpath.splitext(x.file.split(" -> ")[0])
        return ext.lower() or "-"
    if level == "chain":
        return x.chain_sig or "-"
    if level == "async":
        return "async" if x.interim is not None else "sync"
    raise ValueError(f"unknown level {level!r}")


def level_values(cap: Capture, x: Exchange, level: str) -> tuple[str, ...]:
    """Like level_value, but `path` expands to one entry per component;
    a rename keeps its target on the last one."""
    if level != "path":
        return (level_value(cap, x, level),)
    name, arrow, target = x.file.partition(" -> ")
    parts = [p for p in name.replace("/", "\\").split("\\") if p]
    if not parts:
        return (x.file or "-",)
    parts[-1] += arrow + target
    return tuple(parts)


def parse_levels(text: str) -> list[str]:
    levels = [p.strip() for p in text.split(",") if p.strip()]
    for lv in levels:
        if lv not in LEVELS:
            raise ValueError(
                f"unknown level {lv!r}; one of {', '.join(LEVELS)}")
    return levels


def levels_help() -> str:
    return "; ".join(f"{k}: {v}" for k, v in LEVELS.items())
