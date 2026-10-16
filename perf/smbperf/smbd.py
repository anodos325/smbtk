"""smbd processes and their clients, and the SMB2 command a stack of
smbd's belongs to."""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import time
from dataclasses import dataclass, field

from .stacks import LOOP, bare

SMB_PORTS = (445, 139)


@dataclass
class Proc:
    pid: int
    ppid: int
    comm: str
    threads: int = 1
    cpu_s: float = 0.0
    started: float = 0.0
    clients: list[str] = field(default_factory=list)
    title_client: str | None = None

    @property
    def name(self) -> str:
        """smbd[client] with the whole address (comm keeps 15 bytes): from
        the connections when they can be seen, else from the title."""
        if self.comm.startswith("smbd["):
            hosts = sorted({host_of(c) for c in self.clients}) or (
                [self.title_client] if self.title_client else [])
            if hosts:
                return "smbd[" + ",".join(hosts) + "]"
        return self.comm


def _read(path: str) -> str:
    with open(path, errors="replace") as f:
        return f.read()


def _boot_time() -> float:
    for line in _read("/proc/stat").splitlines():
        if line.startswith("btime "):
            return float(line.split()[1])
    return 0.0


_TITLE = re.compile(r"smbd: client \[(.+)\]")


def client_in_title(title: str) -> str | None:
    """"smbd: client [10.1.2.3]" -> "10.1.2.3"."""
    m = _TITLE.match(title.strip())
    return m.group(1) if m else None


def title_client(pid: int) -> str | None:
    """The client address in a child smbd's process title; cmdline is
    readable by anyone where /proc/<pid>/fd is the owner's only."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
    except OSError:
        return None
    return client_in_title(raw.split(b"\0", 1)[0].decode(errors="replace"))


def processes(match=None) -> list[Proc]:
    """Processes from /proc; `match(comm)` picks them."""
    hz = os.sysconf("SC_CLK_TCK")
    boot = _boot_time()
    out = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            stat = _read(f"/proc/{d}/stat")
        except OSError:
            continue
        comm = stat[stat.index("(") + 1:stat.rindex(")")]
        if match is not None and not match(comm):
            continue
        f = stat[stat.rindex(")") + 2:].split()
        out.append(Proc(
            pid=int(d), ppid=int(f[1]), comm=comm, threads=int(f[17]),
            cpu_s=(int(f[11]) + int(f[12])) / hz,
            started=boot + int(f[19]) / hz,
            title_client=title_client(int(d)) if comm.startswith("smbd[")
            else None))
    return sorted(out, key=lambda p: p.pid)


def is_smbd(comm: str) -> bool:
    return comm == "smbd" or comm.startswith(("smbd[", "smbd-", "smbd:"))


def threads(pid: int) -> list[int]:
    try:
        return sorted(int(t) for t in os.listdir(f"/proc/{pid}/task"))
    except OSError:
        return []


def _addr(hexaddr: str) -> str:
    ip, port = hexaddr.split(":")
    raw = bytes.fromhex(ip)
    # /proc/net/tcp prints each 32-bit word in host (little-endian) order.
    raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    a = ipaddress.ip_address(raw)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    p = int(port, 16)
    return f"[{a}]:{p}" if a.version == 6 else f"{a}:{p}"


def _connections(pid: int, ports: set[int]) -> dict[int, tuple[str, int]]:
    """Established TCP connections to one of `ports`, by socket inode:
    (client address, server port), from the pid's network namespace."""
    out = {}
    for name in ("tcp", "tcp6"):
        try:
            text = _read(f"/proc/{pid}/net/{name}")
        except OSError:
            continue
        for line in text.splitlines()[1:]:
            f = line.split()
            if len(f) < 10 or f[3] != "01":
                continue
            lport = int(f[1].rsplit(":", 1)[1], 16)
            if lport in ports:
                out[int(f[9])] = (_addr(f[2]), lport)
    return out


def clients(pids: list[int], ports=SMB_PORTS) -> dict[int, list[str]]:
    """The client addresses (addr:port) of each pid's SMB connections."""
    portset = set(ports)
    tables: dict[str, dict[int, tuple[str, int]]] = {}
    out: dict[int, list[str]] = {}
    for pid in pids:
        try:
            ns = os.readlink(f"/proc/{pid}/ns/net")
        except OSError:
            continue
        if ns not in tables:
            tables[ns] = _connections(pid, portset)
        conns = tables[ns]
        if not conns:
            continue
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if link.startswith("socket:["):
                c = conns.get(int(link[8:-1]))
                if c:
                    out.setdefault(pid, []).append(c[0])
    return out


def smbd_processes(ports=SMB_PORTS) -> list[Proc]:
    procs = processes(is_smbd)
    cl = clients([p.pid for p in procs], ports)
    for p in procs:
        p.clients = sorted(cl.get(p.pid, []))
    return procs


def host_of(addr: str) -> str:
    """10.1.2.3:51234 -> 10.1.2.3; [fe80::1]:51234 -> fe80::1."""
    host = addr.rsplit(":", 1)[0] if addr.count(":") == 1 or \
        addr.startswith("[") else addr
    return host.strip("[]")


def select(client: list[str], pids: list[int], comms: list[str],
           ports=SMB_PORTS) -> list[Proc]:
    """smbd processes serving `client` addresses, plus `pids` and
    processes named like `comms`; every smbd process when all are
    empty."""
    procs = smbd_processes(ports)
    if not (client or pids or comms):
        return procs
    chosen = {}
    for p in procs:
        if any(host_of(c) in client for c in p.clients):
            chosen[p.pid] = p
    if pids or comms:
        for p in processes():
            if p.pid in pids or any(fnmatch.fnmatchcase(p.comm, g)
                                    for g in comms):
                chosen.setdefault(p.pid, p)
    return sorted(chosen.values(), key=lambda p: p.pid)


class Watcher:
    """Which smbd processes existed during a run and whom they served;
    polled, since connections come and go."""

    def __init__(self, ports=SMB_PORTS) -> None:
        self.ports = ports
        self.seen: dict[int, dict] = {}

    def poll(self) -> None:
        now = time.time()
        for p in smbd_processes(self.ports):
            e = self.seen.setdefault(p.pid, {
                "comm": p.comm, "ppid": p.ppid, "clients": [],
                "first_seen": now})
            e["comm"] = p.comm
            e["last_seen"] = now
            if p.title_client:
                e["title_client"] = p.title_client
            for c in p.clients:
                if c not in e["clients"]:
                    e["clients"].append(c)

    def names(self) -> dict[int, str]:
        out = {}
        for pid, e in self.seen.items():
            hosts = sorted({host_of(c) for c in e["clients"]}) or (
                [e["title_client"]] if e.get("title_client") else [])
            if hosts and e["comm"].startswith("smbd["):
                out[pid] = "smbd[" + ",".join(hosts) + "]"
        return out


# -- SMB2 commands in smbd's stacks ------------------------------------------

_WORDS = {
    "negprot": "NEGOTIATE", "negotiate": "NEGOTIATE",
    "multi_protocol_reply_negprot": "NEGOTIATE",
    "protocol_dialect": "NEGOTIATE",
    "sesssetup": "SESSION_SETUP", "session_setup": "SESSION_SETUP",
    "auth_generic_return": "SESSION_SETUP",
    "reauth_generic_return": "SESSION_SETUP",
    "bind_auth_return": "SESSION_SETUP",
    "logoff": "LOGOFF", "tcon": "TREE_CONNECT",
    "tree_connect": "TREE_CONNECT", "tdis": "TREE_DISCONNECT",
    "create": "CREATE", "close": "CLOSE", "flush": "FLUSH", "read": "READ",
    "write": "WRITE", "lock": "LOCK", "ioctl": "IOCTL", "cancel": "CANCEL",
    "keepalive": "ECHO", "query_directory": "QUERY_DIRECTORY",
    "find": "QUERY_DIRECTORY", "notify": "CHANGE_NOTIFY",
    "getinfo": "QUERY_INFO", "setinfo": "SET_INFO",
    "break": "OPLOCK_BREAK", "lease_break": "OPLOCK_BREAK",
    "oplock_break": "OPLOCK_BREAK",
}
_CMD = re.compile(
    r"^(?:smbd_smb2_request_process_|smbd_smb2_request_|smbd_smb2_|smb2_)("
    + "|".join(sorted(_WORDS, key=len, reverse=True)) + r")(?:_|$)")
# Named like a command, but the connection's send path.
_NOT_CMD = {"smbd_smb2_flush_send_queue", "smbd_smb2_flush_with_sendmsg"}
_URING = re.compile(r"^vfs_io_uring_(pread|pwrite|fsync)")
_URING_CMD = {"pread": "READ", "pwrite": "WRITE", "fsync": "FLUSH"}
_IOWQ = {"io_read": "READ", "io_write": "WRITE", "io_fsync": "FLUSH"}
_SMB1 = re.compile(r"^(construct_reply|process_smb1|smb1_|reply_[a-z])")
_LOOP = {"epoll_wait", "epoll_pwait", "__GI_epoll_wait", "__epoll_wait"}
_LOOP_WORK = ("tevent_", "_tevent_", "talloc", "_talloc", "__talloc",
              "_tc_")
_ENTRY = {"_start", "__libc_start_main", "__libc_start_call_main", "main",
          "start_thread", "clone", "clone3", "__clone", "__clone3",
          "ret_from_fork_asm", "ret_from_fork", "kthread"}


def frame_command(name: str) -> str | None:
    name = bare(name)
    if name in _NOT_CMD:
        return None
    m = _CMD.match(name)
    if m:
        return _WORDS[m.group(1)]
    m = _URING.match(name)
    if m:
        return _URING_CMD[m.group(1)]
    return None


def command(stack: tuple[str, ...]) -> str:
    """The SMB2 command a stack works for: the outermost frame named
    after one. Otherwise what the process was doing in broad terms."""
    if not stack:
        return "other"
    head = bare(stack[0])
    worker = head.startswith("iou-")
    if not worker and not head.startswith("smbd"):
        return "not smbd"
    if not worker and len(stack) > 1 and bare(stack[1]).startswith("iou-"):
        worker = True
        stack = stack[1:]
    if worker:
        for f in stack[1:]:
            c = _IOWQ.get(bare(f))
            if c:
                return f"{c} (io_uring worker)"
        return "io_uring worker"
    names = [bare(f) for f in stack]
    for n in names:
        if n in _NOT_CMD:
            continue
        c = frame_command(n)
        if c:
            return c
    if any(_SMB1.match(n) for n in names):
        return "SMB1"
    if any(n.startswith("vfs_io_uring_") for n in names):
        return "io_uring completion"
    if "smbd_smb2_request_dispatch" in names or \
            "smbd_smb2_request_dispatch_immediate" in names:
        return "SMB2 dispatch"
    if any(n in ("smbd_smb2_io_handler", "smbd_smb2_connection_handler")
           or n in _NOT_CMD for n in names):
        return "SMB2 receive and send"
    if any(n.startswith(("messaging_", "msg_dgm_")) for n in names):
        return "messaging"
    if any(n in _LOOP or n.startswith("smbd_tevent_trace_callback")
           for n in names):
        return "event loop"
    if len(names) > 1 and names[1] == LOOP and (
            len(names) == 2 or names[2].startswith(_LOOP_WORK)):
        return "event loop"
    if len(names) > 1 and names[1] not in _ENTRY and names[1] != LOOP:
        return "incomplete stack"
    return "other"


# -- Samba's daemons and smbstatus ---------------------------------------------

SAMBA_COMMS = ("smbd", "winbindd", "nmbd", "samba", "rpcd_", "ctdbd", "lpqd")


def is_samba(comm: str) -> bool:
    return comm == "smbd" or comm.startswith(SAMBA_COMMS)


def samba_processes(ports=SMB_PORTS) -> list[Proc]:
    """Every Samba daemon, smbd's with their clients."""
    procs = processes(is_samba)
    cl = clients([p.pid for p in procs if is_smbd(p.comm)], ports)
    for p in procs:
        p.clients = sorted(cl.get(p.pid, []))
    return procs


def _degree(d) -> str | None:
    """smbstatus's {"cipher": ..., "degree": ...} as one word or two."""
    if not isinstance(d, dict):
        return None
    degree, cipher = d.get("degree"), d.get("cipher")
    if degree is None:
        return None
    return f"{degree} ({cipher})" if cipher and cipher != "-" else str(degree)


def _address(text: str | None) -> str | None:
    """ipv4:10.1.2.3:51234 -> 10.1.2.3."""
    if not text:
        return None
    for prefix in ("ipv4:", "ipv6:"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    return text.rsplit(":", 1)[0] if ":" in text else text


def summarize_status(data: dict) -> dict:
    """What matters for performance in smbstatus --json: each session's
    user, client, dialect, encryption, signing and channels; tree
    connections per share; how many files are open and locked."""
    out: dict = {"version": data.get("version"),
                 "timestamp": data.get("timestamp"), "sessions": [],
                 "tcons": [], "open_files": None, "locks": None,
                 "shares": {}}
    sessions = data.get("sessions")
    for sid, s in (sessions.items() if isinstance(sessions, dict) else []):
        if not isinstance(s, dict):
            continue
        chans = s.get("channels")
        chans = list(chans.values()) if isinstance(chans, dict) else []
        out["sessions"].append({
            "id": s.get("session_id", sid),
            "pid": (s.get("server_id") or {}).get("pid"),
            "user": s.get("username"), "group": s.get("groupname"),
            "machine": s.get("remote_machine"), "hostname": s.get("hostname"),
            "dialect": s.get("session_dialect"),
            "encryption": _degree(s.get("encryption")),
            "signing": _degree(s.get("signing")),
            "channels": len(chans),
            "addresses": sorted({_address(c.get("remote_address"))
                                 for c in chans if isinstance(c, dict)
                                 and c.get("remote_address")}),
            "since": s.get("creation_time")})
    tcons = data.get("tcons")
    for tid, t in (tcons.items() if isinstance(tcons, dict) else []):
        if not isinstance(t, dict):
            continue
        share = t.get("service")
        out["tcons"].append({
            "id": t.get("tcon_id", tid), "share": share,
            "session": t.get("session_id"),
            "pid": (t.get("server_id") or {}).get("pid"),
            "machine": t.get("machine"),
            "encryption": _degree(t.get("encryption")),
            "signing": _degree(t.get("signing")),
            "since": t.get("connected_at")})
        e = out["shares"].setdefault(share, {"tcons": 0, "open_files": 0})
        e["tcons"] += 1
    files = data.get("open_files")
    if isinstance(files, dict):
        n = 0
        for f in files.values():
            opens = f.get("opens") if isinstance(f, dict) else None
            k = len(opens) if isinstance(opens, dict) else 1
            n += k
            svc = f.get("service_path") if isinstance(f, dict) else None
            if svc:
                e = out["shares"].setdefault(svc, {"tcons": 0, "open_files": 0})
                e["open_files"] += k
        out["open_files"] = n
    locks = data.get("byte_range_locks")
    if isinstance(locks, dict):
        out["locks"] = sum(len(v) if isinstance(v, (dict, list)) else 1
                           for v in locks.values())
    return out


def smbstatus(smbstatus_bin: str = "smbstatus") -> dict:
    """smbstatus --json, summarized; {"error": why} when it cannot run,
    as it cannot for a user without access to Samba's databases."""
    import json
    import shutil
    import subprocess
    exe = shutil.which(smbstatus_bin)
    if not exe:
        return {"error": "smbstatus not found"}
    try:
        p = subprocess.run([exe, "--json"], capture_output=True, text=True,
                           timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": f"smbstatus: {e}"}
    text = p.stdout
    start = text.find("{")
    if p.returncode != 0 or start < 0:
        err = [ln.strip() for ln in p.stderr.splitlines() if ln.strip()]
        return {"error": "smbstatus: " + (err[0] if err else
                                          f"exit {p.returncode}")}
    try:
        data = json.loads(text[start:])
    except ValueError:
        return {"error": "smbstatus: output is not JSON"}
    out = summarize_status(data)
    out["error"] = None
    return out
