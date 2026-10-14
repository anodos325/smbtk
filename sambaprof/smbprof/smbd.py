"""smbd processes from /proc: the main daemon, the processes serving
clients, and whom they serve."""

from __future__ import annotations

import ipaddress
import os
import time
from dataclasses import dataclass, field

SMB_PORTS = (445, 139)


@dataclass
class Proc:
    pid: int
    ppid: int
    comm: str
    started: float = 0.0
    ticks: int = 0  # start, in clock ticks since boot: the identity
    cpu_us: tuple[int, int] = (0, 0)  # user, system
    clients: list[str] = field(default_factory=list)

    @property
    def hosts(self) -> list[str]:
        return sorted({host_of(c) for c in self.clients})


def _read(path: str) -> str:
    with open(path, errors="replace") as f:
        return f.read()


def processes() -> dict[int, Proc]:
    hz = os.sysconf("SC_CLK_TCK")
    # Start times are clock ticks since boot; /proc/stat's btime is
    # whole seconds, too coarse to say which interval a process began in.
    boot = time.time() - time.clock_gettime(time.CLOCK_BOOTTIME)
    out = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            stat = _read(f"/proc/{d}/stat")
        except OSError:
            continue
        comm = stat[stat.index("(") + 1:stat.rindex(")")]
        if not is_smbd(comm):
            continue
        f = stat[stat.rindex(")") + 2:].split()
        ticks = int(f[19])
        out[int(d)] = Proc(pid=int(d), ppid=int(f[1]), comm=comm,
                           started=boot + ticks / hz, ticks=ticks,
                           cpu_us=(int(f[11]) * 1_000_000 // hz,
                                   int(f[12]) * 1_000_000 // hz))
    return out


def is_smbd(comm: str) -> bool:
    return comm == "smbd" or comm.startswith(("smbd[", "smbd-", "smbd:"))


def _addr(hexaddr: str) -> tuple[str, int]:
    ip, port = hexaddr.split(":")
    raw = bytes.fromhex(ip)
    # /proc/net/tcp prints each 32-bit word in host (little-endian) order.
    raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    a = ipaddress.ip_address(raw)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return str(a), int(port, 16)


def _sockets(pid: int) -> set[int]:
    out = set()
    try:
        fds = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return out
    for fd in fds:
        try:
            link = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        if link.startswith("socket:["):
            out.add(int(link[8:-1]))
    return out


def _tcp(pid: int) -> list[list[str]]:
    rows = []
    for name in ("tcp", "tcp6"):
        try:
            text = _read(f"/proc/{pid}/net/{name}")
        except OSError:
            continue
        rows.extend(line.split() for line in text.splitlines()[1:])
    return [r for r in rows if len(r) >= 10]


def listen_ports(pid: int) -> set[int]:
    """Ports the main smbd listens on."""
    mine = _sockets(pid)
    return {_addr(r[1])[1] for r in _tcp(pid)
            if r[3] == "0A" and int(r[9]) in mine}


def attach_clients(procs: dict[int, Proc], ports) -> None:
    """Fill in each process's client addresses (addr:port) from its
    established connections to `ports`, per network namespace."""
    ports = set(ports)
    tables: dict[str, dict[int, str]] = {}
    for p in procs.values():
        try:
            ns = os.readlink(f"/proc/{p.pid}/ns/net")
        except OSError:
            continue
        if ns not in tables:
            conns = {}
            for r in _tcp(p.pid):
                if r[3] != "01" or _addr(r[1])[1] not in ports:
                    continue
                host, port = _addr(r[2])
                conns[int(r[9])] = f"[{host}]:{port}" if ":" in host \
                    else f"{host}:{port}"
            tables[ns] = conns
        conns = tables[ns]
        p.clients = sorted(conns[i] for i in _sockets(p.pid) if i in conns)


def host_of(addr: str) -> str:
    """10.1.2.3:51234 -> 10.1.2.3; [fe80::1]:51234 -> fe80::1."""
    if addr.startswith("["):
        return addr[1:addr.index("]")]
    return addr.rsplit(":", 1)[0] if addr.count(":") == 1 else addr


def instance(main: int | None, ports=None) -> tuple[int | None,
                                                   dict[int, Proc]]:
    """The main smbd and its children (the main one from its pidfile,
    else the only smbd whose parent is not an smbd), with clients."""
    procs = processes()
    if main is None or main not in procs:
        roots = [p.pid for p in procs.values()
                 if p.comm == "smbd" and p.ppid not in procs]
        main = roots[0] if len(roots) == 1 else None
    if main is not None:
        procs = {pid: p for pid, p in procs.items()
                 if pid == main or p.ppid == main}
    if ports is None:
        ports = (listen_ports(main) if main is not None else set()) or \
            set(SMB_PORTS)
    attach_clients(procs, ports)
    return main, procs


def with_port(host: str, port: int = 0) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _norm(host: str) -> str:
    try:
        a = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return host
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return str(a)


def serves(clients: list[str], client: str) -> bool:
    """`client` is an address, or address:port."""
    if client.count(":") == 1 or "]:" in client:
        host, port = client.rsplit(":", 1)
        return any(_norm(host_of(c)) == _norm(host) and
                   c.rsplit(":", 1)[1] == port for c in clients)
    return any(_norm(host_of(c)) == _norm(client) for c in clients)
