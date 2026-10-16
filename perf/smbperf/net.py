"""The network the SMB connections ride on: the interfaces and what their
drivers are set to, what the kernel counts for them and for TCP, and
each SMB connection as TCP sees it."""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess

from .blockdev import sysctl

NET_SYSCTLS = (
    "net.core.rmem_max", "net.core.wmem_max", "net.core.rmem_default",
    "net.core.wmem_default", "net.core.optmem_max",
    "net.core.netdev_max_backlog", "net.core.netdev_budget",
    "net.core.netdev_budget_usecs", "net.core.somaxconn", "net.core.busy_poll",
    "net.core.busy_read", "net.core.rps_sock_flow_entries",
    "net.core.default_qdisc", "net.core.dev_weight",
    "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem", "net.ipv4.tcp_mem",
    "net.ipv4.tcp_congestion_control", "net.ipv4.tcp_window_scaling",
    "net.ipv4.tcp_sack", "net.ipv4.tcp_timestamps",
    "net.ipv4.tcp_moderate_rcvbuf", "net.ipv4.tcp_no_metrics_save",
    "net.ipv4.tcp_slow_start_after_idle", "net.ipv4.tcp_mtu_probing",
    "net.ipv4.tcp_autocorking", "net.ipv4.tcp_notsent_lowat",
    "net.ipv4.tcp_max_syn_backlog", "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_tw_reuse", "net.ipv4.tcp_keepalive_time",
    "net.ipv4.tcp_low_latency", "net.ipv4.tcp_fastopen", "net.ipv4.tcp_ecn",
    "net.ipv4.tcp_adv_win_scale", "net.ipv4.tcp_limit_output_bytes",
    "net.ipv4.tcp_tso_win_divisor", "net.ipv4.tcp_min_tso_segs",
    "net.ipv4.tcp_pacing_ss_ratio", "net.ipv4.tcp_pacing_ca_ratio",
    "net.ipv4.tcp_retries2", "net.ipv4.tcp_syncookies",
    "net.ipv4.tcp_abort_on_overflow", "net.ipv4.tcp_shrink_window",
    "net.ipv4.ip_local_port_range")
# Driver features that decide how much of a packet's work the NIC does;
# ethtool -k's names and the short names printed.
FEATURES = (("rx-checksumming", "rx-csum"), ("tx-checksumming", "tx-csum"),
            ("scatter-gather", "sg"), ("tcp-segmentation-offload", "tso"),
            ("generic-segmentation-offload", "gso"),
            ("generic-receive-offload", "gro"), ("rx-gro-hw", "gro-hw"),
            ("large-receive-offload", "lro"), ("rx-vlan-offload", "rxvlan"),
            ("tx-vlan-offload", "txvlan"), ("receive-hashing", "rxhash"),
            ("ntuple-filters", "ntuple"))
# Names of driver counters (ethtool -S) that count trouble.
TROUBLE = re.compile(r"drop|discard|miss|err|out_of_buffer|no_buf|timeout|"
                     r"fifo|crc|pause|overrun|collision|reset|congest|xoff|"
                     r"xon|oversize|undersize|jabber|retrans|fail|bad|lost|"
                     r"stall|full|squeeze", re.I)
# /proc/net/snmp and netstat counters kept, per protocol block.
SNMP_KEYS = {
    "Ip": ("InReceives", "InHdrErrors", "InAddrErrors", "InDiscards",
           "OutRequests", "OutDiscards", "OutNoRoutes", "ReasmFails",
           "FragFails"),
    "Tcp": ("ActiveOpens", "PassiveOpens", "AttemptFails", "EstabResets",
            "CurrEstab", "InSegs", "OutSegs", "RetransSegs", "InErrs",
            "OutRsts", "InCsumErrors"),
    "TcpExt": ("TCPTimeouts", "ListenOverflows", "ListenDrops",
               "TCPBacklogDrop", "TCPRcvQDrop", "PruneCalled", "RcvPruned",
               "OfoPruned", "TCPRcvCollapsed", "TCPAbortOnMemory",
               "TCPMemoryPressures", "TCPMemoryPressuresChrono",
               "TCPLossProbes", "TCPLostRetransmit", "TCPFastRetrans",
               "TCPSlowStartRetrans", "TCPSynRetrans", "TCPSpuriousRTOs",
               "TCPSACKReorder", "TCPTSReorder", "TCPOFOQueue", "TCPOFOMerge",
               "TCPDSACKRecv", "TCPDSACKOfoRecv", "TCPZeroWindowDrop",
               "TCPWqueueTooBig", "TCPOrigDataSent", "TCPDelivered",
               "TCPRcvCoalesce", "TCPAutoCorking", "TCPHPHits", "TCPPureAcks",
               "TCPHPAcks", "DelayedACKs", "TCPAckCompressed",
               "TCPFromZeroWindowAdv", "TCPToZeroWindowAdv",
               "TCPWantZeroWindowAdv"),
    "IpExt": ("InNoRoutes", "InTruncatedPkts", "InCsumErrors", "InOctets",
              "OutOctets"),
}
BPS = {"bps": 1, "Kbps": 1e3, "Mbps": 1e6, "Gbps": 1e9, "Tbps": 1e12}
# ss -i's bare words that are flags, not the congestion control's name.
SS_FLAGS = {"ts", "sack", "ecn", "ecnseen", "fastopen", "app_limited",
            "cwnd_limited", "tcp-ulp-mptcp"}
SS_MS = {"rto", "ato", "minrtt", "rcv_rtt", "lastsnd", "lastrcv", "lastack",
         "busy", "rwnd_limited", "sndbuf_limited"}


def _read(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _int(text: str | None) -> int | None:
    if text is not None and re.fullmatch(r"-?\d+", text):
        return int(text)
    return None


def _run(cmd: list[str], timeout: float = 15) -> str | None:
    """A command's stdout, or None when it is missing or fails."""
    exe = shutil.which(cmd[0])
    if not exe:
        return None
    try:
        p = subprocess.run([exe] + cmd[1:], capture_output=True, text=True,
                           timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout if p.returncode == 0 else None


# -- interfaces ----------------------------------------------------------------

def interfaces() -> list[str]:
    try:
        return sorted(n for n in os.listdir("/sys/class/net")
                      if os.path.isdir(f"/sys/class/net/{n}"))
    except OSError:
        return []


def link(name: str) -> dict:
    """What sysfs says about an interface: state, speed, MTU, what kind
    of device it is, its driver, bus address, NUMA node, queues, IRQs,
    and what it is stacked on or under."""
    base = f"/sys/class/net/{name}"
    out: dict = {"name": name, "state": _read(f"{base}/operstate")}
    c = _read(f"{base}/carrier")
    out["carrier"] = None if c is None else c == "1"
    sp = _int(_read(f"{base}/speed"))
    out["speed_mbps"] = sp if sp and sp > 0 else None
    out["duplex"] = _read(f"{base}/duplex")
    out["mtu"] = _int(_read(f"{base}/mtu"))
    out["address"] = _read(f"{base}/address")
    m = re.search(r"^DEVTYPE=(\S+)", _read(f"{base}/uevent") or "", re.M)
    has_device = os.path.exists(f"{base}/device")
    out["kind"] = m.group(1) if m else (
        "loopback" if _read(f"{base}/type") == "772" else
        "physical" if has_device else "virtual")
    if has_device:
        if os.path.exists(f"{base}/device/driver"):
            out["driver"] = os.path.basename(
                os.path.realpath(f"{base}/device/driver"))
        out["bus"] = os.path.basename(os.path.realpath(f"{base}/device"))
        nn = _int(_read(f"{base}/device/numa_node"))
        out["numa_node"] = nn if nn is not None and nn >= 0 else None
        irqs: list[int] = []
        try:
            irqs = sorted(int(x) for x in
                          os.listdir(f"{base}/device/msi_irqs") if x.isdigit())
        except OSError:
            irq = _int(_read(f"{base}/device/irq"))
            if irq:
                irqs = [irq]
        out["irqs"] = irqs
    rxq = glob.glob(f"{base}/queues/rx-*")
    out["queues"] = {"rx": len(rxq), "tx": len(glob.glob(f"{base}/queues/tx-*"))}
    out["rps"] = any((_read(f"{q}/rps_cpus") or "0").replace(",", "")
                     .strip("0") for q in rxq)
    out["tx_queue_len"] = _int(_read(f"{base}/tx_queue_len"))
    if os.path.islink(f"{base}/master"):
        out["master"] = os.path.basename(os.readlink(f"{base}/master"))
    try:
        entries = os.listdir(base)
    except OSError:
        entries = []
    out["lower"] = sorted(e[6:] for e in entries if e.startswith("lower_"))
    out["upper"] = sorted(e[6:] for e in entries if e.startswith("upper_"))
    if os.path.isdir(f"{base}/bonding"):
        out["bonding"] = {
            k: _read(f"{base}/bonding/{k}")
            for k in ("mode", "slaves", "xmit_hash_policy", "miimon",
                      "lacp_rate") if _read(f"{base}/bonding/{k}") is not None}
    if os.path.isdir(f"{base}/brif"):
        out["bridge_ports"] = sorted(os.listdir(f"{base}/brif"))
    return out


def read_stats(name: str) -> dict[str, int]:
    """The kernel's counters for an interface (sysfs statistics)."""
    out = {}
    d = f"/sys/class/net/{name}/statistics"
    try:
        names = os.listdir(d)
    except OSError:
        return out
    for n in names:
        v = _int(_read(f"{d}/{n}"))
        if v is not None:
            out[n] = v
    return out


def stat_rates(before: dict, after: dict, seconds: float) -> dict:
    """Bytes and packets a second each way, and every counter that moved
    (errors, drops) as its delta."""
    if seconds <= 0:
        return {}
    d = {k: after[k] - before[k] for k in after if k in before}
    out = {k + "_s": d.get(k, 0) / seconds
           for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")}
    out["delta"] = {k: v for k, v in d.items() if v and k not in (
        "rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "multicast")}
    return out


# -- ethtool -------------------------------------------------------------------

def parse_features(text: str) -> dict[str, dict]:
    """ethtool -k: {feature: {"on": bool, "fixed": bool}}."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([\w-]+):\s*(on|off)(?:\s+\[(fixed|requested"
                     r" on|requested off)\])?", line)
        if m:
            out[m.group(1)] = {"on": m.group(2) == "on",
                               "fixed": m.group(3) == "fixed"}
    return out


def parse_sections(text: str) -> dict[str, dict]:
    """ethtool -g and -l: 'Pre-set maximums' and 'Current hardware
    settings' as {"max": {...}, "current": {...}}, n/a as None."""
    out: dict[str, dict] = {"max": {}, "current": {}}
    cur = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Pre-set maximums"):
            cur = "max"
            continue
        if s.startswith("Current hardware settings"):
            cur = "current"
            continue
        m = re.match(r"^([A-Za-z][\w -]*?):\s*(\S.*)$", s)
        if cur and m:
            v = m.group(2).strip()
            out[cur][m.group(1).strip().lower()] = (
                int(v) if v.isdigit() else None if v == "n/a" else v)
    return out


def parse_coalesce(text: str) -> dict:
    out: dict = {}
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^Adaptive RX:\s*(\w+)\s+TX:\s*(\w+)", s)
        if m:
            out["adaptive_rx"] = m.group(1) == "on"
            out["adaptive_tx"] = m.group(2) == "on"
            continue
        m = re.match(r"^([\w-]+):\s*(\S+)$", s)
        if m:
            v = m.group(2)
            out[m.group(1)] = (int(v) if v.lstrip("-").isdigit()
                               else None if v == "n/a" else v)
    return out


def parse_driver(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^([\w-]+):\s*(.*)$", line.strip())
        if m and m.group(2):
            out[m.group(1)] = m.group(2)
    return out


def parse_settings(text: str) -> dict:
    """ethtool DEV: speed, duplex, link, autonegotiation, port, and the
    fastest mode the NIC supports."""
    blocks: dict[str, str] = {}
    key = None
    for line in text.splitlines()[1:]:
        m = re.match(r"^\t([A-Za-z][\w /-]*?):\s*(.*)$", line)
        if m:
            key = m.group(1)
            blocks[key] = m.group(2)
        elif key and line.strip():
            blocks[key] += " " + line.strip()
    out: dict = {}
    m = re.match(r"(\d+)Mb/s", blocks.get("Speed", ""))
    out["speed_mbps"] = int(m.group(1)) if m else None
    out["duplex"] = blocks.get("Duplex")
    out["link"] = {"yes": True, "no": False}.get(blocks.get("Link detected"))
    out["autoneg"] = blocks.get("Auto-negotiation")
    out["port"] = blocks.get("Port")
    modes = [int(n) for n in re.findall(r"(\d+)base",
                                        blocks.get("Supported link modes", ""))]
    out["supported_max_mbps"] = max(modes) if modes else None
    return out


def parse_stats(text: str) -> dict[str, int]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([^:]+):\s*(-?\d+)\s*$", line)
        if m:
            out[m.group(1).strip()] = int(m.group(2))
    return out


def nic(name: str) -> dict:
    """What ethtool reports for an interface: driver, settings, features,
    rings, channels, coalescing; None for each it cannot get."""
    out: dict = {}
    text = _run(["ethtool", "-i", name])
    out["driver"] = parse_driver(text) if text else None
    text = _run(["ethtool", name])
    out["settings"] = parse_settings(text) if text else None
    text = _run(["ethtool", "-k", name])
    out["features"] = parse_features(text) if text else None
    text = _run(["ethtool", "-g", name])
    out["rings"] = parse_sections(text) if text else None
    text = _run(["ethtool", "-l", name])
    out["channels"] = parse_sections(text) if text else None
    text = _run(["ethtool", "-c", name])
    out["coalesce"] = parse_coalesce(text) if text else None
    return out


def nic_stats(name: str, pattern=TROUBLE) -> dict[str, int]:
    """The driver's own counters (ethtool -S) whose names speak of
    trouble."""
    text = _run(["ethtool", "-S", name])
    if not text:
        return {}
    return {k: v for k, v in parse_stats(text).items() if pattern.search(k)}


# -- the stack -----------------------------------------------------------------

def parse_snmp(text: str) -> dict[str, dict[str, int]]:
    """/proc/net/snmp and /proc/net/netstat: a header line and a value
    line per protocol block."""
    out: dict[str, dict[str, int]] = {}
    lines = text.splitlines()
    i = 0
    while i + 1 < len(lines):
        h, v = lines[i].split(), lines[i + 1].split()
        if h and v and h[0] == v[0] and h[0].endswith(":") and len(h) == len(v):
            d = out.setdefault(h[0][:-1], {})
            for k, x in zip(h[1:], v[1:]):
                if x.lstrip("-").isdigit():
                    d[k] = int(x)
            i += 2
        else:
            i += 1
    return out


def read_snmp(keys=SNMP_KEYS) -> dict[str, dict[str, int]]:
    all_ = parse_snmp(_read("/proc/net/snmp") or "")
    for proto, d in parse_snmp(_read("/proc/net/netstat") or "").items():
        all_.setdefault(proto, {}).update(d)
    return {p: {k: all_[p][k] for k in names if k in all_[p]}
            for p, names in keys.items() if p in all_}


def snmp_delta(before: dict, after: dict) -> dict[str, dict[str, int]]:
    out = {}
    for proto, a in after.items():
        b = before.get(proto, {})
        out[proto] = {k: a[k] - b[k] for k in a if k in b}
    return out


def parse_softnet(text: str) -> list[dict]:
    """/proc/net/softnet_stat, one row per CPU, the columns that matter:
    packets processed, dropped for a full backlog, and polls cut short
    by the budget (time squeezed)."""
    rows = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 3:
            continue
        try:
            v = [int(x, 16) for x in f]
        except ValueError:
            continue
        rows.append({"processed": v[0], "dropped": v[1], "time_squeeze": v[2],
                     "received_rps": v[9] if len(v) > 9 else 0,
                     "flow_limit_count": v[10] if len(v) > 10 else 0})
    return rows


def read_softnet() -> list[dict]:
    return parse_softnet(_read("/proc/net/softnet_stat") or "")


def softnet_delta(before: list[dict], after: list[dict]) -> dict:
    out = {k: 0 for k in ("processed", "dropped", "time_squeeze",
                          "received_rps", "flow_limit_count")}
    dropping = 0
    for b, a in zip(before, after):
        for k in out:
            out[k] += a[k] - b[k]
        if a["dropped"] > b["dropped"]:
            dropping += 1
    out["cpus_dropping"] = dropping
    return out


def parse_sockstat(text: str) -> dict:
    """/proc/net/sockstat: sockets in use; TCP's in use, orphaned,
    time-wait, allocated, and pages of memory."""
    out: dict = {}
    for line in text.splitlines():
        proto, _, rest = line.partition(":")
        f = rest.split()
        vals = {f[i]: int(f[i + 1]) for i in range(0, len(f) - 1, 2)
                if f[i + 1].isdigit()}
        if proto == "sockets":
            out["sockets_used"] = vals.get("used")
        elif proto in ("TCP", "UDP"):
            out[proto] = vals
    return out


def read_sockstat() -> dict:
    out = parse_sockstat(_read("/proc/net/sockstat") or "")
    out["page_size"] = os.sysconf("SC_PAGE_SIZE")
    return out


def sysctls(names=NET_SYSCTLS) -> dict:
    out = {}
    for n in names:
        v = sysctl(n)
        if v is not None:
            out[n] = " ".join(v.split()) if isinstance(v, str) else v
    return out


# -- addresses -----------------------------------------------------------------

def addresses() -> dict[str, list[str]]:
    """The addresses on each interface, from ip -j addr."""
    text = _run(["ip", "-j", "addr", "show"])
    if not text:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    out: dict[str, list[str]] = {}
    for link_ in data:
        name = link_.get("ifname")
        if not name:
            continue
        out[name] = [a["local"] for a in link_.get("addr_info", [])
                     if a.get("local") and a.get("scope") != "link"]
    return out


def strip_mapped(addr: str) -> str:
    """::ffff:10.1.2.3 -> 10.1.2.3; fe80::1%eth0 -> fe80::1."""
    a = addr.strip("[]")
    if a.lower().startswith("::ffff:") and "." in a:
        a = a[7:]
    return a.split("%", 1)[0]


def interface_of(addr: str, addrs: dict[str, list[str]]) -> str | None:
    a = strip_mapped(addr)
    for name, lst in addrs.items():
        if a in lst:
            return name
    return None


# -- connections ---------------------------------------------------------------

def _split_addr(text: str) -> tuple[str, int | None]:
    host, _, port = text.rpartition(":")
    if not host:
        return text, None
    return strip_mapped(host), int(port) if port.isdigit() else None


def _bps(text: str) -> float | None:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([KMGT]?bps)", text)
    return float(m.group(1)) * BPS[m.group(2)] if m else None


def _num(text: str):
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    return text


def _info(c: dict, key: str, value: str) -> None:
    if key == "rtt":
        a, _, b = value.partition("/")
        c["rtt_ms"], c["rttvar_ms"] = _num(a), _num(b) if b else None
    elif key == "retrans":
        a, _, b = value.partition("/")
        c["retrans"], c["retrans_total"] = _num(a), _num(b) if b else None
    elif key in ("busy", "rwnd_limited", "sndbuf_limited"):
        m = re.fullmatch(r"(\d+(?:\.\d+)?)ms(?:\((\d+(?:\.\d+)?)%\))?", value)
        if m:
            c[key + "_ms"] = float(m.group(1))
            if m.group(2) is not None:
                c[key + "_pct"] = float(m.group(2))
    elif key in SS_MS:
        c[key + "_ms"] = _num(value.replace("ms", ""))
    elif key == "wscale":
        c[key] = value
    else:
        c[key] = _num(value)


def parse_ss(text: str) -> list[dict]:
    """ss -tina (with -i's TCP information on the same or the next
    line): one dict per socket with state, queues, addresses and the
    TCP_INFO fields by name (times in ms, rates in bits a second)."""
    lines: list[str] = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if raw[0].isspace() and lines:
            lines[-1] += " " + raw.strip()
        else:
            lines.append(raw.rstrip())
    out = []
    for line in lines:
        f = line.split()
        if len(f) < 4 or f[0] in ("State", "Netid", "Recv-Q"):
            continue
        # With a state filter ss leaves the State column out.
        state = None if f[0].isdigit() else f.pop(0)
        if len(f) < 4 or not (f[0].isdigit() and f[1].isdigit()):
            continue
        c: dict = {"state": state or "ESTAB", "recvq": int(f[0]),
                   "sendq": int(f[1])}
        c["local"], c["lport"] = _split_addr(f[2])
        c["peer"], c["pport"] = _split_addr(f[3])
        info = f[4:]
        i = 0
        while i < len(info):
            t = info[i]
            if t in ("send", "pacing_rate", "delivery_rate") and \
                    i + 1 < len(info):
                c[t + "_bps"] = _bps(info[i + 1])
                i += 2
                continue
            if t.startswith("users:("):
                m = re.search(r"pid=(\d+)", t)
                if m:
                    c["pid"] = int(m.group(1))
            elif ":" in t:
                k, _, v = t.partition(":")
                _info(c, k, v)
            elif t in SS_FLAGS:
                c.setdefault("flags", []).append(t)
            elif "cc" not in c and re.fullmatch(r"[a-z][\w-]*", t):
                c["cc"] = t
            i += 1
        if "busy_ms" in c:
            # ss prints these only when they are not zero
            for k in ("rwnd_limited", "sndbuf_limited"):
                c.setdefault(k + "_ms", 0.0)
                c.setdefault(k + "_pct", 0.0)
        out.append(c)
    return out


def ss_connections(ports=(445, 139)) -> tuple[list[dict], str | None]:
    """TCP sockets on the SMB ports, with TCP_INFO, from ss."""
    exe = shutil.which("ss")
    if not exe:
        return [], "ss not found"
    filt = "( " + " or ".join(f"sport = :{p}" for p in ports) + " )"
    for flags in ("-tinaH", "-tina"):
        try:
            p = subprocess.run([exe, flags, filt], capture_output=True,
                               text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            return [], f"ss: {e}"
        if p.returncode == 0:
            return parse_ss(p.stdout), None
    err = [ln.strip() for ln in p.stderr.splitlines() if ln.strip()]
    return [], "ss: " + (err[0] if err else f"exit {p.returncode}")
