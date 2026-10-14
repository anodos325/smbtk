"""smb-capture: capture SMB traffic with tcpdump (or dumpcap) into
rotating files, optionally cut down to headers or anonymized as each
file completes, so a long capture holds one raw file per interface at a
time."""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
import platform
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

from . import mapping, pcapio
from .sanitize import DEFAULT_PORTS, make_engine, rewrite, summary, write_map

POLL_S = 1.0
NIC_COUNTERS = ("rx_packets", "rx_dropped", "rx_missed_errors",
                "rx_fifo_errors", "rx_over_errors", "rx_errors",
                "tx_packets", "tx_dropped", "tx_errors")
OFFLOADS = ("generic-receive-offload", "large-receive-offload",
            "tcp-segmentation-offload", "generic-segmentation-offload",
            "rx-checksumming", "tx-checksumming")


def note(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def parse_duration(text: str) -> float:
    """Seconds from '90', '90s', '10m', '1h30m', '250ms'."""
    t = text.strip().lower()
    if re.fullmatch(r"\d+(\.\d+)?", t):
        return float(t)
    total = 0.0
    pos = 0
    for m in re.finditer(r"(\d+(?:\.\d+)?)(ms|s|m|h|d)", t):
        if m.start() != pos:
            break
        total += float(m.group(1)) * {"ms": 0.001, "s": 1, "m": 60,
                                      "h": 3600, "d": 86400}[m.group(2)]
        pos = m.end()
    if pos != len(t) or not t:
        raise ValueError(f"bad duration {text!r}")
    return total


# -- the host -------------------------------------------------------------------

def addressed_interfaces() -> list[str]:
    """Interfaces holding a global address: where SMB clients connect,
    and never a bond member as well as its bond (which would capture
    every frame twice)."""
    try:
        out = subprocess.run(["ip", "-j", "addr", "show"], capture_output=True,
                             text=True, timeout=10).stdout
        links = json.loads(out or "[]")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []
    names = []
    for link in links:
        if link.get("ifname") == "lo" or "UP" not in link.get("flags", []):
            continue
        if any(a.get("scope") == "global" for a in link.get("addr_info", [])):
            names.append(link["ifname"])
    return names


def interface_info(name: str) -> dict:
    base = f"/sys/class/net/{name}"
    info: dict = {}
    for key in ("mtu", "speed", "operstate"):
        try:
            with open(f"{base}/{key}") as f:
                v = f.read().strip()
            info[key] = int(v) if v.lstrip("-").isdigit() else v
        except OSError:
            pass
    if shutil.which("ethtool"):
        try:
            out = subprocess.run(["ethtool", "-k", name], capture_output=True,
                                 text=True, timeout=10).stdout
            off = {}
            for line in out.splitlines():
                k, _, v = line.strip().partition(":")
                if k in OFFLOADS:
                    off[k] = v.split()[0] if v.split() else ""
            if off:
                info["offloads"] = off
        except (OSError, subprocess.TimeoutExpired):
            pass
    return info


def nic_counters(name: str) -> dict[str, int]:
    out = {}
    for c in NIC_COUNTERS:
        try:
            with open(f"/sys/class/net/{name}/statistics/{c}") as f:
                out[c] = int(f.read())
        except (OSError, ValueError):
            pass
    return out


def host_info(anon: bool) -> dict:
    info = {"kernel": platform.release()}
    for path in ("/etc/version", "/etc/os-release"):
        try:
            with open(path) as f:
                text = f.read()
        except OSError:
            continue
        if path == "/etc/version":
            info["truenas"] = text.strip()
        else:
            m = re.search(r'^PRETTY_NAME="?([^"\n]*)', text, re.M)
            if m:
                info["os"] = m.group(1)
    if not anon:
        info["hostname"] = platform.node()
    return info


def smbstatus(path: str) -> None:
    if not shutil.which("smbstatus"):
        return
    try:
        out = subprocess.run(["smbstatus", "--json"], capture_output=True,
                             text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return
    if out.strip():
        with open(path, "w") as f:
            f.write(out)


# -- capture programs -----------------------------------------------------------

def build_filter(ports: list[int], hosts: list[str], vlan: bool) -> str:
    f = " or ".join(f"tcp port {p}" for p in ports)
    if hosts:
        f = f"({f}) and ({' or '.join(f'host {h}' for h in hosts)})"
    if vlan:
        f = f"({f}) or (vlan and ({f}))"
    return f


class Tcpdump:
    """One tcpdump per interface, each rotating its own files."""

    name = "tcpdump"

    def __init__(self, binary: str, ifaces: list[str], snaplen: int,
                 buffer_mb: int, file_mb: int, flt: str):
        self.binary = binary
        self.ifaces = ifaces
        self.snaplen = snaplen
        self.buffer_mb = buffer_mb
        self.file_mb = file_mb
        self.flt = flt
        self.nano = True

    def commands(self, raw: str) -> list[tuple[str, list[str]]]:
        out = []
        for i in self.ifaces:
            cmd = [self.binary, "-i", i, "-n", "-s", str(self.snaplen),
                   "-B", str(self.buffer_mb * 1024), "-Z", "root",
                   "-C", str(self.file_mb), "-w", os.path.join(raw, f"{i}.pcap")]
            if self.nano:
                cmd.append("--time-stamp-precision=nano")
            cmd.append(self.flt)
            out.append((i, cmd))
        return out

    @staticmethod
    def files(raw: str) -> dict[str, list[tuple[int, str]]]:
        seqs: dict[str, list[tuple[int, str]]] = {}
        for name in os.listdir(raw):
            m = re.fullmatch(r"(.+)\.pcap(\d*)", name)
            if m:  # name, name1, name2 ...: numbered from 1 here
                seqs.setdefault(m.group(1), []).append(
                    (int(m.group(2) or 0) + 1, os.path.join(raw, name)))
        return {k: sorted(v) for k, v in seqs.items()}

    @staticmethod
    def stats(log: str) -> dict[str, int]:
        out = {}
        for m in re.finditer(r"^(\d+) packets? (captured|received by filter|"
                             r"dropped by kernel|dropped by interface)", log,
                             re.M):
            out[m.group(2).replace(" ", "_")] = int(m.group(1))
        return out


class Dumpcap:
    """One dumpcap for all interfaces, writing pcapng."""

    name = "dumpcap"

    def __init__(self, binary: str, ifaces: list[str], snaplen: int,
                 buffer_mb: int, file_mb: int, flt: str):
        self.binary = binary
        self.ifaces = ifaces
        self.snaplen = snaplen
        self.buffer_mb = buffer_mb
        self.file_mb = file_mb
        self.flt = flt
        self.nano = False

    def commands(self, raw: str) -> list[tuple[str, list[str]]]:
        label = "+".join(self.ifaces) if len(self.ifaces) <= 3 else "multi"
        cmd = [self.binary, "-q", "-f", self.flt, "-s", str(self.snaplen),
               "-B", str(self.buffer_mb)]
        for i in self.ifaces:
            cmd += ["-i", i]
        cmd += ["-b", f"filesize:{self.file_mb * 1000}",
                "-w", os.path.join(raw, f"{label}.pcapng")]
        return [(label, cmd)]

    @staticmethod
    def files(raw: str) -> dict[str, list[tuple[int, str]]]:
        seqs: dict[str, list[tuple[int, str]]] = {}
        for name in os.listdir(raw):
            m = re.fullmatch(r"(.+)_(\d{5,})_\d{14}\.pcapng", name)
            if m:
                seqs.setdefault(m.group(1), []).append(
                    (int(m.group(2)), os.path.join(raw, name)))
        return {k: sorted(v) for k, v in seqs.items()}

    @staticmethod
    def stats(log: str) -> dict[str, int]:
        out: dict[str, int] = {}
        m = re.search(r"Packets captured: (\d+)", log)
        if m:
            out["captured"] = int(m.group(1))
        for m in re.finditer(r"Packets received/dropped on interface "
                             r"'([^']*)': (\d+)/(\d+)", log):
            out["received_by_filter"] = out.get("received_by_filter", 0) + \
                int(m.group(2))
            out["dropped_by_kernel"] = out.get("dropped_by_kernel", 0) + \
                int(m.group(3))
        return out


# -- turning raw files into results ------------------------------------------

class Pipeline:
    def __init__(self, outdir: str, mode: str, mapper, compress: bool,
                 ring: int, ports: list[int]):
        self.outdir = outdir
        self.mode = mode
        self.mapper = mapper
        self.compress = compress
        self.ring = ring
        self.ports = ports
        self.engines: dict = {}
        self.files: list[dict] = []
        self.pdus = 0
        self.q: queue.Queue = queue.Queue()
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._work, daemon=True)
        self.thread.start()

    def submit(self, label: str, seq: int, path: str) -> None:
        self.q.put((label, seq, path))

    def finish(self) -> None:
        self.q.put(None)
        self.thread.join()

    def backlog(self) -> int:
        return self.q.qsize()

    @property
    def encrypted(self) -> int:
        return sum(e.h.encrypted for e in self.engines.values())

    def _work(self) -> None:
        while True:
            item = self.q.get()
            if item is None:
                return
            try:
                self._process(*item)
            except BaseException as e:  # keep capturing; report at the end
                self.error = e
                note(f"error processing {item[2]}: {e}")

    def _process(self, label: str, seq: int, raw: str) -> None:
        ext = ".pcapng" if raw.endswith(".pcapng") and self.mode == "full" \
            else ".pcap"
        out = os.path.join(self.outdir, f"{label}-{seq:05d}{ext}"
                           + (".gz" if self.compress else ""))
        entry: dict = {"name": os.path.basename(out), "raw_bytes":
                       os.path.getsize(raw)}
        if self.mode == "full":
            if self.compress:
                with open(raw, "rb") as fi, \
                        pcapio.create(out + ".part", out) as fo:
                    shutil.copyfileobj(fi, fo, 1 << 20)
                os.replace(out + ".part", out)
                os.unlink(raw)
            else:
                os.replace(raw, out)
        else:
            engine = self.engines.get(label)
            if engine is None:
                engine = make_engine(self.mapper, self.ports)
                self.engines[label] = engine
            st = rewrite(raw, out, engine)
            os.unlink(raw)
            entry.update(frames=st.frames_out, pdus=st.pdus)
            self.pdus += st.pdus
            note(f"  {entry['name']}: "
                 f"{summary(st, entry['raw_bytes'], os.path.getsize(out))}")
        entry["bytes"] = os.path.getsize(out)
        self.files.append(entry)
        if self.ring:
            mine = [f for f in self.files if f["name"].startswith(label + "-")
                    and not f.get("deleted")]
            for old in mine[:-self.ring]:
                try:
                    os.unlink(os.path.join(self.outdir, old["name"]))
                except FileNotFoundError:
                    pass
                old["deleted"] = True


# -- the command ------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Capture SMB traffic into rotating files, optionally "
                    "keeping only the SMB headers or anonymizing each file "
                    "as it completes. Stop with Ctrl-C or --duration.",
        epilog="Modes: full keeps every byte; --headers cuts file data, "
               "directory listings and RPC out of each finished file (the "
               "headers and names stay, and latencies stay exact); "
               "--anonymize also replaces addresses and names. --snaplen "
               "is the cheap alternative to --headers: the kernel cuts "
               "every frame, and requests sharing a frame with a large one "
               "are lost.")
    ap.add_argument("-i", "--interface", action="append", default=[],
                    metavar="IFACE", help="interface to capture on, "
                    "repeatable (default: every interface with a global "
                    "address)")
    ap.add_argument("-o", "--output", metavar="DIR",
                    help="output directory (default: ./smbcap-<time>)")
    ap.add_argument("--host", action="append", default=[], metavar="ADDR",
                    help="only traffic to or from ADDR (a client), "
                    "repeatable")
    ap.add_argument("--port", action="append", type=int, default=[],
                    metavar="N", help="an SMB port besides 445 and 139")
    ap.add_argument("--filter", metavar="BPF",
                    help="capture filter replacing the built-in one")
    ap.add_argument("--vlan", action="store_true",
                    help="also match VLAN-tagged frames (trunk interfaces)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--headers", action="store_true",
                      help="keep SMB headers and names, cut bulk data")
    mode.add_argument("--anonymize", action="store_true",
                      help="headers only, with addresses, names, SIDs and "
                      "GUIDs replaced (see smb-anonymize)")
    mode.add_argument("--snaplen", type=int, metavar="BYTES",
                      help="have the kernel keep only the first BYTES of "
                      "each frame")
    ap.add_argument("--key", metavar="FILE",
                    help="anonymization key file (default: a new key in "
                    "the private directory)")
    ap.add_argument("--duration", metavar="T",
                    help="stop after T (90s, 10m, 2h)")
    ap.add_argument("--file-size", type=int, default=200, metavar="MB",
                    help="rotate raw files at this size (default 200)")
    ap.add_argument("--files", type=int, default=0, metavar="N",
                    help="keep only the newest N output files per "
                    "interface (a ring)")
    ap.add_argument("--max-size", type=int, default=0, metavar="MB",
                    help="stop once the output reaches this size")
    ap.add_argument("--min-free", type=float, default=2.0, metavar="GB",
                    help="stop when the output file system has less free "
                    "(default 2)")
    ap.add_argument("--compress", action="store_true",
                    help="gzip each finished file (tshark reads .pcap.gz)")
    ap.add_argument("--buffer", type=int, default=64, metavar="MB",
                    help="kernel capture buffer per interface (default 64)")
    ap.add_argument("--tool", choices=("auto", "tcpdump", "dumpcap"),
                    default="auto", help="capture program (default: tcpdump "
                    "if installed, else dumpcap)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would run and exit")
    args = ap.parse_args(argv)

    try:
        duration = parse_duration(args.duration) if args.duration else None
    except ValueError as e:
        ap.error(str(e))
    ifaces = args.interface or addressed_interfaces()
    if not ifaces:
        ap.error("no interface given and none found with an address; use -i")
    for i in ifaces:
        if i != "any" and not os.path.exists(f"/sys/class/net/{i}"):
            ap.error(f"no interface {i}")
    tool = args.tool
    if tool == "auto":
        tool = "tcpdump" if shutil.which("tcpdump") else "dumpcap"
    binary = shutil.which(tool)
    if binary is None:
        ap.error(f"{tool} not found")
    ports = sorted(set(DEFAULT_PORTS) | set(args.port))
    flt = args.filter or build_filter(ports, args.host, args.vlan)
    mode = "anonymized" if args.anonymize else "headers" if args.headers \
        else "full"
    snaplen = args.snaplen or 262144
    backend = (Tcpdump if tool == "tcpdump" else Dumpcap)(
        binary, ifaces, snaplen, args.buffer, args.file_size, flt)
    started = datetime.datetime.now(datetime.timezone.utc)
    outdir = os.path.abspath(args.output or
                             f"smbcap-{started.strftime('%Y%m%d-%H%M%S')}")
    raw = os.path.join(outdir, ".raw")
    private = outdir + ".private" if args.anonymize else None

    if args.dry_run:
        print(f"output: {outdir} ({mode})")
        if private:
            print(f"key and map: {private}")
        for _, cmd in backend.commands(raw):
            print(" ".join(_quote(c) for c in cmd))
        return 0

    os.makedirs(raw, exist_ok=True)
    free = shutil.disk_usage(outdir).free
    need = args.min_free * 1e9 + 2 * args.file_size * 1e6 * len(ifaces)
    if free < need:
        note(f"error: {outdir} has {free / 1e9:.1f} GB free; this capture "
             f"needs {need / 1e9:.1f} GB (--min-free plus two raw files per "
             "interface)")
        for d in (raw, outdir):
            try:
                os.rmdir(d)
            except OSError:
                pass
        return 1
    mapper = None
    if args.anonymize:
        os.makedirs(private, mode=0o700, exist_ok=True)
        try:
            key = mapping.load_key(args.key or os.path.join(private, "key"))
        except (OSError, ValueError) as e:
            note(f"error: {e}")
            return 1
        mapper = mapping.Mapper(key)
    else:
        smbstatus(os.path.join(outdir, "smbstatus-start.json"))

    stop = threading.Event()
    reason = ["interrupted"]
    procs: list = []

    def on_signal(signum, frame):
        if stop.is_set():
            # The capture programs run in their own sessions: stop them.
            for _, p, _ in procs:
                if p.poll() is None:
                    p.send_signal(signal.SIGINT)
            note(f"second interrupt: raw files left in {raw}")
            os._exit(130)
        stop.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    nic_before = {i: nic_counters(i) for i in ifaces if i != "any"}
    pipeline = Pipeline(outdir, mode, mapper, args.compress, args.files, ports)
    started_procs = _start(backend, raw)
    if started_procs is None:
        return 1
    procs.extend(started_procs)
    note(f"capturing on {', '.join(ifaces)} with {tool} into {outdir} "
         f"({mode}); Ctrl-C stops")
    submitted: set[str] = set()
    t0 = time.monotonic()
    last_note = t0
    while not stop.wait(POLL_S):
        now = time.monotonic()
        if duration is not None and now - t0 >= duration:
            reason[0] = "duration reached"
            break
        if all(p.poll() is not None for _, p, _ in procs):
            reason[0] = "capture program exited"
            break
        _submit(backend, raw, pipeline, submitted, final=False)
        if shutil.disk_usage(outdir).free < args.min_free * 1e9:
            reason[0] = f"less than {args.min_free:g} GB free"
            break
        out_bytes = sum(f["bytes"] for f in pipeline.files
                        if not f.get("deleted"))
        if args.max_size and out_bytes >= args.max_size * 1e6:
            reason[0] = "--max-size reached"
            break
        if now - last_note >= 60:
            last_note = now
            note(f"  {_elapsed(now - t0)}: {len(pipeline.files)} files "
                 f"done, {out_bytes / 1e6:.1f} MB"
                 + (f", {pipeline.backlog()} waiting" if pipeline.backlog()
                    else ""))
    note(f"stopping: {reason[0]}")
    exited = {lb: p.returncode for lb, p, _ in procs if p.poll() is not None}
    logs = _stop(procs)
    for lb, rc in exited.items():
        note(f"warning: {backend.name} on {lb} exited early ({rc}):\n"
             + _clean(logs.get(lb, "")))
    _submit(backend, raw, pipeline, submitted, final=True)
    pipeline.finish()
    stopped = datetime.datetime.now(datetime.timezone.utc)

    meta = {
        "tool": "smb-capture",
        "started": started.isoformat(timespec="seconds"),
        "stopped": stopped.isoformat(timespec="seconds"),
        "duration_s": round((stopped - started).total_seconds(), 1),
        "stop_reason": reason[0], "mode": mode, "capture_program": tool,
        "snaplen": snaplen, "filter": _anon_filter(flt, mapper),
        "host": host_info(mapper is not None),
        "interfaces": {}, "kernel_drops": {},
        "files": [f for f in pipeline.files if not f.get("deleted")],
    }
    for i in ifaces:
        info = interface_info(i) if i != "any" else {}
        after = nic_counters(i) if i != "any" else {}
        before = nic_before.get(i, {})
        delta = {k: after[k] - before[k] for k in after if k in before}
        if delta:
            info["counters_during_capture"] = delta
        meta["interfaces"][i] = info
    for label, log in logs.items():
        meta["kernel_drops"][label] = backend.stats(log)
    with open(os.path.join(outdir, "capture.json"), "w") as f:
        json.dump(meta, f, indent=1)
        f.write("\n")
    if mapper is None:
        smbstatus(os.path.join(outdir, "smbstatus-end.json"))
    else:
        write_map(mapper, os.path.join(private, "map.json"))
    try:
        os.rmdir(raw)
    except OSError:
        pass

    _report(meta, pipeline, outdir, private, logs, raw)
    return 1 if pipeline.error else 0


def _quote(s: str) -> str:
    return s if re.fullmatch(r"[\w@%+=:,./-]+", s) else "'" + \
        s.replace("'", "'\\''") + "'"


def _elapsed(s: float) -> str:
    s = int(s)
    return f"{s // 3600}:{s // 60 % 60:02d}:{s % 60:02d}"


def _start(backend, raw: str):
    """Start the capture programs; None if one fails at once."""
    procs = []
    for attempt in range(2):
        procs = []
        for label, cmd in backend.commands(raw):
            log = open(os.path.join(raw, f"{label}.log"), "w+")
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=log,
                                 start_new_session=True)
            procs.append((label, p, log))
        time.sleep(1.5)
        failed = [(lb, p, lg) for lb, p, lg in procs if p.poll() is not None]
        if not failed:
            return procs
        for _, p, _ in procs:
            if p.poll() is None:
                p.send_signal(signal.SIGINT)
                p.wait()
        logs = {lb: _read(lg) for lb, _, lg in procs}
        text = "\n".join(logs.values())
        if attempt == 0 and backend.nano and "precision" in text.lower():
            backend.nano = False  # this libpcap or NIC cannot do ns
            for f in os.listdir(raw):
                os.unlink(os.path.join(raw, f))
            continue
        for lb, _, _ in failed:
            note(f"error: {backend.name} on {lb} failed:\n"
                 + _clean(logs[lb]))
        return None
    return None


def _stop(procs) -> dict[str, str]:
    for _, p, _ in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGINT)
    deadline = time.monotonic() + 15
    for _, p, _ in procs:
        try:
            p.wait(max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    logs = {}
    for label, _, log in procs:
        logs[label] = _read(log)
        log.close()
        try:
            os.unlink(log.name)
        except OSError:
            pass
    return logs


def _read(log) -> str:
    log.flush()
    log.seek(0)
    return log.read()


def _clean(log: str) -> str:
    return "\n".join("  " + line for line in log.splitlines()
                     if line.strip() and "Running as user" not in line)


def _submit(backend, raw: str, pipeline: Pipeline, submitted: set[str],
            final: bool) -> None:
    """Hand finished raw files to the pipeline: every file but the
    newest of each sequence while capturing, all of them at the end."""
    for label, seqs in backend.files(raw).items():
        done = seqs if final else seqs[:-1]
        for seq, path in done:
            if path not in submitted:
                submitted.add(path)
                pipeline.submit(label, seq, path)


def _anon_filter(flt: str, mapper) -> str:
    if mapper is None:
        return flt

    def sub(m: re.Match) -> str:
        try:
            a = ipaddress.ip_address(m.group(0))
        except ValueError:
            return m.group(0)
        return str(ipaddress.ip_address(mapper.ip(a.packed)))

    return re.sub(r"[0-9A-Fa-f:.]*[.:][0-9A-Fa-f:.]+", sub, flt)


def _report(meta: dict, pipeline: Pipeline, outdir: str, private, logs,
            raw: str) -> None:
    files = meta["files"]
    total = sum(f["bytes"] for f in files)
    note(f"{len(files)} files, {total / 1e6:.1f} MB in {outdir}")
    for label, st in meta["kernel_drops"].items():
        if st.get("dropped_by_kernel"):
            note(f"warning: {label}: {st['dropped_by_kernel']} packets "
                 "dropped by the kernel; raise --buffer or narrow the "
                 "filter")
    for i, info in meta["interfaces"].items():
        c = info.get("counters_during_capture", {})
        lost = sum(c.get(k, 0) for k in ("rx_dropped", "rx_missed_errors",
                                         "rx_fifo_errors", "rx_over_errors"))
        if lost:
            note(f"warning: {i} dropped {lost} received frames during the "
                 "capture (NIC counters); the capture may miss them too")
    if pipeline.pdus and pipeline.encrypted * 2 > pipeline.pdus:
        note(f"warning: {pipeline.encrypted} of {pipeline.pdus} SMB messages "
             "are encrypted (SMB3); the analysis tools need the session keys "
             "to see inside them")
    if private:
        note(f"key and replacement map: {private} (keep them, do not "
             "share them)")
    if os.path.isdir(raw):
        note(f"raw files left in {raw}")
