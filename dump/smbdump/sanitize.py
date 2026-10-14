"""smb-trim and smb-anonymize: rewrite captures."""

from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
import time

from . import mapping, pcapio
from .engine import Engine, Stats
from .smb2 import Handlers

DEFAULT_PORTS = (445, 139)


def rewrite(src: str, dst: str, engine: Engine) -> Stats:
    """Run one capture through an engine into dst (written atomically).
    An engine reused across files keeps its per-connection state."""
    before = Stats()
    before.add(engine.stats)
    tmp = dst + ".part"
    try:
        with pcapio.open_capture(src) as fi, \
                pcapio.create(tmp, dst) as fo:
            records = pcapio.read(fi)
            first = next(records, None)
            link = first.link if first is not None else pcapio.LINK_ETHERNET
            writer = pcapio.Writer(fo, link)
            if first is not None:
                engine.run(itertools.chain([first], records), writer)
        os.replace(tmp, dst)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    st = Stats()
    for k, v in vars(engine.stats).items():
        setattr(st, k, v - getattr(before, k))
    return st


def make_engine(mapper: mapping.Mapper | None, ports=DEFAULT_PORTS,
                zero: bool = False, full: bool = False,
                keep_other: bool = False) -> Engine:
    return Engine(Handlers(mapper, full), ports, strip=not zero,
                  anon=mapper is not None, keep_other=keep_other)


def summary(st: Stats, size_in: int, size_out: int) -> str:
    """One line on a rewrite; the sizes are the files'."""
    parts = [f"{st.frames} frames", f"{size_in / 1e6:.1f} MB -> "
             f"{size_out / 1e6:.1f} MB", f"{st.pdus} PDUs"]
    if st.frames_out != st.frames:
        parts.append(f"{st.frames_out} frames out")
    if st.dropped:
        parts.append(f"{st.dropped} non-SMB frames dropped")
    if st.gaps:
        parts.append(f"{st.gaps} gaps in the capture")
    if st.partial:
        parts.append(f"{st.partial} PDUs incomplete")
    if st.unknown:
        parts.append(f"{st.unknown} bytes not attributable to a PDU")
    return ", ".join(parts)


def _outputs(inputs: list[str], output: str | None, suffix: str) -> list[str]:
    if output and (len(inputs) > 1 or os.path.isdir(output)):
        os.makedirs(output, exist_ok=True)
        return [os.path.join(output, _name(os.path.basename(p), suffix))
                for p in inputs]
    if output:
        return [output]
    return [_name(p, suffix) for p in inputs]


def _name(src: str, suffix: str) -> str:
    base, gz = (src[:-3], ".gz") if src.endswith(".gz") else (src, "")
    for ext in (".pcapng", ".pcap", ".cap"):
        if base.endswith(ext):
            base = base[:-len(ext)]
            break
    return base + suffix + gz


def _common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("captures", nargs="+", metavar="CAPTURE",
                    help="pcap or pcapng, gzipped or not; several (a "
                    "rotated set) are processed with shared state")
    ap.add_argument("-o", "--output", metavar="PATH",
                    help="output file, or directory for several inputs")
    ap.add_argument("--zero", action="store_true",
                    help="overwrite payloads with zeros instead of cutting "
                    "them: frames keep their sizes")
    ap.add_argument("--port", action="append", type=int, default=[],
                    metavar="N", help="an SMB port besides 445 and 139")
    ap.add_argument("-q", "--quiet", action="store_true")


def _run(args, engine: Engine, suffix: str) -> int:
    outs = _outputs(args.captures, args.output, suffix)
    for src, dst in zip(args.captures, outs):
        t0 = time.time()
        try:
            st = rewrite(src, dst, engine)
        except (OSError, pcapio.FormatError) as e:
            print(f"error: {src}: {e}", file=sys.stderr)
            return 1
        if not args.quiet:
            sizes = os.path.getsize(src), os.path.getsize(dst)
            print(f"{dst}: {summary(st, *sizes)} ({time.time() - t0:.1f}s)",
                  file=sys.stderr)
    return 0


def main_trim(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Cut bulk data out of SMB captures: READ and WRITE "
                    "payloads, directory listings, change notifications, "
                    "named-pipe RPC and encrypted payloads. Every SMB "
                    "header and name stays, and tshark still finds every "
                    "request.")
    _common(ap)
    args = ap.parse_args(argv)
    ports = set(DEFAULT_PORTS) | set(args.port)
    return _run(args, make_engine(None, ports, args.zero), ".trim.pcap")


def main_anonymize(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Anonymize SMB captures: addresses, MACs, host, "
                    "domain, user, share and file names, SIDs and GUIDs "
                    "are replaced consistently by keyed hashes; "
                    "credentials and bulk data are removed; anything not "
                    "understood is zeroed; frames other than SMB are "
                    "dropped.",
        epilog="Without --key a random key is used and discarded, so only "
               "the --map table relates the output to the original. Keep "
               "the key and the map to yourself.")
    _common(ap)
    ap.add_argument("--key", metavar="FILE",
                    help="hex key file, created if missing; the same key "
                    "gives the same replacements across captures")
    ap.add_argument("--map", metavar="FILE",
                    help="write the replacements made (JSON) here")
    ap.add_argument("--full", action="store_true",
                    help="keep directory listings and change notifications, "
                    "names replaced, instead of cutting them")
    ap.add_argument("--hash-ext", action="store_true",
                    help="replace file extensions too")
    ap.add_argument("--keep-other", action="store_true",
                    help="keep non-SMB IP frames, addresses replaced and "
                    "payloads cut")
    args = ap.parse_args(argv)
    try:
        key = mapping.load_key(args.key) if args.key else mapping.new_key()
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    m = mapping.Mapper(key, keep_ext=not args.hash_ext)
    ports = set(DEFAULT_PORTS) | set(args.port)
    rc = _run(args, make_engine(m, ports, args.zero, args.full,
                                args.keep_other), ".anon.pcap")
    if rc:
        return rc
    if not args.quiet:
        counts = ", ".join(f"{n} {k}" for k, n in sorted(m.counts().items()))
        print(f"replaced: {counts or 'nothing'}", file=sys.stderr)
    if args.map:
        write_map(m, args.map)
    return 0


def write_map(m: mapping.Mapper, path: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(m.table(), f, indent=1, ensure_ascii=False)
        f.write("\n")
