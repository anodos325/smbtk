"""smb-prof-ctl: which smbd processes count, switching one or all on and
off, and zeroing the counters."""

from __future__ import annotations

import argparse
import json

from . import cli, smbd
from .cmd_record import serving, session_extra
from .collect import Collector
from .samba import Samba, SambaError
from .tdb import Reader, TdbError, wipe


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Samba's profiling counters per smbd process. status "
        "(default): each process with its clients, user, profiling level "
        "and what its counters hold. on, count, off: set the level in the "
        "processes chosen. reset: delete the counters' records, so "
        "smbstatus --profile starts again from zero.",
        epilog="on counts requests, time and latency; count only counts. "
        "A process started by the main smbd takes the main one's level, so "
        "--all covers new connections too. Per-share counters also need "
        "'smbd profiling share = yes' on the share, and start with the "
        "tree connect.")
    ap.add_argument("action", nargs="?", default="status",
                    choices=("status", "on", "count", "off", "reset"))
    g = ap.add_argument_group("processes (on, count, off)")
    g.add_argument("--client", action="append", default=[], metavar="ADDR",
                   help="the smbd serving this client (repeatable)")
    g.add_argument("--pid", action="append", type=int, default=[])
    g.add_argument("--all", action="store_true",
                   help="the main smbd and every process serving clients")
    g.add_argument("--port", action="append", type=int, default=[],
                   help="SMB port, to find clients (default: the main "
                   "smbd's listening ports)")
    ap.add_argument("--json", action="store_true", help="status as JSON")
    cli.add_samba_args(ap)
    args = ap.parse_args(argv)
    samba = Samba(args.samba, args.configfile)
    try:
        main_pid, procs = smbd.instance(samba.main_pid(), args.port or None)
    except OSError as e:
        raise SystemExit(f"smb-prof-ctl: {e}")
    serve = {p: pr for p, pr in procs.items() if serving(pr, main_pid)}
    if not serve:
        raise SystemExit("smb-prof-ctl: no smbd running")
    try:
        if args.action == "reset":
            path = args.tdb or samba.tdb_path()
            try:
                wipe(path, args.samba)
            except (OSError, TdbError) as e:
                raise SystemExit(f"smb-prof-ctl: {path}: {e}")
            print(f"{path}: every record deleted; processes counting "
                  "write theirs again within a second")
            return 0
        if args.action in ("on", "count", "off"):
            if not (args.all or args.client or args.pid):
                ap.error("say which: --all, --client or --pid")
            chosen = sorted(p for p, pr in serve.items() if args.all or
                            p in args.pid or any(smbd.serves(pr.clients, c)
                                                 for c in args.client))
            missing = set(args.pid) - set(serve)
            if missing:
                raise SystemExit(f"smb-prof-ctl: not an smbd of this "
                                 f"instance: {sorted(missing)}")
            if not chosen:
                raise SystemExit("smb-prof-ctl: no smbd serves "
                                 + ", ".join(args.client))
            res = samba.set_levels(chosen, args.action)
            for p in chosen:
                pr = serve[p]
                who = "main smbd" if p == main_pid else \
                    ",".join(pr.clients) or pr.comm
                print(f"{p:>8}  {who}: "
                      f"{args.action if res[p] else 'no answer'}")
            return 0 if all(res.values()) else 1
        return status(args, samba, main_pid, serve)
    except SambaError as e:
        raise SystemExit(f"smb-prof-ctl: {e}")


def status(args, samba: Samba, main_pid: int | None, serve: dict) -> int:
    levels = samba.get_levels(sorted(serve))
    extra = session_extra(samba.sessions())
    info = {"samba": samba.version(),
            "configured_level": samba.param("smbd profiling level"),
            "main_pid": main_pid}
    records = {}
    shares = []
    try:
        layout = samba.layout()
        path = args.tdb or samba.tdb_path()
        reader = Reader(path, args.samba, not args.no_bindings)
        raw = reader.read()
        col = Collector(layout, {m for m in (layout.magic(16),
                                             layout.magic(8)) if m})
        p_now, s_now = col.decode(raw)
        req = layout.by_name.get("request")
        for pid, words in p_now.items():
            records[pid] = words[req.offset] if req else None
        shares = sorted(s_now)
        info.update(tdb=path, reader=reader.how, records=len(raw),
                    foreign_records=col.foreign)
    except (SambaError, OSError, TdbError) as e:
        info["tdb_error"] = str(e)
    procs = []
    for p in sorted(serve):
        pr = serve[p]
        procs.append({"pid": p, "comm": pr.comm, "main": p == main_pid,
                      "clients": pr.clients, **extra.get(p, {}),
                      "level": levels.get(p), "requests": records.get(p)})
    info["processes"] = procs
    info["share_records"] = shares
    if args.json:
        print(json.dumps(info, indent=1))
        return 0
    print(f"Samba {info['samba']}; smbd profiling level = "
          f"{info['configured_level'] or '?'} in smb.conf")
    if "tdb_error" in info:
        print(f"counters: {info['tdb_error']}")
    else:
        foreign = f", {info['foreign_records']} from another build" \
            if info["foreign_records"] else ""
        print(f"counters: {info['tdb']} ({info['records']} records"
              f"{foreign}; {info['reader']})")
    print()
    rows = []
    for x in procs:
        if x["main"]:
            rec = "closed connections" if x["requests"] is not None else ""
        else:
            rec = ""
        req = x["requests"]
        rows.append([x["pid"], x["comm"] + (" (main)" if x["main"] else ""),
                     ", ".join(x["clients"]) or "-",
                     ",".join(x.get("users", [])) or "-",
                     x["level"] or "no answer",
                     ("-" if req is None else f"{req} requests") +
                     (f" ({rec})" if rec else "")])
    print(cli.table(rows, ["pid", "process", "clients", "user", "level",
                           "counted since reset"], "rlllll"))
    if shares:
        print("\nper-share records: " + ", ".join(shares))
    return 0
