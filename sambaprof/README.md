# Samba profiling counters

Python around the counters smbd keeps when built with profiling (TrueNAS
builds it so): switch them on in one smbd, found by its client's
address, or in all of them; sample them every second into JSON lines;
read the samples back by SMB2 command, process, client, user or share.
Python 3.10+ and Samba's own `smbstatus`, `smbcontrol` and `testparm`.
Samba's `tdb` Python module, when installed (TrueNAS has it), reads the
counters under Samba's locks; otherwise a reader here does, without.

| tool               | does                                                    |
|--------------------|---------------------------------------------------------|
| `smb-prof-ctl`     | which smbd processes count; switch them on, off; reset  |
| `smb-prof-record`  | sample the counters of chosen processes as JSON lines   |
| `smb-prof-summary` | requests, bytes, time, CPU; every command and syscall   |
| `smb-prof-latency` | latency of each SMB2 command from Samba's buckets       |
| `smb-prof-hist`    | counters over time, one column per command or group     |
| `smb-prof-compare` | recordings side by side, per request                    |

## Recording

```
smb-prof-ctl                                  # processes, clients, levels
smb-prof-record --client 10.1.2.3             # one client's smbd; Ctrl-C ends
smb-prof-record --duration 10m -o day.jsonl.gz
smb-prof-record -o new.jsonl -- ./workload.sh # while a workload runs
smb-prof-ctl on --client 10.1.2.3             # or by hand
```

smbd counts only at profiling level `on` (counts, time, latency
buckets) or `count` (counts only); `smbd profiling level` sets it at
start, default `off`, and TrueNAS leaves it off. `smbcontrol PID profile
on` sets one process, and a process the main smbd forks starts at the
main one's level. Each process adds what it counted to its record in
`smbprofile.tdb`, in the cache directory (`/var/run/samba-cache` on
TrueNAS), about once a second; when it exits, cleanupd adds its record
to the main smbd's. With `smbd profiling share = yes` on a share, each
tree connect made while counting also gets a record of its own,
`share:pid.snum[client]`, gone with the tree connect.

`smb-prof-record` turns profiling on in the processes chosen, reads the
tdb every `--interval` (1 s) and writes what changed, per process and
per share, until `--duration`, the workload's end or Ctrl-C; then it
puts each level back (`--keep` leaves them on, `--no-enable` touches
none). The default is every smbd, the main one included, so new
connections count from their first request; `--client ADDR` takes the
processes serving that address and switches on any that start serving
it, from the next interval; `--pid` takes one process. The recording
starts from its first sample, so it needs no reset. A process that
exits has its last moments counted when cleanupd merges its record:
given back to it if it left alone, else under the main smbd as closed
connections. One line per interval shows requests, failures, mean
latency, bytes in and out, CPU and the busiest commands; a summary
follows at the end.

The file (`-o`, `.gz` compresses) is JSON lines: `start` (host, Samba
version, level, the counter layout), `proc` (pid, clients, users,
dialect, encryption, signing), `share`, `sample`, `exit`, `event`,
`end`. A sample has `t`, `dt` and, per pid and per share record, the
counters that moved: `{"d": {"smb2_read": {"count": 12, "time": 9840,
"buckets": [...], "outbytes": 786432}}, "g": {"num_files": 3}}`, the
names Samba's and times in microseconds; `g`, the gauges
(sessions, tree connects, open files), only when they change.

```
jq -c 'select(.type=="sample") | [.t, .procs["4242"].d.smb2_read.count]' run.jsonl
```

Cost to smbd: two clock reads per request and one tdb write per process
per second.

## Reading the numbers

- **Time** is smbd's, from dispatch to the reply built. *Parked* is
  the part a request waited for an event (a deferred open, a notify);
  *busy* leaves it out. CHANGE_NOTIFY waits for changes by design, so
  its time stays out of totals unless `--waits`.
- **Latency bins** are Samba's: below 1, 2, 4 ... 256 ms, then the
  rest. Percentiles are shown as the bin holding them (`p99 4-8ms`);
  means are exact. Level `count` keeps neither.
- **Bytes** in and out are request and response sizes, headers
  included: WRITE data comes in, READ data goes out.
- **CPU** is each process's rusage, all threads (io_uring workers
  too); *per request* divides by SMB2 requests.
- **System calls** are the calls Samba's VFS makes (`asys_` ones run
  in its thread pool or io_uring), and *per request* is a good number
  to compare builds by: a build that opens every directory entry it
  lists shows an `openat` per entry.
- **Identity switches** are set_sec_ctx and set_root_sec_ctx: becoming
  the user, becoming root.
- **Rows**: a process writes about once a second, so a one-second row
  can hold none or two of its writes; longer rows (`--interval`)
  smooth that out.

## Reset

`smb-prof-ctl reset` (and `smb-prof-record --reset`) delete every
record through a tdb handle opened just for it, so `smbstatus
--profile` starts again from zero; processes counting write theirs
again within a second, and per-share records come back with their
totals since the tree connect. It needs the tdb module.

The tools never send Samba's own reset, `smbcontrol PID profile flush`.
On Samba 4.24 it can leave the profile tdb broken until smbd restarts.
The main smbd wipes through the handle it opened at start, whose idea
of the file size predates the records its children added. The records
past that size stay behind, unlisted, and tdb merges each later
expansion into the free record left of it, which is one of those
records. Every store then fails and expands the file again, until it
reaches 4 GB, in tmpfs on TrueNAS.

## Analysis

The analysis tools read a recording and share these options:
`--from T`, `--to T` (seconds into the recording, or wall clock:
`@EPOCH`, ISO 8601, `HH:MM:SS`, UTC), `--client ADDR`, `--pid PID`,
`--share NAME` (per-share records).

**smb-prof-summary** `[--by pid|client|user|share] [--top N] [--waits]
[--json]`. Requests with rate and failures, bytes, SMB2 time and mean,
CPU per request, identity switches, sessions; every SMB2 command with
rate, failures, mean, p50 and p99 bins, share of time, time parked,
bytes; system calls and ACL calls with calls per request and mean time.
`--by` adds a row per group with its busiest command.

**smb-prof-latency** `[--by ...] [--op OPS] [--counts] [--hist]
[--syscalls] [--json]`. Per SMB2 command: count, failures, mean, busy
mean, the share of requests in each bin, the p50, p90 and p99 bins;
`--hist` draws each command's bins; `--syscalls` adds each system call's
mean time.

**smb-prof-hist** `[--by op|none|pid|client|user|share] [--metric
rate|count|failed|time|mean|p99|in|out|cpu] [--op OPS] [--interval T]
[--top N] [--waits] [--csv] [--bars]`. One row per interval, one column
per command (default) or group; `--op` picks commands or system calls
(`READ,WRITE`, `openat`).

**smb-prof-compare** `FILE... [--label A,B] [--op OPS] [--top N]
[--waits] [--json]`. Against the first recording: requests per second,
mean latency and p99 bin, CPU, system calls and identity switches per
request, bytes; then each SMB2 command (rate, mean, p99) and each
system call (per request, mean).

`--op` takes SMB2 names (`QUERY_DIRECTORY`), short forms (`FIND`,
`GETINFO`, `NOTIFY` ...) or Samba's (`smb2_find`, `syscall_openat`,
`openat`).

```
smb-prof-summary run.jsonl --by client
smb-prof-latency run.jsonl --op READ,WRITE --hist
smb-prof-hist run.jsonl --metric mean --by client --interval 10s
smb-prof-compare old.jsonl new.jsonl --label old,new
```

## Samba builds

`--samba DIR` uses a Samba installed under DIR (its `bin/`, `sbin/` and
Python modules), `-s FILE` its smb.conf; `--tdb` names the counters'
file, `--no-bindings` reads it without the tdb module. The counter
layout comes from `smbstatus --profile` and is checked against the
magic smbd stamps on its records (SHA-1 of the layout), so a different
Samba version reads correctly and a mismatched one is reported. Clients
are found from `/proc`: established connections to the ports the main
smbd listens on (`--port` to override).

## Tests

```
python3 -m pytest sambaprof/tests
SMBPROF_SAMBA=/usr/local/samba python3 -m pytest sambaprof/tests  # as root
```

Synthetic tdb files (plain and mutex) and counter snapshots cover the
reader, the layout of a real 4.24 `smbstatus --profile` against its
magic, the deltas (resets, exits merged into the main smbd, CPU of a
process switched on while running, pid reuse, shares) and every tool.
With a Samba build given, a private smbd on a free port is recorded
under two clients and the sums are checked field by field against
`smbstatus --profile`, and both tdb readers and the reset are checked.
