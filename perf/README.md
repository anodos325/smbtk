# smbd profiling

Python around Linux `perf` for finding where smbd's time goes: on the
CPU, waiting, or in system calls, and by SMB2 command. Python 3.10+ and
perf (`linux-perf`), nothing else; flame graphs are drawn here, and the
folded stacks also work with flamegraph.pl, inferno and speedscope.

| tool               | does                                                        |
|--------------------|-------------------------------------------------------------|
| `smb-perf-record`  | record smbd: perf.data, folded stacks, flame graph, summary |
| `smb-perf-flame`   | flame graph or call tree of a recording, or of a change     |
| `smb-perf-top`     | tables: functions, SMB2 commands, callers, stacks, binaries |
| `smb-perf-fold`    | folded stacks for other tools                               |
| `smb-perf-stat`    | CPU time, cycles, instructions of smbd over a workload      |
| `smb-perf-compare` | A/B table of `smb-perf-stat` runs                           |

## Recording

```
smb-perf-record                          # every smbd, 10 s, on-CPU
smb-perf-record --client 10.1.2.3        # the smbd serving one client
smb-perf-record --mode off --duration 5  # where smbd waits
smb-perf-record --mode syscalls          # which code makes which system calls
smb-perf-record -- ./replay.sh           # for as long as a workload runs
smb-perf-record --list                   # smbd processes and their clients
```

Modes:

- **cpu** (default): cycles sampled 999 times a second per thread.
- **off**: every switch off the CPU, timed until the thread runs again
  and charged to the stack it blocked in: waiting for requests, disk,
  locks, or runnable but preempted.
- **syscalls**: every system call with the stack making it.

Output, in `./smbperf-<mode>-<time>/` or `-o DIR`: `perf.data`,
`perf.json` (what was recorded, when, the processes and their clients,
CPU, clock policy, versions), `perf.folded`, `flame.svg`, and a summary
on screen: weight by process and by SMB2 command, or system calls by
count.

By default every smbd process is recorded, the parent daemon included,
so connections made during the recording are recorded too (perf follows
forks); `--client`, `--pid`, `--comm` pick processes running now,
`--system` records everything. io_uring workers (`iou-wrk`) are threads
of their smbd and appear under it. perf starts with its events off and
they are switched on and off through its control FIFOs, so the
recording covers the workload or the duration exactly.

Size: cpu mode copies 16 KB of stack per sample, about 16 MB a second
per busy thread; off and syscalls modes take a sample per switch or
call, so keep them to a few seconds. `--max-size` (4G) caps the file.

`perf.data` can only be read on the machine that recorded it (it needs
its binaries); `perf.folded`, `flame.svg` and `perf.json` can travel,
and the tools read `perf.folded` when a directory comes from another
host. Static functions need Samba's debug symbols; without them their
time goes to the nearest exported function.

## Reading the numbers

- **Cycles, not seconds.** With the `schedutil` or `powersave`
  governor a request-response workload runs at a fraction of full
  clock, so time per request moves between runs while cycles do not.
  The tools print the governor; set `performance` for timing runs.
- **Stacks.** Samba is built without frame pointers, so user stacks
  are unwound from the copy of the stack taken with each sample (DWARF,
  `--call-graph`). A stack deeper than the copy loses its outermost
  frames. The tools start smbd's stacks at the handler its event loop
  ran, under one `[event loop]` frame, so cut and whole stacks line up
  (`--keep-loop` to see them as recorded).
- **SMB2 commands** (`--ops`, and the recording summary): each stack
  goes to the outermost smbd function named after a command: its
  handler (`smbd_smb2_request_process_create`), its completion
  (`smbd_smb2_request_create_done`), io_uring completions; io_uring
  workers by operation. The rest: SMB2 dispatch, receive and send,
  event loop, messaging, incomplete stack (unwinding stopped short of
  the handler), other. `--requests` with `smb-latency --json --by cmd`
  for the same window adds the cost per request.
- **Off-CPU.** `[preempted]` marks time runnable but not running,
  `[uninterruptible]` time in D state (disk, some locks); idle
  io_uring workers and the event loop's `epoll_wait` are smbd waiting
  for work. `[preempted]` is read from perf's switch records, so it
  survives a perf built without libtraceevent (TrueNAS ships one),
  which prints no tracepoint fields; `[uninterruptible]` needs them.
- **Frames.** Kernel functions end in `_[k]`, as stackcollapse-perf.pl
  marks them; inlined functions are frames of their own. In the SVG the
  kernel is orange, kernel modules (ZFS, SPL) teal, user code red to
  yellow, frames these tools add lavender. On loopback, socket sends and
  receives cost both ends on one box.

## Analysis

`smb-perf-flame`, `smb-perf-top` and `smb-perf-fold` take a recording
directory, a `perf.data`, saved `perf script` output or folded stacks,
and share these options:

- **selection** (not for folded input): `--from T`, `--to T` (seconds
  into the recording, or wall clock: `@EPOCH`, ISO 8601, `HH:MM:SS.f`,
  UTC unless given an offset; `smb-summary` prints a capture's start in
  UTC), `--client ADDR`, `--comm GLOB`, `--pid`, `--tid`, `--event`,
  `--root process|role|comm|pid|none` (the first frames: `smbd[client]`
  then the thread role; `role` merges clients), `--samples`,
  `--no-inline`, `--user-only`, `--no-kernel-mark`.
- **stacks**: `--grep RE`, `--exclude RE`, `--focus RE` (start at
  that function, callers merged), `--keep-loop`, `--unit` (for folded
  input without its `perf.json`).

`perf script` runs once per recording; its output is cached under
`~/.cache/smb_toolkit/perf/` (`--refresh`, `--no-cache`).

**smb-perf-flame** `[-o FILE] [--diff BASE [--widths new|base]
[--absolute] [--per N[:UNIT] --base-per N[:UNIT]] [--base-from T]
[--base-to T]] [--reverse] [--icicle] [--title T] [--width PX]
[--tree [--min-pct P] [--depth N] [--top N]]`. Self-contained SVG:
hover for the numbers, click to zoom, Ctrl-F to search (shows the
share matched). `--diff` keeps INPUT's widths and colours each
function by the change in its own share, red more, blue less; shares
of each total unless `--absolute` or per unit of work with `--per` and
`--base-per`. `--tree` prints the call tree as text, chains of single
children on one line, with the base and change in a diff.

**smb-perf-top** `[--ops | --below FUNC | --callers FUNC | --stacks [N]
| --dso | --process] [--depth N] [--sort self|total] [--top N]
[--per N[:UNIT]] [--requests FILE] [--diff BASE ...] [--json]`.
Functions by own and total share; `--below` what runs under a function
(`--depth` for call paths), `--callers` the chains above it,
`--stacks` the heaviest stacks by their last N frames (off-CPU: what
smbd waits in, with counts and mean wait), `--dso` own weight by binary
(a system call by the binary above the C library), `--process` by
process and thread. `--diff` lists the functions, or with `--ops` the
commands, whose total moved most.

**smb-perf-fold** `[-o FILE]`: one line per stack, root first, `;`
between frames, weight last.

```
smb-perf-top rec/ --ops --per 3000:file
smb-perf-top rec/ --below smbd_smb2_request_process_create --depth 2
smb-perf-top rec/ --callers memcpy_orig --depth 6
smb-perf-flame rec/ --client 10.1.2.3 --from 12 --to 14 -o slow.svg
smb-perf-flame rec/ --focus open_file_ntcreate --tree --min-pct 2
smb-perf-flame new/ --diff old/ -o change.svg
smb-perf-fold rec/perf.data --root comm | flamegraph.pl > fg.svg
```

## Counting and A/B

**smb-perf-stat** `[--client|--pid|--comm|--system] [--duration T |
-- COMMAND] [--interval T] [--per N[:UNIT]] [--label L] [-o FILE]
[--json]` counts CPU time, cycles, instructions, context switches,
migrations and page faults (`--events`) of smbd over a workload or a
time: totals, GHz while running, instructions per cycle, per process,
per interval, per unit of work. A workload that opens its own
connection is counted through the parent smbd (the default).

**smb-perf-compare** `RUN.json... [--base LABEL] [--per] [--json]`:
median and range per label, change against the base, `*` where the
ranges do not overlap.

```
for i in 1 2 3; do                  # interleaved, A B B A ...
  smb-perf-stat --label old -o runs/old-$i.json --per 3000:file -- ./replay.sh old
  smb-perf-stat --label new -o runs/new-$i.json --per 3000:file -- ./replay.sh new
done
smb-perf-compare runs/*.json --per
smb-perf-top new/ --diff old/ --ops --per 3000:file --base-per 3000:file
```

## Tests

```
python3 -m pytest perf/tests
```

Synthetic perf script output covers parsing, folding (stackcollapse-
perf.pl's naming), off-CPU pairing, system calls, the event-loop cut,
the SMB2 command split and every tool; the flame graph's script runs
under node when installed; with root and perf, live recordings of a
busy and a sleeping process. `tools/gen_syscalls.py` regenerates
`smbperf/syscalls_gen.py` from a kernel tree.
