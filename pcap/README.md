# SMB capture analysis

Python tools that run tshark over an SMB capture and report what is in
it, how long the server took, what the client keeps doing and what
failed. Python 3.10+ and tshark (tested with 4.4), nothing else.
Captures are pcap or pcapng, gzipped or not; [`../dump`](../dump/README.md)
takes, trims and anonymizes them. Payloads are never extracted: a READ
or WRITE is kept as file id, offset and length.

| tool           | shows                                                       |
|----------------|-------------------------------------------------------------|
| `smb-summary`  | connections, sessions, shares, command mix, resets          |
| `smb-latency`  | latency per command or any level; the slowest, in context   |
| `smb-flame`    | flame graph or tree of where time, count, bytes, idle went  |
| `smb-hist`     | requests over time: count, errors, time, bytes, queue depth |
| `smb-repeats`  | the same request to the same target, over and over          |
| `smb-dirscans` | directories listed again, and the entries read each time    |
| `smb-errors`   | failures sorted into errors, probes, collateral and flow    |
| `smb-trace`    | one line per request, with frame numbers                    |
| `smb-extract`  | the per-PDU records the others read                         |

## Selecting

Every tool takes the same selection options, each repeatable:
`--client IP`, `--server IP`, `--share NAME`, `--user TEXT`,
`--file GLOB`, `--cmd CMD`, `--status STATUS`, `--stream N`,
`--session ID`, `--from T`, `--to T`, `--errors-only`.

```
smb-latency cap.pcap --client 10.1.2.3 --share data --from 1m --to 1m30s
smb-trace   cap.pcap --file '*.docx' --cmd CREATE,SET_INFO
smb-errors  cap.pcap --user alice --status ACCESS_DENIED
smb-flame   cap.pcap --cmd READ,WRITE --stack share,file,sub -o io.svg
```

`--cmd` takes SMB2 command names, short forms (FIND, GETINFO, SETINFO,
NOTIFY, BREAK, TCON, TDIS) or numbers; `--status` an NT status name
with or without `STATUS_`, or a number. Several captures given at once
(a rotated set, in any order) are taken in time order, a connection
running on into the next file stays one connection, and frames show as
`file:frame`. A `.smbx` file from `smb-extract` is accepted in place of
a capture.

## Reading the numbers

- **Latency** is request last byte to response last byte at the
  capture point. Each tool says whether the capture looks taken on the
  server (latency is server time), on the client (plus a round trip)
  or elsewhere, judged from the TCP handshake, which side ACKs within
  microseconds, and the fastest response against the fastest client
  turnaround. In a cut capture (a snapshot length, `smb-trim`) tshark
  sees a long message where it starts; it is timed by the frame
  holding its last byte instead, so latencies match a full capture. If
  that frame is missing, the last frame before it stands in.
- **Compounds** are answered in one message, so their members share
  one latency wherever time is summed; per-request views still show
  each member's own value.
- **Waits** (CHANGE_NOTIFY, FSCTL_PIPE_WAIT) measure the event, not
  the server, and are left out of time-weighted views unless `--waits`.
- **Idle** (`--idle`, `smb-flame --weight idle`, `smb-hist --metric
  idle`) is how long a client, by address, had nothing outstanding
  before a request: from its last response's last byte to the request's
  first byte. That is the client's think time, plus the round trip when
  seen from the server. Waits never count as outstanding; a compound's
  idle goes to its first member; a client's first request in the
  capture has none.
- **Failure classes**: *error* is a real failure (ACCESS_DENIED,
  SHARING_VIOLATION, LOCK_NOT_GRANTED ...); *probe* a negative answer
  the client asked for (NOT_FOUND on an existence check, NOT_SUPPORTED
  on an FSCTL tried once); *collateral* a compound member skipped
  because an earlier member failed; *flow* part of a normal exchange
  (MORE_PROCESSING_REQUIRED, NO_MORE_FILES, END_OF_FILE, PENDING, a
  cancelled notify); *unanswered* never got a response.
- **Names**: shares from TREE_CONNECT, users from SESSION_SETUP
  (NTLMSSP; Kerberos shows the service name), paths from CREATE, tied
  to later requests by file id. Anything set up before the capture
  began shows as `tid:0x..` or `fid:..`.

## Tools

**smb-summary** `[--top N] [--idle]`. Connections with dialect, request
count, fastest response and TCP trouble; sessions; shares with bytes
read and written; commands with p50/p99/max and share of time; breaks;
requests still unanswered at the end; resets; extractor diagnostics;
directories listed again, as in `smb-dirscans`. `--idle` adds a row per
client: span from first request to last response, idle time and its
share of the span, pauses, longest and median pause.

**smb-latency** `[--by LEVELS] [--sort time|n|p50|p99|max|idle]
[--top N] [--min-count N] [--hist] [--slowest N] [--idle] [--json]`.
One row per group. `--slowest` lists requests with what else was going
on: went async (and when), cancelled, in a compound, breaks sent while
outstanding. `--idle` adds the idle time before each group's requests,
total and median.

**smb-flame** `[--stack LEVELS] [--weight time|count|bytes|idle]
[--idle] [-o FILE] [--tree] [--json] [--collapsed] [--top N]
[--title T] [--width PX] [--min-pct P]`. Self-contained SVG. `--weight`
sets what a frame's width means; each frame is labelled with its
request count when it fits, and hovering shows its time, share,
request count, time per request and bytes. Click to zoom. Default
stack `client,share,cmd,sub,status`, default output
`<capture>.flame.svg`. `--tree` prints the same tree as indented text
with those numbers per row, children largest first and everything past
`--top` per node summed into one row; `--json` prints it as nested
objects (name, value, n, time_ns, bytes, children), which
d3-flame-graph reads as is; `--collapsed` prints folded stacks for
flamegraph.pl or speedscope. `--idle` adds idle time to the tree, the
JSON (`idle_ns`) and the hover text; `--weight idle` sizes the frames
by it, so the widest show what the client hesitates before.

```
smb-flame cap.pcap --tree --stack share,path,op --weight count
smb-flame cap.pcap --tree --stack client,cmd,sub --idle
```

The first walks the share's directory tree with the operations on each
file as leaves; the second sets server time and client idle time side
by side.

**smb-hist** `[--by LEVEL] [--metric count|errors|time|idle|bytes|
inflight|p50|max] [--interval T] [--top N] [--csv] [--bars]`. One row
per interval, one column per group (`--by none` for a single column).
`inflight` is the most requests outstanding at once.

**smb-repeats** `[--top N] [--min-count N] [--all-clients]
[--window S]`. Groups by client, command and target (path; path with
offset and length for READ/WRITE; path and info level; directory and
pattern) and lists the most repeated with peak count per window, span,
statuses and time spent.

**smb-dirscans** `[--top N] [--min-scans N] [--min-ratio R] [--all]
[--scans] [--json]`. Directories a client listed more than once. A scan
is one pass through one handle: from a query that starts at the top
(RESTART_SCANS, REOPEN, the first query on a handle opened in the
capture, or a reply starting with `.`) to the end of the directory,
the handle's CLOSE, the next restart, a failure or the end of the
capture. Each scan after the first is a *rewind* (an earlier one
stopped short of the end), a *repeat* (an earlier one reached it) or
an *overlap* (another was still open). Scans from the top place each
entry by position, so the entries they covered give the directory's
size, and the entries returned against it give the ratio; a scan
already running when the capture began is placed by a reply whose
first and last names sit as far apart in a scan from the top. If the
directory changed between scans the count is marked `~`. Queries for
one name without wildcards are counted as lookups. Shown: two scans
or more and twice the entries returned, unless `--all`; `--scans`
lists each scan with where it started and ended.

```
smb-dirscans finder.pcap --scans
```

A Mac listing a folder of 100,000 files over SMB shows here as scans
that each start again at the first entry and get a few hundred entries
further than the last: the folder is read tens of times over to list
it once.

**smb-errors** `[--examples N] [--all] [--by-client]`. A table per
class with counts, share of the command, first and last seen, example
targets; then unanswered requests with time outstanding, responses
whose request predates the capture, resets with who sent them, and
retransmissions.

**smb-trace** `[--limit N] [--events] [--json] [--wide] [--idle]`.
Time, request and response frames, client, user, operation, target,
status, latency, compound/async/cancel marks. `--events` interleaves
breaks, resets and retransmissions; `--idle` adds the idle time before
each request.

**smb-extract** `CAPTURE [-o FILE] [--filter F] [--pref P]
[--tshark BIN]`. Writes the records (gzip JSON lines, one per PDU plus
TCP events) to `<capture>.smbx`. `--filter` narrows the capture with a
display filter (`ip.addr == 10.1.2.3`); `--pref` passes a tshark `-o`
preference, which is how SMB3 session keys are supplied.

Levels for `--by` and `--stack`: client, server, user, session, stream,
share, cmd, sub (info level, FSCTL, disposition, size bucket ...), op
(cmd and sub), status, class, file, path (the file split into one
level per component, in `--stack` only), dir, ext, chain (compound
shape), async.

## Extraction

One `tshark -T fields` pass with about ninety header, body and TCP
fields, turned into one record per PDU in Python. The SMB2 header
fields occur once per PDU and define the PDUs in a frame; each body
field is handed to the PDUs that can carry it using the dissector's
per-command counts (a CREATE request has one name, an error response
none, a LOCK request one offset per element ...). Where the counts do
not add up the frame keeps its header records and drops that field,
and `smb-summary` reports how often. The tree output (`-T json`) was
rejected because it hex-encodes every READ and WRITE payload: a 277 MB
capture became 4.8 GB of JSON, where the fields pass takes 5 s and
carries no data bytes. A QUERY_DIRECTORY reply keeps its entry count
and its first and last names, not the list; when two replies that
carry names share a frame, the names cannot be split between them and
are dropped. tshark reports a request spread over several
frames in the last one; the client's earlier frames are read too, so
idle time ends at the request's first byte.

The records are cached under `~/.cache/smb_toolkit/` (or
`$XDG_CACHE_HOME`), keyed by name, size and mtime, so tshark runs once
per capture. `--refresh` reruns it, `--no-cache` skips writing it,
`--tshark-filter` narrows it and is part of the key.

Limits: encrypted SMB3 is counted, not read, unless keys are given;
SMB1 is paired and timed but only the first AndX command is attributed;
a response whose request predates the capture has no latency; latency
runs to the response's last byte, so a large READ's includes the
transfer.

## Tests

```
python3 -m pytest pcap/tests
```

Builds a synthetic capture (`tests/mkpcap.py`) with compounds,
multi-segment I/O, async notify and cancel, an oplock break, error
bodies, an unanswered request, an SMB1 negotiate answered in SMB2, a
filename with a tab and a quote, a retransmission and a reset, and
checks extraction, pairing and every tool against it. A second one
lists directories again in each way `smb-dirscans` tells apart.
`tools/gen_names.py` regenerates `smbpcap/names_gen.py` from the
installed tshark's value tables.
