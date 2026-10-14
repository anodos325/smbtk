# SMB captures: taking, trimming, anonymizing

Python 3.10+ around tcpdump (or Wireshark's dumpcap); nothing else.
The results feed the analysis tools in [`../pcap`](../pcap/README.md).

| tool            | does                                                    |
|-----------------|---------------------------------------------------------|
| `smb-capture`   | capture SMB on one or more interfaces into rotating files |
| `smb-trim`      | cut bulk data out of a capture, keep every SMB header   |
| `smb-anonymize` | replace addresses and names, remove credentials and data |

## smb-capture

```
smb-capture                                 # every interface with an address
smb-capture -i bond0 --host 10.1.2.3        # one client
smb-capture --headers --duration 2h         # long run, headers only
smb-capture --anonymize --compress          # for sending out
smb-capture --files 10 --file-size 500      # full capture, 5 GB ring
smb-capture --dry-run ...                   # show the tcpdump commands
```

Modes, one per run:

- **full** (default): every byte.
- **--headers**: each finished raw file goes through `smb-trim` and is
  deleted, so a long capture costs one raw file per interface plus the
  trimmed output. Every request stays visible and timed exactly as in
  a full capture.
- **--anonymize**: the same, through `smb-anonymize`. The key and the
  replacement map go to `<output>.private/` (mode 0700), not into the
  output directory.
- **--snaplen N**: the kernel keeps the first N bytes of each frame.
  Cheapest, but a frame (or 64 KB offload super-frame) carrying several
  SMB messages shows only the first, so requests go missing.

Output: `<iface>-00001.pcap` ... and `capture.json` (times, filter,
mode, kernel drop counts, NIC counters before and after, offloads,
file list). Without `--anonymize`, `smbstatus --json` is saved at start
and end to tie session ids to users and machines.

Safety: the capture stops when the file system has less than
`--min-free` GB (default 2) and refuses to start without room for it;
`--max-size` caps the output; `--files N` keeps only the newest N files.
Ctrl-C (or SIGTERM) stops cleanly and processes the last file; a second
Ctrl-C quits at once and leaves raw files in `.raw/`.

Where to capture:

- On the server, latencies are server time; on a client, they include
  the round trip. The analysis tools say which they see.
- Capture on the interface carrying the addresses (bond, VLAN, bridge),
  not also its members: each frame would appear twice. That is the
  default.
- With receive and segmentation offloads on, frames up to 64 KB appear;
  the tools handle them. `capture.json` records the offload settings.
- Kernel drops are reported at the end; raise `--buffer` or narrow the
  filter with `--host`.

## smb-trim

```
smb-trim cap.pcap                    # cap.trim.pcap
smb-trim rot*.pcap -o trimmed/       # a rotated set, state carried across
smb-trim --zero cap.pcap             # zero payloads instead, keep sizes
```

Cuts READ and WRITE payloads, directory listings, change notifications,
named-pipe RPC and encrypted SMB3 payloads; keeps every header, name,
status and length. A frame holding the end of a cut payload and the
start of the next message is split in two, so tshark finds every
message (it cannot reassemble past a cut frame), and the analysis tools
time a cut message by the frame holding its last byte, so latencies
match the full capture's. Data inside a compound, with members after
it, is zeroed rather than cut, so those members stay readable.

Every frame stays, cut to its headers (about 90 bytes on disk), so the
gain depends on frame size. On the sample captures, file transfers
shrank 16 fold in 1500-byte frames and 44 to 84 fold with offload
frames of up to 64 KB; metadata traffic, mostly headers already,
shrank 1.5 to 4 fold.

## smb-anonymize

```
smb-anonymize cap.pcap --map map.json          # cap.anon.pcap
smb-anonymize *.pcap -o out/ --key site.key    # same names across runs
```

Replaced, consistently, by HMAC-SHA256 under a 256-bit key from
`secrets` (fresh and discarded unless `--key` names a file):

- **addresses**: IPv4 and IPv6 prefix-preserving (one subnet stays one
  subnet), private and link-local ranges kept recognizable, text forms
  keep their length; MACs keep the vendor prefix.
- **names**: host, domain and realm labels (NetBIOS, DNS, Kerberos and
  NTLM forms agree), users, shares, every path component, stream names,
  the server name in UNC paths, DFS referral requests. Length and
  punctuation stay; extensions stay unless `--hash-ext`. Well-known
  names (`IPC$`, pipe names, `.DS_Store`, `$DATA` ...) are kept.
- **SIDs** (domain part and RIDs from 1000, Unix ids), **GUIDs** (client
  and server), addresses in network interface queries.

Removed: credentials (NTLM responses, session keys, MICs, Kerberos
tickets and authenticators), file data, extended attributes, directory
listings and change notifications (`--full` keeps them with names
replaced), RPC, ciphertext, NetBIOS session request names, and every
frame that is not SMB over TCP (`--keep-other` keeps them with payloads
cut). A buffered message
starts zeroed and only fields a handler knows are copied back, so
anything unexpected comes out as zeros.

Kept: SMB headers (ids, credits, flags, statuses), command fields and
sizes, timing, file ids, lease keys, client OS versions in NTLM, and
absolute timestamps.

`--map` writes the replacements made (original -> token) for the key
holder to translate findings back; keep it and the key private.

TraceWrangler sanitizes up to layer 4 and drops payloads it cannot
parse, SMB included; this keeps SMB analyzable. Its output can still go
through TraceWrangler for anything else it offers.

## Encrypted SMB3

Encrypted sessions show only transform headers. Samba logs session
keys with `debug encryption = yes` in the global section (level 0, on
every session setup; remove it afterwards). Give them to tshark, the
session id as its eight bytes in wire order:

```
smb-summary cap.pcap \
  --pref 'uat:smb2_seskey_list:"<session id>","<session key>","",""'
```

## Tests

```
python3 -m pytest dump/tests
```

Unit tests for the mapping, frame splitting and checksums; end-to-end
tests trim and anonymize the synthetic capture from `pcap/tests` and
compare every request, status and latency through tshark.
