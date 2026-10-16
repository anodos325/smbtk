# smb_toolkit

Tools for working on SMB problems.

- `dump/`: taking SMB captures with tcpdump on one or more interfaces,
  cutting them down to headers, and anonymizing them for sharing. See
  [dump/README.md](dump/README.md).
- `pcap/`: analysis of SMB captures on top of tshark: what the capture
  holds, where the server's time went, which requests are repeated,
  which directories are listed again, what failed and what never came
  back. See
  [pcap/README.md](pcap/README.md).
- `perf/`: profiling smbd with Linux perf: where its CPU time goes,
  where it waits and which code makes which system calls, by SMB2
  command, as flame graphs and tables; counting and A/B comparison of
  builds or settings; and the storage under the shares in one look:
  pools, vdevs, disks and their queues, ARC, ZIL, the datasets and
  their settings, I/O over a few seconds; and the whole box in one
  report, by section: host, CPUs, memory, disks, pools, network and
  Samba itself, with notes on what costs time. See
  [perf/README.md](perf/README.md).
- `sambaprof/`: Samba's own profiling counters: switching them on in
  one smbd (by client address) or all, sampling them into JSON lines,
  and reading them back by SMB2 command, client, user or share:
  latency bins, time, CPU and system calls per request, over time and
  between runs. See [sambaprof/README.md](sambaprof/README.md).
- `bpf/`: bpftrace scripts. `smbd-io-sizes.bt` histograms the sizes of
  smbd's pread and pwrite calls, the synchronous path taken with
  `aio read size = 0` and `aio write size = 0`, with calls, bytes and
  errors per smbd process; needs root and runs on TrueNAS 27 as is.
