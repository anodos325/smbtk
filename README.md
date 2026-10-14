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
  builds or settings. See [perf/README.md](perf/README.md).
- `sambaprof/`: Samba's own profiling counters: switching them on in
  one smbd (by client address) or all, sampling them into JSON lines,
  and reading them back by SMB2 command, client, user or share:
  latency bins, time, CPU and system calls per request, over time and
  between runs. See [sambaprof/README.md](sambaprof/README.md).
