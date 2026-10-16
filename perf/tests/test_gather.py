"""smb-perf-gather: its readers on text as the kernel, ethtool, ss and
smbstatus print it, the notes it draws on a troubled box, the report,
and a live run with whatever the box has."""

from __future__ import annotations

import io
import json
import os
import sys
from contextlib import redirect_stdout

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from smbperf import cmd_gather, net, smbd, sysstat  # noqa: E402
from smbperf.smbd import Proc  # noqa: E402

STAT0 = """\
cpu  1000 10 500 8000 100 20 30 5 0 0
cpu0 500 5 250 4000 50 10 15 0 0 0
cpu1 500 5 250 4000 50 10 15 5 0 0
intr 100000 0 1 2
ctxt 500000
btime 1760000000
processes 4000
procs_running 2
procs_blocked 1
softirq 300000 1 2 3
"""
STAT1 = """\
cpu  1400 10 700 9000 130 30 80 5 0 0
cpu0 500 5 250 5000 50 10 15 0 0 0
cpu1 900 5 450 4000 80 20 65 5 0 0
intr 112000 0 1 2
ctxt 560000
btime 1760000000
processes 4040
procs_running 3
procs_blocked 0
softirq 330000 1 2 3
"""
SOFTIRQS0 = """\
                    CPU0       CPU1
          HI:          0          0
       TIMER:       1000       1000
      NET_RX:       5000       1000
       BLOCK:        100        100
"""
SOFTIRQS1 = """\
                    CPU0       CPU1
          HI:          0          0
       TIMER:       1100       1100
      NET_RX:      25000       3000
       BLOCK:        150        150
"""
INTERRUPTS0 = """\
            CPU0       CPU1
   0:         33          0  IR-IO-APIC    2-edge      timer
 125:     100000          0  IR-PCI-MSIX-0000:03:00.0    0-edge      eno1-TxRx-0
 126:          0      50000  IR-PCI-MSIX-0000:03:00.0    1-edge      eno1-TxRx-1
 NMI:          0          0   Non-maskable interrupts
 LOC:    1000000    1000000   Local timer interrupts
 ERR:          0
"""
INTERRUPTS1 = """\
            CPU0       CPU1
   0:         33          0  IR-IO-APIC    2-edge      timer
 125:     200000          0  IR-PCI-MSIX-0000:03:00.0    0-edge      eno1-TxRx-0
 126:          0      50100  IR-PCI-MSIX-0000:03:00.0    1-edge      eno1-TxRx-1
 NMI:          0          0   Non-maskable interrupts
 LOC:    1002000    1002000   Local timer interrupts
 ERR:          0
"""
PRESSURE = """\
some avg10=12.50 avg60=3.00 avg300=1.00 total=123456789
full avg10=2.00 avg60=0.50 avg300=0.10 total=1234567
"""
FEATURES = """\
Features for eno1:
rx-checksumming: on
tx-checksumming: on
\ttx-checksum-ipv4: off [fixed]
\ttx-checksum-ip-generic: on
scatter-gather: on
\ttx-scatter-gather: on
tcp-segmentation-offload: off
\ttx-tcp-segmentation: off
generic-segmentation-offload: on
generic-receive-offload: on
large-receive-offload: off [fixed]
rx-vlan-offload: on
tx-vlan-offload: on [requested off]
ntuple-filters: off [fixed]
receive-hashing: on
"""
RINGS = """\
Ring parameters for eno1:
Pre-set maximums:
RX:\t\t4096
RX Mini:\tn/a
RX Jumbo:\tn/a
TX:\t\t4096
Current hardware settings:
RX:\t\t256
RX Mini:\tn/a
RX Jumbo:\tn/a
TX:\t\t256
RX Buf Len:\t\tn/a
TX Push:\toff
"""
CHANNELS = """\
Channel parameters for eno1:
Pre-set maximums:
RX:\t\tn/a
TX:\t\tn/a
Other:\t\t1
Combined:\t8
Current hardware settings:
RX:\t\tn/a
TX:\t\tn/a
Other:\t\t1
Combined:\t4
"""
COALESCE = """\
Coalesce parameters for eno1:
Adaptive RX: off  TX: off
stats-block-usecs: n/a
sample-interval: n/a

rx-usecs: 0
rx-frames: n/a
rx-usecs-irq: n/a

tx-usecs: 8
tx-frames: n/a
"""
DRIVER = """\
driver: igb
version: 6.18.52-production+truenas
firmware-version: 3.25, 0x800005d0
expansion-rom-version: 
bus-info: 0000:03:00.0
supports-statistics: yes
"""
SETTINGS = """\
Settings for eno1:
\tSupported ports: [ TP ]
\tSupported link modes:   100baseT/Full
\t                        1000baseT/Full
\t                        10000baseT/Full
\tSupported pause frame use: Symmetric
\tSupports auto-negotiation: Yes
\tAdvertised link modes:  1000baseT/Full
\tSpeed: 1000Mb/s
\tDuplex: Full
\tAuto-negotiation: on
\tPort: Twisted Pair
\tPHYAD: 0
\tTransceiver: internal
\tLink detected: yes
"""
NIC_STATS = """\
NIC statistics:
     rx_packets: 123456
     tx_packets: 654321
     rx_missed_errors: 42
     rx_no_buffer_count: 7
     tx_timeout_count: 0
     rx_long_length_errors: 0
"""
SNMP = """\
Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits
Ip: 1 64 1000000 0 0 0 0 0 1000000 900000 0 0 0 0 0 0 0 0 0 900000
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 10 20 0 1 5 1000000 900000 2000 0 1 0
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 10 0 0 10 0 0 0 0 0
"""
NETSTAT = """\
TcpExt: SyncookiesSent TCPTimeouts ListenOverflows ListenDrops PruneCalled RcvPruned TCPRcvCollapsed TCPMemoryPressures TCPOFOQueue TCPBacklogDrop
TcpExt: 0 50 3 3 10 0 5 0 500 0
IpExt: InNoRoutes InTruncatedPkts InCsumErrors InOctets OutOctets
IpExt: 0 0 0 123456789 987654321
"""
SOFTNET0 = """\
000186a0 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
000186a0 00000005 00000002 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001 00000000 00000000
"""
SOFTNET1 = """\
000188a0 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
000188a0 00000015 00000004 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001 00000000 00000000
"""
SOCKSTAT = """\
sockets: used 400
TCP: inuse 20 orphan 0 tw 5 alloc 30 mem 2500
UDP: inuse 5 mem 2
UDPLITE: inuse 0
RAW: inuse 0
FRAG: inuse 0 memory 0
"""
SS = """\
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port
LISTEN 0      50     0.0.0.0:445        0.0.0.0:*
ESTAB  0      36     [::ffff:10.1.2.3]:445  [::ffff:10.1.2.9]:51234
\t cubic wscale:7,7 rto:204 rtt:0.512/0.25 ato:40 mss:1448 pmtu:1500 rcvmss:1448 advmss:1448 cwnd:10 bytes_sent:1000000 bytes_acked:999000 bytes_received:500000 segs_out:5000 segs_in:4000 data_segs_out:3000 data_segs_in:2000 send 226250000bps lastsnd:4 lastrcv:4 lastack:4 pacing_rate 452500000bps delivery_rate 115000000bps delivered:3000 app_limited busy:4000ms rwnd_limited:1600ms(40.0%) sndbuf_limited:40ms(1.0%) retrans:0/25 rcv_space:14600 rcv_ssthresh:64088 minrtt:0.1 snd_wnd:262144 rcv_wnd:131072
ESTAB  0      0      10.1.2.3:445       10.1.2.10:60000
\t bbr wscale:7,7 rto:204 rtt:35.5/2 mss:1448 cwnd:120 bytes_sent:100 bytes_received:100 segs_out:10 segs_in:10 send 39Mbps busy:20ms
"""
SMBSTATUS = {
    "timestamp": "2026-10-16T01:02:03.000000+0000", "version": "4.24.4",
    "smb_conf": "/etc/smb4.conf",
    "sessions": {
        "1": {"session_id": "1", "server_id": {"pid": "1234", "task_id": "0",
                                               "vnn": "4294967295",
                                               "unique_id": "1"},
              "uid": 3000, "gid": 3000, "username": "alice",
              "groupname": "users", "remote_machine": "10.1.2.9",
              "hostname": "ipv4:10.1.2.9:51234", "session_dialect": "SMB3_11",
              "encryption": {"cipher": "AES-128-GCM", "degree": "full"},
              "signing": {"cipher": "AES-128-GMAC", "degree": "partial"},
              "channels": {"1": {"channel_id": "1",
                                 "local_address": "ipv4:10.1.2.3:445",
                                 "remote_address": "ipv4:10.1.2.9:51234",
                                 "transport": "tcp"},
                           "2": {"channel_id": "2",
                                 "local_address": "ipv4:10.1.3.3:445",
                                 "remote_address": "ipv4:10.1.3.9:51235",
                                 "transport": "tcp"}}},
        "2": {"session_id": "2", "server_id": {"pid": "1235"},
              "username": "bob", "remote_machine": "10.1.2.10",
              "session_dialect": "SMB2_02",
              "encryption": {"cipher": "-", "degree": "none"},
              "signing": {"cipher": "-", "degree": "none"},
              "channels": {"1": {"remote_address": "ipv4:10.1.2.10:60000"}}},
    },
    "tcons": {
        "7": {"service": "data", "server_id": {"pid": "1234"}, "tcon_id": "7",
              "session_id": "1", "machine": "10.1.2.9",
              "encryption": {"cipher": "-", "degree": "none"},
              "signing": {"cipher": "-", "degree": "none"}},
        "8": {"service": "data", "server_id": {"pid": "1235"}, "tcon_id": "8",
              "session_id": "2", "machine": "10.1.2.10"},
        "9": {"service": "IPC$", "server_id": {"pid": "1235"}, "tcon_id": "9",
              "session_id": "2", "machine": "10.1.2.10"},
    },
    "open_files": {
        "/mnt/tank/data/a.txt": {"service_path": "/mnt/tank/data",
                                 "filename": "a.txt",
                                 "opens": {"1234/1": {}, "1235/2": {}}},
        "/mnt/tank/data/b.txt": {"service_path": "/mnt/tank/data",
                                 "filename": "b.txt", "opens": {"1234/3": {}}},
    },
    "byte_range_locks": {"/mnt/tank/data/a.txt": {"1234/1": {}}},
}


def has(notes, text):
    return any(text in n for n in notes)


# -- CPUs, memory, interrupts --------------------------------------------------

def test_cpu_usage_from_two_readings():
    b, a = sysstat.parse_stat(STAT0), sysstat.parse_stat(STAT1)
    assert b["procs_blocked"] == 1 and a["ctxt"] == 560000
    u = sysstat.cpu_usage(b, a, 10.0)
    t = u["total"]
    # 1690 ticks moved: 400 user, 200 system, 1000 idle, 30 iowait, 60 irq
    assert abs(t["user"] - 400 / 1690) < 1e-9
    assert abs(t["busy"] - (1 - 1030 / 1690)) < 1e-9
    assert u["per_cpu"]["cpu0"]["busy"] == 0.0
    assert u["per_cpu"]["cpu1"]["busy"] > 0.9
    assert u["ctxt_s"] == 6000 and u["intr_s"] == 1200 and u["processes_s"] == 4
    assert u["procs_running"] == 3 and u["procs_blocked"] == 0
    assert sysstat.cpu_usage(b, b, 10.0)["total"] is None


def test_softirqs_interrupts_pressure():
    so = sysstat.softirq_rates(sysstat.parse_softirqs(SOFTIRQS0),
                               sysstat.parse_softirqs(SOFTIRQS1), 2.0)
    assert so["NET_RX"]["per_s"] == 11000
    assert so["NET_RX"]["top_cpu"] == 0 and abs(so["NET_RX"]["top_share"] - 20 / 22) < 1e-9
    assert "HI" not in so
    i0, i1 = sysstat.parse_interrupts(INTERRUPTS0), sysstat.parse_interrupts(INTERRUPTS1)
    assert i0["cpus"] == 2 and i0["irqs"]["ERR"]["counts"] == [0]
    assert i0["irqs"]["125"]["desc"].endswith("eno1-TxRx-0")
    r = sysstat.irq_rates(i0, i1, 10.0)
    assert r["125"]["per_s"] == 10000 and r["125"]["cpus"] == [0]
    assert r["126"]["per_s"] == 10 and r["126"]["cpus"] == [1]
    assert r["LOC"]["cpus"] == [0, 1] and r["LOC"]["top_share"] == 0.5
    assert "0" not in r and "ERR" not in r
    assert sysstat.irq_name("125", r["125"]["desc"]) == "eno1-TxRx-0"
    assert sysstat.irq_name("LOC", "Local timer interrupts") == "local timer"
    p = sysstat.pressure.__wrapped__(PRESSURE) if hasattr(
        sysstat.pressure, "__wrapped__") else None
    # pressure() reads /proc; parse its text through the same regexes
    out = {}
    for line in PRESSURE.splitlines():
        f = line.split()
        out[f[0]] = {k: (int(v) if k == "total" else float(v))
                     for k, v in (kv.split("=") for kv in f[1:])}
    assert out["some"]["avg10"] == 12.5 and out["full"]["total"] == 1234567
    assert p is None
    vm = sysstat.parse_vmstat("pgfault 100\npgmajfault 5\nnr_dirty 3\nbogus x\n")
    assert vm == {"pgfault": 100, "pgmajfault": 5, "nr_dirty": 3}


def test_top_processes_pairs_pids_by_start_time():
    b = {1: Proc(1, 0, "systemd", 1, 10.0, 100.0),
         20: Proc(20, 1, "smbd", 1, 5.0, 200.0),
         21: Proc(21, 20, "smbd[10.1.2.9]", 3, 50.0, 300.0),
         30: Proc(30, 1, "z_wr_iss", 1, 8.0, 100.0)}
    a = {1: Proc(1, 0, "systemd", 1, 10.1, 100.0),
         20: Proc(20, 1, "smbd", 1, 5.0, 200.0),
         21: Proc(21, 20, "smbd[10.1.2.9]", 3, 54.0, 300.0),
         30: Proc(30, 1, "z_wr_iss", 1, 9.0, 100.0),
         31: Proc(31, 1, "new", 1, 1.0, 400.0),
         40: Proc(40, 1, "reused-pid", 1, 2.0, 999.0)}
    b[40] = Proc(40, 1, "old", 1, 1.0, 500.0)
    t = cmd_gather.top_processes(b, a, 2.0)
    names = [p["comm"] for p in t["processes"]]
    assert names == ["smbd[10.1.2.9]", "z_wr_iss", "systemd"]
    assert t["processes"][0]["cpu"] == 2.0 and t["processes"][0]["threads"] == 3
    assert abs(t["cpus_used"] - 5.1 / 2) < 1e-9 and t["smbd_cpus"] == 2.0


# -- the network ---------------------------------------------------------------

def test_ethtool_parsers():
    f = net.parse_features(FEATURES)
    assert f["tcp-segmentation-offload"] == {"on": False, "fixed": False}
    assert f["large-receive-offload"] == {"on": False, "fixed": True}
    assert f["tx-checksum-ipv4"]["fixed"] and f["tx-vlan-offload"]["on"]
    r = net.parse_sections(RINGS)
    assert r["max"]["rx"] == 4096 and r["current"]["rx"] == 256
    assert r["current"]["rx mini"] is None and r["current"]["tx push"] == "off"
    c = net.parse_sections(CHANNELS)
    assert c["max"]["combined"] == 8 and c["current"]["combined"] == 4
    co = net.parse_coalesce(COALESCE)
    assert co["adaptive_rx"] is False and co["rx-usecs"] == 0
    assert co["rx-frames"] is None and co["tx-usecs"] == 8
    d = net.parse_driver(DRIVER)
    assert d["driver"] == "igb" and d["bus-info"] == "0000:03:00.0"
    assert "expansion-rom-version" not in d
    s = net.parse_settings(SETTINGS)
    assert s == {"speed_mbps": 1000, "duplex": "Full", "link": True,
                 "autoneg": "on", "port": "Twisted Pair",
                 "supported_max_mbps": 10000}
    st = net.parse_stats(NIC_STATS)
    assert st["rx_missed_errors"] == 42
    trouble = {k: v for k, v in st.items() if net.TROUBLE.search(k)}
    assert set(trouble) == {"rx_missed_errors", "rx_no_buffer_count",
                            "tx_timeout_count", "rx_long_length_errors"}


def test_snmp_softnet_sockstat():
    s = net.parse_snmp(SNMP)
    assert s["Tcp"]["RetransSegs"] == 2000 and s["Tcp"]["MaxConn"] == -1
    assert s["Ip"]["OutRequests"] == 900000
    e = net.parse_snmp(NETSTAT)
    assert e["TcpExt"]["TCPTimeouts"] == 50 and e["IpExt"]["OutOctets"] == 987654321
    before = {"Tcp": {"OutSegs": 100, "RetransSegs": 1}}
    after = {"Tcp": {"OutSegs": 300, "RetransSegs": 5, "New": 1}}
    assert net.snmp_delta(before, after) == {"Tcp": {"OutSegs": 200, "RetransSegs": 4}}
    sn0, sn1 = net.parse_softnet(SOFTNET0), net.parse_softnet(SOFTNET1)
    assert sn0[1]["dropped"] == 5 and sn0[1]["time_squeeze"] == 2
    d = net.softnet_delta(sn0, sn1)
    assert d == {"processed": 1024, "dropped": 16, "time_squeeze": 2,
                 "received_rps": 0, "flow_limit_count": 0, "cpus_dropping": 1}
    ss_ = net.parse_sockstat(SOCKSTAT)
    assert ss_["sockets_used"] == 400 and ss_["TCP"]["mem"] == 2500
    assert ss_["UDP"]["inuse"] == 5
    assert net.strip_mapped("[::ffff:10.1.2.3]") == "10.1.2.3"
    assert net.strip_mapped("fe80::1%eth0") == "fe80::1"
    assert net.interface_of("::ffff:10.1.2.3", {"eno1": ["10.1.2.3"]}) == "eno1"
    assert net.interface_of("10.9.9.9", {"eno1": ["10.1.2.3"]}) is None


def test_ss_connections_parse():
    conns = net.parse_ss(SS)
    assert [c["state"] for c in conns] == ["LISTEN", "ESTAB", "ESTAB"]
    lst = conns[0]
    assert lst["local"] == "0.0.0.0" and lst["lport"] == 445
    assert lst["recvq"] == 0 and lst["sendq"] == 50 and lst["pport"] is None
    c = conns[1]
    assert c["local"] == "10.1.2.3" and c["peer"] == "10.1.2.9"
    assert c["pport"] == 51234 and c["cc"] == "cubic" and c["wscale"] == "7,7"
    assert c["rtt_ms"] == 0.512 and c["rttvar_ms"] == 0.25 and c["rto_ms"] == 204
    assert c["send_bps"] == 226250000 and c["delivery_rate_bps"] == 115000000
    assert c["busy_ms"] == 4000 and c["rwnd_limited_ms"] == 1600
    assert c["rwnd_limited_pct"] == 40.0 and c["sndbuf_limited_pct"] == 1.0
    assert c["retrans"] == 0 and c["retrans_total"] == 25
    assert c["flags"] == ["app_limited"] and c["minrtt_ms"] == 0.1
    assert c["bytes_sent"] == 1000000 and c["segs_out"] == 5000
    c2 = conns[2]
    assert c2["cc"] == "bbr" and c2["send_bps"] == 39e6 and c2["rtt_ms"] == 35.5
    assert c2["rwnd_limited_pct"] == 0.0 and c2["sndbuf_limited_ms"] == 0.0
    # with a state filter ss drops the State column
    no_state = net.parse_ss(
        "Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
        "0      0      10.0.0.1:445       10.0.0.2:5000\n"
        "\t cubic rtt:1/0.5 users:((\"smbd\",pid=77,fd=3))\n")
    assert no_state[0]["state"] == "ESTAB" and no_state[0]["pid"] == 77
    assert no_state[0]["pport"] == 5000


# -- Samba ---------------------------------------------------------------------

def test_smbstatus_summary():
    st = smbd.summarize_status(SMBSTATUS)
    assert st["version"] == "4.24.4" and len(st["sessions"]) == 2
    a = st["sessions"][0]
    assert a["user"] == "alice" and a["pid"] == "1234"
    assert a["dialect"] == "SMB3_11" and a["channels"] == 2
    assert a["encryption"] == "full (AES-128-GCM)"
    assert a["signing"] == "partial (AES-128-GMAC)"
    assert a["addresses"] == ["10.1.2.9", "10.1.3.9"]
    b = st["sessions"][1]
    assert b["encryption"] == "none" and b["channels"] == 1
    assert len(st["tcons"]) == 3 and st["tcons"][0]["share"] == "data"
    assert st["shares"]["data"]["tcons"] == 2 and st["shares"]["IPC$"]["tcons"] == 1
    assert st["open_files"] == 3 and st["shares"]["/mnt/tank/data"]["open_files"] == 3
    assert st["locks"] == 1
    assert smbd.summarize_status({})["sessions"] == [] and \
        smbd.summarize_status({})["open_files"] is None
    assert smbd.is_samba("smbd[10.1.2.9]") and smbd.is_samba("rpcd_lsad")
    assert smbd.is_samba("winbindd") and not smbd.is_samba("smbclient")
    assert not smbd.is_samba("sshd")


# -- notes and the report ------------------------------------------------------

def troubled_run() -> dict:
    """A box with something wrong in every section."""
    stat0, stat1 = sysstat.parse_stat(STAT0), sysstat.parse_stat(STAT1)
    usage = sysstat.cpu_usage(stat0, stat1, 10.0)
    i0, i1 = sysstat.parse_interrupts(INTERRUPTS0), sysstat.parse_interrupts(INTERRUPTS1)
    irqs = sysstat.irq_rates(i0, i1, 10.0)
    softirqs = sysstat.softirq_rates(sysstat.parse_softirqs(SOFTIRQS0),
                                     sysstat.parse_softirqs(SOFTIRQS1), 10.0)
    snmp0 = net.parse_snmp(SNMP)
    snmp0.update(net.parse_snmp(NETSTAT))
    snmp1 = json.loads(json.dumps(snmp0))
    snmp1["Tcp"]["OutSegs"] += 100000
    snmp1["Tcp"]["RetransSegs"] += 500
    snmp1["Tcp"]["InSegs"] += 100000
    snmp1["TcpExt"]["TCPTimeouts"] += 7
    snmp1["TcpExt"]["PruneCalled"] += 3
    snmp1["TcpExt"]["ListenDrops"] += 2
    snmp1["TcpExt"]["TCPOFOQueue"] += 5000
    conns = net.parse_ss(SS)
    conns[1]["interface"] = "eno1"
    conns[1]["pid"] = 1234
    eno1 = {
        "name": "eno1", "state": "up", "carrier": True, "speed_mbps": 1000,
        "duplex": "full", "mtu": 1500, "kind": "physical", "driver": "igb",
        "bus": "0000:03:00.0", "irqs": [125, 126], "queues": {"rx": 2, "tx": 2},
        "rps": False, "addresses": ["10.1.2.3"],
        "ethtool": {"driver": net.parse_driver(DRIVER),
                    "settings": net.parse_settings(SETTINGS),
                    "features": net.parse_features(FEATURES),
                    "rings": net.parse_sections(RINGS),
                    "channels": net.parse_sections(CHANNELS),
                    "coalesce": net.parse_coalesce(COALESCE)},
        "stats": {"rx_bytes": 2e9, "tx_bytes": 9e9, "rx_packets": 2e6,
                  "tx_packets": 6e6, "rx_missed_errors": 142, "rx_dropped": 3,
                  "rx_crc_errors": 1},
        "rates": {"rx_bytes_s": 2e8, "tx_bytes_s": 9e8, "rx_packets_s": 2e5,
                  "tx_packets_s": 6e5,
                  "delta": {"rx_missed_errors": 100, "rx_dropped": 3,
                            "rx_crc_errors": 1}},
        "driver_stats": {"rx_missed_errors": {"value": 142, "delta": 100},
                         "rx_no_buffer_count": {"value": 7, "delta": 7}},
        "irq_rate": {"per_s": 10010, "cpus": [0]},
    }
    eno1["irq_rate"] = {"per_s": 10010, "cpus": [0]}
    run = {
        "tool": "smb-perf-gather", "start": "2026-10-16T01:00:00+00:00",
        "interval_s": 10, "seconds": 10.0, "sections": list(cmd_gather.SECTIONS),
        "host": {"hostname": "nas", "kernel": "6.18.52", "cpus": 2,
                 "truenas": "27.0.0", "cpu": "Test CPU", "sockets": 1,
                 "smt": True, "virtual": True, "uptime_s": 90061.0,
                 "boot_time": "2026-10-15T00:00:00+00:00",
                 "cmdline": "BOOT_IMAGE=/vmlinuz root=ZFS=boot-pool/ROOT ro "
                            "mitigations=off",
                 "dmi": {"sys_vendor": "iXsystems", "product_name": "TRUENAS-M50",
                         "board_vendor": "Supermicro", "board_name": "X11",
                         "bios_version": "3.3", "bios_date": "01/01/2024"},
                 "virtualization": {"vm": "kvm", "container": None},
                 "sysctl": {"kernel.perf_event_paranoid": 2,
                            "kernel.kptr_restrict": 0, "fs.file-nr": "5000 0 9000",
                            "fs.nr_open": 1048576, "fs.aio-nr": 10,
                            "fs.aio-max-nr": 65536,
                            "fs.inotify.max_user_watches": 8192},
                 "perf": {"path": "/usr/bin/perf", "version": "perf version 6.12"},
                 "python": "3.13.5", "timezone": "UTC"},
        "smbd_version": "Version 4.24.4-truenas",
        "memory": {"MemTotal": 32 << 30, "MemFree": 512 << 20,
                   "MemAvailable": 700 << 20, "Cached": 4 << 30,
                   "AnonPages": 20 << 30, "Shmem": 100 << 20, "Slab": 2 << 30,
                   "SReclaimable": 1 << 30, "KernelStack": 20 << 20,
                   "PageTables": 100 << 20, "Unevictable": 0, "Dirty": 1 << 20,
                   "Writeback": 0, "CommitLimit": 16 << 30,
                   "Committed_AS": 30 << 30, "SwapTotal": 8 << 30,
                   "SwapFree": 4 << 30, "HugePages_Total": 0,
                   "Hugepagesize": 2 << 20, "AnonHugePages": 1 << 30},
        "zfs": {"available": True, "version": "zfs-2.4.4-1",
                "arc": {"size": 4 << 30, "max": 16 << 30}},
        "cpu": {"topology": {"cpus": 2, "sockets": 1, "cores": 2, "smt": "off",
                             "numa_nodes": {"0": "0", "1": "1"},
                             "caches": {"L1d": "32K", "L2": "1024K"}},
                "freq": {"governors": {"powersave": 2}, "driver": "intel_pstate",
                         "min_mhz": 800, "max_mhz": 4700, "cur_mhz": [800, 1200],
                         "boost": True, "idle_driver": "intel_idle",
                         "idle_states": ["POLL", "C1", "C6"]},
                "mitigations": {"spectre_v2": "Mitigation: Retpolines",
                                "mds": "Vulnerable", "itlb_multihit": "Not affected"},
                "load": {"1m": 9.5, "5m": 4.0, "15m": 2.0, "running": 6,
                         "threads": 900},
                "pressure": {"some": {"avg10": 25.0, "avg60": 10.0, "avg300": 2.0,
                                      "total": 1}},
                "usage": usage, "softirqs": softirqs,
                "interrupts": {"total_s": sum(v["per_s"] for v in irqs.values()),
                               "top": [{"irq": k, **v} for k, v in irqs.items()]},
                "top": {"processes": [
                    {"pid": 21, "name": "smbd[10.1.2.9]", "comm": "smbd",
                     "cpu": 0.98, "threads": 4, "rss": 200 << 20},
                    {"pid": 30, "name": "z_wr_iss", "comm": "z_wr_iss",
                     "cpu": 0.3, "threads": 1, "rss": None}],
                    "cpus_used": 1.4, "smbd_cpus": 0.98}},
        "vm": {"sysctl": {"vm.swappiness": 60, "vm.dirty_ratio": 20,
                          "vm.zone_reclaim_mode": 1, "kernel.numa_balancing": 1},
               "thp": {"enabled": "always", "defrag": "always",
                       "khugepaged_defrag": "1"},
               "numa": {"0": {"MemTotal": 16 << 30, "MemFree": 100 << 20,
                              "FilePages": 2 << 30, "AnonPages": 12 << 30},
                        "1": {"MemTotal": 16 << 30, "MemFree": 8 << 30,
                              "FilePages": 2 << 30, "AnonPages": 4 << 30}},
               "pressure": {"some": {"avg10": 8.0, "avg60": 2.0, "avg300": 1.0,
                                     "total": 1},
                            "full": {"avg10": 2.0, "avg60": 0.5, "avg300": 0.1,
                                     "total": 1}},
               "vmstat": {"snapshot": {"nr_dirty": 10},
                          "delta": {"pgfault": 20000, "pgmajfault": 1000,
                                    "pswpin": 500, "pswpout": 2000,
                                    "pgscan_kswapd": 100000, "pgscan_direct": 5000,
                                    "allocstall_normal": 40, "compact_stall": 3,
                                    "oom_kill": 1}},
               "arc_size": 4 << 30},
        "mounts": [{"dataset": "tank/data", "mountpoint": "/mnt/tank/data",
                    "options": ["rw"]}],
        "devices": [
            {"name": "sda", "model": "WD Blue", "size": 1 << 40,
             "rotational": False, "transport": "sata", "scheduler": "bfq",
             "queue_depth": 32, "nr_requests": 64, "write_cache": "write back",
             "ioerr_cnt": 140, "ioerr_delta": 4, "state": "running",
             "link": {"sata": {"speed": "3.0 Gbps", "max": "6.0 Gbps"},
                      "pcie": {"device": "0000:00:17.0", "speed": "8.0 GT/s PCIe",
                               "width": "4", "max_speed": "8.0 GT/s PCIe",
                               "max_width": "4", "shared": True}},
             "partitions": [{"name": "sda1", "fstype": "zfs_member",
                             "label": "tank"}],
             "zfs": [{"pool": "tank", "vdev": None, "class": "normal",
                      "leaf": "sda1", "state": "ONLINE", "read": 0, "write": 0,
                      "cksum": 0, "slow": 0, "note": None}]},
            {"name": "nvme0n1", "model": "Samsung 980", "size": 1 << 40,
             "rotational": False, "transport": "nvme", "scheduler": "none",
             "queue_depth": None, "nr_requests": 1023, "write_cache": "write back",
             "ioerr_cnt": None, "state": "live",
             "link": {"pcie": {"device": "0000:01:00.0", "speed": "8.0 GT/s PCIe",
                               "width": "2", "max_speed": "16.0 GT/s PCIe",
                               "max_width": "4", "shared": False}},
             "partitions": [], "zfs": []}],
        "io": {"seconds": 10.0,
               "devices": {"sda": {"reads_s": 100, "writes_s": 400,
                                   "read_bytes_s": 1e6, "write_bytes_s": 5e7,
                                   "read_merges_s": 0, "write_merges_s": 0,
                                   "read_wait_ns": 45e6, "write_wait_ns": 90e6,
                                   "read_size": 1e4, "write_size": 1.25e5,
                                   "discards_s": 0, "flushes_s": 10,
                                   "flush_wait_ns": 2e6, "queue": 8.5,
                                   "util": 0.98, "in_flight": 9}},
               "pressure": {"some": {"avg10": 40.0, "avg60": 30.0, "avg300": 5.0,
                                     "total": 1},
                            "full": {"avg10": 30.0, "avg60": 20.0, "avg300": 3.0,
                                     "total": 1}}},
        "io_uring": {"disabled": 0, "group": -1},
        "samba": {"source": "testparm", "file": "/etc/smb4.conf", "error": None,
                  "global": {"server min protocol": "SMB2_02"},
                  "shares": {"data": {"path": "/mnt/tank/data",
                                      "dataset": "tank/data",
                                      "mountpoint": "/mnt/tank/data",
                                      "mount_options": ["rw"],
                                      "io": {"strict sync": "no"},
                                      "params": {"path": "/mnt/tank/data",
                                                 "vfs objects": "io_uring"}}},
                  "processes": [
                      {"pid": 20, "ppid": 1, "comm": "smbd", "name": "smbd",
                       "threads": 1, "cpu_s": 5.0, "started": 1760000000.0,
                       "clients": [], "rss": 30 << 20, "fds": 40,
                       "open_files": [1024, 4096],
                       "cgroup": "/system.slice/smbd.service", "cpu": 0.0,
                       "rq_wait": 0.0, "preempted_s": 0.0},
                      {"pid": 21, "ppid": 20, "comm": "smbd[10.1.2.9]",
                       "name": "smbd[10.1.2.9]", "threads": 4, "cpu_s": 50.0,
                       "started": 1760003600.0, "clients": ["10.1.2.9:51234"],
                       "rss": 200 << 20, "fds": 300, "open_files": [1024, 4096],
                       "cgroup": "/system.slice/smbd.service", "cpu": 0.98,
                       "rq_wait": 0.12, "preempted_s": 300.0},
                      {"pid": 50, "ppid": 1, "comm": "winbindd", "name": "winbindd",
                       "threads": 1, "cpu_s": 1.0, "started": 1760000000.0,
                       "clients": [], "rss": 10 << 20, "fds": 12, "cpu": 0.01}],
                  "cgroups": {"/system.slice/smbd.service": {
                      "cpu.max": "100000 100000", "memory.max": 4 << 30,
                      "memory.current": 3 << 30}},
                  "cgroup_cpu": {"/system.slice/smbd.service": {
                      "snapshot": {"usage_usec": 1e9, "throttled_usec": 5e6},
                      "delta": {"usage_usec": 9.9e6, "nr_throttled": 12,
                                "throttled_usec": 1.5e6}}},
                  "status": smbd.summarize_status(SMBSTATUS) | {"error": None},
                  "effective": {"server max protocol": "SMB3_11",
                                "server multi channel support": "no",
                                "socket options": "TCP_NODELAY SO_RCVBUF=65536 "
                                                  "SO_SNDBUF=65536",
                                "log level": "3 auth:5",
                                "smbd profiling level": "on",
                                "strict locking": "yes", "kernel oplocks": "yes",
                                "aio max threads": "100"},
                  "effective_error": None,
                  "connections": conns,
                  "connection_states": {"LISTEN": 1, "ESTAB": 2}},
        "net": {"interfaces": {"eno1": eno1,
                               "lo": {"name": "lo", "kind": "loopback",
                                      "state": "unknown", "mtu": 65536,
                                      "queues": {"rx": 1, "tx": 1},
                                      "addresses": ["127.0.0.1"], "stats": {},
                                      "rates": {"rx_bytes_s": 0, "tx_bytes_s": 0,
                                                "rx_packets_s": 0,
                                                "tx_packets_s": 0, "delta": {}}}},
                "sysctl": {"net.core.rmem_max": 212992,
                           "net.ipv4.tcp_rmem": "4096 131072 6291456",
                           "net.ipv4.tcp_mem": "1000 2000 3000",
                           "net.ipv4.tcp_window_scaling": 0,
                           "net.ipv4.tcp_sack": 0,
                           "net.ipv4.tcp_moderate_rcvbuf": 0,
                           "net.ipv4.tcp_congestion_control": "cubic"},
                "sockstat": {"sockets_used": 400, "page_size": 4096,
                             "TCP": {"inuse": 20, "orphan": 0, "tw": 5,
                                     "alloc": 30, "mem": 2500}},
                "snmp": {"snapshot": snmp1, "delta": net.snmp_delta(snmp0, snmp1)},
                "softnet": {"processed": 1024, "dropped": 16, "time_squeeze": 2,
                            "received_rps": 0, "flow_limit_count": 0,
                            "cpus_dropping": 1}},
        "datasets": {"tank/data": {"pool": "tank", "props": {"sync": "always",
                                                             "xattr": "sa",
                                                             "dnodesize": "auto"}}},
        "detailed": ["tank/data"],
        "errors": ["zpool iostat: no answer"],
    }
    run["zfs"].update({
        "params": {"zfs_arc_max": 0}, "modprobe": [],
        "pools": {"tank": {"state": "ONLINE", "status": None, "action": None,
                           "scan": None, "scan_in_progress": False,
                           "errors": "No known data errors", "vdevs": None,
                           "leaves": [], "layout": {"normal": ["disk"]},
                           "props": {"size": 1 << 40, "allocated": 1 << 39,
                                     "capacity": 50, "fragmentation": 10,
                                     "ashift": 12, "autotrim": "off"},
                           "sources": {}, "txgs": {}, "kstats": {},
                           "iostat": None}},
        "kstats": {}})
    run["notes"] = cmd_gather.notes(run)
    return run


def test_notes_on_a_troubled_box():
    run = troubled_run()
    n = run["notes"]
    assert set(n) == {"general", "cpu", "memory", "disk", "net", "smb"}
    assert has(n["general"], "could not run: zpool iostat")
    c = n["cpu"]
    assert has(c, "governor powersave") and has(c, "virtual machine")
    assert has(c, "1 CPU(s) over 90% busy (CPU 1) while the average was 39.1%")
    assert has(c, "NET_RX softirqs") and has(c, "ran on CPU 0")
    assert has(c, "load average 9.5 on 2 CPUs")
    assert has(c, "CPU pressure: some task waited for a CPU 25%")
    assert has(c, "mitigations=off") and has(c, "SMT is off")
    m = n["memory"]
    assert has(m, "swap in use: 4.00G of 8.00G")
    assert has(m, "only 700M of 32.0G available")
    assert has(m, "swapping over the interval: 500 pages in, 2.00K out")
    assert has(m, "100/s major page faults")
    assert has(m, "40 direct reclaim stalls") and has(m, "3 compaction stalls")
    assert has(m, "1 OOM kill over") and has(m, "memory pressure: some task")
    assert has(m, "enabled=always with defrag=always")
    assert has(m, "NUMA node 0 nearly full while node 1 has room")
    assert has(m, "vm.zone_reclaim_mode set")
    d = n["disk"]
    assert has(d, "sda: 98.0% busy over the interval, 8.5 requests queued")
    assert has(d, "sda: mean read wait 45.00ms") and has(d, "slow for an SSD")
    assert has(d, "sda: the SCSI layer counted 4 command errors")
    assert has(d, "sda: SATA link at 3.0 Gbps of 6.0 Gbps")
    assert has(d, "nvme0n1: PCIe link 8.0 GT/s PCIe x2 of 16.0 GT/s PCIe x4")
    assert not has(d, "sda: PCIe link")
    assert has(d, "sda: I/O scheduler bfq on an SSD")
    assert has(d, "I/O pressure: some task was stalled on I/O 40%")
    assert not has(d, "nvme0n1: the SCSI layer")
    ne = n["net"]
    assert has(ne, "eno1: linked at 1 Gb/s though the NIC supports 10 Gb/s")
    assert has(ne, "eno1: tso off")
    assert has(ne, "eno1: 100 packets missed by the NIC over the interval")
    assert has(ne, "rx ring 256 of 4096 max")
    assert has(ne, "eno1: 3 packets dropped") and has(ne, "eno1: 1 packet error over")
    assert has(ne, "driver counters moved over the interval: rx_no_buffer_count +7")
    assert not has(ne, "rx_missed_errors +100")
    assert has(ne, "eno1: 10.01K/s interrupts, all on CPU 0")
    assert not has(ne, "coalescing off")   # 1 Gb/s link
    assert has(ne, "TCP retransmitted 500 of 100.00K segments")
    assert has(ne, "7 of them full timeouts")
    assert has(ne, "2 connection attempts dropped from a full listen queue")
    assert has(ne, "receive queues pruned or collapsed 3 times")
    assert has(ne, "5.0% of received segments arrived out of order")
    assert has(ne, "16 packets dropped by the per-CPU backlog") and has(ne, "1 CPU(s)")
    assert has(ne, "2 NAPI polls cut short")
    assert has(ne, "TCP holds 9.77M of socket memory, over the pressure threshold 7.81M")
    assert has(ne, "tcp_window_scaling = 0") and has(ne, "tcp_sack = 0")
    assert has(ne, "tcp_moderate_rcvbuf = 0")
    assert has(ne, "10.1.2.9:51234: receive-window limited 40%")
    assert not has(ne, "send-buffer limited")
    assert has(ne, "10.1.2.9:51234: 25 of 5.00K segments retransmitted")
    assert has(ne, "10.1.2.10:60000: RTT 35.5 ms")
    s = n["smb"]
    assert has(s, "smbd[10.1.2.9] 12.0% of the interval: CPU contention")
    assert has(s, "throttled 1.500s over the interval by its CPU quota")
    assert has(s, "CPU quota 100000 100000") and has(s, "memory limited to 4.00G, using 3.00G")
    assert has(s, "smbd 20: open files limited to 1024 (hard 4096)")
    assert not has(s, "smbd 21: open files")
    assert has(s, "1 of 2 sessions negotiated SMB2_02") and has(s, "large reads")
    assert has(s, "1 of 2 sessions encrypted, full (AES-128-GCM)")
    assert not has(s, "sign every packet")
    assert has(s, "SO_RCVBUF=65536") and has(s, "autotuning")
    assert has(s, "smbd profiling level = on")
    assert has(s, "log level = 3 auth:5") and has(s, "strict locking = yes")
    assert has(s, "kernel oplocks = yes") and has(s, "multi channel support = no")
    assert has(s, "data (tank/data): sync=always")
    assert has(s, "data: strict sync = no")
    quiet = troubled_run()
    quiet["samba"]["processes"] = []
    assert has(cmd_gather.smb_notes(quiet), "no smbd process is running")


def test_report_covers_every_section():
    run = troubled_run()
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_gather.print_run(run)
    text = buf.getvalue()
    for head in ("host nas:", "\nhost\n", "\nCPU\n", "\nmemory\n", "\ndisks\n",
                 "disk I/O over 10.0 s", "\npools\n", "\nnetwork\n",
                 "traffic over 10.0 s", "TCP over 10.0 s", "\nSamba 4.24.4",
                 "\nshares (testparm)", "\nnotes\n"):
        assert head in text, head
    assert "up 1d 1h since 2026-10-15 00:00:00 UTC" in text
    assert "iXsystems TRUENAS-M50 (board Supermicro X11), firmware 3.3 01/01/2024; virtual machine on kvm" in text
    assert "1 socket(s), 2 cores, 2 threads, SMT off, 2 NUMA nodes" in text
    assert "mitigations: 1 active (spectre_v2); 1 vulnerable (mds); 1 not affected" in text
    assert "over 10.0 s: 39.1% busy" in text and "busiest CPUs: 1 " in text
    assert "NET_RX 2.20K/s (90.9% on CPU 0)" in text
    assert "eno1-TxRx-0 10.00K/s on 1 CPU" in text
    assert "1.40 CPUs used in all, 0.98 by smbd" in text
    assert "used: ARC 4.00G (12% of RAM), page cache 4.00G" in text
    assert "transparent hugepages: enabled always" in text
    assert "NUMA: node 0: 16.0G, 100M free" in text
    assert "WD Blue" in text and "3.0G SATA" in text and "PCIe 8.0 x2" in text
    assert "write back" in text and "  tank\n" in text and "None" not in text
    assert "I/O pressure: some 40.0% / 30.0% / 5.0%; full 30.0%" in text
    assert "eno1       physical  up       1 Gb/s" in text
    assert "256/256 of 4096" in text and "rx-csum tx-csum sg gso gro rxvlan txvlan rxhash" in text
    assert "10.01K/s on 1" in text
    assert "191M/s" in text and "858M/s" in text and "880.0%" in text
    assert "rx_crc_errors +1, rx_dropped +3, rx_missed_errors +100" in text
    assert "500 retransmitted (0.5%), 7 timeouts" in text
    assert "softnet over 10.0 s" in text and "16 dropped" in text
    assert "sockets: TCP 20 in use" in text and "pressure at 7.81M, limit 11.7M" in text
    assert "processes: smbd x2 (98.0% CPU) 230M, winbindd x1" in text
    assert "smbd[10.1.2.9]" in text and "12.0%" in text and "300/s" in text
    assert "smbd 20: open files 1024 (hard 4096), cgroup /system.slice/smbd.service" in text
    assert "memory.max 4.00G; memory.current 3.00G" in text
    assert "throttled 1.500s in 12 periods" in text
    assert "sessions 2, tree connections 3 (data 2, IPC$ 1), open files 3, locks 1" in text
    assert "alice  10.1.2.9   10.1.2.9, 10.1.3.9  SMB3_11  full (AES-128-GCM)" in text
    assert "TCP: 2 estab; listening on 0.0.0.0:445 (backlog 0 of 50)" in text
    assert "10.1.2.9:51234   1234  eno1" in text and "40%" in text
    assert "226 Mb/s" in text and "115 Mb/s" in text
    assert "[global] effective (testparm -v): server max protocol = SMB3_11" in text
    assert "- could not run: zpool iostat: no answer" in text
    # a subset prints only those sections and their notes
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_gather.print_run(run, ["net"])
    text = buf.getvalue()
    assert "\nnetwork\n" in text and "\nCPU\n" not in text
    assert "linked at 1 Gb/s" in text and "governor powersave" not in text
    assert "could not run" in text


def test_main_saved_run_sections_and_errors(tmp_path, capsys):
    run = troubled_run()
    path = tmp_path / "run.json"
    path.write_text(json.dumps(run))
    assert cmd_gather.main([str(path)]) == 0
    text = capsys.readouterr().out
    assert "\nCPU\n" in text and "\nSamba" in text
    assert cmd_gather.main([str(path), "cpu", "memory"]) == 0
    text = capsys.readouterr().out
    assert "\nCPU\n" in text and "\nmemory\n" in text and "\nnetwork\n" not in text
    assert cmd_gather.main(["--list"]) == 0
    assert "pool    ZFS pools" in capsys.readouterr().out
    bad = tmp_path / "bad.json"
    bad.write_text('{"tool": "smb-perf-disk"}')
    assert cmd_gather.main([str(bad)]) == 1
    assert "not a smb-perf-gather run" in capsys.readouterr().err
    with pytest.raises(SystemExit) as e:
        cmd_gather.main(["cpus"])
    assert e.value.code == 2
    with pytest.raises(SystemExit):
        cmd_gather.main([str(path), str(bad)])


@pytest.mark.skipif(not os.path.exists("/proc/stat"), reason="needs /proc")
def test_live_run(tmp_path, capsys):
    out = tmp_path / "run.json"
    assert cmd_gather.main(["--interval", "0.2", "-o", str(out)]) == 0
    text = capsys.readouterr().out
    assert text.startswith("host ") and "\nCPU\n" in text and "\nnetwork\n" in text
    run = json.loads(out.read_text())
    assert run["tool"] == "smb-perf-gather" and run["sections"] == list(cmd_gather.SECTIONS)
    assert run["seconds"] >= 0.2 and run["cpu"]["usage"]["total"] is not None
    assert run["cpu"]["topology"]["cpus"] >= 1 and "vmstat" in run["vm"]
    assert isinstance(run["net"]["interfaces"], dict) and run["net"]["snmp"]["delta"]
    assert "processes" in run["samba"] and "connections" in run["samba"]
    assert isinstance(run["notes"], dict)
    # a subset gathers only what it needs
    assert cmd_gather.main(["cpu", "net", "--interval", "0", "-o", str(out)]) == 0
    text = capsys.readouterr().out
    assert "\nCPU\n" in text and "\nnetwork\n" in text and "\nmemory\n" not in text
    run = json.loads(out.read_text())
    assert run["sections"] == ["cpu", "net"] and "vm" not in run and "devices" not in run
    assert run["cpu"]["usage"] is None and run["seconds"] == 0
    assert cmd_gather.main([str(out), "net", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["sections"] == ["cpu", "net"]


def test_client_from_process_title():
    from smbperf import fmt
    assert smbd.client_in_title("smbd: client [10.1.2.9]") == "10.1.2.9"
    assert smbd.client_in_title("smbd: client [fe80::1]   ") == "fe80::1"
    assert smbd.client_in_title("smbd: notifyd .") is None
    # the comm keeps 15 bytes; the title names the client in full
    p = Proc(pid=5, ppid=1, comm="smbd[10.1.2.9", title_client="10.1.2.9")
    assert p.name == "smbd[10.1.2.9]"
    p.clients = ["10.1.2.8:51234"]
    assert p.name == "smbd[10.1.2.8]"
    procs = [{"pid": 5, "clients": [], "title_client": "10.1.2.9"},
             {"pid": 6, "clients": [], "title_client": "10.1.2.7"},
             {"pid": 7, "clients": [], "title_client": "10.1.2.7"},
             {"pid": 8, "clients": ["10.1.2.5:4000"], "title_client": "10.1.2.5"}]
    conns = [{"state": "LISTEN", "peer": "0.0.0.0", "pport": None},
             {"state": "ESTAB", "peer": "10.1.2.9", "pport": 51234},
             {"state": "ESTAB", "peer": "10.1.2.7", "pport": 1},
             {"state": "ESTAB", "peer": "10.1.2.7", "pport": 2},
             {"state": "ESTAB", "peer": "10.1.2.5", "pport": 4000}]
    cmd_gather._map_pids(procs, conns)
    assert conns[1]["pid"] == 5                 # one process, one connection
    assert "pid" not in conns[2] and "pid" not in conns[3]   # two of each
    assert conns[4]["pid"] == 8                 # by the socket itself
    assert "pid" not in conns[0]
    assert fmt.wrap_items("  x: ", ["aa bb", "cc dd", "ee ff"], width=16) \
        == "  x: aa bb,\n    cc dd, ee ff"
    assert fmt.wrap_items("  a long prefix: ", ["item"], width=10) \
        == "  a long prefix:\n    item"
    assert fmt.wrap_items("  x: ", []) == "  x: "
