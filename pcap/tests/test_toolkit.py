"""End-to-end tests on the synthetic capture (needs tshark)."""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import sys
from contextlib import redirect_stdout

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import mkpcap  # noqa: E402
from smbpcap import (  # noqa: E402
    cmd_errors, cmd_flame, cmd_hist, cmd_latency, cmd_repeats, cmd_summary,
    cmd_trace, extract, model, names,
)

pytestmark = pytest.mark.skipif(
    shutil.which("tshark") is None, reason="tshark not installed")


@pytest.fixture(scope="module")
def capture(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("cap") / "synth.pcap")
    exp = mkpcap.build(path)
    return path, exp


@pytest.fixture(scope="module")
def records(capture):
    path, _ = capture
    return list(extract.extract(path))


@pytest.fixture(scope="module")
def cap(records):
    c = model.Capture()
    c.add_records(records)
    c.finish()
    c.inputs.append("synth.pcap")
    return c


def pdus(records, frame):
    return [r for r in records if r.get("k") == "p" and r["frame"] == frame]


def exchange(cap, frame, cmd=None):
    for x in cap.exchanges:
        if x.frame == frame and (cmd is None or x.cmd_name == cmd):
            return x
    raise AssertionError(f"no exchange for frame {frame}")


# -- extraction ---------------------------------------------------------------

def test_extraction_is_clean(records):
    diag = records[-1]
    assert diag["k"] == "d"
    assert diag["frames_broken"] == 0
    assert diag["frames_unattributed"] == 0
    assert diag["unattributed"] == {}


def test_compound_fields_land_on_their_pdu(records, capture):
    _, exp = capture
    req = pdus(records, exp["frames"]["compound_ok"])
    assert [p["cmd"] for p in req] == [5, 16, 6]
    assert req[0]["name"] == "dir\\other.txt"
    assert "fid" not in req[0]
    assert req[1]["fid"] == model.ALL_ONES_FID
    assert req[1]["cls"] == 1 and req[1]["lvl"] == 18
    assert req[2]["fid"] == model.ALL_ONES_FID
    assert req[1]["related"] and req[2]["related"] and not req[0]["related"]
    resp = pdus(records, exp["frames"]["compound_ok"] + 1)
    assert resp[0]["fid"] != model.ALL_ONES_FID
    assert resp[0]["action"] == 1
    assert "fid" not in resp[1] and "fid" not in resp[2]


def test_error_bodies_are_told_from_command_bodies(records, capture):
    _, exp = capture
    resp = pdus(records, exp["frames"]["compound_fail"] + 1)
    assert [p["status"] for p in resp] == [0xC0000034, 0xC0000128, 0xC0000128]
    assert all(p.get("errbytes") == 0 for p in resp)
    assert "action" not in resp[0]


def test_durable_context_fid_stays_with_the_create(records, capture):
    _, exp = capture
    (p,) = pdus(records, exp["frames"]["create_a"])
    assert p["ctx"] == ["MxAc", "DHnQ"]
    assert p["name"] == "dir\\file.txt"
    assert p["disp"] == 3
    assert p["isdir"] is False


def test_odd_filename_round_trips(records, capture):
    _, exp = capture
    (p,) = pdus(records, exp["frames"]["weird"])
    assert p["name"] == exp["weird_name"]


def test_async_header_has_aid_not_tid(records, capture):
    _, exp = capture
    (interim,) = pdus(records, exp["frames"]["notify"] + 1)
    assert interim["async"] and interim["status"] == 0x103
    assert interim["aid"] == 0x99 and "tid" not in interim


def test_lock_elements_and_rename_name(records, capture):
    _, exp = capture
    (lock,) = pdus(records, exp["frames"]["lock1"])
    assert lock["nlocks"] == 2 and lock["off"] == [0, 100]
    assert lock["lockflags"] == [0x12, 0x12]
    (ren,) = pdus(records, exp["frames"]["rename"])
    assert ren["name"] == "dir\\renamed.txt" and ren["lvl"] == 10
    (dele,) = pdus(records, exp["frames"]["delete"])
    assert dele["delete"] is True and dele["lvl"] == 13


def test_find_response_counts_entries(records, capture):
    _, exp = capture
    (resp,) = pdus(records, exp["frames"]["find1"] + 1)
    assert "name" not in resp
    assert (resp["ents"], resp["e0"], resp["e1"]) == (2, "a.txt", "b.txt")
    assert "dots" not in resp


def test_two_pdus_in_one_segment(records, capture):
    _, exp = capture
    req = pdus(records, exp["frames"]["pipelined"])
    assert len(req) == 2 and all(p["n"] == 2 for p in req)
    assert [p["off"] for p in req] == [0, 4096]
    assert all(not p["related"] and p["next"] == 0 for p in req)


def test_tcp_events_and_fast_acks(records):
    events = [r for r in records if r.get("k") == "t"]
    assert any("retrans" in r["ev"] for r in events)
    assert any("R" in r["flags"] for r in events)
    assert any(r["flags"] == "SA" and r["ackrtt"] == 20_000 for r in events)


def test_cut_message_whose_last_frame_is_not_read(tmp_path):
    # A whole frame after a cut one is not dissected, so it is not read.
    pcap = mkpcap.Pcap()
    c = mkpcap.Conn(pcap, "10.0.0.2", "10.0.0.1", 50003)
    t = 1_700_000_000 * 1_000_000_000
    c.handshake(t, t + 20 * mkpcap.US, t + 40 * mkpcap.US)
    fid = bytes(16)
    c.send(True, mkpcap.nbss(mkpcap.header(mkpcap.READ, 1)
                             + mkpcap.read_req(fid, 0, 4096)), t + mkpcap.MS)
    frames = c.send(False, mkpcap.nbss(
        mkpcap.header(mkpcap.READ, 1, resp=True)
        + mkpcap.read_resp(bytes(4096))), t + 2 * mkpcap.MS)
    pcap.truncate(frames[0], 54 + 4 + 64 + 16)
    echo = mkpcap.header(mkpcap.ECHO, 2) + mkpcap.small_resp(4)
    c.send(True, mkpcap.nbss(echo), t + 10 * mkpcap.MS)
    c.send(False, mkpcap.nbss(mkpcap.header(mkpcap.ECHO, 2, resp=True)
                              + mkpcap.small_resp(4)), t + 11 * mkpcap.MS)
    path = str(tmp_path / "cut.pcap")
    pcap.write(path)
    recs = list(extract.extract(path))
    cap = model.Capture()
    cap.add_records(recs)
    cap.finish()
    read = next(x for x in cap.exchanges if x.cmd_name == "READ")
    assert read.latency == mkpcap.MS  # its own frame, not the next message's
    assert recs[-1]["cut_unfinished"] == 1


def test_unescape():
    assert extract.unescape(r"a\\b\tc") == "a\\b\tc"
    assert extract.unescape(r"\x41é") == "Aé"
    assert extract.unescape("plain") == "plain"


# -- model ----------------------------------------------------------------------

def test_every_exchange_is_paired_as_expected(cap, capture):
    _, exp = capture
    for label, ms in exp["latency_ms"].items():
        x = exchange(cap, exp["frames"][label])
        assert x.latency is not None, label
        assert abs(x.latency / 1e6 - ms) < 0.05, (label, x.latency)
    assert len(cap.orphans) == 0


def test_idle_is_time_with_nothing_outstanding(cap, capture):
    _, exp = capture

    def idle(label):
        return exchange(cap, exp["frames"][label]).idle

    assert idle("neg1") is None  # the client's first request
    assert idle("neg2") == 800 * mkpcap.US
    # To the WRITE's first segment, not the last one tshark shows it in.
    assert idle("write") == 4700 * mkpcap.US
    # The CHANGE_NOTIFY outstanding meanwhile does not count.
    assert idle("rename") == 507 * mkpcap.MS
    chain = [x.idle for x in cap.exchanges
             if x.frame == exp["frames"]["compound_ok"]]
    assert chain == [500 * mkpcap.US, 0, 0]


def test_unanswered_cancelled_and_breaks(cap, capture):
    _, exp = capture
    flush = exchange(cap, exp["frames"]["flush"])
    assert flush.resp is None and flush.status_class == "unanswered"
    notify = exchange(cap, exp["frames"]["notify"])
    assert notify.interim is not None and notify.cancel is not None
    assert notify.status_name == "CANCELLED" and notify.wait
    assert len(cap.breaks) == 1
    assert cap.breaks[0]["kind"] == "oplock"
    assert cap.breaks[0]["file"] == "dir\\renamed.txt"


def test_names_resolve(cap, capture):
    _, exp = capture
    read = exchange(cap, exp["frames"]["read"])
    assert read.file == "dir\\file.txt" and read.share == "share"
    assert read.user == "LAB\\alice" and read.sub == "64K"
    lock = exchange(cap, exp["frames"]["lock2"])
    assert lock.file == "dir\\renamed.txt"
    denied = exchange(cap, exp["frames"]["denied"])
    assert denied.user == "LAB\\bob" and denied.status_class == "error"
    ipc = exchange(cap, exp["frames"]["tc2"])
    assert ipc.share == "IPC$"
    assert cap.trees[(0x11, 2)].type == 2


def test_compound_members_share_time_and_collateral_failures(cap, capture):
    _, exp = capture
    members = [x for x in cap.exchanges
               if x.frame == exp["frames"]["compound_ok"]]
    assert [x.cmd_name for x in members] == ["CREATE", "QUERY_INFO", "CLOSE"]
    assert all(x.chain_sig == "CREATE+QUERY_INFO+CLOSE" for x in members)
    assert all(x.file == "dir\\other.txt" for x in members)
    assert sum(x.weight for x in members) == pytest.approx(
        members[0].latency, abs=3)
    failed = [x for x in cap.exchanges
              if x.frame == exp["frames"]["compound_fail"]]
    assert failed[0].status_class == "probe"
    assert failed[1].status_class == "collateral"
    assert failed[2].status_class == "collateral"


def test_smb1_negotiate_pairs_with_smb2_response(cap, capture):
    _, exp = capture
    x = exchange(cap, exp["frames"]["neg1"])
    assert x.cmd_name == "NEGOTIATE" and x.sub == "2.??"
    assert x.latency == 200_000


def test_vantage_is_server(cap):
    verdict, detail = cap.vantage()
    assert verdict == "server"
    assert "handshake" in detail


def test_filter(cap):
    f = model.Filter(cmds=[("smb2", names.CREATE)], errors_only=True)
    got = list(f.apply(cap))
    assert {x.status_name for x in got} == {"OBJECT_NAME_NOT_FOUND",
                                           "ACCESS_DENIED"}
    f = model.Filter(files=["*renamed*"])
    assert {x.cmd_name for x in f.apply(cap)} >= {"LOCK", "FLUSH",
                                                  "OPLOCK_BREAK"}


# -- tools --------------------------------------------------------------------

def run(main, *args) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(list(args))
    assert rc == 0
    return buf.getvalue()


def test_summary(capture):
    path, _ = capture
    out = run(cmd_summary.main, path, "--no-cache")
    assert "taken on the server" in out
    assert "LAB\\alice" in out and "IPC$" in out
    assert "Requests without a response (1)" in out
    assert "reset at" in out


def test_latency(capture):
    path, _ = capture
    out = run(cmd_latency.main, path, "--no-cache", "--slowest", "6",
              "--hist")
    lines = out.splitlines()
    first_row = lines[next(i for i, l in enumerate(lines)
                           if l.startswith("---")) + 1]
    assert first_row.startswith("WRITE")
    assert "in CREATE+QUERY_INFO+CLOSE" in out or "async" in out
    out = run(cmd_latency.main, path, "--no-cache", "--by", "share,cmd",
              "--json")
    assert '"levels": [' in out


def test_errors(capture):
    path, _ = capture
    out = run(cmd_errors.main, path, "--no-cache")
    assert "ACCESS_DENIED" in out and "LOCK_NOT_GRANTED" in out
    assert "Collateral (2)" in out
    assert "reset by the server" in out


def test_repeats(capture):
    path, _ = capture
    out = run(cmd_repeats.main, path, "--no-cache", "--min-count", "2")
    assert "QUERY_DIRECTORY" in out


def test_trace(capture):
    path, _ = capture
    out = run(cmd_trace.main, path, "--no-cache", "--events",
              "--file", "renamed")
    assert "SET_INFO FILE/RENAME" in out and "** oplock break" in out
    out = run(cmd_trace.main, path, "--no-cache", "--json", "--cmd", "ECHO")
    assert '"cmd": "ECHO"' in out


def test_hist(capture):
    path, _ = capture
    out = run(cmd_hist.main, path, "--no-cache", "--interval", "100ms",
              "--csv")
    assert out.startswith("start_s,")
    out = run(cmd_hist.main, path, "--no-cache", "--metric", "inflight",
              "--by", "none")
    assert "all" in out


def test_flame(capture, tmp_path):
    path, _ = capture
    out = run(cmd_flame.main, path, "--no-cache", "--collapsed")
    assert "10.0.0.2;share;CREATE;OPEN_IF;SUCCESS 1500000" in out
    svg = tmp_path / "f.svg"
    run(cmd_flame.main, path, "--no-cache", "-o", str(svg),
        "--stack", "cmd,file")
    text = svg.read_text()
    assert text.startswith("<?xml") and "<svg" in text
    assert "dir\\file.txt" in text
    assert re.search(r"<title>all: \S+ \(100\.00%\), \d+ requests, "
                     r"\S+ each, \S+</title>", text)
    assert re.search(r">all \(\d+\)</text>", text)
    assert re.search(r"<title>READ: \S+ \(\S+%\), 4 requests, \S+ each, "
                     r"\S+</title>", text)
    out = run(cmd_flame.main, path, "--no-cache", "--json",
              "--stack", "cmd,file", "--weight", "count")
    tree = json.loads(out)
    assert tree["levels"] == ["cmd", "file"] and tree["weight"] == "count"
    root = tree["root"]
    assert root["name"] == "all" and root["value"] == root["n"]
    read = next(c for c in root["children"] if c["name"] == "READ")
    assert read["n"] == 4 and read["time_ns"] > 0 and read["bytes"] > 0
    assert sum(c["value"] for c in root["children"]) == root["value"]
    assert [c["value"] for c in root["children"]] == sorted(
        (c["value"] for c in root["children"]), reverse=True)
    out = run(cmd_flame.main, path, "--no-cache", "--tree",
              "--stack", "share,path,op", "--weight", "count")
    assert re.search(r"^all\s+\d+\s+100\.0%", out, re.M)
    assert re.search(r"^[├└]─ share\s", out, re.M)
    assert re.search(r"^(?:│  |   )[├└]─ dir\s", out, re.M)
    assert re.search(r"^(?:│  |   ){2}[├└]─ file\.txt\s", out, re.M)
    assert re.search(r"^(?:│  |   ){3}[├└]─ READ 64K\s", out, re.M)
    out = run(cmd_flame.main, path, "--no-cache", "--tree", "--top", "1",
              "--stack", "cmd")
    assert re.search(r"^└─ \(\d+ more\)\s", out, re.M)


def test_idle_views(capture):
    path, _ = capture
    out = run(cmd_flame.main, path, "--no-cache", "--tree", "--idle",
              "--stack", "cmd")
    assert re.search(r"^\s+time\s+%\s+n\s+each\s+idle\s+bytes$", out, re.M)
    tree = json.loads(run(cmd_flame.main, path, "--no-cache", "--json",
                          "--weight", "idle", "--stack", "cmd"))
    root = tree["root"]
    assert root["value"] == root["idle_ns"] > 0
    assert root["children"][0]["name"] == "SET_INFO"
    assert root["children"][0]["idle_ns"] >= 507 * mkpcap.MS
    out = run(cmd_latency.main, path, "--no-cache", "--idle", "--sort",
              "idle")
    lines = out.splitlines()
    assert lines[1].startswith("Idle is the time")
    sep = next(i for i, l in enumerate(lines) if l.startswith("---"))
    assert lines[sep - 1].split()[-2:] == ["idle", "p50"]
    assert lines[sep + 1].startswith("SET_INFO")
    out = run(cmd_trace.main, path, "--no-cache", "--idle", "--file",
              "renamed", "--cmd", "SET_INFO")
    assert "507.00ms" in out
    out = run(cmd_summary.main, path, "--no-cache", "--idle")
    assert "Client idle (think time plus the network round trip)" in out
    assert re.search(r"^  10\.0\.0\.3\s+4\s", out, re.M)
    out = run(cmd_hist.main, path, "--no-cache", "--metric", "idle",
              "--by", "none", "--interval", "1s")
    assert out.startswith("client idle time before requests")
    assert "545.70ms" in out  # both clients', less the 0.9ms before the wait
