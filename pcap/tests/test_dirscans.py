"""smb-dirscans on a synthetic capture of directories listed again (needs
tshark)."""

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
    cmd_dirscans, cmd_summary, dirscans, extract, model,
)

pytestmark = pytest.mark.skipif(
    shutil.which("tshark") is None, reason="tshark not installed")


@pytest.fixture(scope="module")
def capture(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("dirs") / "dirs.pcap")
    return path, mkpcap.build_dirscans(path)


@pytest.fixture(scope="module")
def records(capture):
    return list(extract.extract(capture[0]))


def load(records) -> model.Capture:
    cap = model.Capture()
    cap.add_records(records)
    cap.finish()
    return cap


@pytest.fixture(scope="module")
def dirs(records):
    return {d.path: d for d in dirscans.find(load(records))}


def run(main, *args) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(list(args))
    assert rc == 0
    return buf.getvalue()


def test_replies_carry_entry_counts(records):
    assert records[-1]["unattributed"] == {}
    finds = [r for r in records if r.get("k") == "p" and r["cmd"] == 14
             and r["resp"] and r.get("status") == 0]
    top = next(r for r in finds if r.get("dots"))
    assert (top["dots"], top["ents"], top["e0"], top["e1"]) == (
        2, 10, "f00", "f09")
    one = next(r for r in finds if r.get("e0") == "f05")
    assert one["ents"] == 1 and one["e1"] == "f05"


def test_scans_are_counted(dirs, capture):
    _, exp = capture
    for name in ("big", "small", "again", "two"):
        d = dirs[name]
        got = (len(d.scans), d.count("end", "complete"),
               d.count("kind", "rewind"), d.count("kind", "repeat"),
               d.count("kind", "overlap"), d.returned, d.distinct)
        assert got == exp[name], name
        assert not d.changed
    assert dirs["big"].lookups == 1
    assert not any(p.startswith("fid:") for p in dirs)


def test_scan_from_before_the_capture_is_placed(dirs):
    s = dirs["big"].scans[0]
    assert (s.how, s.kind, s.end) == ("joined", "joined", "closed")
    assert (s.pos0, s.reach, s.new) == (10, 20, 10)
    assert [x.new for x in dirs["big"].scans] == [10, 10, 10, 0]


def test_restart_on_one_handle(dirs):
    a, b = dirs["again"].scans
    assert (a.how, a.kind, a.end) == ("open", "first", "restarted")
    assert (b.how, b.kind, b.end) == ("restart", "rewind", "complete")


def test_tool(capture):
    path, _ = capture
    out = run(cmd_dirscans.main, path, "--no-cache", "--scans")
    assert out.startswith("10 scans of 4 directories returned 116 entries; "
                          "1 lookup of a single name")
    assert re.search(r"^10\.0\.0\.2\s+share\s+big\s+4\s+1\s+3\s+0\s+90\s+30"
                     r"\s+3\.0x\s", out, re.M)
    assert "3 of 4 scans started from the top again" in out
    assert "1 scan listed it again after a complete listing" in out
    assert "1 scan began while another scan of it was still open" in out
    assert re.search(r"^\s+0\s+0\.010\s+joined\s+joined\s+1\s+10\s+10\s+20\s",
                     out, re.M)
    objs = [json.loads(line) for line in
            run(cmd_dirscans.main, path, "--no-cache", "--json").splitlines()]
    assert [o["directory"] for o in objs] == ["big", "again", "small", "two"]
    assert objs[0]["ratio"] == 3.0 and objs[0]["scan_list"][0]["from"] == 10
    out = run(cmd_dirscans.main, path, "--no-cache", "--min-ratio", "2.5")
    assert re.search(r"^10\.0\.0\.2\s+share\s+big\s", out, re.M)
    assert not re.search(r"^10\.0\.0\.2\s+share\s+again\s", out, re.M)


def test_summary_points_at_dirscans(capture):
    path, _ = capture
    out = run(cmd_summary.main, path, "--no-cache")
    assert "Directories listed again (smb-dirscans has the scans):" in out
    assert "big from 10.0.0.2: 4 scans, 3 rewinds; 90 entries returned for " \
           "30 (3.0x)" in out


def test_extraction_without_entry_counts(records):
    old = [{k: v for k, v in r.items() if k not in ("ents", "e0", "e1")}
           for r in records]
    cap = load(old)
    assert dirscans.entry_counts_missing(cap)
    assert not dirscans.entry_counts_missing(load(records))


def test_replies_sharing_a_frame_are_not_split(tmp_path):
    pcap = mkpcap.Pcap()
    c = mkpcap.Conn(pcap, "10.0.0.2", "10.0.0.1", 50011)
    t = 1_700_000_000 * 1_000_000_000
    c.handshake(t, t + 20 * mkpcap.US, t + 40 * mkpcap.US)
    fids = [bytes([n]) * 16 for n in (1, 2)]
    find = mkpcap.QUERY_DIRECTORY
    c.send(True, b"".join(
        mkpcap.nbss(mkpcap.header(find, i + 1, sesid=1, tid=1)
                    + mkpcap.find_req(f, "*")) for i, f in enumerate(fids)),
        t + mkpcap.MS)
    c.send(False, b"".join(
        mkpcap.nbss(mkpcap.header(find, i + 1, resp=True, sesid=1, tid=1)
                    + mkpcap.buffer_resp(mkpcap.dir_entries(names)))
        for i, names in enumerate((["a", "b"], ["c"]))), t + 2 * mkpcap.MS)
    path = str(tmp_path / "two.pcap")
    pcap.write(path)
    recs = list(extract.extract(path))
    assert recs[-1]["unattributed"] == {"entries": 1}
    found = dirscans.find(load(recs))
    assert len(found) == 2
    assert all(len(d.scans) == 1 and d.scans[0].unknown == 1
               and d.distinct is None for d in found)
