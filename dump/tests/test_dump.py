"""Tests for trimming, anonymizing and capturing. The end-to-end ones
read the results back through tshark and the analysis tools."""

from __future__ import annotations

import io
import ipaddress
import os
import shutil
import struct
import sys
from contextlib import redirect_stdout

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
DUMP = os.path.dirname(HERE)
ROOT = os.path.dirname(DUMP)
sys.path.insert(0, DUMP)
sys.path.insert(0, os.path.join(ROOT, "pcap"))
sys.path.insert(0, os.path.join(ROOT, "pcap", "tests"))

import mkpcap  # noqa: E402
from smbdump import capture, mapping, pcapio, sanitize  # noqa: E402
from smbdump.packet import Packet, _sum16  # noqa: E402
from smbpcap import extract, model  # noqa: E402

needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None,
                                  reason="tshark not installed")
KEY = bytes(range(32))
SECRETS = ["alice", "bob", "PC1", "PC2", "srv", "share", "file.txt",
           "other.txt", "renamed.txt", "a.txt", "b.txt", "weïrd",
           "日本"]


@pytest.fixture(scope="module")
def synth(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("synth") / "synth.pcap")
    exp = mkpcap.build(path)
    return path, exp


def load(*paths: str) -> model.Capture:
    cap = model.Capture()
    for i, p in enumerate(paths):
        cap.add_records(extract.extract(p), i)
        cap.inputs.append(p)
    cap.finish()
    return cap


def by_request(cap: model.Capture) -> dict:
    return {(x.req["sport"], x.mid, x.cmd_name): x for x in cap.exchanges}


def records(path: str) -> list[pcapio.Record]:
    with pcapio.open_capture(path) as f:
        return list(pcapio.read(f))


# -- mapping ------------------------------------------------------------------

def test_names_are_keyed_consistent_and_keep_their_shape():
    m, other = mapping.Mapper(KEY), mapping.Mapper(bytes(32))
    t = m.path("Projects\\Budget 2026.xlsx")
    assert t == m.path("PROJECTS\\budget 2026.XLSX".replace("XLSX", "xlsx"))
    assert t != other.path("Projects\\Budget 2026.xlsx")
    assert len(t) == len("Projects\\Budget 2026.xlsx")
    assert t.endswith(".xlsx") and t[8] == "\\" and t[15] == " "
    assert m.path("\U0001F600x").encode("utf-16-le").__len__() == \
        "\U0001F600x".encode("utf-16-le").__len__()
    assert m.path("dir\\.DS_Store") .endswith("\\.DS_Store")
    assert m.path("a.txt:Zone.Identifier:$DATA").endswith(
        ":Zone.Identifier:$DATA")
    assert m.path("._photo.jpg") == "._" + m.path("photo.jpg")
    assert not mapping.Mapper(KEY, keep_ext=False).path(
        "x.docx").endswith(".docx")


def test_host_names_agree_across_forms():
    m = mapping.Mapper(KEY)
    dns = m.name("truenas.example.com")
    assert dns.split(".")[0] == m.name("TRUENAS")
    assert m.name("cifs/truenas.example.com") == "cifs/" + dns
    assert m.unc("\\\\TRUENAS\\data\\x") == \
        "\\\\" + m.name("TRUENAS") + "\\" + m.share("data") + "\\" + m.path("x")
    assert m.user("LAB\\alice") == m.name("LAB") + "\\" + m.user("alice")
    assert m.name("WORKGROUP") == "WORKGROUP"


def test_addresses_keep_prefixes_and_private_ranges():
    m = mapping.Mapper(KEY)
    v4 = [m.ipv4(bytes([192, 168, 7, i])) for i in range(256)]
    assert len(set(v4)) == 256
    assert all(a[:2] == bytes([192, 168]) for a in v4)
    assert len({a[:3] for a in v4}) == 1  # one /24 stays one /24
    a = m.ipv4(bytes([172, 20, 1, 1]))
    assert a[0] == 172 and 16 <= a[1] <= 31
    assert m.ipv4(bytes([10, 1, 2, 3]))[0] == 10
    assert m.ipv4(bytes([224, 0, 0, 251])) == bytes([224, 0, 0, 251])
    assert m.ipv4_text("10.1.2.3") == str(ipaddress.ip_address(
        m.ipv4(bytes([10, 1, 2, 3]))))
    assert len(m.ipv4_text("192.168.100.200")) == len("192.168.100.200")
    mapped = ipaddress.ip_address("::ffff:10.1.2.3").packed
    assert m.ipv6(mapped)[12:] == m.ipv4(bytes([10, 1, 2, 3]))
    ll = ipaddress.ip_address("fe80::5054:ff:fed6:6d52").packed
    assert m.ipv6(ll)[:2] == b"\xfe\x80" and m.ipv6(ll) != ll


def test_sids_and_guids():
    m = mapping.Mapper(KEY)
    sid = b"\x01\x05" + (5).to_bytes(6, "big") + struct.pack(
        "<5I", 21, 111, 222, 333, 1104)
    out = m.sid(sid)
    subs = struct.unpack_from("<5I", out, 8)
    assert subs[0] == 21 and subs[1:4] != (111, 222, 333)
    assert subs[4] >= 1000 and out == m.sid(sid)
    admins = b"\x01\x02" + (5).to_bytes(6, "big") + struct.pack("<2I", 32, 544)
    assert m.sid(admins) == admins
    g = bytes(range(16))
    assert m.guid(g) == m.guid(g) != g and m.guid(bytes(16)) == bytes(16)


# -- frames -------------------------------------------------------------------

def _frame(payload: bytes, seq: int = 1000, partial: bool = False) -> Packet:
    src, dst = "10.0.0.2", "10.0.0.1"
    data = mkpcap.ethernet_ipv4_tcp(b"\x02" * 6, b"\x04" * 6, src, dst,
                                    50000, 445, seq, 1, 0x18, payload)
    pkt = Packet(pcapio.Record(0, bytearray(data), len(data), 1))
    if partial:
        value = pkt._pseudo(True)
    else:
        value = pkt._tcp_sum(pkt.data[:pkt.payload_off],
                             bytes(pkt.data[pkt.payload_off:]))
    struct.pack_into(">H", pkt.data, pkt.csum_off, value)
    return pkt


def _tcp_ok(rec: pcapio.Record) -> bool:
    p = Packet(rec)
    n = p.payload_off - p.l4_off + p.l4_wire
    pseudo = p.src + p.dst + bytes([0, 6]) + n.to_bytes(2, "big")
    s = _sum16(pseudo, 0) + _sum16(bytes(p.data[p.l4_off:p.payload_end]), 0)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def test_a_cut_frame_is_split_where_a_pdu_starts():
    tail = b"\xaa" * 10
    pdu = b"\x00\x00\x00\x48" + b"\xfeSMB" + bytes(68)
    pkt = _frame(tail + pdu + b"\xbb" * 6)
    o = pkt.payload_off
    pkt.starts.append(o + 10)
    pkt.drop(o, o + 10)
    pkt.drop(o + 10 + len(pdu), pkt.payload_end)
    first, second = pkt.pieces()
    assert len(first.data) == o and first.wire == o + 10
    p2 = Packet(second)
    assert p2.seq == 1010 and p2.l4_wire == len(pdu) + 6
    assert bytes(p2.data[p2.payload_off:]) == pdu
    assert struct.unpack_from(">H", first.data, 14 + 2)[0] == 20 + 20 + 10


def test_complete_pieces_get_valid_checksums():
    pdu = b"\x00\x00\x00\x48" + b"\xfeSMB" + bytes(68)
    pkt = _frame(b"\xaa" * 10 + pdu)
    o = pkt.payload_off
    pkt.starts.append(o + 10)
    pkt.drop(o, o + 10)
    _, second = pkt.pieces()
    assert _tcp_ok(second)


def test_partial_checksums_stay_partial():
    pkt = _frame(b"\x00\x00\x00\x04\xfeSMB", partial=True)
    m = mapping.Mapper(KEY)
    pkt.set_addrs(m.ip(pkt.src), m.ip(pkt.dst))
    pkt.edit(pkt.payload_off + 4, b"\xffSMB")
    pkt.finish()
    assert struct.unpack_from(">H", pkt.data, pkt.csum_off)[0] == \
        pkt._pseudo(True)
    full = _frame(b"\x00\x00\x00\x04\xfeSMB")
    full.set_addrs(m.ip(full.src), m.ip(full.dst))
    full.edit(full.payload_off + 4, b"\xffSMB")
    full.finish()
    assert _tcp_ok(full.rec)


# -- trimming and anonymizing ------------------------------------------------

@needs_tshark
def test_trim_keeps_every_request_and_its_latency(synth, tmp_path):
    path, _ = synth
    out = str(tmp_path / "t.pcap")
    sanitize.rewrite(path, out, sanitize.make_engine(None))
    assert os.path.getsize(out) < os.path.getsize(path) / 2
    a, b = by_request(load(path)), by_request(load(out))
    assert a.keys() == b.keys()
    for k, x in a.items():
        y = b[k]
        assert y.status == x.status, k
        if x.latency is not None:
            assert abs(y.latency - x.latency) <= 1000, (k, x.latency,
                                                        y.latency)
    assert b[next(k for k in b if k[2] == "WRITE")].nbytes == 65536


def _compounds(path: str) -> tuple[int, int]:
    """A listing ending a compound, padded to 8 as Samba sends it, and a
    READ inside one; both responses span segments. Returns the listing
    response's sequence range."""
    M = mkpcap
    pcap = M.Pcap()
    c = M.Conn(pcap, "10.0.0.2", "10.0.0.1", 50002)
    t = 1_700_000_000 * 1_000_000_000
    c.handshake(t, t + 20 * M.US, t + 40 * M.US)
    fid = bytes(range(16))
    req = M.compound([
        M.header(M.CREATE, 1) + M.create_req("dir", options=0x21),
        M.header(M.QUERY_DIRECTORY, 2, flags=M.F_RELATED)
        + M.find_req(M.ALL_ONES_FID, "*")])
    listing = M.header(M.QUERY_DIRECTORY, 2, resp=True, flags=M.F_RELATED) \
        + M.buffer_resp(M.dir_entries([f"e{i:02d}" for i in range(60)]))
    assert len(listing) % 8
    resp = M.compound([M.header(M.CREATE, 1, resp=True)
                       + M.create_resp(fid, attrs=0x10),
                       listing.ljust((len(listing) + 7) & ~7, b"\0")])
    c.send(True, M.nbss(req), t + M.MS)
    start = c.seq[False]
    c.send(False, M.nbss(resp), t + 3 * M.MS)
    span = start, c.seq[False]
    req = M.compound([
        M.header(M.CREATE, 3) + M.create_req("f.txt"),
        M.header(M.READ, 4, flags=M.F_RELATED)
        + M.read_req(M.ALL_ONES_FID, 0, 4000),
        M.header(M.CLOSE, 5, flags=M.F_RELATED) + M.close_req(M.ALL_ONES_FID)])
    resp = M.compound([
        M.header(M.CREATE, 3, resp=True) + M.create_resp(fid),
        M.header(M.READ, 4, resp=True, flags=M.F_RELATED)
        + M.read_resp(bytes(range(200)) * 20),
        M.header(M.CLOSE, 5, resp=True, flags=M.F_RELATED) + M.close_resp()])
    c.send(True, M.nbss(req), t + 10 * M.MS)
    c.send(False, M.nbss(resp), t + 12 * M.MS)
    c.send(True, M.nbss(M.header(M.ECHO, 6) + M.small_resp(4)), t + 20 * M.MS)
    c.send(False, M.nbss(M.header(M.ECHO, 6, resp=True) + M.small_resp(4)),
           t + 21 * M.MS)
    pcap.write(path)
    return span


@needs_tshark
def test_trim_cuts_compound_tails_and_keeps_what_follows_data(tmp_path):
    path, out = str(tmp_path / "c.pcap"), str(tmp_path / "c.trim.pcap")
    lo, hi = _compounds(path)
    sanitize.rewrite(path, out, sanitize.make_engine(None))
    a, b = by_request(load(path)), by_request(load(out))
    assert a.keys() == b.keys() and len(a) == 6
    for k, x in a.items():
        assert b[k].status == x.status, k
        assert abs(b[k].latency - x.latency) <= 1000, (k, x.latency,
                                                       b[k].latency)
    # The padding after the listing goes with it, so every segment after
    # the first is cut and the analysis sees the one holding the end.
    tail = [p for p in map(Packet, records(out))
            if p.sport == 445 and lo < p.seq < hi]
    assert len(tail) == 3 and all(p.captured == 0 for p in tail)


@needs_tshark
def test_zeroed_trim_keeps_frame_sizes(synth, tmp_path):
    path, _ = synth
    out = str(tmp_path / "z.pcap")
    sanitize.rewrite(path, out, sanitize.make_engine(None, zero=True))
    assert [r.wire for r in records(out)] == [r.wire for r in records(path)]
    assert by_request(load(out)).keys() == by_request(load(path)).keys()


@needs_tshark
def test_anonymize_hides_names_and_addresses(synth, tmp_path):
    path, exp = synth
    out = str(tmp_path / "a.pcap")
    m = mapping.Mapper(KEY)
    st = sanitize.rewrite(path, out, sanitize.make_engine(m))
    assert st.pdus > 0
    data = open(out, "rb").read()
    for s in SECRETS:
        assert s.encode("utf-16-le") not in data, s
        assert s.encode("utf-8") not in data, s
    for ip in exp["clients"] + [exp["server"]]:
        assert ipaddress.ip_address(ip).packed not in data, ip
    a, b = load(path), load(out)
    assert {(k[0], k[1], k[2]) for k in by_request(a)} == \
        {(k[0], k[1], k[2]) for k in by_request(b)}
    users = {x.user for x in b.exchanges}
    assert m.user("LAB\\alice") in users and "LAB\\alice" not in users
    files = {x.file for x in b.exchanges}
    assert m.path("dir\\file.txt") in files
    assert m.path(exp["weird_name"]) in files
    assert all(Packet(r).is_tcp for r in records(out))


@needs_tshark
def test_anonymize_with_one_key_is_repeatable(synth, tmp_path):
    path, _ = synth
    outs = []
    for i in range(2):
        out = str(tmp_path / f"r{i}.pcap")
        sanitize.rewrite(path, out,
                         sanitize.make_engine(mapping.Mapper(KEY)))
        outs.append(open(out, "rb").read())
    assert outs[0] == outs[1]


@needs_tshark
def test_rotated_files_pair_across_the_boundary(synth, tmp_path):
    path, _ = synth
    recs = records(path)
    half = len(recs) // 2
    parts = []
    for i, chunk in enumerate((recs[:half], recs[half:])):
        p = str(tmp_path / f"part{i}.pcap")
        with open(p, "wb") as f:
            w = pcapio.Writer(f, chunk[0].link)
            for r in chunk:
                w.write(r)
        parts.append(p)
    engine = sanitize.make_engine(None)
    outs = []
    for i, p in enumerate(parts):
        o = str(tmp_path / f"out{i}.pcap")
        sanitize.rewrite(p, o, engine)
        outs.append(o)
    whole = load(path)
    split = load(*outs)
    assert len(split.orphans) == len(whole.orphans)
    answered = sum(1 for x in whole.exchanges if x.resp is not None)
    assert sum(1 for x in split.exchanges if x.resp is not None) >= \
        answered - 1


def test_cli_names_outputs(synth, tmp_path):
    path, _ = synth
    shutil.copy(path, tmp_path / "x.pcap")
    rc = sanitize.main_trim(["-q", str(tmp_path / "x.pcap")])
    assert rc == 0 and (tmp_path / "x.trim.pcap").exists()
    rc = sanitize.main_anonymize(["-q", str(tmp_path / "x.pcap"), "-o",
                                  str(tmp_path / "anon.pcap.gz"), "--map",
                                  str(tmp_path / "map.json"), "--key",
                                  str(tmp_path / "key")])
    assert rc == 0
    assert open(tmp_path / "anon.pcap.gz", "rb").read(2) == b"\x1f\x8b"
    assert oct(os.stat(tmp_path / "key").st_mode & 0o777) == "0o600"
    assert "alice" in (tmp_path / "map.json").read_text()


# -- capturing -----------------------------------------------------------------

def test_rotated_file_names_are_ordered(tmp_path):
    for n in ("lo.pcap", "lo.pcap1", "lo.pcap10", "lo.pcap2", "eth0.pcap",
              "lo.log"):
        (tmp_path / n).write_bytes(b"")
    seqs = capture.Tcpdump.files(str(tmp_path))
    assert [s for s, _ in seqs["lo"]] == [1, 2, 3, 11]
    assert list(seqs) == ["lo", "eth0"] or set(seqs) == {"lo", "eth0"}
    for n in ("all_00002_20261012101010.pcapng",
              "all_00001_20261012101000.pcapng"):
        (tmp_path / n).write_bytes(b"")
    assert [s for s, _ in capture.Dumpcap.files(str(tmp_path))["all"]] == \
        [1, 2]


def test_filters_durations_and_stats():
    assert capture.build_filter([139, 445], ["10.0.0.5"], False) == \
        "(tcp port 139 or tcp port 445) and (host 10.0.0.5)"
    assert "vlan and" in capture.build_filter([445], [], True)
    assert capture.parse_duration("1h30m") == 5400
    assert capture.parse_duration("250ms") == 0.25
    with pytest.raises(ValueError):
        capture.parse_duration("ten minutes")
    log = ("12 packets captured\n14 packets received by filter\n"
           "2 packets dropped by kernel\n")
    assert capture.Tcpdump.stats(log)["dropped_by_kernel"] == 2
    m = mapping.Mapper(KEY)
    flt = capture._anon_filter("tcp port 445 and (host 10.1.2.3)", m)
    assert "10.1.2.3" not in flt and flt.startswith("tcp port 445")


@needs_tshark
def test_pipeline_trims_finished_files(synth, tmp_path):
    path, _ = synth
    raw = tmp_path / ".raw"
    raw.mkdir()
    shutil.copy(path, raw / "lo.pcap")
    p = capture.Pipeline(str(tmp_path), "headers", None, True, 0, [445])
    for seq, f in capture.Tcpdump.files(str(raw))["lo"]:
        p.submit("lo", seq, f)
    p.finish()
    assert p.error is None and not (raw / "lo.pcap").exists()
    out = tmp_path / "lo-00001.pcap.gz"
    assert out.exists() and p.files[0]["pdus"] > 0


@pytest.mark.skipif(not (shutil.which("tcpdump") or shutil.which("dumpcap")),
                    reason="no capture program")
def test_dry_run_prints_the_command():
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = capture.main(["--dry-run", "-i", "lo", "--headers", "--host",
                           "10.0.0.5", "-o", "/nonexistent/out"])
    assert rc == 0
    text = buf.getvalue()
    assert "host 10.0.0.5" in text and "/nonexistent/out/.raw/" in text


# -- authentication and handlers ---------------------------------------------

def _der(tag: int, *content: bytes) -> bytes:
    body = b"".join(content)
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(nb)]) + nb + body


def _krb_spnego(cipher: bytes) -> bytes:
    gstr = lambda s: _der(0x1B, s.encode())  # noqa: E731
    integer = lambda v: _der(0x02, bytes([v]))  # noqa: E731
    enc = _der(0x30, _der(0xA0, integer(18)), _der(0xA2, _der(0x04, cipher)))
    ticket = _der(0x61, _der(0x30,
        _der(0xA0, integer(5)), _der(0xA1, gstr("CORP.EXAMPLE.COM")),
        _der(0xA2, _der(0x30, _der(0xA0, integer(2)), _der(0xA1, _der(
            0x30, gstr("cifs"), gstr("fs1.corp.example.com"))))),
        _der(0xA3, enc)))
    ap_req = _der(0x6E, _der(0x30, _der(0xA0, integer(5)),
                             _der(0xA1, integer(14)),
                             _der(0xA2, _der(0x03, b"\x00\x20\x00\x00\x00")),
                             _der(0xA3, ticket), _der(0xA4, enc)))
    krb_oid = _der(0x06, bytes.fromhex("2a864886f712010202"))
    gss = _der(0x60, krb_oid, b"\x01\x00", ap_req)
    spnego_oid = _der(0x06, bytes.fromhex("2b0601050502"))
    return _der(0x60, spnego_oid, _der(0xA0, _der(0x30, _der(
        0xA0, _der(0x30, krb_oid)), _der(0xA2, _der(0x04, gss)))))


def test_kerberos_names_are_replaced_and_tickets_zeroed():
    from smbdump import gss
    cipher = bytes(range(200, 256)) * 3
    blob = _krb_spnego(cipher)
    m = mapping.Mapper(KEY)
    out = gss.sanitize_blob(blob, m)
    assert len(out) == len(blob)
    assert b"CORP" not in out and b"fs1" not in out and b"cifs" in out
    assert m.name("CORP.EXAMPLE.COM").encode() in out
    assert m.name("fs1.corp.example.com").encode() in out
    assert cipher[:16] not in out
    assert bytes.fromhex("2a864886f712010202") in out  # mechanisms stay
    assert gss._der(out, 0, len(out), bytearray(len(out)), m)


def test_tree_connect_extension_path():
    from smbdump import engine, smb2
    path = "\\\\fs1\\finance".encode("utf-16-le")
    hdr = bytearray(64)
    hdr[0:4] = b"\xfeSMB"
    struct.pack_into("<HH", hdr, 4, 64, 0)
    struct.pack_into("<H", hdr, 12, smb2.TREE_CONNECT)
    body = struct.pack("<HHHH", 9, 4, 64 + 8, len(path))
    ext = struct.pack("<IH10x", 16 + len(path), 0)
    msg = bytes(hdr) + body + ext + path
    buf = len(msg).to_bytes(4, "big") + msg
    m = mapping.Mapper(KEY)
    e = engine.Edit(buf, deny=True)
    smb2.Handlers(m).handle(e, engine.Conn())
    out = bytes(e.out)
    assert "finance".encode("utf-16-le") not in out
    assert m.unc("\\\\fs1\\finance").encode("utf-16-le") == out[-len(path):]
