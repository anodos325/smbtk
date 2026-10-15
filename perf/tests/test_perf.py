"""Tests on synthetic perf script output; live ones need root and perf."""

from __future__ import annotations

import io
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from smbperf import (  # noqa: E402
    cmd_compare, cmd_flame, cmd_fold, cmd_record, cmd_stat, cmd_top, fmt,
    perfdata, smbd, stacks,
)
from smbperf.flame import Diff, render_svg, render_tree  # noqa: E402
from smbperf.perfdata import INLINE, KERNEL, MODULE  # noqa: E402
from smbperf.stacks import LOOP, Selection  # noqa: E402


# -- synthetic perf script output --------------------------------------------

def K(sym):
    return ("ffffffff81000100", sym, "[kernel.kallsyms]")


def M(sym):
    return ("ffffffffc1000100", sym, "[kernel.kallsyms]")


def U(sym, lib="libsmbd-base-private-samba.so"):
    return ("7f0000001000", sym, f"/usr/lib/{lib}")


def I(sym):  # noqa: E743
    return ("7f0000001000", sym, "inlined")


# The connection's loop, leaf first, from the handler it ran to _start.
LOOP_FULL = [
    U("tevent_common_invoke_fd_handler", "libtevent.so.0"),
    U("epoll_event_loop_once", "libtevent.so.0"),
    U("std_event_loop_once", "libtevent.so.0"),
    U("_tevent_loop_once", "libtevent.so.0"),
    U("tevent_common_loop_wait", "libtevent.so.0"),
    U("std_event_loop_wait", "libtevent.so.0"),
    U("smbd_process"),
    U("smbd_accept_connection", "smbd"),
    U("tevent_common_invoke_fd_handler", "libtevent.so.0"),
    U("epoll_event_loop_once", "libtevent.so.0"),
    U("std_event_loop_once", "libtevent.so.0"),
    U("_tevent_loop_once", "libtevent.so.0"),
    U("tevent_common_loop_wait", "libtevent.so.0"),
    U("std_event_loop_wait", "libtevent.so.0"),
    U("smbd_parent_loop", "smbd"),
    U("main", "smbd"),
    U("__libc_start_call_main", "libc.so.6"),
    U("_start", "smbd"),
]
# What perf keeps of it when the stack copy runs out first.
LOOP_CUT = LOOP_FULL[:6]

READ_SEND = [
    K("memcpy_orig"), K("tcp_sendmsg"), K("entry_SYSCALL_64_after_hwframe"),
    U("__libc_sendmsg", "libc.so.6"), U("smbd_smb2_flush_with_sendmsg"),
    I("smbd_smb2_request_reply"), U("smbd_smb2_request_done_ex"),
    U("smbd_smb2_request_read_done"),
    U("smbd_smb2_request_dispatch_immediate"),
]
CREATE = [
    M("zfs_dirlook"), K("do_syscall_64"), U("__GI___openat64", "libc.so.6"),
    U("fd_openat"), U("open_file_ntcreate"), U("create_file_unixpath"),
    U("smbd_smb2_create_send"), U("smbd_smb2_request_process_create"),
    U("smbd_smb2_request_dispatch"), U("smbd_smb2_io_handler"),
    U("smbd_smb2_connection_handler"),
]
WORKER = [K("memcpy_orig"), M("arc_read"), K("io_read"), K("io_issue_sqe"),
          K("io_wq_worker"), K("ret_from_fork_asm")]
IDLE = [K("do_epoll_wait"), K("entry_SYSCALL_64_after_hwframe"),
        U("epoll_wait", "libc.so.6")] + LOOP_FULL[1:]

HEADER = """# ========
# captured on    : Tue Oct 13 01:30:38 2026
# hostname : testhost
# cmdline : /usr/bin/perf record -k monotonic -F 999 -g -p 100
# reference time: 2026-10-13 01:30:38.000000 = 1791855038.000000 (TOD) \
= 1000.000000000 (monotonic)
# ========
"""


def sample(comm, pid, tid, t, period, event, frames, trace=""):
    out = [f"{comm} {pid}/{tid} {t:.9f}: {period:>10} {event}: {trace}"]
    for addr, sym, dso in frames:
        out.append(f"\t{addr:>16} {sym} ({dso})")
    return "\n".join(out) + "\n\n"


def cpu_script() -> str:
    c = "smbd[10.0.0.1]"
    return HEADER + "".join([
        sample(c, 100, 100, 1000.1, 3000, "cycles:P", READ_SEND + LOOP_FULL),
        sample(c, 100, 100, 1000.2, 2000, "cycles:P", CREATE + LOOP_CUT),
        sample(c, 100, 100, 1000.3, 1000, "cycles:P", CREATE + LOOP_FULL),
        sample("iou-wrk-100", 100, 101, 1000.4, 4000, "cycles:P", WORKER),
        sample(c, 100, 100, 1000.5, 500, "cycles:P", IDLE),
        sample("bash", 200, 200, 1000.6, 700, "cycles:P",
               [U("main", "bash")]),
        sample(c, 100, 100, 1000.7, 300, "cycles:P",
               [U("[unknown]", "libtalloc.so.2"),
                U("talloc_free", "libtalloc.so.2")]),
        sample(c, 100, 100, 1000.8, 9999, "instructions:P",
               READ_SEND + LOOP_FULL),
    ])


def fold(text, **kw) -> stacks.Stacks:
    prof = perfdata.parse(io.StringIO(text))
    return stacks.fold(prof, Selection(**kw))


def lines(st: stacks.Stacks) -> dict[str, int]:
    return {";".join(s): w for s, w in st.weights.items()}


# -- parsing -------------------------------------------------------------------

def test_parse_frames_kinds_and_header():
    prof = perfdata.parse(io.StringIO(cpu_script()))
    assert len(prof.samples) == 8
    assert prof.events == ["cycles:P", "instructions:P"]
    kinds = {name: kind for name, _, kind in prof.frames}
    assert kinds["memcpy_orig"] == KERNEL
    assert kinds["zfs_dirlook"] == KERNEL | MODULE
    assert kinds["smbd_smb2_request_reply"] == INLINE
    assert kinds["fd_openat"] == 0
    assert "[libtalloc.so.2]" in kinds
    h = prof.header
    assert h["hostname"] == "testhost"
    assert h["tod_offset_ns"] == (1791855038 - 1000) * 10**9


def test_parse_padded_names_without_callchains_and_offsets():
    text = ("         python3 1524339/1524339 386083.771393:     500500 "
            "cycles:P: \n"
            "         python3 1524339/1524339 386083.772393:     400000 "
            "cycles:P: \n"
            "a b 7/8 1.5:      1 cycles:P: \n"
            "\t    7f0d9dfc9a70 __vsnprintf_internal+0x10 (/lib/libc.so.6)\n"
            "\t    559b1354814f [unknown] ([heap])\n"
            "\t    559b1354814f Foo::bar(int) const (/lib/x.so)\n\n")
    prof = perfdata.parse(io.StringIO(text))
    assert [prof.comms[s[3]] for s in prof.samples] == \
        ["python3", "python3", "a b"]
    st = stacks.fold(prof, Selection(root="comm"))
    assert lines(st) == {"python3": 900500,
                         "a_b;Foo::bar;[[heap]];__vsnprintf_internal": 1}


def test_fold_as_stackcollapse_with_comm_roots():
    st = fold(cpu_script(), root="comm")
    got = lines(st)
    worker = ("iou-wrk-100;ret_from_fork_asm_[k];io_wq_worker_[k];"
              "io_issue_sqe_[k];io_read_[k];arc_read_[k];memcpy_orig_[k]")
    assert got[worker] == 4000
    assert got["bash;main"] == 700
    assert got["smbd[10.0.0.1];talloc_free;[libtalloc.so.2]"] == 300
    assert sum(got.values()) == 3000 + 2000 + 1000 + 4000 + 500 + 700 + 300
    assert st.unit == "cycles"


def test_fold_roots_events_and_filters():
    st = fold(cpu_script())
    roots = {s[:2] if s[1] == "iou-wrk" else s[:1] for s in st.weights}
    assert roots == {("smbd[10.0.0.1]",), ("smbd[10.0.0.1]", "iou-wrk"),
                     ("bash",)}
    st = fold(cpu_script(), root="role", names={100: "smbd[10.0.0.1]"})
    assert {s[0] for s in st.weights} == {"smbd[client]", "bash"}
    st = fold(cpu_script(), event="instructions:P")
    assert st.total() == 9999 and st.unit == "instructions"
    assert fold(cpu_script(), comms=["bash"]).total() == 700
    assert fold(cpu_script(), tids=[101]).total() == 4000
    assert fold(cpu_script(), clients=["10.0.0.1"]).total() == 10800
    with pytest.raises(ValueError):
        fold(cpu_script(), clients=["10.9.9.9"])
    assert fold(cpu_script(), count_samples=True).total() == 7
    user = fold(cpu_script(), user_only=True, root="none")
    assert not any(f.endswith("_[k]") for s in user.weights for f in s)
    no_inline = fold(cpu_script(), inline=False)
    assert not any("smbd_smb2_request_reply" in s
                   for s in no_inline.weights)
    plain = fold(cpu_script(), kernel_mark=False, root="none")
    assert ("memcpy_orig",) in {s[-1:] for s in plain.weights}


def test_time_window_relative_and_wall_clock():
    prof = perfdata.parse(io.StringIO(cpu_script()))
    first = min(s[0] for s in prof.samples)
    off = prof.header["tod_offset_ns"]
    a = fmt.parse_when("0.15", first, off)
    b = fmt.parse_when("@1791855038.45", first, off)
    assert b == 1000_450_000_000
    st = stacks.fold(prof, Selection(t_from=a, t_to=b))
    assert st.total() == 1000 + 4000
    c = fmt.parse_when("2026-10-13T01:30:38.25Z", first, off)
    d = fmt.parse_when("01:30:38.25", first, off)
    assert c == d == 1000_250_000_000
    with pytest.raises(ValueError):
        fmt.parse_when("01:30:38", first, None)


# -- off-CPU and system calls -------------------------------------------------

def switch(comm, pid, tid, t, direction):
    return f"{comm} {pid}/{tid} {t:.9f}: PERF_RECORD_SWITCH {direction}\n"


def off_script() -> str:
    c = "smbd[10.0.0.1]"
    sched = [K("__traceiter_sched_switch"), K("__schedule"), K("schedule")]

    def out(t, state, frames, comm=c, tid=100):
        return sample(comm, 100, tid, t, 1, "sched:sched_switch",
                      sched + frames,
                      f"prev_comm={comm} prev_pid=9{tid} prev_prio=120 "
                      f"prev_state={state} ==> next_comm=swapper/1 "
                      "next_pid=0 next_prio=120")

    wait = [K("schedule_hrtimeout_range_clock"), K("do_epoll_wait"),
            U("epoll_wait", "libc.so.6")] + LOOP_FULL[1:]
    lock = [K("io_schedule"), K("zfs_rangelock_enter"), U("pread", "libc.so.6"),
            U("vfswrap_pread"), U("smbd_smb2_request_process_read")] \
        + LOOP_FULL
    return "".join([
        out(2000.000, "S", wait),
        switch(c, 100, 100, 2000.00001, "OUT"),
        out(2000.001, "S", [K("schedule_timeout"), K("io_wq_worker")],
            "iou-wrk-100", 101),
        switch(c, 100, 100, 2000.003, "IN"),
        out(2000.004, "R+", [K("exit_to_user_mode_loop")]),
        switch(c, 100, 100, 2000.0045, "IN"),
        out(2000.005, "D", lock),
        switch(c, 100, 100, 2000.007, "IN"),
        switch("iou-wrk-100", 100, 101, 2000.009, "IN"),
        out(2000.008, "S", wait),
    ])


def test_off_cpu_time_from_switch_records():
    st = stacks.cut_loop(fold(off_script()))
    assert st.what == "off-CPU" and st.unit == "ns"
    got = lines(st)
    epoll = ("smbd[10.0.0.1];[event loop];epoll_wait;do_epoll_wait_[k];"
             "schedule_hrtimeout_range_clock_[k]")
    assert got[epoll] == 3_000_000
    assert got["smbd[10.0.0.1];exit_to_user_mode_loop_[k];[preempted]"] \
        == 500_000
    read = [k for k in got if k.endswith("[uninterruptible]")]
    assert len(read) == 1 and got[read[0]] == 2_000_000
    assert "smbd_smb2_request_process_read" in read[0]
    assert got["smbd[10.0.0.1];iou-wrk;io_wq_worker_[k];"
               "schedule_timeout_[k]"] == 8_000_000
    assert st.notes and "1 switches out" in st.notes[0]
    prof = perfdata.parse(io.StringIO(off_script()))
    clipped = stacks.fold(prof, Selection(t_from=2000_002_000_000))
    assert clipped.total() == 1_000_000 + 500_000 + 2_000_000 + 7_000_000


def test_off_cpu_preempted_from_switch_records_without_tracepoint_text():
    """perf built without libtraceevent prints no sched_switch fields;
    its switch-out records still say whether the thread was preempted."""
    c = "smbd[10.0.0.1]"
    sched = [K("__traceiter_sched_switch"), K("__schedule"), K("schedule")]

    def out(t, frames):
        return sample(c, 100, 100, t, 1, "sched:sched_switch", sched + frames)

    def wide(t, direction):
        return (f"{c} 100/100 {t:.9f}: PERF_RECORD_SWITCH_CPU_WIDE "
                f"{direction}  {'prev' if direction == 'IN' else 'next'} "
                "pid/tid:   200/200\n")

    sleep = [K("do_nanosleep")]
    text = "".join([
        out(2000.000, [K("exit_to_user_mode_loop")]),
        switch(c, 100, 100, 2000.00001, "OUT preempt"),
        switch(c, 100, 100, 2000.0005, "IN"),
        out(2000.001, [K("do_epoll_wait"), U("epoll_wait", "libc.so.6")]),
        switch(c, 100, 100, 2000.00101, "OUT"),
        switch(c, 100, 100, 2000.003, "IN"),
        out(2000.004, sleep),               # its switch-out record was lost
        switch(c, 100, 100, 2000.005, "IN"),
        out(2000.006, sleep),
        wide(2000.00601, "OUT preempt"),
        wide(2000.007, "IN"),
        out(2000.008, sleep),
        wide(2000.00801, "OUT"),
        wide(2000.009, "IN"),
    ])
    assert lines(fold(text)) == {
        "smbd[10.0.0.1];exit_to_user_mode_loop_[k];[preempted]": 500_000,
        "smbd[10.0.0.1];epoll_wait;do_epoll_wait_[k]": 2_000_000,
        "smbd[10.0.0.1];do_nanosleep_[k]": 2_000_000,
        "smbd[10.0.0.1];do_nanosleep_[k];[preempted]": 1_000_000,
    }


def test_off_cpu_without_switch_records_uses_next_pid():
    text = "".join(
        sample("t", 5, 5, t, 1, "sched:sched_switch",
               [K("schedule"), K("do_nanosleep")],
               f"prev_comm=t prev_pid={p} prev_prio=120 prev_state=S ==> "
               f"next_comm=x next_pid={n} next_prio=120")
        for t, p, n in ((1.0, 5, 6), (1.5, 6, 5)))
    st = fold(text, root="none")
    assert lines(st) == {"do_nanosleep_[k]": 500_000_000}


def test_syscalls_named_with_kernel_frames_dropped():
    text = sample("smbd[10.0.0.1]", 100, 100, 3000.0, 1,
                  "raw_syscalls:sys_enter",
                  [K("syscall_trace_enter"), K("do_syscall_64"),
                   U("__GI___openat64", "libc.so.6"), U("fd_openat"),
                   U("smbd_smb2_request_process_create")] + LOOP_FULL,
                  "NR 257 (ffffff9c, 7ffd, 0, 0, 0, 0)")
    text += sample("smbd[10.0.0.1]", 100, 100, 3000.1, 1,
                   "raw_syscalls:sys_enter", [U("x")], "NR 9999 (0)")
    st = stacks.cut_loop(fold(text))
    assert st.unit == "calls"
    assert lines(st) == {
        "smbd[10.0.0.1];[event loop];smbd_smb2_request_process_create;"
        "fd_openat;__GI___openat64;openat()": 1,
        "smbd[10.0.0.1];x;syscall 9999()": 1}


# -- stacks ----------------------------------------------------------------------

def test_cut_loop_lines_up_truncated_and_whole_stacks():
    st = stacks.cut_loop(fold(cpu_script()))
    got = lines(st)
    create = [k for k in got if "smbd_smb2_request_process_create" in k]
    assert len(create) == 1 and got[create[0]] == 3000
    assert create[0].startswith("smbd[10.0.0.1];[event loop];"
                                "smbd_smb2_connection_handler;")
    idle = [k for k in got if k.endswith("do_epoll_wait_[k]")]
    assert idle == ["smbd[10.0.0.1];[event loop];epoll_wait;"
                    "entry_SYSCALL_64_after_hwframe_[k];do_epoll_wait_[k]"]
    nested = ("p", "smbd_process", "std_event_loop_wait",
              "tevent_common_invoke_fd_handler", "handler", "tevent_req_poll",
              "_tevent_loop_once", "tevent_common_invoke_fd_handler", "inner")
    st2 = stacks.Stacks()
    st2.add(nested, 1)
    assert list(stacks.cut_loop(st2).weights) == [
        ("p", LOOP, "handler", "tevent_req_poll", "_tevent_loop_once",
         "tevent_common_invoke_fd_handler", "inner")]


def test_folded_round_trip_and_detection(tmp_path):
    st = stacks.cut_loop(fold(cpu_script()))
    buf = io.StringIO()
    stacks.write_folded(st, buf)
    text = buf.getvalue()
    assert stacks.looks_folded(text.splitlines(True))
    assert not stacks.looks_folded(cpu_script().splitlines(True))
    back = stacks.read_folded(io.StringIO(text))
    assert lines(back) == lines(st)
    assert back.kind("memcpy_orig_[k]") == KERNEL
    assert lines(stacks.cut_loop(back)) == lines(st)


def test_grep_exclude_focus_reverse():
    st = stacks.cut_loop(fold(cpu_script()))
    assert stacks.grep(st, "zfs_dirlook").total() == 3000
    assert stacks.grep(st, "zfs_", keep=False).total() == 11500 - 3000
    f = stacks.focus(st, "smbd_smb2_request_process_create")
    assert {s[0] for s in f.weights} == {"smbd_smb2_request_process_create"}
    r = stacks.reverse(st)
    assert all(s[-1] in ("smbd[10.0.0.1]", "iou-wrk", "bash")
               for s in r.weights)


# -- smbd ------------------------------------------------------------------------

def test_frame_commands():
    cases = {
        "smbd_smb2_request_process_create": "CREATE",
        "smbd_smb2_request_create_done": "CREATE",
        "smbd_smb2_request_find_done": "QUERY_DIRECTORY",
        "smb2_query_directory_next_entry": "QUERY_DIRECTORY",
        "smbd_smb2_request_process_getinfo": "QUERY_INFO",
        "smbd_smb2_setinfo_rename_dst_delay_done": "SET_INFO",
        "smbd_smb2_ioctl_pipe_read_done": "IOCTL",
        "smb2_ioctl_network_fs_copychunk_done": "IOCTL",
        "smbd_smb2_read_pipe_done": "READ",
        "smbd_smb2_request_process_tdis": "TREE_DISCONNECT",
        "smbd_smb2_tree_connect_send": "TREE_CONNECT",
        "smbd_smb2_session_setup_wrap_send": "SESSION_SETUP",
        "smbd_smb2_auth_generic_return": "SESSION_SETUP",
        "smb2_multi_protocol_reply_negprot": "NEGOTIATE",
        "smbd_smb2_request_lease_break_done": "OPLOCK_BREAK",
        "smbd_smb2_request_process_keepalive": "ECHO",
        "smbd_smb2_notify_reply": "CHANGE_NOTIFY",
        "vfs_io_uring_pwrite_completion": "WRITE",
        "smbd_smb2_flush_send_queue": None,
        "smbd_smb2_flush_with_sendmsg": None,
        "smbd_smb2_request_dispatch": None,
        "smb2_signing_sign_pdu": None,
        "smb2_lease_push": None,
    }
    for name, cmd in cases.items():
        assert smbd.frame_command(name) == cmd, name


def test_command_split():
    st = stacks.cut_loop(fold(cpu_script()))
    ops = {}
    for s, w in st.weights.items():
        op = smbd.command(s)
        ops[op] = ops.get(op, 0) + w
    assert ops == {"READ": 3000, "CREATE": 3000,
                   "READ (io_uring worker)": 4000, "event loop": 500,
                   "not smbd": 700, "incomplete stack": 300}
    assert smbd.command(("smbd[1.2.3.4]", "_start", "main", "init")) == \
        "other"


def test_client_from_process_name():
    assert stacks.serves("smbd[10.0.0.1]", "10.0.0.1")
    assert not stacks.serves("smbd[10.0.0.12]", "10.0.0.1")
    assert stacks.serves("smbd[192.168.10", "192.168.100.200")
    assert not stacks.serves("smbd[192.168.10", "192.168.1.2")
    assert stacks.serves("smbd[10.0.0.1,10.0.0.2]", "10.0.0.2")


def test_clients_of_a_process(tmp_path):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    cli = socket.create_connection(("127.0.0.1", port))
    conn, peer = srv.accept()
    try:
        got = smbd.clients([os.getpid()], ports=[port])
        assert got[os.getpid()] == [f"127.0.0.1:{peer[1]}"]
        assert smbd.host_of(got[os.getpid()][0]) == "127.0.0.1"
        assert smbd.host_of("[fe80::1]:445") == "fe80::1"
    finally:
        for s in (conn, cli, srv):
            s.close()


# -- rendering -------------------------------------------------------------------

def test_svg_is_well_formed_with_frames_and_details():
    st = stacks.cut_loop(fold(cpu_script()))
    svg = render_svg(stacks.tree(st), st, "title <&>", "sub")
    root = ET.fromstring(svg)
    ns = "{http://www.w3.org/2000/svg}"
    frames = root.findall(f".//{ns}g")
    names = {g.get("data-n") for g in frames}
    assert {"all", "smbd[10.0.0.1]", "[event loop]", "memcpy_orig_[k]",
            "zfs_dirlook_[k]"} <= names
    titles = [g.find(f"{ns}title").text for g in frames]
    assert any(t.startswith("all: 11.50K") for t in titles)
    fills = {g.get("data-n"): g.find(f"{ns}rect").get("fill") for g in frames}
    assert fills["zfs_dirlook_[k]"] != fills["memcpy_orig_[k]"]


def test_diff_colors_and_tree():
    a = stacks.Stacks("cycles")
    a.add(("p", "f", "g"), 100)
    a.add(("p", "h"), 100)
    b = stacks.Stacks("cycles")
    b.add(("p", "f", "g"), 300)
    b.add(("p", "h"), 100)
    root = stacks.tree(b, a, b.total() / a.total())
    svg = render_svg(root, b, "t", diff=Diff(2.0, ("b", "a")))
    ns = "{http://www.w3.org/2000/svg}"
    fills = {g.get("data-n"): g.find(f"{ns}rect").get("fill")
             for g in ET.fromstring(svg).findall(f".//{ns}g")}
    assert fills["g"].startswith("rgb(255,") and fills["g"] != \
        "rgb(255,255,255)"
    assert fills["h"].endswith(",255)") and fills["h"] != "rgb(255,255,255)"
    assert fills["f"] == "rgb(255,255,255)"
    text = render_tree(root, "cycles", min_pct=0, diff=Diff(2.0, ("b", "a")))
    assert "a %" in text.splitlines()[0]
    g_line = next(ln for ln in text.splitlines() if ln.endswith("f > g"))
    assert "+25.00" in g_line
    plain = render_tree(stacks.tree(b), "cycles", min_pct=0)
    assert plain.splitlines()[1].endswith("all")


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_svg_zoom_and_search_in_javascript(tmp_path):
    st = stacks.cut_loop(fold(cpu_script()))
    path = tmp_path / "f.svg"
    path.write_text(render_svg(stacks.tree(st), st, "t"))
    res = subprocess.run(["node", os.path.join(HERE, "flame_js.js"),
                          str(path), "zfs_dirlook_[k]", "memcpy"],
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout)
    assert out["zoomed"] == [10.0, 1180.0]
    assert out["hidden"] > 0 and out["restored"]
    assert out["matched"] == f"Matched: {100 * 7000 / 11500:.2f}%"


# -- tools -------------------------------------------------------------------------

def run(main, *argv) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(list(argv)) == 0
    return buf.getvalue()


@pytest.fixture
def script_file(tmp_path):
    path = tmp_path / "perf.txt"
    path.write_text(cpu_script())
    return str(path)


def test_fold_tool(script_file, tmp_path):
    out = tmp_path / "x.folded"
    run(cmd_fold.main, script_file, "-o", str(out))
    got = stacks.read_folded(open(out))
    assert got.total() == 11500
    assert any(s[1] == LOOP for s in got.weights)
    text = run(cmd_fold.main, script_file, "--root", "comm", "--keep-loop",
               "--comm", "bash")
    assert text == "bash;main 700\n"


def test_top_tool_views(script_file, tmp_path):
    out = run(cmd_top.main, script_file, "--top", "5")
    assert out.splitlines()[0] == "11.50K cycles in 7 samples"
    assert "memcpy_orig_[k]" in out.splitlines()[3]
    ops = run(cmd_top.main, script_file, "--ops", "--per", "2:file")
    line = next(ln for ln in ops.splitlines()
                if ln.startswith("READ (io_uring worker)"))
    assert line.split()[-3:] == ["34.78", "4.00K", "2.00K"]
    req = tmp_path / "lat.json"
    req.write_text(json.dumps({"levels": ["cmd"], "groups": [
        {"key": ["CREATE"], "n": 3}, {"key": ["READ"], "n": 6}]}))
    ops = run(cmd_top.main, script_file, "--ops", "--requests", str(req))
    line = next(ln for ln in ops.splitlines() if ln.startswith("CREATE"))
    assert line.split()[-2:] == ["3", "1.00K"]
    below = run(cmd_top.main, script_file, "--below",
                "smbd_smb2_request_process_create", "--depth", "1")
    assert below.splitlines()[-1].split() == [
        "100.00", "3.00K", "smbd_smb2_create_send"]
    callers = run(cmd_top.main, script_file, "--callers", "memcpy_orig",
                  "--depth", "2")
    assert "arc_read_[k]" in callers and "tcp_sendmsg_[k]" in callers
    st = run(cmd_top.main, script_file, "--stacks", "2")
    assert "memcpy_orig_[k] <- arc_read_[k]" in st
    dso = run(cmd_top.main, script_file, "--dso")
    assert "kernel modules" in dso and "libtalloc.so.2" in dso
    proc = run(cmd_top.main, script_file, "--process")
    assert "iou-wrk" in proc and "bash" in proc
    js = json.loads(run(cmd_top.main, script_file, "--ops", "--json"))
    assert js["total"] == 11500 and js["unit"] == "cycles"


def test_diff_tools(script_file, tmp_path):
    base = tmp_path / "base.txt"
    base.write_text(cpu_script().replace(" 3000 cycles", " 1000 cycles"))
    out = run(cmd_top.main, script_file, "--diff", str(base), "--ops",
              "--absolute")
    read = next(ln for ln in out.splitlines() if ln.endswith(" READ"))
    assert "+200.0%" in read
    svg = tmp_path / "d.svg"
    run(cmd_flame.main, script_file, "--diff", str(base), "-o", str(svg))
    assert ET.parse(svg).getroot().tag.endswith("svg")
    tree = run(cmd_flame.main, script_file, "--diff", str(base), "--tree",
               "--min-pct", "5")
    assert "points" in tree.splitlines()[0]


def test_flame_tool_tree_and_files(script_file, tmp_path):
    out = run(cmd_flame.main, script_file, "--tree", "--min-pct", "10")
    assert out.splitlines()[1].split()[-1] == "all"
    assert "iou-wrk > ret_from_fork_asm_[k]" in out
    svg = tmp_path / "f.svg"
    run(cmd_flame.main, script_file, "-o", str(svg), "--icicle",
        "--reverse", "--client", "10.0.0.1")
    assert "bash" not in svg.read_text()


# -- counting -----------------------------------------------------------------------

STAT_CSV = """# started on Tue Oct 13 02:02:08 2026

smbd-100,780020536,,cycles,251637067,100.00,3.100,GHz
smbd-100,2689212437,,instructions,251655835,100.00,3.45,insn per cycle
smbd-100,251.65,msec,task-clock,251654392,100.00,1.000,CPUs utilized
iou-wrk-100-101,20000000,,cycles,251637067,100.00,,
iou-wrk-100-101,10.0,msec,task-clock,251654392,100.00,,
smbd-200,<not counted>,,cycles,0,100.00,,
"""


def test_stat_parsing_and_derived():
    rows = cmd_stat.parse_stat(STAT_CSV, interval=False, per_thread=True)
    tot = cmd_stat.totals(rows)
    assert tot["cycles"] == 800020536 and tot["task-clock"] == 261.65
    d = cmd_stat.derived(tot, 0.5)
    assert round(d["cpus"], 3) == 0.523 and round(d["ghz"], 2) == 3.06
    procs = cmd_stat._by_process(rows, {100: 100, 101: 100},
                                 {100: "smbd[10.0.0.1]"})
    assert procs[0]["process"] == "smbd[10.0.0.1] 100"
    assert procs[0]["cycles"] == 800020536
    iv = cmd_stat.parse_stat("0.100,5,,cycles,1,100,,\n0.200,7,,cycles,1,"
                             "100,,\n", interval=True, per_thread=False)
    assert cmd_stat._intervals(iv)[1] == {"t": 0.2, "seconds": 0.1,
                                          "cycles": 7.0}


def test_compare(tmp_path):
    paths = []
    for i, (label, wall, cycles) in enumerate(
            [("A", 10.0, 100e9), ("B", 8.0, 80e9), ("B", 8.2, 82e9),
             ("A", 10.4, 104e9)]):
        p = tmp_path / f"r{i}.json"
        p.write_text(json.dumps({
            "tool": "smb-perf-stat", "label": label, "wall_s": wall,
            "cpu_s": wall / 2, "ghz": 3.0, "ipc": 1.5,
            "per": {"n": 1000, "unit": "file"},
            "totals": {"cycles": cycles, "instructions": cycles * 1.5,
                       "context-switches": 10, "cpu-migrations": 1}}))
        paths.append(str(p))
    out = run(cmd_compare.main, *paths)
    line = next(ln for ln in out.splitlines() if ln.startswith("cycles"))
    assert line.split()[-2:] == ["-20.6%", "*"]
    out = run(cmd_compare.main, "--per", "--base", "B", *paths)
    line = next(ln for ln in out.splitlines() if ln.startswith("elapsed"))
    assert line.startswith("elapsed ms per file") and "+25.9% *" in line


def test_durations_and_counts():
    assert fmt.parse_duration("1m30s") == 90
    assert fmt.parse_duration("250ms") == 0.25
    with pytest.raises(ValueError):
        fmt.parse_duration("5 parsecs")
    assert fmt.parse_per("3000:file") == (3000.0, "file")
    assert fmt.fmt_val(1_500_000, "ns") == "1.50ms"
    assert fmt.fmt_val(2.5e9, "cycles") == "2.50G"


# -- live -------------------------------------------------------------------------

def _perf_works() -> bool:
    if os.geteuid() != 0 or shutil.which("perf") is None:
        return False
    r = subprocess.run(["perf", "stat", "-e", "task-clock", "true"],
                       capture_output=True)
    return r.returncode == 0


live = pytest.mark.skipif(not _perf_works(), reason="needs root and perf")


@pytest.fixture
def busy():
    p = subprocess.Popen([sys.executable, "-c",
                          "import time\nwhile True: time.time()"])
    yield p.pid
    p.kill()
    p.wait()


@live
def test_record_live(busy, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    out = tmp_path / "rec"
    run(cmd_record.main, "--pid", str(busy), "--duration", "1", "-o",
        str(out))
    meta = json.loads((out / "perf.json").read_text())
    assert meta["mode"] == "cpu" and meta["unit"] == "cycles"
    assert 0.9 < meta["seconds"] < 3
    folded = stacks.read_folded(open(out / "perf.folded"))
    assert folded.total() > 0
    assert ET.parse(out / "flame.svg").getroot().tag.endswith("svg")
    top = run(cmd_top.main, str(out), "--process")
    assert "python" in top


@live
def test_record_off_cpu_live(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    p = subprocess.Popen([sys.executable, "-c",
                          "import time\nwhile True: time.sleep(0.01)"])
    try:
        out = tmp_path / "off"
        run(cmd_record.main, "--pid", str(p.pid), "--mode", "off",
            "--duration", "1", "-o", str(out))
    finally:
        p.kill()
        p.wait()
    folded = stacks.read_folded(open(out / "perf.folded"), "ns")
    # Asleep for most of the second, in roughly 10 ms waits.
    assert 0.5e9 < folded.total() < 1.5e9
    assert len(folded.weights) >= 1


@live
def test_stat_live(busy, tmp_path):
    path = tmp_path / "run.json"
    t0 = time.monotonic()
    run(cmd_stat.main, "--pid", str(busy), "--label", "x", "-o", str(path),
        "--", "sleep", "0.5")
    assert time.monotonic() - t0 < 10
    r = json.loads(path.read_text())
    assert 0.4 < r["cpu_s"] < 0.65 and r["status"] == 0
