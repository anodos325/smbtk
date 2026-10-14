"""Names for the numbers in SMB2 and SMB1 messages."""

from __future__ import annotations

from . import names_gen

SMB2_CMD = {
    0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT",
    4: "TREE_DISCONNECT", 5: "CREATE", 6: "CLOSE", 7: "FLUSH", 8: "READ",
    9: "WRITE", 10: "LOCK", 11: "IOCTL", 12: "CANCEL", 13: "ECHO",
    14: "QUERY_DIRECTORY", 15: "CHANGE_NOTIFY", 16: "QUERY_INFO",
    17: "SET_INFO", 18: "OPLOCK_BREAK",
}
SMB2_CMD_BY_NAME = {v: k for k, v in SMB2_CMD.items()}
# Shorter aliases accepted on the command line.
SMB2_CMD_ALIASES = {
    "FIND": 14, "QUERY_DIR": 14, "QUERYDIR": 14, "NOTIFY": 15,
    "GETINFO": 16, "SETINFO": 17, "BREAK": 18, "TCON": 3, "TDIS": 4,
    "NEG": 0, "SS": 1,
}

(
    NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT, TREE_DISCONNECT, CREATE,
    CLOSE, FLUSH, READ, WRITE, LOCK, IOCTL, CANCEL, ECHO, QUERY_DIRECTORY,
    CHANGE_NOTIFY, QUERY_INFO, SET_INFO, OPLOCK_BREAK,
) = range(19)

STATUS_SUCCESS = 0x0
STATUS_PENDING = 0x103
STATUS_NOTIFY_CLEANUP = 0x10B
STATUS_NOTIFY_ENUM_DIR = 0x10C
STATUS_BUFFER_OVERFLOW = 0x80000005
STATUS_NO_MORE_FILES = 0x80000006
STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
STATUS_CANCELLED = 0xC0000120

INFO_CLASS = {1: "FILE", 2: "FS", 3: "SECURITY", 4: "QUOTA"}
CREATE_DISPOSITION = {
    0: "SUPERSEDE", 1: "OPEN", 2: "CREATE", 3: "OPEN_IF", 4: "OVERWRITE",
    5: "OVERWRITE_IF",
}
CREATE_ACTION = {0: "SUPERSEDED", 1: "OPENED", 2: "CREATED", 3: "OVERWRITTEN"}
DIALECT = {
    0x202: "2.0.2", 0x210: "2.1", 0x300: "3.0", 0x302: "3.0.2",
    0x311: "3.1.1", 0x2FF: "2.??",
}
SHARE_TYPE = {1: "DISK", 2: "PIPE", 3: "PRINT"}
OPLOCK = {0: "NONE", 1: "II", 8: "EXCLUSIVE", 9: "BATCH", 0xFF: "LEASE"}
CIPHER = {
    1: "AES-128-CCM", 2: "AES-128-GCM", 3: "AES-256-CCM", 4: "AES-256-GCM",
}
NTLMSSP_TYPE = {1: "NTLMSSP_NEGOTIATE", 2: "NTLMSSP_CHALLENGE", 3: "NTLMSSP_AUTH"}

# Statuses that are part of a normal exchange rather than a failure, per
# command; "*" applies to every command.
FLOW_STATUS: dict[str, set[int]] = {
    "*": {STATUS_PENDING},
    "SESSION_SETUP": {STATUS_MORE_PROCESSING_REQUIRED},
    "QUERY_DIRECTORY": {STATUS_NO_MORE_FILES, 0xC000000F},  # NO_SUCH_FILE
    "CHANGE_NOTIFY": {STATUS_NOTIFY_ENUM_DIR, STATUS_NOTIFY_CLEANUP,
                      STATUS_CANCELLED, 0xC0000128},  # FILE_CLOSED
    "READ": {0xC0000011, STATUS_BUFFER_OVERFLOW},  # END_OF_FILE
    "IOCTL": {STATUS_BUFFER_OVERFLOW},
    "QUERY_INFO": {STATUS_BUFFER_OVERFLOW},
}
# Negative answers clients ask for on purpose: existence checks and
# capability probes.
PROBE_STATUS: dict[str, set[int]] = {
    "CREATE": {0xC0000034, 0xC000003A, 0xC000003B, 0xC000003C,
               0xC00000F9},  # NOT_FOUND, PATH_NOT_FOUND, STOPPED_ON_SYMLINK
    "IOCTL": {0xC00000BB, 0xC0000010, 0xC000000D, 0xC0000225,
              0xC0000002},  # NOT_SUPPORTED, INVALID_DEVICE_REQUEST, ...
    "QUERY_INFO": {0xC00000BB, 0xC0000003, 0xC000000D, 0xC0000002},
    "SET_INFO": {0xC00000BB, 0xC0000003, 0xC0000002},
    "QUERY_DIRECTORY": {0xC0000034},
}


def cmd_name(proto: str, cmd: int) -> str:
    if proto == "smb2":
        return SMB2_CMD.get(cmd, f"SMB2_{cmd:#x}")
    return names_gen.SMB1_CMD.get(cmd, f"SMB1_{cmd:#x}")


def status_name(status: int | None, strip: bool = True) -> str:
    if status is None:
        return "-"
    name = names_gen.NT_STATUS.get(status)
    if name is None:
        return f"{status:#010x}"
    if strip and name.startswith("STATUS_"):
        return name[7:]
    return name


def status_class(cmd: str, status: int) -> str:
    """'ok', 'flow', 'probe' or 'error'."""
    if status == 0:
        return "ok"
    if status in FLOW_STATUS["*"] or status in FLOW_STATUS.get(cmd, ()):
        return "flow"
    if status in PROBE_STATUS.get(cmd, ()):
        return "probe"
    return "error"


def fsctl_name(code: int | None) -> str:
    if code is None:
        return "?"
    return names_gen.FSCTL.get(code, f"FSCTL_{code:#010x}")


def info_name(cls: int | None, level: int | None) -> str:
    if cls is None or level is None:
        return "?"
    cname = INFO_CLASS.get(cls, f"CLASS{cls}")
    if cls == 1:
        lname = names_gen.FILE_INFO_LEVEL.get(level)
    elif cls == 2:
        lname = names_gen.FS_INFO_LEVEL.get(level)
        if lname and lname.startswith("FileFs"):
            lname = lname[6:]
    elif cls == 3:
        lname = "SD"
    else:
        lname = None
    return f"{cname}/{lname or level}"


def find_level_name(level: int | None) -> str:
    if level is None:
        return "?"
    return names_gen.FIND_LEVEL.get(level, f"LEVEL{level}")


def parse_cmd(text: str) -> tuple[str, int]:
    """A command given by name or number on the command line."""
    key = text.strip().upper()
    if key in SMB2_CMD_BY_NAME:
        return "smb2", SMB2_CMD_BY_NAME[key]
    if key in SMB2_CMD_ALIASES:
        return "smb2", SMB2_CMD_ALIASES[key]
    if key.startswith("SMB1_"):
        for code, name in names_gen.SMB1_CMD.items():
            if name == key[5:]:
                return "smb", code
    try:
        return "smb2", int(key, 0)
    except ValueError:
        raise ValueError(f"unknown command {text!r}") from None
