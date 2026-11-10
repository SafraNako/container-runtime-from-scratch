"""The Linux system calls a container runtime is made of, through ``ctypes``.

Python's standard library has ``os.fork``, ``os.chroot`` and ``os.mknod``, but no ``mount``, ``pivot_root``, ``setns`` (before 3.12),
``prctl`` or ``capset``; here they are.  Each wrapper raises ``OSError`` with the right ``errno`` and the name of the call.  The module can
be imported anywhere (the tests of the pure parts run on a Mac); calling a system call on another system raises ``OSError(ENOSYS)``.
"""
from __future__ import annotations

import ctypes
import errno
import os
import platform
import sys
from typing import Dict, Iterable, List, NamedTuple, Optional

ON_LINUX = sys.platform.startswith("linux")

# clone / unshare flags
CLONE_NEWNS = 0x00020000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000

# mount flags
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_SYNCHRONOUS = 16
MS_REMOUNT = 32
MS_MANDLOCK = 64
MS_DIRSYNC = 128
MS_NOATIME = 1024
MS_NODIRATIME = 2048
MS_BIND = 4096
MS_MOVE = 8192
MS_REC = 16384
MS_SILENT = 32768
MS_UNBINDABLE = 1 << 17
MS_PRIVATE = 1 << 18
MS_SLAVE = 1 << 19
MS_SHARED = 1 << 20
MS_RELATIME = 1 << 21
MS_STRICTATIME = 1 << 24
MNT_FORCE = 1
MNT_DETACH = 2

# prctl
PR_SET_PDEATHSIG = 1
PR_SET_DUMPABLE = 4
PR_SET_NAME = 15
PR_CAPBSET_READ = 23
PR_CAPBSET_DROP = 24
PR_SET_KEEPCAPS = 8
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

CAP_NAMES = [
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE",
    "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER", "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT",
    "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD", "LEASE",
    "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ",
    "PERFMON", "BPF", "CHECKPOINT_RESTORE",
]
CAPS: Dict[str, int] = {name: i for i, name in enumerate(CAP_NAMES)}
#: the capabilities Docker gives a container by default
DEFAULT_CAPS = (
    "CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID", "SETFCAP", "SETPCAP", "NET_BIND_SERVICE",
    "SYS_CHROOT", "KILL", "AUDIT_WRITE",
)

_SYSCALLS = {  # number of the calls that glibc does not wrap
    "x86_64": {"pivot_root": 155, "capget": 125, "capset": 126},
    "aarch64": {"pivot_root": 41, "capget": 90, "capset": 91},
}

_libc = None


def libc():
    global _libc
    if _libc is None:
        if not ON_LINUX:
            raise OSError(errno.ENOSYS, "this needs Linux")
        _libc = ctypes.CDLL(None, use_errno=True)
    return _libc


def _syscall_number(name: str) -> int:
    try:
        return _SYSCALLS[platform.machine()][name]
    except KeyError:
        raise OSError(errno.ENOSYS, "no system call number for %s on %s" % (name, platform.machine())) from None


def _check(result: int, what: str, path: Optional[str] = None) -> int:
    if result == -1:
        e = ctypes.get_errno()
        raise OSError(e, "%s: %s" % (what, os.strerror(e)), path)
    return result


def _b(value: Optional[str]) -> Optional[bytes]:
    return None if value is None else os.fsencode(value)


def unshare(flags: int) -> None:
    _check(libc().unshare(flags), "unshare")


def setns(fd: int, nstype: int = 0) -> None:
    _check(libc().setns(fd, nstype), "setns")


def mount(source: Optional[str], target: str, fstype: Optional[str] = None, flags: int = 0, data: Optional[str] = None) -> None:
    result = libc().mount(_b(source), _b(target), _b(fstype), ctypes.c_ulong(flags), _b(data))
    _check(result, "mount %s on %s%s" % (source or fstype or "", target, " (%s)" % fstype if fstype and source else ""), target)


def umount(target: str, flags: int = 0) -> None:
    _check(libc().umount2(_b(target), flags), "umount", target)


def pivot_root(new_root: str, put_old: str) -> None:
    _check(libc().syscall(_syscall_number("pivot_root"), _b(new_root), _b(put_old)), "pivot_root", new_root)


def sethostname(name: str) -> None:
    data = name.encode()
    _check(libc().sethostname(data, len(data)), "sethostname")


def setdomainname(name: str) -> None:
    data = name.encode()
    _check(libc().setdomainname(data, len(data)), "setdomainname")


def prctl(option: int, arg2: int = 0, arg3: int = 0, arg4: int = 0, arg5: int = 0) -> int:
    return _check(libc().prctl(option, ctypes.c_ulong(arg2), ctypes.c_ulong(arg3), ctypes.c_ulong(arg4), ctypes.c_ulong(arg5)), "prctl")


def bind_mount(source: str, target: str, readonly: bool = False, recursive: bool = True, extra_flags: int = MS_NOSUID | MS_NODEV) -> None:
    """Makes ``source`` visible at ``target`` too.  A read-only bind needs a second, remounting step (the kernel ignores MS_RDONLY on the
    first one)."""
    mount(source, target, None, MS_BIND | (MS_REC if recursive else 0))
    if readonly:
        mount(None, target, None, MS_BIND | MS_REMOUNT | MS_RDONLY | extra_flags | (MS_REC if recursive else 0))


def make_private(path: str = "/") -> None:
    mount(None, path, None, MS_REC | MS_PRIVATE)


# ------------------------------------------------------------------------------------------------------------ capabilities

class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]


_CAP_VERSION_3 = 0x20080522


class CapSets(NamedTuple):
    effective: int
    permitted: int
    inheritable: int


def mask(names: Iterable[str]) -> int:
    """The bit mask of capability names (``"NET_RAW"`` or ``"CAP_NET_RAW"``)."""
    m = 0
    for n in names:
        key = n[4:] if n.upper().startswith("CAP_") else n
        try:
            m |= 1 << CAPS[key.upper()]
        except KeyError:
            raise ValueError("unknown capability %r" % n) from None
    return m


def names(value: int) -> List[str]:
    return [n for i, n in enumerate(CAP_NAMES) if value >> i & 1]


def get_caps() -> CapSets:
    header = _CapHeader(_CAP_VERSION_3, 0)
    data = (_CapData * 2)()
    _check(libc().syscall(_syscall_number("capget"), ctypes.byref(header), data), "capget")
    return CapSets(*(data[0].__getattribute__(f) | data[1].__getattribute__(f) << 32 for f in ("effective", "permitted", "inheritable")))


def set_caps(effective: int, permitted: int, inheritable: int) -> None:
    header = _CapHeader(_CAP_VERSION_3, 0)
    data = (_CapData * 2)()
    for i in (0, 1):
        sh = 32 * i
        data[i].effective = effective >> sh & 0xFFFFFFFF
        data[i].permitted = permitted >> sh & 0xFFFFFFFF
        data[i].inheritable = inheritable >> sh & 0xFFFFFFFF
    _check(libc().syscall(_syscall_number("capset"), ctypes.byref(header), data), "capset")


def last_cap() -> int:
    try:
        with open("/proc/sys/kernel/cap_last_cap") as fh:
            return int(fh.read())
    except OSError:
        return len(CAP_NAMES) - 1


def drop_bounding_set(keep: int) -> None:
    """Removes from the bounding set every capability that is not in the mask ``keep`` (nothing can get it back, not even by exec)."""
    for cap in range(last_cap() + 1):
        if not keep >> cap & 1:
            prctl(PR_CAPBSET_DROP, cap)


def bounding_set() -> int:
    m = 0
    for cap in range(last_cap() + 1):
        if prctl(PR_CAPBSET_READ, cap):
            m |= 1 << cap
    return m


def restrict_capabilities(keep: int) -> None:
    """The process keeps only the capabilities of ``keep``: bounding set, permitted and effective; the inheritable and ambient sets are
    emptied (this is what ``docker run`` does for root)."""
    drop_bounding_set(keep)
    set_caps(keep, keep, 0)
    try:
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)
    except OSError:  # kernels before 4.3
        pass


def set_no_new_privs() -> None:
    prctl(PR_SET_NO_NEW_PRIVS, 1)


# ------------------------------------------------------------------------------------------------------------ /proc readers

class MountInfo(NamedTuple):
    mount_id: int
    parent_id: int
    major_minor: str
    root: str
    mount_point: str
    options: str
    fields: str
    fstype: str
    source: str
    super_options: str


def _unescape(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 3 < len(s) + 0 and s[i + 1 : i + 4].isdigit():
            out.append(chr(int(s[i + 1 : i + 4], 8)))
            i += 4
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def parse_mountinfo(text: str) -> List[MountInfo]:
    """``/proc/self/mountinfo`` (see proc(5)) as a list of tuples."""
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        left, right = line.split(" - ", 1)
        a = left.split(" ")
        r = right.split(" ")
        out.append(MountInfo(int(a[0]), int(a[1]), a[2], _unescape(a[3]), _unescape(a[4]), a[5], " ".join(a[6:]), r[0], _unescape(r[1]), r[2] if len(r) > 2 else ""))
    return out


def mounts(pid: Optional[int] = None) -> List[MountInfo]:
    with open("/proc/%s/mountinfo" % (pid if pid is not None else "self")) as fh:
        return parse_mountinfo(fh.read())


def proc_status(pid: Optional[int] = None) -> Dict[str, str]:
    out: Dict[str, str] = {}
    with open("/proc/%s/status" % (pid if pid is not None else "self")) as fh:
        for line in fh:
            k, _, v = line.partition(":")
            out[k] = v.strip()
    return out
