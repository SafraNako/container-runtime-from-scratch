"""A seccomp filter, written as BPF by hand.

seccomp lets a process hand the kernel a small program that is run for every system call it makes: the program sees the number of the call,
the architecture and the six arguments (``struct seccomp_data``) and answers ``ALLOW``, ``ERRNO(n)`` (the call fails with that error),
``KILL`` ... The program is classic BPF: instructions ``(code, jt, jf, k)`` with jumps that only go forward.

The filter here is a deny list (Docker's own profile is an allow list of about 350 calls and comes from libseccomp, which is not used):
the calls that load kernel modules, reboot, set the clock, mount and unshare, trace other processes' memory, create keys or use ``bpf`` and
``perf_event_open`` fail with ``EPERM``; ``clone`` with a namespace flag fails with ``EPERM`` and ``clone3`` (whose flags cannot be looked at) with
``ENOSYS``, so that libc falls back to ``clone``; any other architecture (32-bit calls, the x32 ABI) is refused.  Without ``CAP_SYS_ADMIN`` most
of these calls would fail anyway: the filter is a second wall.
"""
from __future__ import annotations

import ctypes
import errno
import platform
from typing import Dict, List, Optional, Sequence, Tuple

from . import linux

# BPF
BPF_LD, BPF_JMP, BPF_RET = 0x00, 0x05, 0x06
BPF_W, BPF_ABS = 0x00, 0x20
BPF_JEQ, BPF_JSET, BPF_JGE = 0x10, 0x40, 0x30
BPF_K = 0x00

SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_KILL_PROCESS = 0x80000000
EPERM, ENOSYS = 1, 38  # the numbers on Linux (the module can be imported on another system)

# struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; }
OFF_NR, OFF_ARCH, OFF_ARGS = 0, 4, 16

AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
X32_BIT = 0x40000000

# system call numbers on the two architectures that have a table here (checked against libseccomp in the tests)
NUMBERS: Dict[str, Dict[str, int]] = {
    "x86_64": {
        "acct": 163, "add_key": 248, "bpf": 321, "clock_adjtime": 305, "clock_settime": 227, "create_module": 174, "delete_module": 176,
        "finit_module": 313, "get_kernel_syms": 177, "get_mempolicy": 239, "init_module": 175, "ioperm": 173, "iopl": 172, "kcmp": 312,
        "kexec_file_load": 320, "kexec_load": 246, "keyctl": 250, "lookup_dcookie": 212, "mbind": 237, "mount": 165, "move_pages": 279,
        "name_to_handle_at": 303, "nfsservctl": 180, "open_by_handle_at": 304, "perf_event_open": 298, "pivot_root": 155,
        "process_vm_readv": 310, "process_vm_writev": 311, "query_module": 178, "quotactl": 179, "reboot": 169, "request_key": 249,
        "set_mempolicy": 238, "setns": 308, "settimeofday": 164, "swapoff": 168, "swapon": 167, "sysfs": 139, "_sysctl": 156,
        "umount2": 166, "unshare": 272, "uselib": 134, "userfaultfd": 323, "ustat": 136, "move_mount": 429, "open_tree": 428,
        "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433, "mount_setattr": 442, "clone": 56, "clone3": 435,
    },
    "aarch64": {
        "acct": 89, "add_key": 217, "bpf": 280, "clock_adjtime": 266, "clock_settime": 112, "delete_module": 106, "finit_module": 273,
        "get_mempolicy": 236, "init_module": 105, "kcmp": 272, "kexec_file_load": 294, "kexec_load": 104, "keyctl": 219,
        "lookup_dcookie": 18, "mbind": 235, "mount": 40, "nfsservctl": 42, "move_pages": 239, "name_to_handle_at": 264, "open_by_handle_at": 265,
        "perf_event_open": 241, "pivot_root": 41, "process_vm_readv": 270, "process_vm_writev": 271, "quotactl": 60, "reboot": 142,
        "request_key": 218, "set_mempolicy": 237, "setns": 268, "settimeofday": 170, "swapoff": 225, "swapon": 224, "umount2": 39,
        "unshare": 97, "userfaultfd": 282, "move_mount": 429, "open_tree": 428, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
        "fspick": 433, "mount_setattr": 442, "clone": 220, "clone3": 435,
    },
}

#: fail with EPERM
DENIED = (
    "acct", "add_key", "bpf", "clock_adjtime", "clock_settime", "create_module", "delete_module", "finit_module", "get_kernel_syms",
    "get_mempolicy", "init_module", "ioperm", "iopl", "kcmp", "kexec_file_load", "kexec_load", "keyctl", "lookup_dcookie", "mbind", "mount",
    "move_pages", "name_to_handle_at", "nfsservctl", "open_by_handle_at", "perf_event_open", "pivot_root", "process_vm_readv",
    "process_vm_writev", "query_module", "quotactl", "reboot", "request_key", "set_mempolicy", "setns", "settimeofday", "swapoff", "swapon",
    "sysfs", "_sysctl", "umount2", "unshare", "uselib", "userfaultfd", "ustat", "move_mount", "open_tree", "fsopen", "fsconfig", "fsmount",
    "fspick", "mount_setattr",
)
#: the flags of ``clone`` that make a new namespace
CLONE_NS_FLAGS = (
    linux.CLONE_NEWNS | linux.CLONE_NEWCGROUP | linux.CLONE_NEWUTS | linux.CLONE_NEWIPC | linux.CLONE_NEWUSER | linux.CLONE_NEWPID | linux.CLONE_NEWNET
)

Instruction = Tuple[int, int, int, int]


class Program:
    """A list of BPF instructions with names for the places that jumps go to."""

    def __init__(self) -> None:
        self.items: List[Tuple[str, object]] = []  # ("ins", (code, k, jt_label, jf_label)) or ("label", name)

    def label(self, name: str) -> None:
        self.items.append(("label", name))

    def load(self, offset: int) -> None:
        self.items.append(("ins", (BPF_LD | BPF_W | BPF_ABS, offset, None, None)))

    def jump_eq(self, k: int, yes: Optional[str], no: Optional[str]) -> None:
        self.items.append(("ins", (BPF_JMP | BPF_JEQ | BPF_K, k, yes, no)))

    def jump_set(self, k: int, yes: Optional[str], no: Optional[str]) -> None:
        self.items.append(("ins", (BPF_JMP | BPF_JSET | BPF_K, k, yes, no)))

    def jump_ge(self, k: int, yes: Optional[str], no: Optional[str]) -> None:
        self.items.append(("ins", (BPF_JMP | BPF_JGE | BPF_K, k, yes, no)))

    def ret(self, value: int) -> None:
        self.items.append(("ins", (BPF_RET | BPF_K, value, None, None)))

    def assemble(self) -> List[Instruction]:
        position: Dict[str, int] = {}
        n = 0
        for kind, value in self.items:
            if kind == "label":
                position[value] = n  # type: ignore[index]
            else:
                n += 1
        out: List[Instruction] = []
        i = 0
        for kind, value in self.items:
            if kind == "label":
                continue
            code, k, yes, no = value  # type: ignore[misc]
            jt = jf = 0
            if code & 0x07 == BPF_JMP:
                # jump targets are relative to the next instruction and only forward, in 8 bits
                jt = (position[yes] - (i + 1)) if yes is not None else 0
                jf = (position[no] - (i + 1)) if no is not None else 0
                if not (0 <= jt <= 255 and 0 <= jf <= 255):
                    raise ValueError("a jump of %d/%d instructions does not fit in a BPF instruction" % (jt, jf))
            out.append((code, jt, jf, k))
            i += 1
        return out


def build_filter(denied: Sequence[int], clone_nr: Optional[int], clone3_nr: Optional[int], arch: int, x32: bool = False) -> List[Instruction]:
    """The program: wrong architecture -> EPERM; the x32 bit -> EPERM; ``denied`` numbers -> EPERM; ``clone`` with a namespace flag -> EPERM;
    ``clone3`` -> ENOSYS; everything else -> ALLOW."""
    p = Program()
    p.load(OFF_ARCH)
    p.jump_eq(arch, "arch_ok", "deny")
    p.label("arch_ok")
    p.load(OFF_NR)
    if x32:
        p.jump_ge(X32_BIT, "deny", "nr_ok")  # on x86_64 this bit selects the 32-bit-pointer ABI, whose numbers are a second table
    p.label("nr_ok")
    for nr in denied:
        p.jump_eq(nr, "deny", None)
    if clone3_nr is not None:
        p.jump_eq(clone3_nr, "enosys", None)
    if clone_nr is not None:
        p.jump_eq(clone_nr, "check_clone", None)
    p.ret(SECCOMP_RET_ALLOW)
    p.label("check_clone")
    p.load(OFF_ARGS)  # the low half of the first argument: the flags
    p.jump_set(CLONE_NS_FLAGS, "deny", "allow")
    p.label("allow")
    p.ret(SECCOMP_RET_ALLOW)
    p.label("enosys")
    p.ret(SECCOMP_RET_ERRNO | ENOSYS)
    p.label("deny")
    p.ret(SECCOMP_RET_ERRNO | EPERM)
    return p.assemble()


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_SockFilter))]


def default_program() -> List[Instruction]:
    machine = platform.machine()
    if machine not in NUMBERS:
        raise OSError(errno.ENOSYS, "no seccomp table for %s" % machine)
    table = NUMBERS[machine]
    denied = [table[name] for name in DENIED if name in table]
    return build_filter(denied, table.get("clone"), table.get("clone3"), AUDIT_ARCH[machine], x32=machine == "x86_64")


def install(program: Sequence[Instruction]) -> None:
    """Puts the filter on the calling process (and every process it creates).  Needs ``CAP_SYS_ADMIN`` or ``no_new_privs``."""
    arr = (_SockFilter * len(program))(*[_SockFilter(*ins) for ins in program])
    prog = _SockFprog(len(program), ctypes.cast(arr, ctypes.POINTER(_SockFilter)))
    linux.prctl(linux.PR_SET_SECCOMP, linux.SECCOMP_MODE_FILTER, ctypes.addressof(prog))


def apply_default() -> None:
    install(default_program())


def run(program: Sequence[Instruction], nr: int, arch: Optional[int] = None, args: Sequence[int] = ()) -> int:
    """Runs the program on a system call, the way the kernel would, and returns its answer (a small BPF interpreter: used by the tests to
    check the filter against what the kernel really does)."""
    data = {OFF_NR: nr & 0xFFFFFFFF, OFF_ARCH: arch if arch is not None else AUDIT_ARCH[platform.machine()]}
    for i, a in enumerate(args):
        data[OFF_ARGS + 8 * i] = a & 0xFFFFFFFF
        data[OFF_ARGS + 8 * i + 4] = a >> 32 & 0xFFFFFFFF
    acc = 0
    pc = 0
    while pc < len(program):
        code, jt, jf, k = program[pc]
        cls = code & 0x07
        if cls == BPF_LD:
            acc = data.get(k, 0)
        elif cls == BPF_JMP:
            op = code & 0xF0
            if op == BPF_JEQ:
                hit = acc == k
            elif op == BPF_JSET:
                hit = bool(acc & k)
            elif op == BPF_JGE:
                hit = acc >= k
            else:
                raise ValueError("unknown jump")
            pc += jt if hit else jf
        elif cls == BPF_RET:
            return k
        pc += 1
    raise ValueError("the program ran off its end")
