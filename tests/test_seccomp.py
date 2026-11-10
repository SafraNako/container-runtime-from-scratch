"""The seccomp filter: its system call numbers against libseccomp, and its answers against the kernel that runs it."""
import ctypes
import ctypes.util
import errno
import os
import platform
import sys
import threading

import pytest

from conftest import SRC, needs_root, on_linux

sys.path.insert(0, SRC)
from kendi_konteyner import seccomp  # noqa: E402
from kendi_konteyner.linux import CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS  # noqa: E402

libseccomp_path = ctypes.util.find_library("seccomp")
needs_libseccomp = pytest.mark.skipif(libseccomp_path is None, reason="needs libseccomp as the oracle for system call numbers")


def libseccomp():
    lib = ctypes.CDLL(libseccomp_path)
    lib.seccomp_arch_resolve_name.restype = ctypes.c_uint32
    lib.seccomp_arch_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name_arch.restype = ctypes.c_int
    lib.seccomp_syscall_resolve_name_arch.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    return lib


@needs_libseccomp
@pytest.mark.parametrize("arch", sorted(seccomp.NUMBERS))
def test_the_numbers_are_the_numbers_of_libseccomp(arch):
    lib = libseccomp()
    token = lib.seccomp_arch_resolve_name(arch.encode())
    assert token, "libseccomp does not know %s" % arch
    wrong, unknown = {}, []
    for name, number in seccomp.NUMBERS[arch].items():
        theirs = lib.seccomp_syscall_resolve_name_arch(token, name.encode())
        if theirs < 0:
            unknown.append(name)  # a call that this libseccomp is too old to know
        elif theirs != number:
            wrong[name] = (number, theirs)
    assert not wrong, wrong
    assert not unknown, "libseccomp %s does not know: %s" % (arch, unknown)


@needs_libseccomp
@pytest.mark.parametrize("arch", sorted(seccomp.NUMBERS))
def test_every_denied_call_is_in_the_table_unless_the_architecture_does_not_have_it(arch):
    lib = libseccomp()
    token = lib.seccomp_arch_resolve_name(arch.encode())
    missing = [n for n in seccomp.DENIED if n not in seccomp.NUMBERS[arch]]
    # what is missing must be a call that this architecture really has no number for (libseccomp answers a negative pseudo number)
    for name in missing:
        assert lib.seccomp_syscall_resolve_name_arch(token, name.encode()) < 0, "%s exists on %s but is not denied there" % (name, arch)


def test_the_two_tables_agree_on_the_calls_they_name_in_common():
    for name in set(seccomp.NUMBERS["x86_64"]) & set(seccomp.NUMBERS["aarch64"]):
        assert (name in seccomp.DENIED) or name in ("clone", "clone3"), name


# ---------------------------------------------------------------------------------------------------------------- the program on paper

def answers(program, nr, *args, arch=None):
    return seccomp.run(program, nr, arch=arch, args=args)


EPERM_ANSWER = seccomp.SECCOMP_RET_ERRNO | errno.EPERM
ENOSYS_ANSWER = seccomp.SECCOMP_RET_ERRNO | errno.ENOSYS


@pytest.mark.parametrize("machine", sorted(seccomp.NUMBERS))
def test_the_rules_on_paper(machine, monkeypatch):
    monkeypatch.setattr(platform, "machine", lambda: machine)
    program = seccomp.default_program()
    table = seccomp.NUMBERS[machine]
    arch = seccomp.AUDIT_ARCH[machine]
    for name in seccomp.DENIED:
        if name in table:
            assert answers(program, table[name], arch=arch) == EPERM_ANSWER, name
    assert answers(program, table["clone3"], arch=arch) == ENOSYS_ANSWER
    for flag in (CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWUSER):
        assert answers(program, table["clone"], flag | 17, arch=arch) == EPERM_ANSWER, hex(flag)
    assert answers(program, table["clone"], 0x00011200 | 17, arch=arch) == seccomp.SECCOMP_RET_ALLOW  # what a thread or a fork asks for
    assert answers(program, table["clone"], 17, 0xFFFFFFFF00000000, arch=arch) == seccomp.SECCOMP_RET_ALLOW  # only the flags are looked at
    for other in (0, 1, 39, 60, 231):  # read, write, getpid, exit ...: whatever is not named is allowed
        if other not in table.values():
            assert answers(program, other, arch=arch) == seccomp.SECCOMP_RET_ALLOW
    foreign = 0x40000003 if machine == "x86_64" else 0xC000003E  # i386, or x86_64 seen from an arm kernel
    assert answers(program, 39, arch=foreign) == EPERM_ANSWER
    if machine == "x86_64":
        assert answers(program, 39 | seccomp.X32_BIT, arch=arch) == EPERM_ANSWER  # the x32 ABI is another table of numbers


# ---------------------------------------------------------------------------------------------------------------- the program in the kernel

pytestmark_kernel = [needs_root, pytest.mark.skipif(not on_linux or platform.machine() not in seccomp.NUMBERS, reason="needs Linux on x86_64 or arm64")]

libc = ctypes.CDLL(None, use_errno=True) if on_linux else None


def in_child(body):
    """Runs ``body()`` in a forked process with the filter installed; returns what it returned (an exit code, 0..255)."""
    pid = os.fork()
    if pid == 0:
        code = 99
        try:
            seccomp_install()
            code = body()
        except BaseException:  # noqa: B902
            code = 98
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def seccomp_install():
    from kendi_konteyner import linux

    linux.set_no_new_privs()
    seccomp.apply_default()


def call(nr, *args):
    padded = list(args) + [0] * (6 - len(args))
    ctypes.set_errno(0)
    result = libc.syscall(ctypes.c_long(nr), *[ctypes.c_ulong(a) for a in padded])
    return result, ctypes.get_errno()


@pytest.mark.skipif(not on_linux or platform.machine() not in seccomp.NUMBERS, reason="needs Linux on x86_64 or arm64")
@needs_root
def test_the_kernel_refuses_every_denied_call_with_eperm():
    table = seccomp.NUMBERS[platform.machine()]
    refused = {}
    for name in seccomp.DENIED:
        if name not in table:
            continue
        nr = table[name]
        if in_child(lambda: 0 if call(nr) == (-1, errno.EPERM) else 1) != 0:
            refused[name] = False
    assert not refused, "not refused with EPERM: %s" % sorted(refused)


@pytest.mark.skipif(not on_linux or platform.machine() not in seccomp.NUMBERS, reason="needs Linux on x86_64 or arm64")
@needs_root
def test_the_program_on_paper_and_the_kernel_agree():
    table = seccomp.NUMBERS[platform.machine()]
    program = seccomp.default_program()
    getpid = {"x86_64": 39, "aarch64": 172}[platform.machine()]
    for name in sorted(seccomp.DENIED):
        if name in table:
            on_paper = answers(program, table[name]) == EPERM_ANSWER
            in_kernel = in_child(lambda: 0 if call(table[name]) == (-1, errno.EPERM) else 1) == 0
            assert on_paper and in_kernel, name
    assert answers(program, getpid) == seccomp.SECCOMP_RET_ALLOW
    assert in_child(lambda: 0 if call(getpid)[0] == os.getpid() else 1) == 0


@pytest.mark.skipif(not on_linux or platform.machine() not in seccomp.NUMBERS, reason="needs Linux on x86_64 or arm64")
@needs_root
def test_a_new_namespace_is_refused_but_an_ordinary_clone_is_not():
    table = seccomp.NUMBERS[platform.machine()]

    def new_uts_namespace():
        result, err = call(table["clone"], CLONE_NEWUTS | 17, 0)
        return 0 if (result, err) == (-1, errno.EPERM) else 1

    assert in_child(new_uts_namespace) == 0
    assert in_child(lambda: 0 if libc.unshare(CLONE_NEWUTS) == -1 and ctypes.get_errno() == errno.EPERM else 1) == 0

    def fork_and_thread():
        child = os.fork()  # clone3 says ENOSYS and libc falls back to clone
        if child == 0:
            os._exit(7)
        _, status = os.waitpid(child, 0)
        done = []
        t = threading.Thread(target=lambda: done.append(1))
        t.start()
        t.join()
        return 0 if os.waitstatus_to_exitcode(status) == 7 and done else 1

    assert in_child(fork_and_thread) == 0


@pytest.mark.skipif(not on_linux or platform.machine() not in seccomp.NUMBERS, reason="needs Linux on x86_64 or arm64")
@needs_root
def test_clone3_is_not_implemented_so_that_libc_falls_back():
    nr = seccomp.NUMBERS[platform.machine()]["clone3"]
    assert in_child(lambda: 0 if call(nr, 0, 0) == (-1, errno.ENOSYS) else 1) == 0


@pytest.mark.skipif(not on_linux or platform.machine() != "x86_64", reason="x86_64 only: the x32 bit")
@needs_root
def test_the_x32_abi_is_refused_by_the_kernel_too():
    getpid_x32 = 39 | seccomp.X32_BIT
    assert in_child(lambda: 0 if call(getpid_x32) == (-1, errno.EPERM) else 1) == 0
