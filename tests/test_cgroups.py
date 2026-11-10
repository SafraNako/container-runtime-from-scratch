"""The cgroup directory API against the kernel's own files, and against the cgroup that Docker makes for the same limits."""
import os
import signal
import subprocess
import sys
import time

import pytest

from conftest import IMAGE, SRC, needs_docker, needs_root

pytestmark = needs_root


@pytest.fixture
def cg():
    sys.path.insert(0, SRC)
    from kendi_konteyner.cgroups import Cgroup

    group = Cgroup("kk-unit-%d" % os.getpid()).create()
    yield group
    group.remove()


def read(group, name):
    with open(os.path.join(group.path, name)) as fh:
        return fh.read().strip()


def test_a_new_group_has_the_controllers_and_no_processes(cg):
    assert os.path.isdir(cg.path) and cg.exists()
    assert {"cpu", "memory", "pids"} <= set(read(cg, "cgroup.controllers").split())
    assert cg.procs() == [] and cg.stats()["pids"] == 0


def test_limits_are_the_files_of_the_kernel(cg):
    cg.set_memory(64 * 1024 * 1024)
    cg.set_cpus(0.5)
    cg.set_pids(20)
    assert read(cg, "memory.max") == "67108864" and read(cg, "cpu.max") == "50000 100000" and read(cg, "pids.max") == "20"
    assert read(cg, "memory.swap.max") == "0"  # a container that can swap out is not limited
    assert cg.limits() == {"memory.max": "67108864", "memory.swap.max": "0", "cpu.max": "50000 100000", "pids.max": "20"}
    cg.set_cpus(2)
    assert read(cg, "cpu.max") == "200000 100000"  # more than one CPU is a quota of more than one period


def test_none_changes_nothing_and_swap_can_be_allowed(cg):
    before = cg.limits()
    cg.set_memory(None)
    cg.set_cpus(None)
    cg.set_pids(None)
    assert cg.limits() == before and before["memory.max"] == "max" and before["pids.max"] == "max"
    cg.set_memory(32 * 1024 * 1024, swap=True)
    assert read(cg, "memory.max") == "33554432" and read(cg, "memory.swap.max") == "max"


def test_processes_are_put_in_and_all_of_them_are_killed(cg):
    # the shell joins the group before it runs, so that the two sleeps it forks are born in it
    p = subprocess.Popen(["sh", "-c", "sleep 60 & sleep 60 & wait"], preexec_fn=lambda: open(os.path.join(cg.path, "cgroup.procs"), "w").write("0"))
    try:
        time.sleep(0.5)
        procs = cg.procs()
        assert p.pid in procs and len(procs) == 3 and cg.stats()["pids"] == 3
        cg.kill_all()
        assert p.wait(timeout=10) == -signal.SIGKILL
        for _ in range(100):
            if not cg.procs():
                break
            time.sleep(0.05)
        assert cg.procs() == []
    finally:
        p.kill()
        p.wait()


def test_leave_moves_a_process_to_the_root(cg):
    p = subprocess.Popen(["sleep", "60"])
    try:
        cg.add(p.pid)
        assert p.pid in cg.procs()
        cg.leave(p.pid)
        assert cg.procs() == [] and open("/proc/%d/cgroup" % p.pid).read().strip() == "0::/"
    finally:
        p.kill()
        p.wait()


def test_remove_kills_what_is_left_and_can_be_repeated(cg):
    p = subprocess.Popen(["sleep", "60"])
    cg.add(p.pid)
    cg.remove()
    assert not cg.exists() and p.wait(timeout=10) == -signal.SIGKILL
    cg.remove()  # nothing left to remove: not an error


def test_what_is_in_the_group_counts_against_the_limit(cg):
    cg.set_pids(3)
    cg.set_memory(32 * 1024 * 1024)
    code = (
        "import subprocess\n"
        "kids = []\n"
        "try:\n"
        "    for _ in range(5):\n"
        "        kids.append(subprocess.Popen(['sleep', '5']))\n"
        "except OSError as e:\n"
        "    print('refused', e.errno)\n"
        "for k in kids:\n"
        "    k.kill()\n"
    )
    p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True, preexec_fn=lambda: open(os.path.join(cg.path, "cgroup.procs"), "w").write("0"))
    out, _ = p.communicate(timeout=30)
    assert out.strip() == "refused 11"  # EAGAIN: the third process of the group is the last
    assert int(open(os.path.join(cg.path, "pids.events")).read().split()[-1]) >= 1  # "max": how often the limit stopped a fork


def test_the_oom_killer_is_counted(cg):
    cg.set_memory(32 * 1024 * 1024)
    p = subprocess.Popen(
        [sys.executable, "-c", "x = bytearray(200 * 1024 * 1024); print('survived')"],
        stdout=subprocess.PIPE, text=True, preexec_fn=lambda: open(os.path.join(cg.path, "cgroup.procs"), "w").write("0"),
    )
    out, _ = p.communicate(timeout=60)
    assert p.returncode == -signal.SIGKILL and "survived" not in out
    assert cg.events()["oom_kill"] >= 1 and cg.oom_killed()
    assert cg.events()["max"] >= 1 and cg.stats()["memory_peak"] <= 33 * 1024 * 1024


@needs_docker
def test_docker_writes_the_same_numbers(cg, docker):
    """Same flags, same files: the cgroup of a Docker container and this one hold the same limits."""
    cg.set_memory(64 * 1024 * 1024)
    cg.set_cpus(0.5)
    cg.set_pids(20)
    name = "kk-cg-oracle"
    docker("rm", "-f", name)
    try:
        assert docker("run", "-d", "--name", name, "-m", "64m", "--cpus", "0.5", "--pids-limit", "20", IMAGE, "sleep", "60").code == 0
        pid = docker("inspect", "-f", "{{.State.Pid}}", name).out.strip()
        with open("/proc/%s/cgroup" % pid) as fh:
            path = fh.read().strip().split("::", 1)[1]
        theirs = {}
        for key in ("memory.max", "cpu.max", "pids.max"):
            with open("/sys/fs/cgroup%s/%s" % (path, key)) as fh:
                theirs[key] = fh.read().strip()
        mine = {k: v for k, v in cg.limits().items() if k in theirs}
        assert mine == theirs, (mine, theirs)
    finally:
        docker("rm", "-f", name)
