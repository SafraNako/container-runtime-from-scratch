"""Running a second process in a running container."""
import os
import time

import pytest

from conftest import IMAGE, needs_docker

pytestmark = needs_docker

FACTS = (
    "echo ---ps; ps -o pid,user,args; echo ---status; grep -E '^(CapInh|CapPrm|CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status; "
    "echo ---id; id; echo ---pwd; pwd; echo ---env; env | grep -vE '^(HOSTNAME|HOME)=' | sort; echo ---cgroup; cat /proc/self/cgroup; "
    "echo ---hostname; hostname; echo ---root; ls / | tr '\\n' ' '"
)


@pytest.fixture
def pair(kk, docker, image):
    """The same container, started the same way, in this runtime and in Docker."""
    kk("run", "-d", "--name", "sleeper", "--network", "none", "--hostname", "boxed", "-e", "FROM_RUN=1", IMAGE, "sleep", "300")
    docker("run", "-d", "--name", "kk-sleeper", "--network", "none", "--hostname", "boxed", "-e", "FROM_RUN=1", IMAGE, "sleep", "300")
    time.sleep(0.5)
    yield
    docker("rm", "-f", "kk-sleeper")


def no_pids(text):
    """The ps lines without the process numbers: Docker's exec uses a few numbers more for its own helper processes."""
    import re

    return re.sub(r"(?m)^\s*\d+ ", "N ", text)


def test_exec_sees_what_the_container_sees(kk, docker, pair):
    mine = kk("exec", "sleeper", "sh", "-c", FACTS)
    theirs = docker("exec", "kk-sleeper", "sh", "-c", FACTS)
    assert mine.code == theirs.code == 0
    a, b = no_pids(mine.out), no_pids(theirs.out)
    assert a == b, "\n".join(__import__("difflib").unified_diff(b.splitlines(), a.splitlines(), "docker", "mine", lineterm=""))
    assert "sleep 300" in mine.out  # the container's PID 1 is in its process list
    # the same number of mounts, but the six device files that are bind mounts here
    count = "wc -l < /proc/self/mountinfo"
    assert int(kk("exec", "sleeper", "sh", "-c", count).out) == int(docker("exec", "kk-sleeper", "sh", "-c", count).out) + 6


def test_exec_options(kk, docker, pair):
    for argv in (["-e", "X=1", "-e", "Y=a b"], ["-u", "nobody"], ["-w", "/usr/share"], ["-u", "daemon", "-w", "/var", "-e", "Z=3"]):
        script = "id; pwd; echo $X $Y $Z; grep -E '^(CapEff|CapPrm):' /proc/self/status; echo $HOME"
        mine = kk("exec", *argv, "sleeper", "sh", "-c", script)
        theirs = docker("exec", *argv, "kk-sleeper", "sh", "-c", script)
        assert mine.out == theirs.out and mine.code == theirs.code, argv


def test_exec_exit_codes_and_errors(kk, docker, pair):
    assert kk("exec", "sleeper", "sh", "-c", "exit 9").code == 9
    assert kk("exec", "sleeper", "true").code == 0
    out = kk("exec", "sleeper", "/no/such/program")
    assert out.code == 127 and "not found" in out.err
    for program, code in (("/no/such/program", 127), ("/etc/passwd", 126)):  # missing: 127, not executable: 126, as in Docker
        assert kk("exec", "sleeper", program).code == docker("exec", "kk-sleeper", program).code == code, program
    assert kk("exec", "nonexistent", "true").code != 0


def test_exec_shares_the_namespaces_of_the_container(kk, pair):
    script = "for n in ipc uts net pid mnt cgroup; do printf '%s=' $n; readlink /proc/self/ns/$n; done"
    # a process of the container and an exec'd one: the same namespaces; the host's are different
    ours = kk("exec", "sleeper", "sh", "-c", script).out.splitlines()
    init = kk("exec", "sleeper", "sh", "-c", "for n in ipc uts net pid mnt cgroup; do printf '%s=' $n; readlink /proc/1/ns/$n; done").out.splitlines()
    assert ours == init and len(ours) == 6
    for line in ours:
        name, _, value = line.partition("=")
        assert value != os.readlink("/proc/self/ns/%s" % name), name


def test_exec_runs_in_the_cgroup_of_the_container(kk, runtime, pair):
    cid = runtime.resolve("sleeper")
    # while an exec'd process runs, the cgroup of the container holds it
    import subprocess, sys

    p = subprocess.Popen([sys.executable, "-m", "kendi_konteyner", "exec", "sleeper", "sleep", "3"], env=dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"), KONTEYNER_ROOT=runtime.store.root))
    time.sleep(1)
    try:
        procs = open("/sys/fs/cgroup/kendi-konteyner/%s/cgroup.procs" % cid).read().split()
        assert len(procs) >= 2  # the container's PID 1 and the sleep
    finally:
        p.wait()
    assert p.returncode == 0


def test_exec_counts_against_the_limits(kk, image):
    kk("run", "-d", "--name", "limited", "--network", "none", "--pids-limit", "5", IMAGE, "sleep", "300")
    time.sleep(0.5)
    out = kk("exec", "limited", "sh", "-c", "for i in 1 2 3 4 5 6 7 8; do sleep 20 & done 2>&1; echo done")
    assert out.code != 0 or "Resource temporarily unavailable" in out.err + out.out


def test_exec_into_a_stopped_container_is_refused(kk, image):
    kk("run", "--name", "gone", "--network", "none", IMAGE, "true")
    out = kk("exec", "gone", "true")
    assert out.code != 0 and "not running" in out.err


def test_exec_cannot_leave_the_container(kk, pair):
    out = kk("exec", "sleeper", "sh", "-c", "ls /var/tmp 2>&1 | head -1; cat /proc/1/cmdline | tr '\\0' ' '; ls /proc/1/root | head -3 | tr '\\n' ' '")
    assert "sleep 300" in out.out and "kk-" not in out.out
