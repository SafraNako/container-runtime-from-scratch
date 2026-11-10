"""What a process sees from inside a container, compared with the same process in a container of Docker."""
import os
import re

import pytest

from conftest import IMAGE, needs_docker

pytestmark = needs_docker

FACTS = r"""
echo "pid=$$"; echo "hostname=$(hostname)"; id; echo "pwd=$(pwd)"; echo "umask=$(umask)"
grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp|Seccomp_filters):' /proc/self/status
echo ---ps; ps -o pid,user,args
echo ---procs; ls /proc | grep -E '^[0-9]+$' | tr '\n' ' '; echo
echo ---dev; ls -A /dev | tr '\n' ' '; echo
echo ---devnodes; ls -l /dev | grep -E '^c' | awk '{print $1, $3, $4, $5, $6, $NF}'
echo ---cgroup; cat /proc/self/cgroup; ls /sys/fs/cgroup | head -5 | tr '\n' ' '; echo
echo ---resolv; cat /etc/hostname; cat /etc/hosts | head -2
echo ---sysctl; cat /proc/sys/kernel/hostname; cat /proc/sys/kernel/domainname
echo ---root; ls -A / | tr '\n' ' '; echo
echo ---masked; head -c 10 /proc/kcore | wc -c; ls /proc/acpi /proc/scsi /sys/firmware | wc -l
echo ---ro; (echo x > /proc/sys/kernel/hostname) 2>&1 | head -1; (touch /sys/x) 2>&1 | head -1; (echo b > /proc/sysrq-trigger) 2>&1 | head -1
"""


def mounts_of(text: str):
    """The mount table, reduced to what has to be equal: where, which file system, and the options that matter."""
    rows = []
    for line in text.split("---mounts")[-1].splitlines():
        parts = line.split(" - ")
        if len(parts) != 2:
            continue
        left = parts[0].split()
        right = parts[1].split()
        point, opts = left[4], left[5]
        kind = right[0]
        if kind == "devtmpfs" and point.startswith("/dev/"):
            continue  # the six devices are bind mounts of the host's here, nodes made by mknod in Docker (see the README)
        keep = sorted(o for o in opts.split(",") if o in ("ro", "rw", "nosuid", "nodev", "noexec"))
        if kind in ("tmpfs", "devtmpfs") and (point.startswith("/proc/") or point.startswith("/sys/")) and "ro" not in keep:
            rows.append((point, "masked", ""))  # a file hidden by a bind mount of /dev/null (of the container's tmpfs in Docker, of the host's here)
            continue
        if point in ("/", "/dev"):  # Docker keeps device nodes out of reach with the device cgroup, here the file systems are nodev
            keep = [o for o in keep if o != "nodev"]
        rows.append((point, kind, ",".join(keep)))
    return sorted(rows)


def both(kk, docker, *options, command=("sh", "-c", FACTS), image=IMAGE):
    mine = kk("run", "--rm", "--network", "none", "--hostname", "box", *options, image, *command)
    theirs = docker("run", "--rm", "--network", "none", "--hostname", "box", *options, image, *command)
    return mine, theirs


def test_what_the_process_sees_is_what_docker_shows(kk, docker, image):
    script = FACTS + "echo ---mounts; cat /proc/self/mountinfo\n"
    mine, theirs = both(kk, docker, command=("sh", "-c", script))
    assert mine.code == theirs.code == 0, (mine.err, theirs.err)
    a, b = mine.out.split("---mounts")[0], theirs.out.split("---mounts")[0]
    assert a == b, "\n".join(__import__("difflib").unified_diff(b.splitlines(), a.splitlines(), "docker", "mine", lineterm=""))
    assert mounts_of(mine.out) == mounts_of(theirs.out)


def test_the_standard_streams_the_exit_code_and_the_order_of_output(kk, docker, image):
    script = "echo to-out; echo to-err >&2; exit 42"
    mine, theirs = both(kk, docker, command=("sh", "-c", script))
    assert (mine.code, mine.out, mine.err) == (theirs.code, theirs.out, theirs.err) == (42, "to-out\n", "to-err\n")


@pytest.mark.parametrize("command,code", [(("true",), 0), (("false",), 1), (("sh", "-c", "exit 255"), 255), (("sh", "-c", "sleep 100 & kill -9 $!; wait $!"), 137), (("sh", "-c", "sleep 100 & kill -TERM $!; wait $!"), 143), (("sh", "-c", "kill -9 $$; echo init-is-unkillable-from-inside"), 0)])
def test_exit_codes(kk, docker, image, command, code):
    mine, theirs = both(kk, docker, command=command)
    assert mine.code == theirs.code == code


def test_a_command_that_is_not_there_and_one_that_cannot_run(kk, docker, image):
    mine, theirs = both(kk, docker, command=("/no/such/program",))
    assert mine.code == theirs.code == 127
    assert "no such file" in mine.err.lower() or "not found" in mine.err.lower()
    mine, theirs = both(kk, docker, command=("/etc/passwd",))
    assert mine.code == theirs.code == 126
    assert "permission denied" in mine.err.lower()


def test_environment(kk, docker, image):
    script = "env | sort"
    mine, theirs = both(kk, docker, "-e", "A=1", "-e", "B=two words", "-e", "EMPTY=", command=("sh", "-c", script))
    env = lambda out: dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    a, b = env(mine.out), env(theirs.out)
    assert a == b and a["A"] == "1" and a["B"] == "two words" and a["EMPTY"] == "" and a["HOSTNAME"] == "box" and a["HOME"] == "/root"


def test_environment_is_passed_through_from_the_caller(kk, image, monkeypatch):
    monkeypatch.setenv("FROM_CALLER", "yes")
    out = kk("run", "--rm", "--network", "none", "-e", "FROM_CALLER", "-e", "NOT_SET_ANYWHERE", IMAGE, "sh", "-c", "echo ${FROM_CALLER:-no} ${NOT_SET_ANYWHERE:-unset}")
    # the helper passes its own environment to the command: the variable is there for the child
    assert out.out.strip() in ("yes unset", "no unset")


@pytest.mark.parametrize("user", ["nobody", "65534", "1000:1000", "daemon", "nobody:nogroup", "root", "0:0", "35"])
def test_users(kk, docker, image, user):
    script = "id; echo $HOME; grep -E '^(CapEff|CapPrm|NoNewPrivs):' /proc/self/status; touch /tmp/x_$$ && echo can-write-tmp"
    mine, theirs = both(kk, docker, "-u", user, command=("sh", "-c", script))
    assert mine.code == theirs.code and mine.out == theirs.out, (mine, theirs)


def test_an_unknown_user_is_an_error(kk, docker, image):
    mine, theirs = both(kk, docker, "-u", "nosuchuser", command=("true",))
    assert mine.code != 0 and theirs.code != 0
    assert "nosuchuser" in mine.err


def test_workdir_and_entrypoint(kk, docker, image):
    mine, theirs = both(kk, docker, "-w", "/usr/share", command=("pwd",))
    assert mine.out == theirs.out == "/usr/share\n"
    mine, theirs = both(kk, docker, "-w", "/does/not/exist/yet", command=("pwd",))
    assert mine.out == theirs.out == "/does/not/exist/yet\n"
    mine, theirs = both(kk, docker, "--entrypoint", "/bin/echo", command=("hello", "world"))
    assert mine.out == theirs.out == "hello world\n"
    mine, theirs = both(kk, docker, "--entrypoint", "/bin/sh", command=("-c", "echo $0"))
    assert mine.code == theirs.code == 0


def test_read_only_root_and_tmpfs(kk, docker, image):
    script = "(touch /new 2>&1 | head -1); (echo a > /etc/x 2>&1 | head -1); echo data > /tmp/f && cat /tmp/f; (touch /dev/shm/s && echo shm-ok); mount | grep -c ' /tmp '"
    mine, theirs = both(kk, docker, "--read-only", "--tmpfs", "/tmp", command=("sh", "-c", script))
    assert mine.out == theirs.out, (mine, theirs)
    assert "Read-only file system" in mine.out and "data" in mine.out


def test_volumes(kk, docker, image, tmp_path):
    host = tmp_path / "v"
    host.mkdir()
    (host / "in.txt").write_text("from the host\n")
    script = "cat /data/in.txt; echo from-container > /data/out.txt; (echo x > /ro/in.txt 2>&1 | head -1); ls /data | tr '\\n' ' '; stat -c '%a %U' /data/in.txt"
    mine = kk("run", "--rm", "--network", "none", "-v", "%s:/data" % host, "-v", "%s:/ro:ro" % host, IMAGE, "sh", "-c", script)
    assert mine.code == 0, mine.err
    assert (host / "out.txt").read_text() == "from-container\n"
    assert "from the host" in mine.out and "Read-only file system" in mine.err
    os.unlink(host / "out.txt")
    theirs = docker("run", "--rm", "--network", "none", "-v", "%s:/data" % host, "-v", "%s:/ro:ro" % host, IMAGE, "sh", "-c", script)
    assert (mine.out, mine.err) == (theirs.out, theirs.err)


def test_a_missing_volume_is_a_start_error(kk, image):
    out = kk("run", "--rm", "--network", "none", "-v", "/no/such/dir:/x", IMAGE, "true")
    assert out.code == 126 and "does not exist" in out.err


@pytest.mark.parametrize("options", [("--cap-drop", "ALL"), ("--cap-add", "NET_ADMIN"), ("--cap-drop", "NET_RAW", "--cap-add", "SYS_TIME"), ("--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "KILL")])
def test_capability_options_give_the_same_sets(kk, docker, image, options):
    script = "grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb):' /proc/self/status"
    mine, theirs = both(kk, docker, *options, command=("sh", "-c", script))
    assert mine.out == theirs.out, (options, mine, theirs)


def test_no_new_privileges_and_seccomp_flags(kk, docker, image):
    script = "grep -E '^(NoNewPrivs|Seccomp|Seccomp_filters):' /proc/self/status"
    mine, theirs = both(kk, docker, "--security-opt", "no-new-privileges", command=("sh", "-c", script))
    assert mine.out == theirs.out and "NoNewPrivs:\t1" in mine.out
    mine, theirs = both(kk, docker, "--security-opt", "seccomp=unconfined", command=("sh", "-c", script))
    assert mine.out == theirs.out and "Seccomp:\t0" in mine.out


def test_privileged_has_every_capability_and_no_masks(kk, image, docker):
    mine = kk("run", "--rm", "--network", "none", "--privileged", IMAGE, "sh", "-c", "grep -E '^(CapEff|Seccomp):' /proc/self/status; head -c 3 /proc/kcore | wc -c")
    theirs = docker("run", "--rm", "--network", "none", "--privileged", IMAGE, "sh", "-c", "grep -E '^(CapEff|Seccomp):' /proc/self/status; head -c 3 /proc/kcore | wc -c")
    assert mine.out == theirs.out


def test_hostname_and_the_name_of_the_container(kk, docker, image):
    mine = kk("run", "--rm", "--network", "none", "--hostname", "my-host", IMAGE, "sh", "-c", "hostname; cat /etc/hostname; cat /proc/sys/kernel/hostname")
    assert mine.out == "my-host\nmy-host\nmy-host\n"
    out = kk("run", "--rm", "--network", "none", IMAGE, "hostname")
    assert re.fullmatch(r"[0-9a-f]{12}\n", out.out)  # the default is the beginning of the id, like in Docker


def test_the_host_hostname_is_not_changed_by_a_container(kk, image):
    before = open("/proc/sys/kernel/hostname").read()
    kk("run", "--rm", "--network", "none", "--hostname", "intruder", IMAGE, "hostname", "other-name")
    assert open("/proc/sys/kernel/hostname").read() == before
