"""What a process in a container must not be able to do, and how Docker answers the same attempts."""
import socket
import subprocess


from conftest import IMAGE, needs_docker

pytestmark = needs_docker


def both(kk, docker, *options, script):
    a = kk("run", "--rm", "--network", "none", *options, IMAGE, "sh", "-c", script)
    b = docker("run", "--rm", "--network", "none", *options, IMAGE, "sh", "-c", script)
    return a, b


def test_mount_and_other_privileged_calls_are_refused(kk, docker, image):
    script = "mount -t tmpfs none /mnt 2>&1; hostname other 2>&1; date -s '2000-01-01' 2>&1 | head -1; mknod /dev/x b 8 0 && echo made-node; ip link add dummy0 type dummy 2>&1 | head -1"
    mine, theirs = both(kk, docker, script=script)
    assert mine.out == theirs.out and "Operation not permitted" in mine.out and "Permission denied" not in mine.out.split("made-node")[0]


def test_a_device_node_can_be_made_but_not_used(kk, docker, image):
    # CAP_MKNOD is in Docker's default set; the files systems of the container do not allow device nodes (here), a device cgroup denies them (Docker)
    script = "mknod /dev/sdx b 8 0 && echo made; (head -c 512 /dev/sdx > /tmp/sector) 2>&1 | head -1; test -s /tmp/sector && echo READ-THE-DISK; mknod /dev/mem c 1 1 && (head -c 1 /dev/mem) 2>&1 | head -1; test -e /dev/vda && echo host-disk-visible"
    mine, theirs = both(kk, docker, script=script)
    for out in (mine.out, theirs.out):
        assert "made" in out and "READ-THE-DISK" not in out and "host-disk-visible" not in out
        assert "Permission denied" in out or "Operation not permitted" in out
    assert mine.code == theirs.code


def test_the_host_is_not_visible(kk, docker, image):
    # the number of processes of a pipeline depends on when it is counted: look at the highest pid instead (a small number: nothing else is there)
    script = "ls /var/tmp | wc -l; ls /Users /home 2>&1 | head -3; cat /proc/1/cmdline | tr '\\0' ' '; echo; ls /proc | grep -E '^[0-9]+$' | sort -n | tail -1 | awk '{print ($1 < 10) ? \"few-pids\" : \"many-pids\"}'; ls /sys/class/net | tr '\\n' ' '"
    mine, theirs = both(kk, docker, script=script)
    assert mine.out == theirs.out, (mine, theirs)
    assert mine.out.splitlines()[0] == "0" and "few-pids" in mine.out


def test_host_processes_cannot_be_reached(kk, image):
    victim = subprocess.Popen(["sleep", "60"])
    try:
        out = kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", "kill -9 %d 2>&1; echo $?" % victim.pid)
        assert "No such process" in out.out and out.out.strip().endswith("1")
        assert victim.poll() is None  # still alive
    finally:
        victim.kill()
        victim.wait()


def test_the_loopback_of_the_host_is_not_reachable_without_the_host_network(kk, image):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        isolated = kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", "nc -z -w 2 127.0.0.1 %d && echo CONNECTED || echo refused" % port)
        assert isolated.out.strip() == "refused"
        host = kk("run", "--rm", "--network", "host", IMAGE, "sh", "-c", "nc -z -w 2 127.0.0.1 %d && echo CONNECTED || echo refused" % port)
        assert host.out.strip() == "CONNECTED"  # the host network is the host's: as it should be
    finally:
        srv.close()


def test_the_old_root_is_gone(kk, image):
    """After pivot_root the host's file systems are not mounted in the container: its mount table lists only what was put there."""
    out = kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", "awk '{print $5}' /proc/self/mountinfo | sort | tr '\\n' ' '")
    points = out.out.split()
    assert "/" in points and not [p for p in points if p.startswith(("/Users", "/home", "/var/lib", "/run/", "/mnt/", "/boot"))]
    assert kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", "ls /proc/1/root/etc/alpine-release; ls /proc/1/root/var/tmp | wc -l").out.endswith("0\n")


def test_proc_and_sys_cannot_be_used_to_reach_the_host(kk, docker, image):
    script = (
        "head -c 4 /proc/kcore | wc -c; cat /proc/keys | wc -c; cat /proc/timer_list | wc -c; ls /proc/scsi /proc/acpi /sys/firmware | wc -l; "
        "(echo 1 > /proc/sys/kernel/panic) 2>&1 | head -1; (echo b > /proc/sysrq-trigger) 2>&1 | head -1; (mkdir /sys/fs/cgroup/x) 2>&1 | head -1; "
        "(echo 0 > /sys/kernel/uevent_helper) 2>&1 | head -1; mount -o remount,rw /proc/sys 2>&1 | head -1"
    )
    mine, theirs = both(kk, docker, script=script)
    assert mine.out == theirs.out and mine.code == theirs.code
    assert "Read-only file system" in mine.out


def test_unshare_is_refused_by_seccomp_and_allowed_without_it(kk, docker, image):
    script = "unshare -u true 2>&1; echo status=$?"
    mine, theirs = both(kk, docker, script=script)
    assert mine.out == theirs.out and "Operation not permitted" in mine.out
    allowed = "unshare -u sh -c 'hostname inside-new-uts; hostname'; hostname"
    options = ("--cap-add", "SYS_ADMIN", "--security-opt", "seccomp=unconfined")
    mine, theirs = both(kk, docker, *options, "--hostname", "outer-name", script=allowed)
    assert mine.out == theirs.out and mine.out.splitlines()[0] == "inside-new-uts" and mine.out.splitlines()[1] != "inside-new-uts"


def test_seccomp_still_applies_to_a_new_process_of_exec(kk, image):
    kk("run", "-d", "--name", "sc", "--network", "none", IMAGE, "sleep", "60")
    out = kk("exec", "sc", "sh", "-c", "grep -E '^(Seccomp|Seccomp_filters):' /proc/self/status; unshare -m true 2>&1")
    assert "Seccomp:\t2" in out.out and "Operation not permitted" in out.out


def test_a_read_only_root_cannot_be_remounted_without_the_capability(kk, docker, image):
    script = "mount -o remount,rw / 2>&1 | head -1; touch /x 2>&1 | head -1"
    mine, theirs = both(kk, docker, "--read-only", script=script)
    assert mine.out == theirs.out and "Read-only file system" in mine.out


def test_a_user_cannot_become_root_again(kk, docker, image):
    script = "id -u; grep -E '^Cap(Eff|Prm|Bnd):' /proc/self/status; (echo x > /etc/passwd) 2>&1 | head -1; su -c id root 2>&1 | head -1"
    mine, theirs = both(kk, docker, "-u", "nobody", "--security-opt", "no-new-privileges", script=script)
    assert mine.out.splitlines()[:5] == theirs.out.splitlines()[:5] and mine.out.splitlines()[0] == "65534"
    assert "CapEff:\t0000000000000000" in mine.out and "Permission denied" in mine.out
