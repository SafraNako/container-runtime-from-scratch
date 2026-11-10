"""Memory, process and CPU limits (cgroups v2), against the same limits in Docker."""
import json


from conftest import IMAGE, needs_docker

pytestmark = needs_docker

HAS_CGROUP2 = __import__("os").path.exists("/sys/fs/cgroup/cgroup.controllers")


def inspect_state(kk, name):
    out = kk("inspect", name)
    assert out.code == 0, out.err
    return json.loads(out.out)[0]["State"]


def test_the_limits_are_written_where_the_container_can_read_them(kk, docker, image):
    script = "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max /sys/fs/cgroup/cpu.max; cat /proc/self/cgroup"
    mine = kk("run", "--rm", "--network", "none", "-m", "64m", "--pids-limit", "50", "--cpus", "1.5", IMAGE, "sh", "-c", script)
    theirs = docker("run", "--rm", "--network", "none", "-m", "64m", "--pids-limit", "50", "--cpus", "1.5", IMAGE, "sh", "-c", script)
    assert mine.out == theirs.out == "67108864\n50\n150000 100000\n0::/\n"


def test_without_limits_everything_is_max(kk, docker, image):
    script = "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max /sys/fs/cgroup/cpu.max"
    mine = kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", script)
    theirs = docker("run", "--rm", "--network", "none", IMAGE, "sh", "-c", script)
    assert mine.out == theirs.out == "max\nmax\nmax 100000\n"


def test_a_process_that_uses_too_much_memory_is_killed(kk, docker, image):
    # tail keeps reading a "line" that never ends, so its memory grows until the limit
    mine = kk("run", "--name", "oom1", "--network", "none", "-m", "32m", IMAGE, "tail", "/dev/zero")
    theirs = docker("run", "--name", "kk-oom1", "--network", "none", "-m", "32m", IMAGE, "tail", "/dev/zero")
    try:
        assert mine.code == theirs.code == 137
        assert inspect_state(kk, "oom1")["oom_killed"] is True
        assert json.loads(docker("inspect", "kk-oom1").out)[0]["State"]["OOMKilled"] is True
    finally:
        docker("rm", "-f", "kk-oom1")


def test_a_process_within_the_limit_is_left_alone(kk, image):
    out = kk("run", "--name", "ok1", "--network", "none", "-m", "64m", IMAGE, "sh", "-c", "dd if=/dev/zero of=/dev/null bs=1M count=200 2>&1 | tail -1; head -c 10000000 /dev/zero | wc -c")
    assert out.code == 0 and "10000000" in out.out
    assert inspect_state(kk, "ok1")["oom_killed"] is False


def test_the_memory_of_the_cgroup_is_counted(kk, image):
    import time

    out = kk("run", "-d", "--name", "mem2", "--network", "none", "-m", "100m", IMAGE, "sh", "-c", "head -c 20000000 /dev/zero | tail -c 1 > /dev/null; sleep 5")
    assert out.code == 0
    cid = out.out.strip()
    time.sleep(1)
    stats = kk("stats").out
    rows = [l for l in stats.splitlines() if l.startswith(cid[:12])]
    assert rows and "104.9MB" in rows[0]  # the limit, 100 MiB, as "MB" of 1000 * 1000
    kk("kill", "mem2")


def count_script(n):
    """Starts ``n`` sleeping processes.  The shell gives up at the first one that cannot be started, so each one writes its number to a file first
    and the shell's own commands (no new process) print the file when the shell exits."""
    return (
        "trap 'while read -r l; do echo $l; done < /tmp/started' EXIT; for i in $(seq 1 %d); do sleep 20 & echo $i >> /tmp/started; done" % n
    )


def test_the_number_of_processes_is_limited(kk, docker, image):
    script = count_script(20)
    mine = kk("run", "--rm", "--network", "none", "--pids-limit", "8", IMAGE, "sh", "-c", script)
    theirs = docker("run", "--rm", "--network", "none", "--pids-limit", "8", IMAGE, "sh", "-c", script)
    started = mine.out.split()
    assert mine.out == theirs.out and mine.code == theirs.code
    assert len(started) == 7, started  # the shell is one of the 8 processes
    assert "Resource temporarily unavailable" in mine.err and "Resource temporarily unavailable" in theirs.err
    unlimited = kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", script)
    assert len(unlimited.out.split()) == 20


def test_a_fork_bomb_stays_inside_its_limit(kk, image):
    out = kk("run", "--name", "bomb", "--network", "none", "--pids-limit", "30", "-m", "64m", IMAGE, "sh", "-c",
             "b() { b | b & }; b 2>/dev/null; sleep 1; echo survived; cat /sys/fs/cgroup/pids.current /sys/fs/cgroup/pids.events | tr '\\n' ' '")
    assert out.code == 0 and "survived" in out.out
    current = int(out.out.split("survived")[1].split()[0])
    assert current <= 30
    assert "max" in out.out.split("survived")[1]  # pids.events counts the forks that were refused


def busy_script(seconds):
    return (
        "u() { awk '/usage_usec/{print $2}' /sys/fs/cgroup/cpu.stat; }; a=$(u); end=$(( $(date +%%s) + %d )); "
        "while [ $(date +%%s) -lt $end ]; do :; done; b=$(u); echo $(( (b - a) / 1000 ))" % seconds
    )


def test_cpu_limit_shares_the_time(kk, docker, image):
    # two busy loops in a container that may use half a CPU: in 3 seconds it gets about 1.5 seconds of CPU time
    script = busy_script(3).replace("while [", "( while [").replace("do :; done;", "do :; done ) & while [ $(date +%s) -lt $end ]; do :; done;")
    mine = kk("run", "--rm", "--network", "none", "--cpus", "0.5", IMAGE, "sh", "-c", script)
    theirs = docker("run", "--rm", "--network", "none", "--cpus", "0.5", IMAGE, "sh", "-c", script)
    a, b = int(mine.out.split()[-1]), int(theirs.out.split()[-1])
    assert 1000 < a < 2200 and 1000 < b < 2200, (a, b)
    assert abs(a - b) < 700
    full = kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", script)
    assert int(full.out.split()[-1]) > 2.2 * 1000 or int(full.out.split()[-1]) > a  # without the limit it gets more
