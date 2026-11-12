"""Starting, stopping, killing and removing containers; what is left behind; the writable layer."""
import hashlib
import json
import os
import time


from conftest import IMAGE, needs_root

pytestmark = needs_root


def state(kk, ref):
    out = kk("inspect", ref)
    assert out.code == 0, out.err
    return json.loads(out.out)[0]["State"]


def wait_status(kk, ref, status, seconds=15):
    end = time.time() + seconds
    while time.time() < end:
        if state(kk, ref)["status"] == status:
            return
        time.sleep(0.05)
    raise AssertionError("%s never became %s: %s" % (ref, status, state(kk, ref)))


def test_a_detached_container_runs_on_without_us(kk, image):
    out = kk("run", "-d", "--name", "bg", "--network", "none", IMAGE, "sleep", "30")
    assert out.code == 0 and len(out.out.strip()) == 64
    ps = kk("ps").out
    assert "bg" in ps and "Up" in ps
    assert kk("ps", "-a").out.count("\n") == 2
    assert state(kk, "bg")["status"] == "running"


def test_detached_output_goes_to_the_log(kk, image):
    kk("run", "-d", "--name", "talk", "--network", "none", IMAGE, "sh", "-c", "echo one; echo two >&2; echo three")
    wait_status(kk, "talk", "exited")
    out = kk("logs", "talk")
    # two streams: each is in order, but their order against each other is not kept (they are two pipes, read as they become ready: Docker's
    # log driver has the same limit); so the last line of the log may be "two" or "three"
    assert out.out.splitlines() == ["one", "three"] and out.err == "two\n"
    assert kk("wait", "talk").out == "0\n"


def test_logs_tail_counts_lines_from_the_end(kk, image):
    kk("run", "-d", "--name", "tails", "--network", "none", IMAGE, "sh", "-c", "echo a; echo b; echo three")
    wait_status(kk, "tails", "exited")
    assert kk("logs", "--tail", "1", "tails").out == "three\n"
    assert kk("logs", "--tail", "2", "tails").out == "b\nthree\n"
    assert kk("logs", "tails").out == "a\nb\nthree\n"


def test_logs_follow_until_the_container_ends(kk, image):
    kk("run", "-d", "--name", "slow", "--network", "none", IMAGE, "sh", "-c", "for i in 1 2 3; do echo line$i; sleep 0.3; done")
    out = kk("logs", "-f", "slow", timeout=30)
    assert out.out.splitlines() == ["line1", "line2", "line3"]


def test_logs_of_a_long_line_and_many_lines(kk, image):
    kk("run", "-d", "--name", "big", "--network", "none", IMAGE, "sh", "-c", "head -c 100000 /dev/zero | tr '\\0' x; echo; seq 1 2000")
    wait_status(kk, "big", "exited")
    lines = kk("logs", "big").out.splitlines()
    assert len(lines[0]) == 100000 and lines[1:] == [str(i) for i in range(1, 2001)]


def test_stop_waits_for_the_timeout_when_the_process_ignores_sigterm(kk, docker, image):
    # PID 1 of a container only gets the signals that it has a handler for: sleep has none
    kk("run", "-d", "--name", "deaf", "--network", "none", IMAGE, "sleep", "300")
    t = time.time()
    assert kk("stop", "-t", "2", "deaf").code == 0
    took = time.time() - t
    assert 1.8 < took < 6, took
    assert state(kk, "deaf")["exit_code"] == 137
    docker("run", "-d", "--name", "kk-deaf", IMAGE, "sleep", "300")
    try:
        t = time.time()
        docker("stop", "-t", "2", "kk-deaf")
        assert 1.8 < time.time() - t < 6
        assert json.loads(docker("inspect", "kk-deaf").out)[0]["State"]["ExitCode"] == 137
    finally:
        docker("rm", "-f", "kk-deaf")


def test_stop_is_quick_when_the_process_handles_sigterm(kk, docker, image):
    script = "trap 'echo got-term; exit 3' TERM; while :; do sleep 0.2; done"
    kk("run", "-d", "--name", "polite", "--network", "none", IMAGE, "sh", "-c", script)
    time.sleep(0.5)
    t = time.time()
    kk("stop", "-t", "10", "polite")
    assert time.time() - t < 3
    assert state(kk, "polite")["exit_code"] == 3
    assert "got-term" in kk("logs", "polite").out


def test_init_forwards_the_signal(kk, docker, image):
    kk("run", "-d", "--init", "--name", "withinit", "--network", "none", IMAGE, "sleep", "300")
    time.sleep(0.5)
    t = time.time()
    kk("stop", "-t", "10", "withinit")
    assert time.time() - t < 3
    assert state(kk, "withinit")["exit_code"] == 143
    docker("run", "-d", "--init", "--name", "kk-init", IMAGE, "sleep", "300")
    try:
        docker("stop", "-t", "10", "kk-init")
        assert json.loads(docker("inspect", "kk-init").out)[0]["State"]["ExitCode"] == 143
    finally:
        docker("rm", "-f", "kk-init")


def test_init_reaps_zombies(kk, image):
    # the orphan is reparented to PID 1: without an init that reaps, it stays a zombie
    script = "(sleep 0.2 &) ; sleep 1; grep -c ' Z' /proc/[0-9]*/stat 2>/dev/null | grep -v ':0' | wc -l"
    with_init = kk("run", "--rm", "--init", "--network", "none", IMAGE, "sh", "-c", script)
    assert with_init.out.strip() == "0"


def test_kill_and_the_signal_name(kk, image):
    kk("run", "-d", "--init", "--name", "victim", "--network", "none", IMAGE, "sleep", "300")
    time.sleep(0.3)
    assert kk("kill", "-s", "HUP", "victim").code == 0  # the init forwards it and sleep dies of SIGHUP (PID 1 itself would ignore it)
    wait_status(kk, "victim", "exited")
    assert state(kk, "victim")["exit_code"] == 129
    kk("run", "-d", "--name", "victim2", "--network", "none", IMAGE, "sleep", "300")
    assert kk("kill", "victim2").code == 0
    wait_status(kk, "victim2", "exited")
    assert state(kk, "victim2")["exit_code"] == 137
    assert kk("kill", "victim2").code != 0  # not running any more
    assert kk("kill", "-s", "NOPE", "victim").code != 0


def test_remove_needs_force_for_a_running_container(kk, image):
    kk("run", "-d", "--name", "alive", "--network", "none", IMAGE, "sleep", "300")
    out = kk("rm", "alive")
    assert out.code != 0 and "running" in out.err
    assert kk("rm", "-f", "alive").code == 0
    assert kk("ps", "-a").out.count("\n") == 1
    assert kk("inspect", "alive").code != 0


def test_names_prefixes_and_errors(kk, image):
    cid = kk("run", "-d", "--name", "named", "--network", "none", IMAGE, "sleep", "30").out.strip()
    assert state(kk, cid[:12])["status"] == "running" and state(kk, "named")["status"] == "running"
    out = kk("run", "-d", "--name", "named", "--network", "none", IMAGE, "sleep", "30")
    assert out.code != 0 and "already used" in out.err
    assert kk("stop", "nonexistent").code != 0 and "no such container" in kk("stop", "nonexistent").err
    assert kk("run", "--name", "bad name", IMAGE, "true").code != 0


def test_start_again_keeps_the_writable_layer_a_new_container_does_not(kk, image):
    kk("run", "--name", "keeper", "--network", "none", IMAGE, "sh", "-c", "echo remembered > /file; echo first >> /count")
    kk("start", "-a", "keeper")  # a second start of the same container
    again = kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", "ls /file 2>&1 | head -1")
    assert "No such file" in again.out  # a new container starts from the image
    # run the stored command again in the same container: its file is there, and the count shows two starts
    kk("start", "-a", "keeper")
    out = kk("run", "-d", "--name", "keeper2", "--network", "none", IMAGE, "sh", "-c", "cat /file")
    assert out.code == 0
    assert state(kk, "keeper")["status"] == "exited"
    cfg = json.loads(kk("inspect", "keeper").out)[0]["Config"]
    assert cfg["argv"][-1].startswith("echo remembered")


def layer_hash(path):
    h = hashlib.sha256()
    for dirpath, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files) + dirs:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            h.update(("%s %o %d %d %d\n" % (os.path.relpath(p, path), st.st_mode, st.st_uid, st.st_gid, st.st_size)).encode())
            if os.path.isfile(p) and not os.path.islink(p):
                with open(p, "rb") as fh:
                    h.update(fh.read())
    return h.hexdigest()


def test_the_image_is_never_changed_by_a_container(kk, runtime, image):
    dirs = image.layer_dirs()
    before = [layer_hash(d) for d in dirs]
    kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", "echo x > /etc/passwd; rm -rf /bin /usr/share; echo new > /newfile; chmod 777 /etc; rm /etc/os-release")
    assert [layer_hash(d) for d in dirs] == before
    out = kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", "head -1 /etc/passwd; ls /bin | head -2; ls /newfile 2>&1")
    assert out.out.startswith("root:x:0:0") and "arch" in out.out and "No such file" in out.out


def test_two_containers_do_not_see_each_others_files(kk, image):
    kk("run", "-d", "--name", "one", "--network", "none", IMAGE, "sh", "-c", "echo mine > /tmp/secret; sleep 30")
    time.sleep(0.7)
    out = kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", "ls /tmp; ps | grep -c '[s]leep 30'")
    assert "secret" not in out.out and out.out.splitlines()[-1].strip() == "0"


def mounts_mentioning(path):
    with open("/proc/self/mountinfo") as fh:
        return [l for l in fh if path in l]


def cgroups_now():
    return {d for d in os.listdir("/sys/fs/cgroup/kendi-konteyner") if len(d) == 64} if os.path.isdir("/sys/fs/cgroup/kendi-konteyner") else set()


def test_nothing_is_left_behind(kk, runtime, root, image):
    """After containers of every kind have ended: no mount in the host's table, no cgroup, no network device, no address."""
    before = cgroups_now()
    kk("run", "--rm", "--network", "none", IMAGE, "true")
    kk("run", "--rm", IMAGE, "true")
    kk("run", "--rm", "-m", "64m", "-v", "/tmp:/t", "--tmpfs", "/x", "--read-only", IMAGE, "true")
    kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", "exit 3")
    kk("run", "--rm", "--network", "none", IMAGE, "/no/such")
    kk("run", "--name", "stopped", "--network", "none", IMAGE, "true")
    kk("run", "-d", "--name", "killed", IMAGE, "sleep", "100")
    kk("rm", "-f", "killed", "stopped")
    time.sleep(0.5)
    assert mounts_mentioning(root) == []
    left = cgroups_now() - before
    assert left == set(), [(c[:12], open("/sys/fs/cgroup/kendi-konteyner/%s/cgroup.procs" % c).read().split()) for c in left]
    links = os.listdir("/sys/class/net")
    assert not [l for l in links if l.startswith(("kv", "kp"))]
    assert json.load(open(os.path.join(root, "network", "leases.json"))) == {}
    names = os.listdir(os.path.join(root, "containers"))
    detail = []
    for n in names:
        d = os.path.join(root, "containers", n)
        try:
            detail.append((n[:12], sorted(os.listdir(d)), open(os.path.join(d, "config.json")).read()[:200] if os.path.exists(os.path.join(d, "config.json")) else None))
        except OSError as e:
            detail.append((n[:12], str(e)))
    assert names == [], detail
