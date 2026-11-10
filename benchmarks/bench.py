"""How this runtime compares with Docker on two numbers: the time from the command to the exit of ``true``, and the memory of the
processes that stay outside the container while it runs.

    sudo python3 benchmarks/bench.py            # 20 runs of each
    sudo python3 benchmarks/bench.py 50

Needs Linux, root and (to compare) Docker.  Both start the same image (``alpine:3.19``, or ``$KONTEYNER_TEST_IMAGE``) from a local copy:
nothing is downloaded while the clock runs.  Docker has a daemon that is already running and a copy of the image that is already
unpacked; this runtime unpacks nothing either (the layers are unpacked once, by ``load``), but it is a Python process that starts, imports
its modules, and forks three times for every container.
"""
from __future__ import annotations

import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "src")
IMAGE = os.environ.get("KONTEYNER_TEST_IMAGE", "alpine:3.19")


def have_docker() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def timed(argv, env=None, runs=20):
    """Milliseconds of ``runs`` runs of a command (after one that is not counted: the files are in the cache)."""
    subprocess.run(argv, env=env, capture_output=True, check=True)
    out = []
    for _ in range(runs):
        start = time.perf_counter()
        subprocess.run(argv, env=env, capture_output=True, check=True)
        out.append((time.perf_counter() - start) * 1000)
    return out


def row(name, samples):
    samples = sorted(samples)
    p90 = samples[min(len(samples) - 1, int(len(samples) * 0.9))]
    return "| %-34s | %8.0f | %8.0f | %8.0f |" % (name, statistics.median(samples), samples[0], p90)


def rss_kb(pid: int) -> int:
    with open("/proc/%d/status" % pid) as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def ppid(pid: int) -> int:
    with open("/proc/%d/stat" % pid) as fh:
        return int(fh.read().rsplit(")", 1)[1].split()[1])


def children(pid: int):
    out = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                if ppid(int(entry)) == pid:
                    out.append(int(entry))
            except (OSError, ValueError, IndexError):
                pass
    return out


def main() -> int:
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        print("this needs Linux and root")
        return 1
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    docker = have_docker()
    root = tempfile.mkdtemp(prefix="kk-bench-", dir="/var/tmp")
    env = dict(os.environ, PYTHONPATH=SRC, KONTEYNER_ROOT=root, PYTHONDONTWRITEBYTECODE="1")
    kk = [sys.executable, "-m", "kendi_konteyner"]
    try:
        if docker:
            if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode != 0:
                subprocess.run(["docker", "pull", IMAGE], check=True, capture_output=True)
            tar = os.path.join(root, "image.tar")
            subprocess.run(["docker", "save", IMAGE, "-o", tar], check=True)
            subprocess.run(kk + ["load", tar], env=env, check=True, capture_output=True)
            os.unlink(tar)
        else:
            subprocess.run(kk + ["pull", IMAGE], env=env, check=True, capture_output=True)

        print("python %s, kernel %s, %d runs each (milliseconds)\n" % (sys.version.split()[0], os.uname().release, runs))
        print("| %-34s | %8s | %8s | %8s |" % ("run --rm IMAGE true", "median", "best", "p90"))
        print("|%s|%s|%s|%s|" % ("-" * 36, "-" * 10, "-" * 10, "-" * 10))
        for network in ("none", "bridge"):
            print(row("this runtime, --network " + network, timed(kk + ["run", "--rm", "--network", network, IMAGE, "true"], env, runs)))
            if docker:
                print(row("docker,       --network " + network, timed(["docker", "run", "--rm", "--network", network, IMAGE, "true"], None, runs)))
        print()
        print("what stays outside while ten containers run (`sleep 300`, kilobytes of resident memory)\n")
        print("| %-34s | %8s |" % ("", "per box"))
        print("|%s|%s|" % ("-" * 36, "-" * 10))
        names = []
        try:
            for i in range(10):
                name = "bench%d" % i
                subprocess.run(kk + ["run", "-d", "--name", name, "--network", "none", IMAGE, "sleep", "300"], env=env, check=True, capture_output=True)
                names.append(name)
            time.sleep(0.5)
            total = 0
            for name in names:
                import json

                state = json.loads(subprocess.run(kk + ["inspect", name], env=env, capture_output=True, text=True).stdout)[0]["State"]
                shim = state["shim_pid"]
                total += rss_kb(shim) + sum(rss_kb(c) for c in children(shim) if c != state["init_pid"])  # the shim and its log process
            print("| %-34s | %8d |" % ("this runtime (shim + log process)", total // len(names)))
        finally:
            for name in names:
                subprocess.run(kk + ["rm", "-f", name], env=env, capture_output=True)
        if docker:
            ids = []
            try:
                for i in range(10):
                    ids.append(subprocess.run(["docker", "run", "-d", "--network", "none", IMAGE, "sleep", "300"], capture_output=True, text=True, check=True).stdout.strip())
                time.sleep(0.5)
                total = 0
                for cid in ids:
                    pid = int(subprocess.run(["docker", "inspect", "-f", "{{.State.Pid}}", cid], capture_output=True, text=True).stdout)
                    total += rss_kb(ppid(pid))  # containerd-shim
                print("| %-34s | %8d |" % ("docker (containerd-shim only)", total // len(ids)))
            finally:
                for cid in ids:
                    subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
    finally:
        subprocess.run(kk + ["ps", "-a"], env=env, capture_output=True)
        shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
