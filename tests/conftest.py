"""Fixtures for the tests that start real containers.

The tests run on Linux as root (a container needs namespaces, mounts and cgroups).  The oracle is Docker itself: the same image, the same
command, the same limits run in ``docker run`` and in this runtime, and what the process sees from inside is compared.  Tests that need
root, Linux, Docker or the network are skipped where those are not there.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from typing import List, NamedTuple, Optional

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
IMAGE = os.environ.get("KONTEYNER_TEST_IMAGE", "alpine:3.19")

on_linux = sys.platform.startswith("linux")
is_root = on_linux and os.geteuid() == 0


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


needs_root = pytest.mark.skipif(not is_root, reason="needs Linux and root (namespaces, mounts, cgroups)")
needs_docker = pytest.mark.skipif(not (is_root and _docker_ok()), reason="needs Docker as the oracle")


class Out(NamedTuple):
    code: int
    out: str
    err: str


def _run(argv: List[str], timeout: float = 120, input: Optional[str] = None, env: Optional[dict] = None) -> Out:
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input, env=env)
    return Out(p.returncode, p.stdout, p.stderr)


@pytest.fixture(scope="session")
def root():
    """A store on a real file system (overlayfs does not work on every file system: /var/tmp is ext4 or xfs)."""
    d = tempfile.mkdtemp(prefix="kk-test-", dir="/var/tmp")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="session")
def kk(root):
    """Runs the ``konteyner`` command: ``kk("run", "alpine", "echo", "hi")``."""
    env = dict(os.environ, PYTHONPATH=SRC, KONTEYNER_ROOT=root, PYTHONDONTWRITEBYTECODE="1")

    def call(*args: str, timeout: float = 120, input: Optional[str] = None) -> Out:
        return _run([sys.executable, "-m", "kendi_konteyner", *args], timeout, input, env)

    return call


@pytest.fixture(scope="session")
def docker():
    def call(*args: str, timeout: float = 120, input: Optional[str] = None) -> Out:
        return _run(["docker", *args], timeout, input)

    return call


@pytest.fixture(scope="session")
def runtime(root):
    sys.path.insert(0, SRC)
    from kendi_konteyner.runtime import Runtime
    from kendi_konteyner.store import Store

    return Runtime(Store(root))


@pytest.fixture(scope="session")
def image(runtime, docker):
    """The test image, loaded the way a user would: ``docker save`` and ``konteyner load`` (the pull is tested on its own)."""
    if _docker_ok():
        have = docker("image", "inspect", IMAGE)
        if have.code != 0:
            docker("pull", IMAGE, timeout=300)
        tar = os.path.join(tempfile.mkdtemp(prefix="kk-save-", dir="/var/tmp"), "image.tar")
        out = docker("save", IMAGE, "-o", tar, timeout=300)
        assert out.code == 0, out.err
        runtime.images.load(tar)
        shutil.rmtree(os.path.dirname(tar), ignore_errors=True)
    else:
        runtime.images.pull(IMAGE)
    return runtime.images.get(IMAGE)


@pytest.fixture(autouse=True)
def clean_containers(request):
    """After every test that used the runtime: no container left (the next test starts from nothing)."""
    yield
    if "runtime" in request.fixturenames:
        rt = request.getfixturevalue("runtime")
        for cfg, st in rt.list(all_=True):
            try:
                rt.remove(cfg.id, force=True)
            except Exception:
                pass
    elif "kk" in request.fixturenames:
        kk = request.getfixturevalue("kk")
        out = kk("ps", "-a")
        for line in out.out.splitlines()[1:]:
            kk("rm", "-f", line.split()[0])
