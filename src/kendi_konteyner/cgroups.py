"""Resource limits with cgroups version 2 (the unified hierarchy under ``/sys/fs/cgroup``).

A cgroup is a directory.  Making a directory creates the group, writing a process id into ``cgroup.procs`` puts the process in it, and
the files of the controllers hold the limits: ``memory.max`` (bytes), ``pids.max`` (processes), ``cpu.max`` ("quota period" in
microseconds: ``50000 100000`` is half a CPU).  The runtime keeps every container in ``kendi-konteyner/<id>``; the controllers have to be
switched on in ``cgroup.subtree_control`` of the parent before the children can use them.
"""
from __future__ import annotations

import os
import re
import signal
import time
from typing import Dict, List, Optional

ROOT = "/sys/fs/cgroup"
PARENT = "kendi-konteyner"
CONTROLLERS = ("cpu", "memory", "pids")

_SIZE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)b?\s*$", re.I)
_UNITS = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}


class CgroupError(OSError):
    pass


def parse_size(text: str) -> int:
    """``"128m"`` -> 134217728 (the units of Docker: k, m, g, t are powers of 1024, an optional ``b`` is ignored)."""
    m = _SIZE.match(str(text))
    if not m:
        raise ValueError("%r is not a size (try 64m or 1g)" % (text,))
    return int(float(m.group(1)) * _UNITS[m.group(2).lower()])


def cpu_max(cpus: float, period: int = 100000) -> str:
    """The line of ``cpu.max`` for a number of CPUs (``0.5``, ``2``)."""
    if cpus <= 0:
        raise ValueError("the number of CPUs must be positive")
    return "%d %d" % (round(cpus * period), period)


def available(root: str = ROOT) -> bool:
    return os.path.exists(os.path.join(root, "cgroup.controllers"))


def _write(path: str, value: str) -> None:
    try:
        with open(path, "w") as fh:
            fh.write(value)
    except OSError as e:
        raise CgroupError(e.errno, "cannot write %r to %s: %s" % (value, path, e.strerror)) from None


def _read(path: str) -> str:
    with open(path) as fh:
        return fh.read().strip()


def _flat(path: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for line in _read(path).splitlines():
        k, _, v = line.partition(" ")
        try:
            out[k] = int(v)
        except ValueError:
            pass
    return out


class Cgroup:
    """One container's group."""

    def __init__(self, name: str, root: str = ROOT, parent: str = PARENT) -> None:
        self.name = name
        self.root = root
        self.parent_path = os.path.join(root, parent)
        self.path = os.path.join(self.parent_path, name)

    # -- life

    def _enable_controllers(self, directory: str) -> None:
        have = _read(os.path.join(directory, "cgroup.controllers")).split()
        enabled = _read(os.path.join(directory, "cgroup.subtree_control")).split()
        want = ["+" + c for c in CONTROLLERS if c in have and c not in enabled]
        if want:
            _write(os.path.join(directory, "cgroup.subtree_control"), " ".join(want))

    def create(self) -> "Cgroup":
        self._enable_controllers(self.root)
        os.makedirs(self.parent_path, exist_ok=True)
        self._enable_controllers(self.parent_path)
        os.makedirs(self.path, exist_ok=True)
        return self

    def exists(self) -> bool:
        return os.path.isdir(self.path)

    def procs(self) -> List[int]:
        try:
            return [int(x) for x in _read(os.path.join(self.path, "cgroup.procs")).split()]
        except FileNotFoundError:
            return []

    def add(self, pid: int) -> None:
        _write(os.path.join(self.path, "cgroup.procs"), str(pid))

    def leave(self, pid: int) -> None:
        """Moves a process out of the group, to the root of the hierarchy (the shim has to, before it can remove the group: removing kills
        what is in it)."""
        _write(os.path.join(self.root, "cgroup.procs"), str(pid))

    def kill_all(self) -> None:
        """SIGKILL for every process of the group (``cgroup.kill`` where the kernel has it, a loop otherwise)."""
        kill_file = os.path.join(self.path, "cgroup.kill")
        if os.path.exists(kill_file):
            try:
                _write(kill_file, "1")
                return
            except CgroupError:
                pass
        for _ in range(50):
            pids = self.procs()
            if not pids:
                return
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            time.sleep(0.02)

    def remove(self, timeout: float = 5.0) -> None:
        """Kills what is left and removes the directory (which the kernel refuses while a process or a child group is in it)."""
        if not self.exists():
            return
        self.kill_all()
        deadline = time.time() + timeout
        while True:
            try:
                os.rmdir(self.path)
                return
            except FileNotFoundError:
                return
            except OSError:
                if time.time() > deadline:
                    raise
                time.sleep(0.02)

    # -- limits

    def set_memory(self, limit: Optional[int], swap: bool = False) -> None:
        """``limit`` bytes of memory (the process is killed by the OOM killer when it goes beyond); the swap is switched off, as a
        container that can swap out is not limited at all."""
        if limit is None:
            return
        _write(os.path.join(self.path, "memory.max"), str(limit))
        swap_file = os.path.join(self.path, "memory.swap.max")
        if not swap and os.path.exists(swap_file):
            _write(swap_file, "0")

    def set_cpus(self, cpus: Optional[float]) -> None:
        if cpus is not None:
            _write(os.path.join(self.path, "cpu.max"), cpu_max(cpus))

    def set_pids(self, limit: Optional[int]) -> None:
        if limit is not None:
            _write(os.path.join(self.path, "pids.max"), str(limit))

    def limits(self) -> Dict[str, str]:
        out = {}
        for key in ("memory.max", "memory.swap.max", "cpu.max", "pids.max"):
            try:
                out[key] = _read(os.path.join(self.path, key))
            except OSError:
                pass
        return out

    # -- numbers

    def stats(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for key, fname in (("memory", "memory.current"), ("memory_peak", "memory.peak"), ("pids", "pids.current")):
            try:
                out[key] = int(_read(os.path.join(self.path, fname)))
            except (OSError, ValueError):
                pass
        try:
            cpu = _flat(os.path.join(self.path, "cpu.stat"))
            out["cpu_usec"] = cpu.get("usage_usec", 0)
            out["throttled_periods"] = cpu.get("nr_throttled", 0)
            out["throttled_usec"] = cpu.get("throttled_usec", 0)
        except OSError:
            pass
        return out

    def events(self) -> Dict[str, int]:
        """``memory.events``: how many times the limit was hit (``max``) and how many processes the OOM killer killed (``oom_kill``)."""
        try:
            return _flat(os.path.join(self.path, "memory.events"))
        except OSError:
            return {}

    def oom_killed(self) -> bool:
        return self.events().get("oom_kill", 0) > 0
