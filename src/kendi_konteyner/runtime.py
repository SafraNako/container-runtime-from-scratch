"""Running a container.

What a container is, on Linux: an ordinary process that was given its own view of the system and a limit on what it may use.

* **namespaces** (``unshare``): its own process ids (it is PID 1), host name, mount table, IPC objects, network stack and cgroup root;
* a **root file system**: an overlayfs of the image's layers (read only) and a directory for what the container writes, made the root of
  the process with ``pivot_root`` after the old root has been detached;
* **cgroups**: memory, CPU and process-count limits, and a way to find and kill everything in the container;
* **capabilities**, ``no_new_privs`` and a **seccomp** filter: what the process may ask the kernel for;
* **masked paths**: files of ``/proc`` and ``/sys`` that would tell too much or allow too much are hidden or made read only.

Three processes take part.  The *parent* (the command line) prepares the files and the cgroup, starts the shim and waits.  The *shim*
joins the cgroup, enters a new PID namespace, forks the *init* and waits for it; when the init is gone the shim records the exit code,
the out-of-memory kills and the time, and cleans up.  The *init* is PID 1 of the container: it enters the other namespaces, waits until the
parent has done what has to be done from outside (a network interface), builds the file system, drops what the process may not have and
``exec``s the command, which takes its place (so the command is PID 1, as in Docker).
"""
from __future__ import annotations

import fcntl
import json
import os
import select
import signal
import socket
import struct
import sys
import termios
import time
import tty
from typing import Dict, List, Optional, Tuple

from . import linux, network, seccomp  # imported now: after the pivot the host's Python files are out of reach
from .cgroups import Cgroup
from .errors import KonteynerError, NoSuchContainer, StartError
from .image import Image, ImageStore
from .spec import DEFAULT_PATH, Config, effective_caps
from .store import Store

# files that Docker hides (bind mounts of /dev/null, empty read-only tmpfs) or makes read only
MASKED_PATHS = (
    "/proc/asound", "/proc/acpi", "/proc/interrupts", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list",
    "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi", "/sys/firmware", "/sys/devices/virtual/powercap",
)
READONLY_PATHS = ("/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger")

DEVICES = (("null", 1, 3), ("zero", 1, 5), ("full", 1, 7), ("random", 1, 8), ("urandom", 1, 9), ("tty", 5, 0))


class Paths:
    def __init__(self, store: Store, cid: str) -> None:
        self.dir = store.path("containers", cid)
        self.config = os.path.join(self.dir, "config.json")
        self.state = os.path.join(self.dir, "state.json")
        self.upper = os.path.join(self.dir, "upper")
        self.work = os.path.join(self.dir, "work")
        self.merged = os.path.join(self.dir, "merged")
        self.hostname = os.path.join(self.dir, "hostname")
        self.hosts = os.path.join(self.dir, "hosts")
        self.resolv = os.path.join(self.dir, "resolv.conf")
        self.log = os.path.join(self.dir, "container.log")


class Context:
    """What the processes of one start share (the file descriptors of the pipes between them and the paths)."""

    def __init__(self, cfg: Config, paths: Paths, image: Image) -> None:
        self.cfg = cfg
        self.paths = paths
        self.image = image
        self.pid_r, self.pid_w = os.pipe()  # shim -> parent: the host pid of the init
        self.status_r, self.status_w = os.pipe()  # init -> parent: "N" (namespaces ready), "E<message>", or EOF when the command started
        self.go_r, self.go_w = os.pipe()  # parent -> init: go on
        self.master = -1  # the master side of the container's terminal (made inside the container, see ``_open_terminal``)
        self.pty_host: Optional[socket.socket] = None  # init -> parent (or the logger): the master, sent as a file descriptor
        self.pty_init: Optional[socket.socket] = None
        self.detach = cfg.detach
        self.tty_number = -1
        self.log_out_r = self.log_out_w = self.log_err_r = self.log_err_w = -1
        self.ip: Optional[str] = None


def resolv_conf_for_container() -> str:
    """The name servers of the host that a container can reach (not the stub resolver on 127.0.0.53), else a public one."""
    servers: List[str] = []
    for path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            with open(path) as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver" and not parts[1].startswith("127.") and parts[1] != "::1":
                        servers.append(parts[1])
        except OSError:
            continue
        if servers:
            break
    return "".join("nameserver %s\n" % s for s in (servers or ["1.1.1.1", "8.8.8.8"]))


# ---------------------------------------------------------------------------------------------------------------- the init

def _write_status(fd: int, kind: bytes, message: str = "", code: int = 126) -> None:
    """What the init tells the parent: ``E<exit code>:<message>`` when the container could not start."""
    try:
        os.write(fd, kind + ("%d:%s" % (code, message)).encode("utf-8", "replace"))
    except OSError:
        pass


def start_error(raw: bytes) -> StartError:
    """The error that the init reported (see ``_write_status``)."""
    text = raw.decode("utf-8", "replace")
    if text.startswith("E"):
        text = text[1:]
    head, _, rest = text.partition(":")
    if head.isdigit():
        return StartError(rest, int(head))
    return StartError(text or "the container could not be started")


def _mkfile(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.lexists(path):
        open(path, "a").close()


def _bind_target(source: str, target: str) -> None:
    if os.path.isdir(source):
        os.makedirs(target, exist_ok=True)
    else:
        _mkfile(target)


TIOCGPTN = getattr(termios, "TIOCGPTN", 0x80045430)
TIOCSPTLCK = getattr(termios, "TIOCSPTLCK", 0x40045431)
TTY_GID = 5


def _open_terminal(devpts: str) -> Tuple[int, int, int]:
    """A pseudo terminal of the devpts instance at ``devpts`` (the container's own: it was mounted with ``newinstance``): the master, the
    slave and the number of the slave (``/dev/pts/<n>``).  This is what runc does, and why ``tty`` inside a container says ``/dev/pts/0``:
    a pty of the host's devpts would have no name in the container."""
    master = os.open(devpts + "/ptmx", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    fcntl.ioctl(master, TIOCSPTLCK, struct.pack("i", 0))  # unlockpt
    number = struct.unpack("i", fcntl.ioctl(master, TIOCGPTN, b"\0\0\0\0"))[0]
    slave = os.open("%s/%d" % (devpts, number), os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    return master, slave, number


def _receive_master(sock: socket.socket, timeout: float = 30.0) -> Optional[int]:
    """The master of the container's terminal, sent by the init; ``None`` when the init ended without making one."""
    sock.settimeout(timeout)
    try:
        _, fds, _, _ = socket.recv_fds(sock, 16, 1)
    except (OSError, socket.timeout):
        return None
    finally:
        sock.close()
    return fds[0] if fds else None


def _prepare_rootfs(ctx: Context) -> None:
    """Mounts the overlay and everything that goes in it, then makes it the root."""
    cfg, paths, image = ctx.cfg, ctx.paths, ctx.image
    root = paths.merged
    lower = image.layer_dirs()
    if not lower:
        raise StartError("the image has no layers")
    data = "lowerdir=%s,upperdir=%s,workdir=%s" % (":".join(lower), paths.upper, paths.work)
    if len(data) > 3800:  # the mount data is one page: use short relative names for the layers
        base = os.path.dirname(lower[0])
        os.chdir(base)
        data = "lowerdir=%s,upperdir=%s,workdir=%s" % (":".join(os.path.relpath(d, base) for d in lower), paths.upper, paths.work)
    # nodev: a container's root may have the CAP_MKNOD of Docker's default set; without the device cgroup of Docker (a BPF program) the only
    # way to keep it from making a node for the host's disk and opening it is that no file system of the container allows device nodes
    linux.mount("overlay", root, "overlay", linux.MS_NODEV, data)

    def under(path: str) -> str:
        return root + path

    for d in ("/proc", "/sys", "/dev", "/etc"):
        os.makedirs(under(d), exist_ok=True)
    # /proc and /sys
    linux.mount("proc", under("/proc"), "proc", linux.MS_NOSUID | linux.MS_NODEV | linux.MS_NOEXEC)
    linux.mount("sysfs", under("/sys"), "sysfs", linux.MS_RDONLY | linux.MS_NOSUID | linux.MS_NODEV | linux.MS_NOEXEC)
    try:
        linux.mount("cgroup", under("/sys/fs/cgroup"), "cgroup2", linux.MS_RDONLY | linux.MS_NOSUID | linux.MS_NODEV | linux.MS_NOEXEC)
    except OSError:
        pass  # no cgroup v2 on this host
    # /dev: a tmpfs with the few devices a program may use
    linux.mount("tmpfs", under("/dev"), "tmpfs", linux.MS_NOSUID | linux.MS_NODEV | linux.MS_STRICTATIME, "mode=755,size=65536k")
    for name, major, minor in DEVICES:
        node = under("/dev/" + name)
        _mkfile(node)
        linux.mount("/dev/" + name, node, None, linux.MS_BIND)  # the host's device (the tmpfs itself does not allow device nodes)
    os.makedirs(under("/dev/pts"), exist_ok=True)
    linux.mount("devpts", under("/dev/pts"), "devpts", linux.MS_NOSUID | linux.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620,gid=5")
    os.symlink("pts/ptmx", under("/dev/ptmx"))
    os.makedirs(under("/dev/shm"), exist_ok=True)
    linux.mount("shm", under("/dev/shm"), "tmpfs", linux.MS_NOSUID | linux.MS_NODEV | linux.MS_NOEXEC, "mode=1777,size=65536k")
    os.makedirs(under("/dev/mqueue"), exist_ok=True)
    try:
        linux.mount("mqueue", under("/dev/mqueue"), "mqueue", linux.MS_NOSUID | linux.MS_NODEV | linux.MS_NOEXEC)
    except OSError:
        pass
    for link, target in (("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"), ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2"), ("core", "/proc/kcore")):
        os.symlink(target, under("/dev/" + link))
    if cfg.tty:
        master, slave, ctx.tty_number = _open_terminal(under("/dev/pts"))
        assert ctx.pty_init is not None
        socket.send_fds(ctx.pty_init, [b"m"], [master])  # the parent (or the logger of a detached container) gets the master
        ctx.pty_init.close()
        os.close(master)
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)  # init has its own session (see ``_setup_stdio``)
        for fd in (0, 1, 2):
            os.dup2(slave, fd)
        os.close(slave)
        _mkfile(under("/dev/console"))
        linux.mount(under("/dev/pts/%d" % ctx.tty_number), under("/dev/console"), None, linux.MS_BIND)
    # the files that the runtime writes about the container
    for src, dst in ((paths.hostname, "/etc/hostname"), (paths.hosts, "/etc/hosts"), (paths.resolv, "/etc/resolv.conf")):
        _mkfile(under(dst))
        linux.mount(src, under(dst), None, linux.MS_BIND)
    # volumes and tmpfs
    for v in cfg.volumes:
        if not os.path.exists(v.source):
            raise StartError("the volume %s does not exist on the host" % v.source)
        _bind_target(v.source, under(v.target))
        linux.bind_mount(v.source, under(v.target), readonly=v.readonly, extra_flags=linux.MS_NOSUID | linux.MS_NODEV)
    for spec in cfg.tmpfs:
        target, _, options = spec.partition(":")
        os.makedirs(under(target), exist_ok=True)
        linux.mount("tmpfs", under(target), "tmpfs", linux.MS_NOSUID | linux.MS_NODEV, options or "mode=1777")
    # the new root
    os.chdir(root)
    linux.pivot_root(".", ".")  # the old root is stacked under the new one on the same directory ...
    linux.umount(".", linux.MNT_DETACH)  # ... and detached: no way back to the host's files
    os.chdir("/")
    # what is hidden or read only (after the pivot: the paths are the ones that the container sees)
    if not cfg.privileged:
        for path in MASKED_PATHS:
            if os.path.isdir(path):
                linux.mount("tmpfs", path, "tmpfs", linux.MS_RDONLY, "")
            elif os.path.exists(path):
                linux.mount("/dev/null", path, None, linux.MS_BIND)
        for path in READONLY_PATHS:
            if os.path.exists(path):
                linux.bind_mount(path, path, readonly=True, extra_flags=linux.MS_NOSUID | linux.MS_NODEV | linux.MS_NOEXEC)
    if cfg.read_only:
        linux.mount(None, "/", None, linux.MS_REMOUNT | linux.MS_BIND | linux.MS_RDONLY)


def _parse_passwd(path: str) -> List[List[str]]:
    try:
        with open(path) as fh:
            return [line.rstrip("\n").split(":") for line in fh if line.strip() and not line.startswith("#")]
    except OSError:
        return []


def resolve_user(spec: str) -> Tuple[int, int, List[int], Optional[str]]:
    """(uid, gid, supplementary groups, home) for ``name``, ``uid``, ``name:group`` or ``uid:gid``, looked up in the container's files."""
    user, _, group = (spec or "root").partition(":")
    passwd = _parse_passwd("/etc/passwd")
    groups = _parse_passwd("/etc/group")
    entry = None
    for row in passwd:
        if len(row) >= 6 and (row[0] == user or (user.isdigit() and row[2] == user)):
            entry = row
            break
    if entry is not None:
        uid, gid, home = int(entry[2]), int(entry[3]), entry[5]
    elif user.isdigit() or user == "root":
        uid, gid, home = (int(user) if user.isdigit() else 0), (int(user) if user.isdigit() else 0), None
    else:
        raise StartError("unable to find user %s: no matching entry in /etc/passwd" % user)
    if group:
        if group.isdigit():
            gid = int(group)
        else:
            for row in groups:
                if len(row) >= 3 and row[0] == group:
                    gid = int(row[2])
                    break
            else:
                raise StartError("unable to find group %s" % group)
    name = entry[0] if entry is not None else user  # a uid is looked up too: the groups list its members by name
    # Docker adds the groups that list the user only when no group is given ("user", not "user:group")
    extra = [int(row[2]) for row in groups if len(row) >= 4 and name in row[3].split(",")] if entry is not None and not group else []
    return uid, gid, extra, home


def _container_environment(ctx: Context, home: Optional[str]) -> Dict[str, str]:
    env: Dict[str, str] = {"PATH": DEFAULT_PATH, "HOSTNAME": ctx.cfg.hostname}
    for item in ctx.image.defaults()["env"] + ctx.cfg.env:
        k, _, v = item.partition("=")
        env[k] = v
    if "HOME" not in [e.partition("=")[0] for e in ctx.cfg.env]:
        env.setdefault("HOME", home or "/")
    if ctx.cfg.tty:
        env.setdefault("TERM", "xterm")
    return env


def drop_privileges_and_exec(cfg: Config, image_defaults: dict, env_builder, argv: List[str], exec_user: bool = False, tty_path: Optional[str] = None) -> None:
    """The last steps before the command: its directory, its user, what it may do.  Does not return.

    ``exec_user`` is for ``exec -u``: Docker gives such a process the groups of /etc/group that list the user and not the primary group as
    well (a container's first process gets both), and only the primary group when /etc/group lists the user nowhere."""
    uid, gid, extra, home = resolve_user(cfg.user or image_defaults["user"])
    if tty_path:
        os.chown(tty_path, uid, TTY_GID)  # the user of the command owns its terminal (a pty is made by root, here)
    env = env_builder(home)
    workdir = cfg.workdir if cfg.workdir != "/" else image_defaults["workdir"]
    try:
        os.chdir(workdir)
    except FileNotFoundError:
        os.makedirs(workdir, exist_ok=True)
        os.chdir(workdir)
    keep = effective_caps(cfg)
    use_seccomp = cfg.seccomp and not cfg.privileged

    def seccomp_filter() -> None:
        seccomp.apply_default()

    if use_seccomp and not cfg.no_new_privileges:
        seccomp_filter()  # without no_new_privs, installing a filter takes CAP_SYS_ADMIN, which is dropped next
    linux.drop_bounding_set(keep)
    os.setgroups((extra or [gid]) if exec_user else [gid] + extra)  # the primary group comes first and is repeated if /etc/group lists the user in it: that is what Docker does
    if uid != 0 or gid != 0:
        os.setgid(gid)
        os.setuid(uid)  # the kernel empties the permitted and effective sets of a process that stops being root
    else:
        linux.restrict_capabilities(keep)
    if cfg.no_new_privileges:
        linux.set_no_new_privs()
        if use_seccomp:
            seccomp_filter()
    try:
        os.execvpe(argv[0], argv, env)
    except FileNotFoundError:
        raise StartError("exec: %r: executable file not found in $PATH" % argv[0], 127) from None
    except PermissionError:
        raise StartError("exec: %r: permission denied" % argv[0], 126) from None


def _reap_loop(child: int) -> int:
    """PID 1 with ``--init``: forwards the signals it gets to the command, reaps every orphan that is reparented to it and exits with the
    code of the command."""
    def forward(signum, frame):
        try:
            os.kill(child, signum)
        except ProcessLookupError:
            pass

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT, signal.SIGUSR1, signal.SIGUSR2):
        signal.signal(sig, forward)
    code = 0
    while True:
        try:
            pid, status = os.waitpid(-1, 0)
        except ChildProcessError:
            return code
        except InterruptedError:
            continue
        if pid == child:
            code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (
                os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
            )
            code = code if code >= 0 else 128 - code
            # the others get what is left of the container's life: PID 1 leaving takes them with it


def init_main(ctx: Context) -> None:
    """PID 1 of the container."""
    cfg = ctx.cfg
    try:
        os.close(ctx.pid_w)  # the shim wrote the pid here; the other ends were closed before the fork
        if ctx.pty_host is not None:
            ctx.pty_host.close()
        flags = linux.CLONE_NEWNS | linux.CLONE_NEWUTS | linux.CLONE_NEWIPC | linux.CLONE_NEWCGROUP
        if cfg.network != "host":
            flags |= linux.CLONE_NEWNET
        linux.unshare(flags)
        os.write(ctx.status_w, b"N")
        if os.read(ctx.go_r, 1) != b"g":
            os._exit(1)
        os.close(ctx.go_r)
        _setup_stdio(ctx)
        linux.sethostname(cfg.hostname)
        linux.make_private("/")
        if cfg.network != "host":
            network.setup_in_container(cfg.network, ctx.ip, cfg.id)
        _prepare_rootfs(ctx)
        argv = list(cfg.argv)
        defaults = ctx.image.defaults()
        if cfg.init:
            child = os.fork()
            if child:
                os.close(ctx.status_w)  # only the command reports back (by closing it at exec): the parent is not to wait for the supervisor
                code = _reap_loop(child)
                os._exit(code)
        tty_path = "/dev/pts/%d" % ctx.tty_number if cfg.tty else None
        drop_privileges_and_exec(cfg, defaults, lambda home: _container_environment(ctx, home), argv, tty_path=tty_path)
    except StartError as e:
        _write_status(ctx.status_w, b"E", str(e), e.exit_code)
        os._exit(e.exit_code)
    except BaseException as e:  # noqa: B902 - nothing must escape: this process is a container
        _write_status(ctx.status_w, b"E", "%s: %s" % (type(e).__name__, e))
        os._exit(126)
    os._exit(126)


def _setup_stdio(ctx: Context) -> None:
    cfg = ctx.cfg
    if cfg.tty:
        os.setsid()  # the terminal itself is made once the container's /dev/pts exists (``_prepare_rootfs``)
    elif ctx.detach:
        devnull = os.open(os.devnull, os.O_RDONLY)
        os.dup2(devnull, 0)
        os.close(devnull)
        os.dup2(ctx.log_out_w, 1)
        os.dup2(ctx.log_err_w, 2)
        for fd in (ctx.log_out_w, ctx.log_err_w, ctx.log_out_r, ctx.log_err_r):
            os.close(fd)


# ---------------------------------------------------------------------------------------------------------------- the shim

def _exit_code(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 255


def _log_pump(fds: Dict[int, str], path: str) -> None:
    """Copies what the container writes to its standard output and error into the log file, a JSON line for each line of text."""
    buffers = {fd: b"" for fd in fds}
    with open(path, "ab", buffering=0) as out:
        def emit(stream: str, text: bytes) -> None:
            rec = {"time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".%06dZ" % (time.time() % 1 * 1e6), "stream": stream, "log": text.decode("utf-8", "replace")}
            out.write((json.dumps(rec, ensure_ascii=False) + "\n").encode())

        live = set(fds)
        while live:
            ready, _, _ = select.select(list(live), [], [])
            for fd in ready:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    live.discard(fd)
                    if buffers[fd]:
                        emit(fds[fd], buffers[fd])
                        buffers[fd] = b""
                    continue
                buffers[fd] += chunk
                while b"\n" in buffers[fd]:
                    line, _, buffers[fd] = buffers[fd].partition(b"\n")
                    emit(fds[fd], line + b"\n")


def shim_main(rt: "Runtime", ctx: Context) -> None:
    """Joins the cgroup, enters the PID namespace, forks the init and records how it ended.  Never returns."""
    cfg, paths = ctx.cfg, ctx.paths
    cg = Cgroup(cfg.id)
    try:
        if ctx.detach:
            os.setsid()
            devnull = os.open(os.devnull, os.O_RDWR)  # let go of the caller's terminal and pipes: the caller must not wait for the container
            for fd in (0, 1, 2):
                os.dup2(devnull, fd)
            os.close(devnull)
        os.close(ctx.pid_r)
        os.close(ctx.go_w)
        os.close(ctx.status_r)
        logger = 0
        if ctx.detach:
            if not cfg.tty:
                ctx.log_out_r, ctx.log_out_w = os.pipe()
                ctx.log_err_r, ctx.log_err_w = os.pipe()
            # the log is copied by a process of its own, made before the PID namespace: a process cannot start threads after unshare(NEWPID)
            logger = os.fork()
            if logger == 0:
                for fd in (ctx.pid_w, ctx.status_w, ctx.go_r) + ((ctx.log_out_w, ctx.log_err_w) if not cfg.tty else ()):
                    os.close(fd)
                if cfg.tty:
                    assert ctx.pty_init is not None and ctx.pty_host is not None
                    ctx.pty_init.close()
                    master = _receive_master(ctx.pty_host)  # a terminal has one stream: what the process writes and the keys' echo
                    if master is None:
                        os._exit(0)
                    fds = {master: "stdout"}
                else:
                    fds = {ctx.log_out_r: "stdout", ctx.log_err_r: "stderr"}
                try:
                    _log_pump(fds, paths.log)
                finally:
                    os._exit(0)
        cg.add(os.getpid())  # the init inherits the group; the shim leaves it again at once (its processes are not the container's)
        linux.unshare(linux.CLONE_NEWPID)
        init = os.fork()
        if init == 0:
            init_main(ctx)
            os._exit(126)
        if cfg.tty:
            assert ctx.pty_init is not None and ctx.pty_host is not None
            ctx.pty_init.close()  # the init has them; the logger (detached) or the parent keeps the other end
            ctx.pty_host.close()
        cg.leave(os.getpid())
        os.write(ctx.pid_w, str(init).encode())
        os.close(ctx.pid_w)
        os.close(ctx.status_w)
        os.close(ctx.go_r)
        if not cfg.tty and ctx.detach:
            os.close(ctx.log_out_w)
            os.close(ctx.log_err_w)
            os.close(ctx.log_out_r)
            os.close(ctx.log_err_r)
        _, status = os.waitpid(init, 0)
        code = _exit_code(status)
        oom = cg.oom_killed()
        if oom:
            code = 137
        if logger:
            try:
                os.waitpid(logger, 0)  # it ends when everything that held the output open is gone
            except ChildProcessError:
                pass
        cg.remove()
        rt.finish(cfg.id, code, oom)
        os._exit(code)
    except BaseException as e:  # noqa: B902
        try:
            rt.finish(cfg.id, 255, False, error="%s: %s" % (type(e).__name__, e))
        except BaseException:
            pass
        os._exit(255)


# ---------------------------------------------------------------------------------------------------------------- the runtime

class Runtime:
    def __init__(self, store: Optional[Store] = None) -> None:
        self.store = store or Store()
        self.images = ImageStore(self.store)

    # -- state

    def paths(self, cid: str) -> Paths:
        return Paths(self.store, cid)

    def state(self, cid: str) -> dict:
        data = self.store.read_json(self.paths(cid).state)
        if data is None:
            raise NoSuchContainer("no such container: %s" % cid)
        if data.get("status") == "running" and not self._alive(data.get("shim_pid"), data.get("started_at")):
            data["status"] = "exited"
            data.setdefault("exit_code", 255)
            data["error"] = data.get("error") or "the container's monitor process died"
        return data

    @staticmethod
    def _alive(pid: Optional[int], started: Optional[float]) -> bool:
        if not pid:
            return False
        try:
            with open("/proc/%d/stat" % pid) as fh:
                fields = fh.read().rsplit(")", 1)[1].split()
            return fields[0] != "Z"
        except (OSError, IndexError):
            return False

    def _set_state(self, cid: str, **changes) -> dict:
        paths = self.paths(cid)
        with self.store.lock("state.lock"):
            if not os.path.isdir(paths.dir):  # removed while the shim was ending: nothing to write
                return changes
            data = self.store.read_json(paths.state) or {}
            data.update(changes)
            self.store.write_json(paths.state, data)
        return data

    def finish(self, cid: str, code: int, oom: bool, error: Optional[str] = None) -> None:
        changes = {"status": "exited", "exit_code": code, "finished_at": time.time(), "oom_killed": oom}
        if error:
            changes["error"] = error
        self._set_state(cid, **changes)
        try:
            network.release(self.store, cid)
        except Exception:
            pass

    def resolve(self, ref: str) -> str:
        """A container id from a name, the beginning of an id, or an id."""
        base = self.store.path("containers")
        ids = [d for d in os.listdir(base) if os.path.exists(os.path.join(base, d, "config.json"))]
        if ref in ids:
            return ref
        by_name = [i for i in ids if (self.store.read_json(os.path.join(base, i, "config.json")) or {}).get("name") == ref]
        if len(by_name) == 1:
            return by_name[0]
        by_prefix = [i for i in ids if len(ref) >= 3 and i.startswith(ref)]
        if len(by_prefix) == 1:
            return by_prefix[0]
        if len(by_prefix) > 1:
            raise KonteynerError("%r matches several containers" % ref)
        raise NoSuchContainer("no such container: %s" % ref)

    def config(self, cid: str) -> Config:
        data = self.store.read_json(self.paths(cid).config)
        if data is None:
            raise NoSuchContainer("no such container: %s" % cid)
        return Config.from_json(data)

    def list(self, all_: bool = False) -> List[Tuple[Config, dict]]:
        out = []
        base = self.store.path("containers")
        for cid in sorted(os.listdir(base)):
            if not os.path.exists(os.path.join(base, cid, "config.json")):
                continue
            try:
                cfg = self.config(cid)
                st = self.state(cid)
            except KonteynerError:
                continue
            if all_ or st.get("status") == "running":
                out.append((cfg, st))
        out.sort(key=lambda cs: cs[0].created_at)
        return out

    # -- creating

    def create(self, cfg: Config) -> Config:
        paths = self.paths(cfg.id)
        if cfg.name:  # before anything is made: a refused name leaves nothing behind
            for other, _ in self.list(all_=True):
                if other.name == cfg.name:
                    raise KonteynerError('the name "%s" is already used by container %s' % (cfg.name, other.id[:12]))
        for d in (paths.dir, paths.upper, paths.work, paths.merged):
            os.makedirs(d, exist_ok=True)
        self.store.write_json(paths.config, cfg.to_json())
        self.store.write_json(paths.state, {"status": "created", "created_at": cfg.created_at})
        return cfg

    # -- starting

    def start(self, cid: str, attach: bool = True) -> Optional[int]:
        """Starts a created or stopped container.  With ``attach`` waits for it and returns its exit code; otherwise returns ``None``
        as soon as the command is running."""
        cfg = self.config(cid)
        st = self.state(cid)
        if st["status"] == "running":
            raise KonteynerError("the container %s is already running" % cid[:12])
        image = self.images.get(cfg.image_id)
        paths = self.paths(cid)
        # a start after a stop begins with a clean writable layer? No: Docker keeps it, and so does this
        with open(paths.hostname, "w") as fh:
            fh.write(cfg.hostname + "\n")
        with open(paths.hosts, "w") as fh:
            fh.write("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n")
        with open(paths.resolv, "w") as fh:
            fh.write(resolv_conf_for_container())
        cg = Cgroup(cid)
        cg.create()
        cg.set_memory(cfg.memory)
        cg.set_cpus(cfg.cpus)
        cg.set_pids(cfg.pids_limit)
        ctx = Context(cfg, paths, image)
        ctx.detach = cfg.detach or not attach  # nobody is there to read the output: the log is
        if cfg.tty:
            ctx.pty_host, ctx.pty_init = socket.socketpair()
        if cfg.network == "bridge":
            ctx.ip = network.allocate(self.store, cid)
            with open(paths.hosts, "a") as fh:
                fh.write("%s\t%s\n" % (ctx.ip.split("/")[0], cfg.hostname))
        self._set_state(cid, status="starting", exit_code=None, error=None, oom_killed=False, started_at=time.time(), finished_at=None)
        pid = os.fork()
        if pid == 0:
            try:
                shim_main(self, ctx)
            finally:
                os._exit(255)
        # the parent
        os.close(ctx.pid_w)
        os.close(ctx.status_w)
        os.close(ctx.go_r)
        if cfg.tty:
            assert ctx.pty_host is not None and ctx.pty_init is not None
            ctx.pty_init.close()
            if ctx.detach:
                ctx.pty_host.close()  # the logger reads the terminal
        try:
            init_pid = self._read_init_pid(ctx, pid)
            self._set_state(cid, shim_pid=pid, init_pid=init_pid)
            first = os.read(ctx.status_r, 1)
            if first != b"N":
                raise start_error(first + self._read_all(ctx.status_r))
            if cfg.network == "bridge":
                network.connect(self.store, cid, init_pid, ctx.ip)
            self._set_state(cid, status="running")
            os.write(ctx.go_w, b"g")
            os.close(ctx.go_w)
            rest = self._read_all(ctx.status_r)  # empty at the exec of the command (the pipe is closed with it)
            if rest:
                raise start_error(rest)
            if cfg.tty and not ctx.detach:
                assert ctx.pty_host is not None
                master = _receive_master(ctx.pty_host)
                if master is None:
                    raise StartError("the container made no terminal")
                ctx.master = master
        except BaseException as e:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            Cgroup(cid).remove()
            code = e.exit_code if isinstance(e, StartError) else 126
            self.finish(cid, code, False, error=str(e) if isinstance(e, KonteynerError) else repr(e))
            raise
        finally:
            for fd in (ctx.status_r,):
                try:
                    os.close(fd)
                except OSError:
                    pass
            if ctx.pty_host is not None:
                ctx.pty_host.close()
        if not attach:
            return None
        return self._attach(ctx, pid, init_pid)

    @staticmethod
    def _read_all(fd: int) -> bytes:
        chunks = []
        while True:
            data = os.read(fd, 4096)
            if not data:
                return b"".join(chunks)
            chunks.append(data)

    @staticmethod
    def _read_init_pid(ctx: Context, shim: int) -> int:
        data = os.read(ctx.pid_r, 32)
        os.close(ctx.pid_r)
        if not data:
            _, status = os.waitpid(shim, 0)
            raise StartError("the monitor process died while starting (status %d)" % status)
        return int(data)

    def _attach(self, ctx: Context, shim: int, init_pid: int) -> int:
        """Stays with the container until it ends: forwards signals, and with a terminal copies keys and output."""
        old = {}

        def forward(signum, frame):
            try:
                os.kill(init_pid, signum)
            except ProcessLookupError:
                pass

        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            old[sig] = signal.signal(sig, forward if not ctx.cfg.tty else signal.SIG_IGN)
        try:
            if ctx.cfg.tty:
                self._relay_tty(ctx.master, shim)
            _, status = _waitpid_retry(shim)
        finally:
            for sig, handler in old.items():
                signal.signal(sig, handler)
            if ctx.cfg.tty:
                try:
                    os.close(ctx.master)
                except OSError:
                    pass
        return _exit_code(status)

    @staticmethod
    def _relay_tty(master: int, shim: int) -> None:
        stdin_fd = sys.stdin.fileno() if sys.stdin.isatty() else None
        saved = None
        if stdin_fd is not None:
            saved = termios.tcgetattr(stdin_fd)
            tty.setraw(stdin_fd)

            def resize(*_):
                size = fcntl.ioctl(stdin_fd, termios.TIOCGWINSZ, b"\0" * 8)
                fcntl.ioctl(master, termios.TIOCSWINSZ, size)

            signal.signal(signal.SIGWINCH, resize)
            resize()
        try:
            watch = [master] + ([stdin_fd] if stdin_fd is not None else [sys.stdin.fileno()])
            while True:
                try:
                    ready, _, _ = select.select(watch, [], [], 0.5)
                except InterruptedError:
                    continue
                for fd in ready:
                    if fd == master:
                        try:
                            data = os.read(master, 65536)
                        except OSError:  # EIO: the other side of the terminal is closed
                            return
                        if not data:
                            return
                        os.write(1, data)
                    else:
                        data = os.read(fd, 65536)
                        if not data:
                            watch.remove(fd)
                            continue
                        os.write(master, data)
        finally:
            if saved is not None:
                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, saved)

    def run(self, cfg: Config) -> Optional[int]:
        """``create`` and ``start``.  The container is removed afterwards by the caller when it asked for ``--rm``."""
        self.create(cfg)
        return self.start(cfg.id, attach=not cfg.detach)

    # -- stopping

    def init_pid(self, cid: str) -> Optional[int]:
        st = self.state(cid)
        return st.get("init_pid") if st.get("status") == "running" else None

    def kill(self, cid: str, sig: int = signal.SIGKILL) -> None:
        pid = self.init_pid(cid)
        if pid is None:
            raise KonteynerError("the container %s is not running" % cid[:12])
        os.kill(pid, sig)

    def wait(self, cid: str, timeout: Optional[float] = None) -> int:
        deadline = None if timeout is None else time.time() + timeout
        while True:
            st = self.state(cid)
            if st["status"] == "exited":
                return st.get("exit_code", 0)
            if deadline is not None and time.time() > deadline:
                raise KonteynerError("the container %s is still running" % cid[:12])
            time.sleep(0.02)

    def stop(self, cid: str, timeout: Optional[int] = None) -> None:
        """SIGTERM, and SIGKILL when it is still there after ``timeout`` seconds (a PID 1 without a handler ignores SIGTERM)."""
        cfg = self.config(cid)
        pid = self.init_pid(cid)
        if pid is None:
            return
        wait = cfg.stop_timeout if timeout is None else timeout
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.wait(cid, wait)
            return
        except KonteynerError:
            pass
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.wait(cid, 10)

    def remove(self, cid: str, force: bool = False) -> None:
        import shutil

        st = self.state(cid)
        if st["status"] == "running":
            if not force:
                raise KonteynerError("the container %s is running: stop it first (or use --force)" % cid[:12])
            self.kill(cid)
            self.wait(cid, 10)
        # the shim writes the last state and ends a moment after the state says "exited": take the directory away only when it is gone
        shim = (self.store.read_json(self.paths(cid).state) or {}).get("shim_pid")
        deadline = time.time() + 10
        while shim and self._alive(shim, None) and time.time() < deadline:
            time.sleep(0.02)
        Cgroup(cid).remove()
        try:
            network.release(self.store, cid)
        except Exception:
            pass
        for _ in range(100):  # the mount point inside is busy until the kernel has let go of the container's mount namespace
            shutil.rmtree(self.paths(cid).dir, ignore_errors=True)
            if not os.path.exists(self.paths(cid).dir):
                break
            time.sleep(0.05)

    # -- running another process in a running container

    def exec(self, cid: str, argv: List[str], env: Optional[List[str]] = None, user: str = "", workdir: str = "", tty: bool = False) -> int:
        """Like ``docker exec``: a new process that joins the namespaces and the cgroup of the container, with its root file system, its
        capabilities and its seccomp filter.  Returns its exit code."""
        import dataclasses

        cfg = self.config(cid)
        init_pid = self.init_pid(cid)
        if init_pid is None:
            raise KonteynerError("the container %s is not running" % cid[:12])
        image = self.images.get(cfg.image_id)
        run_cfg = dataclasses.replace(cfg, user=user or cfg.user, workdir=workdir or cfg.workdir, env=cfg.env + list(env or []), tty=tty, init=False)
        err_r, err_w = os.pipe()
        master = -1
        sock_host = sock_child = None
        if tty:
            sock_host, sock_child = socket.socketpair()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(err_r)
                if sock_host is not None:
                    sock_host.close()
                Cgroup(cid).add(os.getpid())
                names = ["cgroup", "ipc", "uts", "pid", "mnt"] + (["net"] if cfg.network != "host" else [])
                fds = [(n, os.open("/proc/%d/ns/%s" % (init_pid, n), os.O_RDONLY | os.O_CLOEXEC)) for n in names]
                root_fd = os.open("/proc/%d/root" % init_pid, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                for _, fd in fds:
                    linux.setns(fd, 0)
                os.fchdir(root_fd)
                os.chroot(".")
                os.chdir("/")
                tty_path = None
                if tty:
                    # a terminal of the container's own /dev/pts, like the one of its first process
                    os.setsid()
                    new_master, slave, number = _open_terminal("/dev/pts")
                    assert sock_child is not None
                    socket.send_fds(sock_child, [b"m"], [new_master])
                    sock_child.close()
                    os.close(new_master)
                    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                    for fd in (0, 1, 2):
                        os.dup2(slave, fd)
                    os.close(slave)
                    tty_path = "/dev/pts/%d" % number
                inner = os.fork()  # the new PID namespace is for the children of this process
                if inner == 0:
                    ctx = Context.__new__(Context)
                    ctx.cfg, ctx.image = run_cfg, image
                    drop_privileges_and_exec(run_cfg, image.defaults(), lambda home: _container_environment(ctx, home), list(argv), exec_user=bool(user), tty_path=tty_path)
                _, status = os.waitpid(inner, 0)
                os._exit(_exit_code(status))
            except StartError as e:
                _write_status(err_w, b"E", str(e), e.exit_code)
                os._exit(e.exit_code)
            except BaseException as e:  # noqa: B902
                _write_status(err_w, b"E", "%s: %s" % (type(e).__name__, e))
                os._exit(126)
        os.close(err_w)
        if tty:
            assert sock_host is not None and sock_child is not None
            sock_child.close()
            received = _receive_master(sock_host)
            if received is None:  # the process ended before it had a terminal: its error is on the pipe
                tty = False
            else:
                master = received
        old = {}

        def forward(signum, frame):
            try:
                os.kill(pid, signum)
            except ProcessLookupError:
                pass

        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old[sig] = signal.signal(sig, signal.SIG_IGN if tty else forward)
        try:
            if tty:
                self._relay_tty(master, pid)
            _, status = _waitpid_retry(pid)
        finally:
            for sig, handler in old.items():
                signal.signal(sig, handler)
            if tty:
                os.close(master)
        message = self._read_all(err_r)
        os.close(err_r)
        if message.startswith(b"E"):
            raise start_error(message)
        return _exit_code(status)

    # -- looking

    def stats(self, cid: str) -> Dict[str, int]:
        return Cgroup(cid).stats()

    def logs(self, cid: str) -> List[dict]:
        out = []
        try:
            with open(self.paths(cid).log) as fh:
                for line in fh:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
        except FileNotFoundError:
            pass
        return out

    def inspect(self, cid: str) -> dict:
        cfg = self.config(cid)
        return {"Id": cid, "Name": cfg.name, "Image": cfg.image_id, "ImageName": cfg.image_name, "Config": cfg.to_json(), "State": self.state(cid),
                "Limits": Cgroup(cid).limits()}


def _waitpid_retry(pid: int) -> Tuple[int, int]:
    while True:
        try:
            return os.waitpid(pid, 0)
        except InterruptedError:
            continue
