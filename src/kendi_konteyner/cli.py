"""The ``konteyner`` command: a very small subset of ``docker``.

    konteyner pull alpine:3.20                    konteyner run --rm alpine echo hello
    konteyner images                              konteyner run -d --name web -m 64m --pids-limit 32 alpine sleep 600
    konteyner load saved.tar | import rootfs.tar  konteyner ps -a | logs | stop | kill | rm | exec | inspect | stats | wait

Making namespaces, mounts and cgroups takes root; the data is kept under ``/var/lib/kendi-konteyner`` (or ``$KONTEYNER_ROOT``).
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from typing import List, Optional, Sequence

from . import __version__
from .cgroups import parse_size
from .errors import KonteynerError, NoSuchImage, StartError
from .runtime import Runtime
from .spec import Config, check_name, new_id, parse_env, parse_volume
from .store import Store


def _need_root() -> None:
    if os.geteuid() != 0:
        raise KonteynerError("this needs root: it makes namespaces, mounts and cgroups (try sudo)")


def _ago(t: Optional[float]) -> str:
    if not t:
        return ""
    d = int(time.time() - t)
    for unit, size in (("days", 86400), ("hours", 3600), ("minutes", 60)):
        if d >= size:
            return "%d %s ago" % (d // size, unit)
    return "%d seconds ago" % d


def _size(n: int) -> str:
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1000 or unit == "GB":
            return "%.1f%s" % (n, unit) if unit != "B" else "%dB" % n
        n /= 1000.0  # type: ignore[assignment]
    return "%dB" % n


def _table(rows: List[List[str]]) -> None:
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for r in rows:
        print("   ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())


def _image(rt: Runtime, ref: str, pull_missing: bool = True):
    try:
        return rt.images.get(ref)
    except NoSuchImage:
        if not pull_missing:
            raise
        print("Unable to find image '%s' locally; pulling" % ref, file=sys.stderr)
        return rt.images.pull(ref, progress=lambda m: print("  " + m, file=sys.stderr))


# ---------------------------------------------------------------------------------------------------------------- commands

def cmd_pull(args, rt: Runtime) -> int:
    img = rt.images.pull(args.image, progress=lambda m: print(m, file=sys.stderr))
    print("%s\n%s" % (img.tags[0] if img.tags else img.id, img.id))
    return 0


def cmd_load(args, rt: Runtime) -> int:
    for img in rt.images.load(args.file, progress=lambda m: print(m, file=sys.stderr)):
        print("Loaded image: %s" % (", ".join(img.tags) or img.id))
    return 0


def cmd_import(args, rt: Runtime) -> int:
    img = rt.images.import_rootfs(args.file, args.name)
    print(img.id)
    return 0


def cmd_images(args, rt: Runtime) -> int:
    rows = [["REPOSITORY:TAG", "IMAGE ID", "CREATED", "LAYERS"]]
    for img in rt.images.all():
        for tag in img.tags or ["<none>"]:
            rows.append([tag, img.short_id, _ago(img.data.get("created_at")), str(len(img.layers))])
    _table(rows)
    return 0


def cmd_rmi(args, rt: Runtime) -> int:
    for ref in args.images:
        rt.images.remove(ref)
        print("Untagged/Deleted: %s" % ref)
    return 0


def build_config(args, rt: Runtime, image) -> Config:
    defaults = image.defaults()
    entry = [args.entrypoint] if args.entrypoint else defaults["entrypoint"]
    if args.entrypoint == "":
        entry = []
    cmd = list(args.command) if args.command else ([] if args.entrypoint is not None else defaults["cmd"])
    if args.command and args.command[0] == "--":
        cmd = list(args.command[1:])
    argv = entry + cmd
    if not argv:
        raise KonteynerError("no command: the image has no CMD and none was given")
    cid = new_id()
    caps_drop = [c for c in (args.cap_drop or [])]
    security = args.security_opt or []
    return Config(
        id=cid, image_id=image.id, image_name=args.image, argv=argv, name=check_name(args.name or ""), env=parse_env(args.env or []),
        workdir=args.workdir or "/", user=args.user or "", hostname=args.hostname or cid[:12],
        memory=parse_size(args.memory) if args.memory else None, cpus=args.cpus, pids_limit=args.pids_limit,
        volumes=[parse_volume(v) for v in (args.volume or [])], tmpfs=list(args.tmpfs or []), read_only=args.read_only,
        network=args.network, tty=args.tty, interactive=args.interactive, detach=args.detach, cap_add=list(args.cap_add or []),
        cap_drop=caps_drop, privileged=args.privileged, no_new_privileges="no-new-privileges" in security or "no-new-privileges=true" in security,
        seccomp="seccomp=unconfined" not in security, init=args.init, stop_timeout=args.stop_timeout,
    )


def cmd_create(args, rt: Runtime) -> int:
    cfg = build_config(args, rt, _image(rt, args.image))
    rt.create(cfg)
    print(cfg.id)
    return 0


def cmd_run(args, rt: Runtime) -> int:
    _need_root()
    cfg = build_config(args, rt, _image(rt, args.image))
    if args.rm and cfg.detach:
        raise KonteynerError("--rm cannot be used with -d")
    rt.create(cfg)
    try:
        code = rt.start(cfg.id, attach=not cfg.detach)
    except StartError as e:
        print("konteyner: %s" % e, file=sys.stderr)
        code = e.exit_code
    finally:
        if args.rm and not cfg.detach:
            rt.remove(cfg.id, force=True)
    if cfg.detach and code is None:
        print(cfg.id)
        return 0
    return code or 0


def cmd_start(args, rt: Runtime) -> int:
    _need_root()
    rc = 0
    for ref in args.containers:
        cid = rt.resolve(ref)
        code = rt.start(cid, attach=args.attach)
        print(ref if code is None else "")
        rc = code or rc
    return rc


def cmd_ps(args, rt: Runtime) -> int:
    rows = [["CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "NAMES"]]
    for cfg, st in rt.list(all_=args.all):
        status = st["status"]
        if status == "running":
            text = "Up " + _ago(st.get("started_at")).replace(" ago", "")
        elif status == "exited":
            text = "Exited (%s) %s" % (st.get("exit_code"), _ago(st.get("finished_at")))
        else:
            text = status.capitalize()
        rows.append([cfg.id[:12], cfg.image_name, '"%s"' % " ".join(cfg.argv)[:30], _ago(cfg.created_at), text, cfg.name])
    _table(rows)
    return 0


def cmd_stop(args, rt: Runtime) -> int:
    for ref in args.containers:
        rt.stop(rt.resolve(ref), args.time)
        print(ref)
    return 0


def cmd_kill(args, rt: Runtime) -> int:
    sig = getattr(signal, "SIG" + args.signal.upper().replace("SIG", ""), None) if not args.signal.isdigit() else int(args.signal)
    if sig is None:
        raise KonteynerError("unknown signal %s" % args.signal)
    for ref in args.containers:
        rt.kill(rt.resolve(ref), sig)
        print(ref)
    return 0


def cmd_rm(args, rt: Runtime) -> int:
    for ref in args.containers:
        rt.remove(rt.resolve(ref), force=args.force)
        print(ref)
    return 0


def cmd_logs(args, rt: Runtime) -> int:
    cid = rt.resolve(args.container)
    seen = 0
    while True:
        records = rt.logs(cid)
        shown = records[-args.tail :] if args.tail is not None and seen == 0 else records[seen:]
        for rec in shown:
            out = sys.stderr if rec.get("stream") == "stderr" else sys.stdout
            out.write(rec.get("log", ""))
            out.flush()
        seen = len(records)
        if not args.follow or rt.state(cid)["status"] != "running":
            if args.follow:
                records = rt.logs(cid)
                for rec in records[seen:]:
                    (sys.stderr if rec.get("stream") == "stderr" else sys.stdout).write(rec.get("log", ""))
            return 0
        time.sleep(0.1)


def cmd_exec(args, rt: Runtime) -> int:
    _need_root()
    cid = rt.resolve(args.container)
    try:
        return rt.exec(cid, list(args.command), env=parse_env(args.env or []), user=args.user or "", workdir=args.workdir or "", tty=args.tty)
    except StartError as e:
        print("konteyner: %s" % e, file=sys.stderr)
        return e.exit_code


def cmd_inspect(args, rt: Runtime) -> int:
    print(json.dumps([rt.inspect(rt.resolve(r)) for r in args.containers], indent=2, default=str))
    return 0


def cmd_stats(args, rt: Runtime) -> int:
    rows = [["CONTAINER ID", "MEM USAGE", "MEM LIMIT", "PIDS", "CPU TIME"]]
    for cfg, st in rt.list(all_=False):
        s = rt.stats(cfg.id)
        rows.append([cfg.id[:12], _size(s.get("memory", 0)), _size(cfg.memory) if cfg.memory else "unlimited", str(s.get("pids", 0)), "%.2fs" % (s.get("cpu_usec", 0) / 1e6)])
    _table(rows)
    return 0


def cmd_wait(args, rt: Runtime) -> int:
    for ref in args.containers:
        print(rt.wait(rt.resolve(ref)))
    return 0


# ---------------------------------------------------------------------------------------------------------------- parser

def _run_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("-d", "--detach", action="store_true", help="run in the background and print the container id")
    p.add_argument("-i", "--interactive", action="store_true", help="keep standard input open")
    p.add_argument("-t", "--tty", action="store_true", help="allocate a pseudo terminal")
    p.add_argument("--name", help="a name for the container")
    p.add_argument("--hostname", dest="hostname", help="the host name inside (default: the first 12 characters of the id)")
    p.add_argument("-e", "--env", action="append", metavar="KEY=VALUE")
    p.add_argument("-v", "--volume", action="append", metavar="HOST:CONTAINER[:ro]", help="bind mount a host path")
    p.add_argument("--tmpfs", action="append", metavar="PATH[:OPTIONS]", help="mount a tmpfs")
    p.add_argument("-w", "--workdir")
    p.add_argument("-u", "--user", help="uid[:gid] or name[:group]")
    p.add_argument("-m", "--memory", metavar="SIZE", help="memory limit, e.g. 64m (processes beyond it are killed)")
    p.add_argument("--cpus", type=float, metavar="N", help="CPU limit, e.g. 0.5")
    p.add_argument("--pids-limit", type=int, metavar="N", help="the most processes the container may have")
    p.add_argument("--read-only", action="store_true", help="mount the root file system read only")
    p.add_argument("--network", "--net", choices=["none", "host", "bridge"], default="bridge")
    p.add_argument("--cap-add", action="append", metavar="CAP")
    p.add_argument("--cap-drop", action="append", metavar="CAP")
    p.add_argument("--privileged", action="store_true", help="all capabilities, no seccomp filter, no masked paths")
    p.add_argument("--security-opt", action="append", metavar="OPT", help="no-new-privileges, seccomp=unconfined")
    p.add_argument("--init", action="store_true", help="run a small init as PID 1 that forwards signals and reaps zombies")
    p.add_argument("--entrypoint", help="replace the entrypoint of the image")
    p.add_argument("--stop-timeout", type=int, default=10, metavar="SECONDS")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="konteyner", description="A very small subset of Docker, written from scratch.")
    p.add_argument("--version", action="version", version="konteyner " + __version__)
    p.add_argument("--root", help="where the images and containers are kept (default /var/lib/kendi-konteyner)")
    sub = p.add_subparsers(dest="command_name", required=True)

    s = sub.add_parser("pull", help="download an image from a registry")
    s.add_argument("image")
    s.set_defaults(func=cmd_pull)

    s = sub.add_parser("load", help="load the images of a tar made by `docker save`")
    s.add_argument("file")
    s.set_defaults(func=cmd_load)

    s = sub.add_parser("import", help="make an image of one layer from the tar of a root file system (`docker export`)")
    s.add_argument("file")
    s.add_argument("name", nargs="?")
    s.set_defaults(func=cmd_import)

    sub.add_parser("images", help="list images").set_defaults(func=cmd_images)

    s = sub.add_parser("rmi", help="remove images")
    s.add_argument("images", nargs="+")
    s.set_defaults(func=cmd_rmi)

    for name, func, help_ in (("run", cmd_run, "create a container and start it"), ("create", cmd_create, "create a container")):
        s = sub.add_parser(name, help=help_, prefix_chars="-")
        _run_options(s)
        if name == "run":
            s.add_argument("--rm", action="store_true", help="remove the container when it exits")
        s.add_argument("image")
        s.add_argument("command", nargs=argparse.REMAINDER)
        s.set_defaults(func=func)

    s = sub.add_parser("start", help="start created or stopped containers")
    s.add_argument("-a", "--attach", action="store_true")
    s.add_argument("containers", nargs="+")
    s.set_defaults(func=cmd_start)

    s = sub.add_parser("ps", help="list containers")
    s.add_argument("-a", "--all", action="store_true")
    s.set_defaults(func=cmd_ps)

    s = sub.add_parser("stop", help="stop containers: SIGTERM, then SIGKILL")
    s.add_argument("-t", "--time", type=int)
    s.add_argument("containers", nargs="+")
    s.set_defaults(func=cmd_stop)

    s = sub.add_parser("kill", help="send a signal to containers (SIGKILL)")
    s.add_argument("-s", "--signal", default="KILL")
    s.add_argument("containers", nargs="+")
    s.set_defaults(func=cmd_kill)

    s = sub.add_parser("rm", help="remove containers")
    s.add_argument("-f", "--force", action="store_true")
    s.add_argument("containers", nargs="+")
    s.set_defaults(func=cmd_rm)

    s = sub.add_parser("logs", help="what a container wrote to its output")
    s.add_argument("-f", "--follow", action="store_true")
    s.add_argument("--tail", type=int)
    s.add_argument("container")
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("exec", help="run a command in a running container")
    s.add_argument("-t", "--tty", action="store_true")
    s.add_argument("-i", "--interactive", action="store_true")
    s.add_argument("-e", "--env", action="append")
    s.add_argument("-u", "--user")
    s.add_argument("-w", "--workdir")
    s.add_argument("container")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(func=cmd_exec)

    s = sub.add_parser("inspect", help="everything about containers, as JSON")
    s.add_argument("containers", nargs="+")
    s.set_defaults(func=cmd_inspect)

    sub.add_parser("stats", help="memory, processes and CPU time of the running containers").set_defaults(func=cmd_stats)

    s = sub.add_parser("wait", help="wait for containers to stop and print their exit codes")
    s.add_argument("containers", nargs="+")
    s.set_defaults(func=cmd_wait)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rt = Runtime(Store(args.root))
        return args.func(args, rt)
    except (KonteynerError, ValueError) as e:
        print("konteyner: %s" % e, file=sys.stderr)
        return getattr(e, "exit_code", 1)
    except PermissionError as e:
        print("konteyner: %s (this needs root)" % e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
