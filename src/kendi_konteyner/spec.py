"""What a container is made of: the options of ``run``, kept as ``config.json`` in the container's directory."""
from __future__ import annotations

import dataclasses
import os
import re
import secrets
import time
from typing import Dict, List, Optional

from .linux import DEFAULT_CAPS

DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
NETWORKS = ("none", "host", "bridge")

_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")


@dataclasses.dataclass
class Volume:
    source: str
    target: str
    readonly: bool = False


@dataclasses.dataclass
class Config:
    id: str
    image_id: str
    image_name: str
    argv: List[str]
    name: str = ""
    env: List[str] = dataclasses.field(default_factory=list)
    workdir: str = "/"
    user: str = ""
    hostname: str = ""
    memory: Optional[int] = None
    cpus: Optional[float] = None
    pids_limit: Optional[int] = None
    volumes: List[Volume] = dataclasses.field(default_factory=list)
    tmpfs: List[str] = dataclasses.field(default_factory=list)
    read_only: bool = False
    network: str = "bridge"
    tty: bool = False
    interactive: bool = False
    detach: bool = False
    cap_add: List[str] = dataclasses.field(default_factory=list)
    cap_drop: List[str] = dataclasses.field(default_factory=list)
    privileged: bool = False
    no_new_privileges: bool = False
    seccomp: bool = True
    init: bool = False
    stop_timeout: int = 10
    created_at: float = dataclasses.field(default_factory=time.time)
    labels: Dict[str, str] = dataclasses.field(default_factory=dict)

    def to_json(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_json(cls, data: dict) -> "Config":
        data = dict(data)
        data["volumes"] = [Volume(**v) for v in data.get("volumes", [])]
        return cls(**data)


def new_id() -> str:
    return secrets.token_hex(32)


def check_name(name: str) -> str:
    if name and not _NAME.match(name):
        raise ValueError("%r is not a valid container name (letters, digits, _ . - and not first)" % name)
    return name


def parse_volume(text: str) -> Volume:
    """``/host:/container`` or ``/host:/container:ro``."""
    parts = text.split(":")
    if len(parts) not in (2, 3) or not parts[0] or not parts[1].startswith("/"):
        raise ValueError("a volume is written /host/path:/container/path[:ro], not %r" % text)
    ro = False
    if len(parts) == 3:
        if parts[2] not in ("ro", "rw"):
            raise ValueError("the option of a volume is ro or rw, not %r" % parts[2])
        ro = parts[2] == "ro"
    if not os.path.isabs(parts[0]):
        raise ValueError("the host path of a volume has to be absolute: %r" % parts[0])
    return Volume(parts[0], os.path.normpath(parts[1]), ro)


def parse_env(items: List[str]) -> List[str]:
    out = []
    for item in items:
        if "=" not in item:
            if item in os.environ:  # -e NAME passes the value of the caller
                out.append("%s=%s" % (item, os.environ[item]))
            continue
        out.append(item)
    return out


def effective_caps(cfg: Config) -> int:
    """The mask of capabilities the container's processes get: Docker's default set, plus ``cap_add``, minus ``cap_drop`` (``ALL`` too)."""
    from . import linux

    if cfg.privileged:
        return (1 << (linux.last_cap() + 1)) - 1 if linux.ON_LINUX else (1 << 41) - 1
    adds = [n.upper() for n in cfg.cap_add]
    drops = [n.upper() for n in cfg.cap_drop]
    keep = 0 if "ALL" in drops else linux.mask(DEFAULT_CAPS) & ~linux.mask([n for n in drops])  # the drops come first, like in Docker
    if "ALL" in adds:
        return (1 << len(linux.CAP_NAMES)) - 1
    return keep | linux.mask(adds)
