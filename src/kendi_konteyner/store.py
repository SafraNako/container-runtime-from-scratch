"""Where everything is kept: images, layers and containers, under one directory (``/var/lib/kendi-konteyner``, or ``$KONTEYNER_ROOT``).

    layers/<sha256 of the uncompressed layer>/      the files of one layer, whiteouts as overlayfs wants them
    images/<image id>.json                          the config of an image, the list of its layers, its tags
    containers/<id>/config.json state.json          what was asked for, what happened
    containers/<id>/upper work                      the writable layer of the container (overlayfs)
    containers/<id>/hostname hosts resolv.conf log  files that are bind mounted into the container
    network/leases.json                             addresses given to containers
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
from typing import Any, Iterator, Optional

DEFAULT_ROOT = "/var/lib/kendi-konteyner"


def default_root() -> str:
    return os.environ.get("KONTEYNER_ROOT", DEFAULT_ROOT)


class Store:
    def __init__(self, root: Optional[str] = None) -> None:
        self.root = os.path.abspath(root or default_root())
        for sub in ("layers", "images", "containers", "network"):
            os.makedirs(os.path.join(self.root, sub), exist_ok=True)

    def path(self, *parts: str) -> str:
        return os.path.join(self.root, *parts)

    @contextlib.contextmanager
    def lock(self, name: str = "lock") -> Iterator[None]:
        fd = os.open(self.path(name), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    # json files that are replaced atomically (a reader never sees half of one)

    def write_json(self, path: str, data: Any) -> None:
        d = os.path.dirname(path)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(data, fh, indent=1, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def read_json(self, path: str, default: Any = None) -> Any:
        try:
            with open(path) as fh:
                return json.load(fh)
        except FileNotFoundError:
            return default
