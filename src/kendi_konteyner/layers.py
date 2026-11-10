"""Unpacking the layers of an image.

An image is a stack of layers, each one a tar file of the files that were added, changed or removed by one step of its build.  A removal
is written in the tar as a *whiteout*: an empty file named ``.wh.<name>`` stands for "``<name>`` is gone", and ``.wh..wh..opq`` in a
directory says "everything below this directory in the layers underneath is gone".  overlayfs has its own way to say the same thing (a
character device 0/0 with the name of the removed file, an extended attribute ``trusted.overlay.opaque=y`` on the directory), so every
layer is unpacked into a directory of its own with its whiteouts converted, and the kernel stacks the directories (``lowerdir=top:...:bottom``).
That is how Docker's overlay2 driver works too.

The tar is not trusted: a name with ``..``, an absolute name, or a path that goes through a symlink of the same archive is refused.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import os
import stat
import tarfile
import zlib
from typing import BinaryIO, Dict, List, Tuple

WHITEOUT = ".wh."
OPAQUE = ".wh..wh..opq"


class LayerError(Exception):
    pass


def normalize(name: str) -> List[str]:
    """The components of a path of an archive.  ``./a//b/`` -> ``["a", "b"]``; ``..`` anywhere is an error."""
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise LayerError("the path %r goes out of the layer" % name)
    return parts


class _Hashing:
    """A file object that hashes what is read from it (the digest of the uncompressed layer, which an image calls its diff id)."""

    def __init__(self, fileobj: BinaryIO) -> None:
        self.f = fileobj
        self.sha = hashlib.sha256()
        self.size = 0

    def read(self, n: int = -1) -> bytes:
        data = self.f.read(n)
        self.sha.update(data)
        self.size += len(data)
        return data

    def drain(self) -> None:
        while self.read(1 << 20):
            pass


def open_decompressed(fileobj: BinaryIO) -> BinaryIO:
    """The tar stream inside a layer file, whether it is compressed with gzip, xz, bzip2 or not at all."""
    head = fileobj.read(6)
    raw = io.BufferedReader(_Prefixed(head, fileobj))  # type: ignore[arg-type]
    if head[:2] == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=raw)  # type: ignore[return-value]
    if head[:6] == b"\xfd7zXZ\x00":
        return lzma.LZMAFile(raw)  # type: ignore[return-value]
    if head[:3] == b"BZh":
        return bz2.BZ2File(raw)  # type: ignore[return-value]
    if head[:4] == b"\x28\xb5\x2f\xfd":
        raise LayerError("zstd compressed layers are not supported")
    return raw


class _Prefixed(io.RawIOBase):
    """``head`` followed by the rest of ``fileobj`` (a few bytes were read to find out the compression)."""

    def __init__(self, head: bytes, fileobj: BinaryIO) -> None:
        self.head = head
        self.f = fileobj

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:  # type: ignore[override]
        if self.head:
            n = min(len(b), len(self.head))
            b[:n] = self.head[:n]
            self.head = self.head[n:]
            return n
        data = self.f.read(len(b))
        b[: len(data)] = data
        return len(data)


def _walk_parents(dest: str, parts: List[str]) -> str:
    """The directory that holds the last component, made on the way; no component may be a symlink."""
    cur = dest
    for p in parts[:-1]:
        cur = os.path.join(cur, p)
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            os.mkdir(cur, 0o755)
            continue
        if stat.S_ISLNK(st.st_mode):
            raise LayerError("the path %s goes through a symlink" % "/".join(parts))
        if not stat.S_ISDIR(st.st_mode):
            raise LayerError("%s is not a directory" % os.path.relpath(cur, dest))
    return cur


def _remove(path: str) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        for name in os.listdir(path):
            _remove(os.path.join(path, name))
        os.rmdir(path)
    else:
        os.unlink(path)


def _apply_xattrs(path: str, member: tarfile.TarInfo) -> None:
    for key, value in member.pax_headers.items():
        if key.startswith("SCHILY.xattr."):
            try:
                os.setxattr(path, key[len("SCHILY.xattr.") :], value.encode("utf-8", "surrogateescape"), follow_symlinks=False)
            except OSError:
                pass  # a file system or a user that cannot hold the attribute


def _chown(path: str, uid: int, gid: int) -> None:
    if os.geteuid() == 0:
        os.lchown(path, uid, gid)


def extract_layer(fileobj: BinaryIO, dest: str, overlay_whiteouts: bool = True) -> Dict[str, object]:
    """Unpacks a layer (see ``_extract_layer``); a damaged archive is a ``LayerError``."""
    try:
        return _extract_layer(fileobj, dest, overlay_whiteouts)
    except (tarfile.TarError, EOFError, zlib.error, lzma.LZMAError, gzip.BadGzipFile) as e:
        raise LayerError("the layer is damaged: %s" % e) from None


def _extract_layer(fileobj: BinaryIO, dest: str, overlay_whiteouts: bool = True) -> Dict[str, object]:
    """Unpacks a layer (a file object of a tar, compressed or not) into the directory ``dest``.

    Returns ``{"diff_id": "sha256:...", "files": n, "bytes": n, "whiteouts": n}``: the digest is of the uncompressed tar."""
    os.makedirs(dest, exist_ok=True)
    stream = _Hashing(open_decompressed(fileobj))
    files = size = whiteouts = 0
    dir_meta: List[Tuple[str, tarfile.TarInfo]] = []
    root = os.path.abspath(dest)
    with tarfile.open(fileobj=stream, mode="r|") as tar:  # type: ignore[arg-type]
        for member in tar:
            parts = normalize(member.name)
            if not parts:  # "." the root of the layer
                if member.isdir():
                    dir_meta.append((root, member))
                continue
            parent = _walk_parents(root, parts)
            base = parts[-1]
            path = os.path.join(parent, base)
            if base.startswith(WHITEOUT):
                if not overlay_whiteouts:
                    raise LayerError("whiteouts need overlayfs")
                if base == OPAQUE:
                    os.setxattr(parent, "trusted.overlay.opaque", b"y")
                else:
                    target = os.path.join(parent, base[len(WHITEOUT) :])
                    _remove(target)
                    os.mknod(target, stat.S_IFCHR | 0o000, os.makedev(0, 0))
                whiteouts += 1
                continue
            if member.isdir():
                try:
                    st = os.lstat(path)
                    if not stat.S_ISDIR(st.st_mode):
                        _remove(path)
                        os.mkdir(path, 0o755)
                except FileNotFoundError:
                    os.mkdir(path, 0o755)
                dir_meta.append((path, member))
                continue
            _remove(path)
            if member.isreg():
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as out:
                    src = tar.extractfile(member)
                    assert src is not None
                    while True:
                        chunk = src.read(1 << 20)
                        if not chunk:
                            break
                        out.write(chunk)
                size += member.size
            elif member.issym():
                os.symlink(member.linkname, path)
            elif member.islnk():
                target_parts = normalize(member.linkname)
                target = os.path.join(root, *target_parts)
                if not target_parts or not os.path.lexists(target):
                    raise LayerError("the hard link %s points to %s, which is not in the layer" % (member.name, member.linkname))
                _walk_parents(root, target_parts)  # refuses a target behind a symlink
                os.link(target, path, follow_symlinks=False)
            elif member.ischr() or member.isblk() or member.isfifo():
                kind = stat.S_IFCHR if member.ischr() else stat.S_IFBLK if member.isblk() else stat.S_IFIFO
                try:
                    os.mknod(path, kind | (member.mode & 0o7777), os.makedev(member.devmajor, member.devminor))
                except PermissionError:
                    continue
            else:
                raise LayerError("%s: unsupported kind of file in a layer" % member.name)
            files += 1
            if not member.islnk():
                _chown(path, member.uid, member.gid)
                if not member.issym():
                    os.chmod(path, member.mode & 0o7777)
                _apply_xattrs(path, member)
                try:
                    os.utime(path, (member.mtime, member.mtime), follow_symlinks=False)
                except (OSError, NotImplementedError):
                    pass
    stream.drain()
    for path, member in reversed(dir_meta):  # a directory is finished last: creating files in it changes its times
        _chown(path, member.uid, member.gid)
        os.chmod(path, member.mode & 0o7777)
        _apply_xattrs(path, member)
        try:
            os.utime(path, (member.mtime, member.mtime))
        except OSError:
            pass
    return {"diff_id": "sha256:" + stream.sha.hexdigest(), "files": files, "bytes": size, "whiteouts": whiteouts}


def tar_digest(fileobj: BinaryIO) -> str:
    """The sha256 of the uncompressed content of a layer file (without unpacking it)."""
    stream = _Hashing(open_decompressed(fileobj))
    try:
        stream.drain()
    except (EOFError, zlib.error, lzma.LZMAError, gzip.BadGzipFile) as e:
        raise LayerError("the layer is damaged: %s" % e) from None
    return "sha256:" + stream.sha.hexdigest()
