"""Unpacking layers: the safety rules, the whiteouts, and what overlayfs makes of the result."""
import bz2
import gzip
import hashlib
import io
import lzma
import os
import stat
import tarfile

import pytest

from conftest import needs_root
from kendi_konteyner import linux
from kendi_konteyner.layers import LayerError, extract_layer, tar_digest


def make_tar(entries, fmt=tarfile.PAX_FORMAT):
    """``entries``: (name, kind, content_or_target, mode) with kind one of f d l h c p."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tar:
        for name, kind, extra, mode in entries:
            ti = tarfile.TarInfo(name)
            ti.mode = mode
            ti.mtime = 1_000_000_000
            if kind == "f":
                data = extra if isinstance(extra, bytes) else extra.encode()
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
            elif kind == "d":
                ti.type = tarfile.DIRTYPE
                tar.addfile(ti)
            elif kind == "l":
                ti.type = tarfile.SYMTYPE
                ti.linkname = extra
                tar.addfile(ti)
            elif kind == "h":
                ti.type = tarfile.LNKTYPE
                ti.linkname = extra
                tar.addfile(ti)
            elif kind == "c":
                ti.type = tarfile.CHRTYPE
                ti.devmajor, ti.devminor = extra
                tar.addfile(ti)
            elif kind == "p":
                ti.type = tarfile.FIFOTYPE
                tar.addfile(ti)
    return buf.getvalue()


def unpack(data, dest):
    return extract_layer(io.BytesIO(data), str(dest))


def test_files_directories_links_and_modes(tmp_path):
    data = make_tar([("a", "d", None, 0o755), ("a/f.txt", "f", "hello", 0o640), ("a/s", "l", "f.txt", 0o777), ("a/hard", "h", "a/f.txt", 0o640), ("e", "d", None, 0o700), ("x.sh", "f", "#!/bin/sh\n", 0o4755)])
    info = unpack(data, tmp_path)
    assert info["files"] == 4 and info["bytes"] == 5 + 10 and info["whiteouts"] == 0
    assert (tmp_path / "a" / "f.txt").read_text() == "hello"
    assert os.readlink(tmp_path / "a" / "s") == "f.txt"
    assert os.stat(tmp_path / "a" / "hard").st_ino == os.stat(tmp_path / "a" / "f.txt").st_ino
    assert stat.S_IMODE(os.stat(tmp_path / "e").st_mode) == 0o700 and stat.S_IMODE(os.stat(tmp_path / "a" / "f.txt").st_mode) == 0o640
    assert os.stat(tmp_path / "x.sh").st_mode & 0o7777 == 0o4755 if os.geteuid() == 0 else True
    assert int(os.stat(tmp_path / "a" / "f.txt").st_mtime) == 1_000_000_000
    assert int(os.stat(tmp_path / "a").st_mtime) == 1_000_000_000  # a directory keeps its time although files were made in it


def test_the_diff_id_is_the_digest_of_the_uncompressed_tar(tmp_path):
    data = make_tar([("f", "f", "x" * 100000, 0o644)] * 1 + [("d", "d", None, 0o755)])
    want = "sha256:" + hashlib.sha256(data).hexdigest()
    for name, blob in (("plain", data), ("gzip", gzip.compress(data)), ("xz", lzma.compress(data)), ("bz2", bz2.compress(data))):
        dest = tmp_path / name
        assert unpack(blob, dest)["diff_id"] == want, name
        assert tar_digest(io.BytesIO(blob)) == want
    # trailing zero blocks and padding are part of the digest too
    assert unpack(data + b"\0" * 4096, tmp_path / "padded")["diff_id"] == "sha256:" + hashlib.sha256(data + b"\0" * 4096).hexdigest()


def test_zstd_is_refused_clearly(tmp_path):
    with pytest.raises(LayerError, match="zstd"):
        unpack(b"\x28\xb5\x2f\xfd" + b"\0" * 100, tmp_path)


@pytest.mark.parametrize("name", ["../evil", "a/../../evil", "/../evil", "a/.."])
def test_paths_that_leave_the_layer_are_refused(tmp_path, name):
    with pytest.raises(LayerError):
        unpack(make_tar([(name, "f", "x", 0o644)]), tmp_path / "layer")
    assert not (tmp_path / "evil").exists()


def test_absolute_names_are_relative_to_the_layer(tmp_path):
    unpack(make_tar([("/etc/passwd", "f", "root", 0o644), ("./usr//bin/", "d", None, 0o755)]), tmp_path / "layer")
    assert (tmp_path / "layer" / "etc" / "passwd").read_text() == "root"
    assert (tmp_path / "layer" / "usr" / "bin").is_dir()
    assert not os.path.exists("/etc/passwd.x")


def test_a_path_through_a_symlink_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    data = make_tar([("link", "l", str(outside), 0o777), ("link/pwned", "f", "x", 0o644)])
    with pytest.raises(LayerError, match="symlink"):
        unpack(data, tmp_path / "layer")
    assert os.listdir(outside) == []
    data = make_tar([("d", "d", None, 0o755), ("d/l", "l", "../..", 0o777), ("d/l/x/y", "f", "x", 0o644)])
    with pytest.raises(LayerError):
        unpack(data, tmp_path / "layer2")


def test_hard_links_must_point_into_the_layer(tmp_path):
    with pytest.raises(LayerError, match="not in the layer"):
        unpack(make_tar([("l", "h", "missing", 0o644)]), tmp_path / "a")
    victim = tmp_path / "victim"
    victim.write_text("do not touch")
    with pytest.raises(LayerError):
        unpack(make_tar([("l", "h", "../victim", 0o644)]), tmp_path / "b")
    assert victim.read_text() == "do not touch" and os.stat(victim).st_nlink == 1


def test_a_later_entry_replaces_an_earlier_one(tmp_path):
    unpack(make_tar([("x", "f", "file", 0o644), ("x", "d", None, 0o755), ("x/inside", "f", "i", 0o644), ("y", "d", None, 0o755), ("y/z", "f", "z", 0o644), ("y", "f", "now a file", 0o644)]), tmp_path)
    assert (tmp_path / "x" / "inside").read_text() == "i"
    assert (tmp_path / "y").read_text() == "now a file"


@needs_root
def test_special_files_and_ownership_are_kept(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, uid, gid in (("owned", 1234, 4321),):
            ti = tarfile.TarInfo(name)
            ti.uid, ti.gid, ti.size = uid, gid, 1
            tar.addfile(ti, io.BytesIO(b"x"))
        ti = tarfile.TarInfo("null")
        ti.type, ti.devmajor, ti.devminor, ti.mode = tarfile.CHRTYPE, 1, 3, 0o666
        tar.addfile(ti)
        ti = tarfile.TarInfo("fifo")
        ti.type, ti.mode = tarfile.FIFOTYPE, 0o600
        tar.addfile(ti)
    unpack(buf.getvalue(), tmp_path)
    st = os.stat(tmp_path / "owned")
    assert (st.st_uid, st.st_gid) == (1234, 4321)
    n = os.stat(tmp_path / "null")
    assert stat.S_ISCHR(n.st_mode) and (os.major(n.st_rdev), os.minor(n.st_rdev)) == (1, 3)
    assert stat.S_ISFIFO(os.stat(tmp_path / "fifo").st_mode)


@needs_root
def test_whiteouts_become_overlay_whiteouts(tmp_path):
    data = make_tar([("d", "d", None, 0o755), ("d/.wh.gone", "f", "", 0o644), ("d/keep", "f", "k", 0o644), ("o", "d", None, 0o755), ("o/.wh..wh..opq", "f", "", 0o644), ("o/new", "f", "n", 0o644)])
    info = unpack(data, tmp_path)
    assert info["whiteouts"] == 2
    gone = os.lstat(tmp_path / "d" / "gone")
    assert stat.S_ISCHR(gone.st_mode) and gone.st_rdev == 0  # the character device 0/0 that overlayfs reads as "deleted"
    assert os.getxattr(tmp_path / "o", "trusted.overlay.opaque") == b"y"
    assert not os.path.exists(tmp_path / "d" / ".wh.gone") and not os.path.exists(tmp_path / "o" / ".wh..wh..opq")


@needs_root
def test_overlayfs_reads_the_converted_layers_like_the_tar_says(tmp_path):
    """The kernel is the oracle: two layers, the upper one deletes a file, empties a directory (opaque), replaces a file by a directory."""
    lower = make_tar([("keep", "f", "k", 0o644), ("del", "f", "d", 0o644), ("dir", "d", None, 0o755), ("dir/a", "f", "a", 0o644), ("dir/b", "f", "b", 0o644),
                      ("file2dir", "f", "was a file", 0o644), ("sub", "d", None, 0o755), ("sub/deep", "d", None, 0o755), ("sub/deep/f", "f", "f", 0o644)])
    upper = make_tar([(".wh.del", "f", "", 0o644), ("dir", "d", None, 0o755), ("dir/.wh..wh..opq", "f", "", 0o644), ("dir/c", "f", "c", 0o644),
                      (".wh.file2dir", "f", "", 0o644), ("file2dir", "d", None, 0o755), ("file2dir/x", "f", "x", 0o644), ("sub/.wh.deep", "f", "", 0o644), ("added", "f", "new", 0o644)])
    unpack(lower, tmp_path / "l")
    unpack(upper, tmp_path / "u")
    for d in ("up", "work", "m"):
        (tmp_path / d).mkdir()
    # the whiteout file ".wh.file2dir" and a new "file2dir" in one layer: the tar lists the deletion first
    linux.mount("overlay", str(tmp_path / "m"), "overlay", 0, "lowerdir=%s:%s,upperdir=%s,workdir=%s" % (tmp_path / "u", tmp_path / "l", tmp_path / "up", tmp_path / "work"))
    try:
        seen = {}
        for dirpath, dirs, files in os.walk(tmp_path / "m"):
            for name in dirs + files:
                p = os.path.join(dirpath, name)
                seen[os.path.relpath(p, tmp_path / "m")] = open(p).read() if os.path.isfile(p) else "<dir>"
        assert seen == {"keep": "k", "dir": "<dir>", "dir/c": "c", "file2dir": "<dir>", "file2dir/x": "x", "sub": "<dir>", "added": "new"}
    finally:
        linux.umount(str(tmp_path / "m"))
