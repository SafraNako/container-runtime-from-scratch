"""Images: loading what Docker saved, importing a root file system, tags; and the layers against Docker's own export of the same image."""
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import textwrap

import pytest

from conftest import IMAGE, needs_docker, needs_root
from kendi_konteyner import linux
from kendi_konteyner.errors import ImageError, NoSuchImage
from kendi_konteyner.image import ImageStore
from kendi_konteyner.store import Store

pytestmark = needs_root


def tree_of_directory(path, skip=lambda rel: False):
    """name -> (type, permissions, uid, gid, size, link target, mtime, sha256 of the content)."""
    out = {}
    for dirpath, dirs, files in os.walk(path):
        for name in dirs + files:
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, path)
            if skip(rel):
                continue
            st = os.lstat(p)
            kind = "d" if stat.S_ISDIR(st.st_mode) else "l" if stat.S_ISLNK(st.st_mode) else "f" if stat.S_ISREG(st.st_mode) else "c" if stat.S_ISCHR(st.st_mode) else "o"
            sha = hashlib.sha256(open(p, "rb").read()).hexdigest() if kind == "f" else None
            out[rel] = (kind, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_size if kind == "f" else 0, os.readlink(p) if kind == "l" else None, int(st.st_mtime) if kind != "d" else 0, sha)
    return out


def tree_of_export(data):
    out = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        members = {m.name.rstrip("/"): m for m in tar}
        for name, m in members.items():
            kind = "d" if m.isdir() else "l" if m.issym() else "f" if m.isreg() or m.islnk() else "c" if m.ischr() else "o"
            target = m.linkname if m.issym() else None
            src = m
            if m.islnk():  # a hard link in a tar: the content is the one of the file it points to
                src = members[m.linkname.rstrip("/")]
            sha = hashlib.sha256(tar.extractfile(src).read()).hexdigest() if kind == "f" else None
            out[name] = (kind, m.mode & 0o7777, m.uid, m.gid, src.size if kind == "f" else 0, target, int(m.mtime) if kind != "d" else 0, sha)
    return out


RUNTIME_FILES = (".dockerenv", "etc/hostname", "etc/hosts", "etc/resolv.conf", "dev", "proc", "sys", "etc/mtab")


def merged_view(image, tmp):
    lower = ":".join(image.layer_dirs())
    for d in ("up", "work", "m"):
        os.makedirs(os.path.join(tmp, d), exist_ok=True)
    linux.mount("overlay", os.path.join(tmp, "m"), "overlay", 0, "lowerdir=%s,upperdir=%s,workdir=%s" % (lower, os.path.join(tmp, "up"), os.path.join(tmp, "work")))
    return os.path.join(tmp, "m")


def compare_with_docker(runtime, docker, image, ref, tmp_path):
    """The root file system that this runtime makes from the layers against the one of ``docker export``."""
    assert docker("create", "--name", "kk-export", ref).code == 0
    try:
        data = subprocess.run(["docker", "export", "kk-export"], capture_output=True, check=True).stdout
    finally:
        docker("rm", "-f", "kk-export")
    theirs = {k: v for k, v in tree_of_export(data).items() if k not in RUNTIME_FILES and not k.startswith("dev/")}
    root = merged_view(image, str(tmp_path))
    try:
        mine = tree_of_directory(root, lambda rel: rel in RUNTIME_FILES or rel.startswith("dev/"))
    finally:
        linux.umount(root)
    # a directory's own time is not compared (the export makes it from the files); everything else has to be equal
    assert sorted(mine) == sorted(theirs)
    different = {k: (mine[k], theirs[k]) for k in mine if mine[k] != theirs[k]}
    assert not different, list(different.items())[:5]
    return mine


@needs_docker
def test_the_layers_of_an_image_are_the_files_of_its_export(runtime, docker, image, tmp_path):
    tree = compare_with_docker(runtime, docker, image, IMAGE, tmp_path)
    assert "bin/busybox" in tree and tree["bin/busybox"][0] == "f" and len(tree) > 400


@needs_docker
def test_removed_files_replaced_directories_links_and_modes_survive_the_layers(runtime, docker, tmp_path):
    ctx = tmp_path / "ctx"
    ctx.mkdir()
    (ctx / "Dockerfile").write_text(
        textwrap.dedent(
            """
            FROM %s
            RUN mkdir -p /d /e /f && echo a > /d/a && echo b > /d/b && echo keep > /e/k && echo x > /f/x && ln -s /d/a /lnk && ln /d/b /d/b_hard \\
                && chmod 4755 /d/a && touch -d @1000000000 /d/b && mkdir /empty && chown 1234:4321 /d/b && echo conf > /etc/to-be-replaced
            RUN rm /d/a && echo c > /d/c && rm -rf /e && mkdir /e && echo new > /e/n && rm /f/x && ln -s /d/c /f/x && rm /etc/to-be-replaced && mkdir /etc/to-be-replaced
            RUN rm -rf /etc/apk/keys && mkdir /etc/apk/keys && echo only > /etc/apk/keys/one && chmod 600 /etc/apk/keys/one
            """
            % IMAGE
        )
    )
    built = docker("build", "-q", "-t", "kk-whiteouts", str(ctx), timeout=300)
    assert built.code == 0, built.err
    try:
        saved = tmp_path / "wo.tar"
        assert docker("save", "kk-whiteouts", "-o", str(saved)).code == 0
        store = Store(tempfile.mkdtemp(prefix="kk-img-", dir="/var/tmp"))
        images = ImageStore(store)
        try:
            (img,) = images.load(str(saved))
            assert len(img.layers) >= 4 and img.tags == ["kk-whiteouts:latest"]
            # the layers contain whiteouts for real: the second one deletes /d/a and /e
            assert any(os.path.lexists(os.path.join(d, "d", "a")) and stat.S_ISCHR(os.lstat(os.path.join(d, "d", "a")).st_mode) for d in img.layer_dirs())
            tree = compare_with_docker(None, docker, img, "kk-whiteouts", tmp_path)
            assert "d/a" not in tree and "e/k" not in tree and tree["e/n"][0] == "f" and tree["d/b_hard"][7] == tree["d/b"][7]
            assert tree["f/x"][0] == "l" and tree["etc/to-be-replaced"][0] == "d" and tree["d/b"][2:4] == (1234, 4321) and tree["d/b"][6] == 1000000000
            assert list(k for k in tree if k.startswith("etc/apk/keys/")) == ["etc/apk/keys/one"]
        finally:
            shutil.rmtree(store.root, ignore_errors=True)
    finally:
        docker("rmi", "-f", "kk-whiteouts")


def config_digest(docker, ref):
    """The digest of the config of an image, from the manifest in ``docker save`` (``docker inspect`` shows another id with Docker's newer image store)."""
    d = tempfile.mkdtemp(prefix="kk-cfg-", dir="/var/tmp")
    try:
        tar = os.path.join(d, "x.tar")
        assert docker("save", ref, "-o", tar).code == 0
        with tarfile.open(tar) as t:
            name = json.load(t.extractfile("manifest.json"))[0]["Config"]
        return "sha256:" + os.path.basename(name).replace(".json", "")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@needs_docker
def test_ids_and_layer_digests_are_the_ones_of_docker(image, docker):
    info = json.loads(docker("image", "inspect", IMAGE).out)[0]
    assert image.id == config_digest(docker, IMAGE)  # the sha256 of the config, the same for everyone who has this image
    assert image.layers == info["RootFS"]["Layers"]  # the diff ids: sha256 of each uncompressed layer
    assert image.config["architecture"] == info["Architecture"] and image.config["config"]["Cmd"] == info["Config"]["Cmd"]
    assert image.defaults()["cmd"] == ["/bin/sh"]
    assert image.tags == [IMAGE]


@needs_docker
def test_loading_twice_changes_nothing_and_layers_are_shared(runtime, image, docker, tmp_path):
    store = Store(tempfile.mkdtemp(prefix="kk-img-", dir="/var/tmp"))
    images = ImageStore(store)
    try:
        tar = str(tmp_path / "a.tar")
        docker("save", IMAGE, "-o", tar)
        (a,) = images.load(tar)
        layers = sorted(os.listdir(store.path("layers")))
        (b,) = images.load(tar)
        assert a.id == b.id and sorted(os.listdir(store.path("layers"))) == layers and len(images.all()) == 1
        images.tag(IMAGE, "mine/alpine:v1")
        assert sorted(images.get("mine/alpine:v1").tags) == sorted([IMAGE, "mine/alpine:v1"])
        assert images.get(a.id).id == a.id and images.get(a.id[7:15]).id == a.id and images.get(a.short_id).id == a.id
        images.remove("mine/alpine:v1")  # only the name goes
        assert images.get(IMAGE).tags == [IMAGE]
        images.remove(IMAGE)  # the image and its layers go
        assert images.all() == [] and os.listdir(store.path("layers")) == []
        with pytest.raises(NoSuchImage):
            images.get(IMAGE)
    finally:
        shutil.rmtree(store.root, ignore_errors=True)


def test_a_tar_that_is_not_docker_save_is_refused(tmp_path):
    store = Store(tempfile.mkdtemp(prefix="kk-img-", dir="/var/tmp"))
    try:
        bad = tmp_path / "bad.tar"
        with tarfile.open(bad, "w") as tar:
            ti = tarfile.TarInfo("hello")
            tar.addfile(ti, io.BytesIO(b""))
        with pytest.raises(ImageError, match="manifest.json"):
            ImageStore(store).load(str(bad))
    finally:
        shutil.rmtree(store.root, ignore_errors=True)


@needs_docker
def test_a_damaged_layer_is_refused_and_leaves_no_trace(docker, tmp_path):
    saved = str(tmp_path / "s.tar")
    docker("save", IMAGE, "-o", saved)
    # flip one byte inside the layer
    with tarfile.open(saved) as tar:
        manifest = json.load(tar.extractfile("manifest.json"))
        layer = manifest[0]["Layers"][0]
        members = [(m, tar.extractfile(m).read() if m.isfile() else None) for m in tar]
    damaged = str(tmp_path / "d.tar")
    with tarfile.open(damaged, "w") as out:
        for m, data in members:
            if m.name == layer:
                data = data[:5000] + bytes([data[5000] ^ 0xFF]) + data[5001:]
            out.addfile(m, io.BytesIO(data) if data is not None else None)
    store = Store(tempfile.mkdtemp(prefix="kk-img-", dir="/var/tmp"))
    try:
        with pytest.raises(ImageError, match="digest|damaged"):
            ImageStore(store).load(damaged)
        assert os.listdir(store.path("layers")) == [] and os.listdir(store.path("images")) == []
    finally:
        shutil.rmtree(store.root, ignore_errors=True)


@needs_docker
def test_a_root_file_system_can_be_imported_and_run(kk, runtime, docker, image, tmp_path):
    assert docker("create", "--name", "kk-exp2", IMAGE).code == 0
    try:
        tar = str(tmp_path / "rootfs.tar")
        subprocess.run(["docker", "export", "kk-exp2", "-o", tar], check=True)
    finally:
        docker("rm", "-f", "kk-exp2")
    out = kk("import", tar, "imported:1")
    assert out.code == 0 and out.out.startswith("sha256:")
    run = kk("run", "--rm", "--network", "none", "imported:1", "sh", "-c", "cat /etc/alpine-release; echo $0")
    assert run.code == 0 and run.out.startswith("3.")
    assert "imported:1" in kk("images").out
    assert kk("rmi", "imported:1").code == 0
