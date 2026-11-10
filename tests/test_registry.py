"""Pulling from a registry: the real Docker Hub (the digests must be Docker's), and a registry of our own for the failures."""
import hashlib
import http.server
import json
import os
import shutil
import socket
import tarfile
import tempfile
import threading

import pytest

from conftest import IMAGE, needs_docker, needs_root
from kendi_konteyner.errors import ImageError
from kendi_konteyner.image import ImageStore
from kendi_konteyner.registry import Registry, RegistryError, parse_reference
from kendi_konteyner.store import Store

pytestmark = needs_root


def hub_reachable() -> bool:
    try:
        socket.create_connection(("registry-1.docker.io", 443), timeout=5).close()
        return True
    except OSError:
        return False


needs_hub = pytest.mark.skipif(not hub_reachable(), reason="Docker Hub is not reachable")


@pytest.fixture
def fresh():
    store = Store(tempfile.mkdtemp(prefix="kk-pull-", dir="/var/tmp"))
    yield ImageStore(store)
    shutil.rmtree(store.root, ignore_errors=True)


@needs_hub
@needs_docker
def test_a_pulled_image_is_the_image_of_docker(fresh, docker):
    img = fresh.pull(IMAGE)
    from test_image import config_digest

    info = json.loads(docker("image", "inspect", IMAGE).out)[0]
    assert img.id == config_digest(docker, IMAGE)
    assert img.layers == info["RootFS"]["Layers"]
    assert img.tags == [IMAGE] and img.data["digest"].startswith("sha256:")
    # the second pull has nothing to download
    messages = []
    fresh.pull(IMAGE, progress=messages.append)
    assert all("already here" in m for m in messages)


@needs_hub
@needs_docker
def test_the_pulled_layers_are_the_files_of_the_export(fresh, docker, tmp_path):
    from test_image import compare_with_docker

    img = fresh.pull(IMAGE)
    compare_with_docker(None, docker, img, IMAGE, tmp_path)


@needs_hub
def test_an_index_gives_the_image_for_this_machine_and_a_digest_can_be_pulled(fresh):
    img = fresh.pull("hello-world")  # the tag points to an index of many platforms
    assert img.config["os"] == "linux" and len(img.layers) == 1 and img.tags == ["hello-world:latest"]
    again = fresh.pull("hello-world@" + img.data["digest"])
    assert again.id == img.id


@needs_hub
def test_errors_are_clear(fresh):
    with pytest.raises(ImageError, match="not found"):
        fresh.pull("library/this-image-does-not-exist-kk:1")  # Docker Hub answers 401 for an unknown name
    with pytest.raises(ValueError):
        fresh.pull("Not A Valid Name")
    reg = Registry(parse_reference("alpine:3.19"))
    with pytest.raises(RegistryError, match="no image for windows"):
        reg.image_manifest(os_name="windows", arch="amd64")


# ---------------------------------------------------------------------------------------------------------------- a registry of our own

class Fake(http.server.BaseHTTPRequestHandler):
    """The few requests of a pull, with a bearer token, serving the layers of an image that was saved by Docker."""

    blobs = {}
    manifests = {}
    tokens = 0
    corrupt = False

    def log_message(self, *a):
        pass

    def reply(self, code, body=b"", ctype="application/octet-stream", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        host = self.headers["Host"]
        if self.path.startswith("/token"):
            Fake.tokens += 1
            return self.reply(200, json.dumps({"token": "secret"}).encode(), "application/json")
        if self.headers.get("Authorization") != "Bearer secret":
            return self.reply(401, b"", headers={"WWW-Authenticate": 'Bearer realm="http://%s/token",service="fake",scope="repository:app:pull"' % host})
        parts = self.path.split("/")
        if "manifests" in parts:
            m = self.manifests.get(parts[-1])
            if m is None:
                return self.reply(404)
            return self.reply(200, m[1], m[0])
        if "blobs" in parts:
            data = self.blobs.get(parts[-1])
            if data is None:
                return self.reply(404)
            if Fake.corrupt and len(data) > 100000:
                data = data[:5000] + bytes([data[5000] ^ 1]) + data[5001:]
            return self.reply(200, data)
        self.reply(404)


@pytest.fixture
def server(docker, tmp_path):
    saved = str(tmp_path / "a.tar")
    docker("save", IMAGE, "-o", saved)
    with tarfile.open(saved) as tar:
        manifest = json.load(tar.extractfile("manifest.json"))[0]
        config = tar.extractfile(manifest["Config"]).read()
        layers = [tar.extractfile(l).read() for l in manifest["Layers"]]
    digest = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()
    blobs = {digest(config): config}
    descs = []
    for l in layers:
        blobs[digest(l)] = l
        descs.append({"mediaType": "application/vnd.docker.image.rootfs.diff.tar", "size": len(l), "digest": digest(l)})
    m = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": len(config), "digest": digest(config)}, "layers": descs}).encode()
    Fake.blobs = blobs
    Fake.manifests = {"v1": ("application/vnd.docker.distribution.manifest.v2+json", m), digest(m): ("application/vnd.docker.distribution.manifest.v2+json", m)}
    Fake.tokens = 0
    Fake.corrupt = False
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield "127.0.0.1:%d" % httpd.server_address[1]
    httpd.shutdown()


@needs_docker
def test_the_token_dance_and_a_pull_from_another_registry(fresh, server, docker):
    from test_image import config_digest

    img = fresh.pull("%s/app:v1" % server)
    info = json.loads(docker("image", "inspect", IMAGE).out)[0]
    assert img.id == config_digest(docker, IMAGE) and img.layers == info["RootFS"]["Layers"]
    assert Fake.tokens == 1 and img.tags == ["%s/app:v1" % server]


@needs_docker
def test_a_blob_with_the_wrong_digest_is_refused_and_nothing_is_kept(fresh, server):
    Fake.corrupt = True
    with pytest.raises(ImageError, match="digest"):
        fresh.pull("%s/app:v1" % server)
    assert os.listdir(fresh.store.path("layers")) == [] and fresh.all() == []


@needs_docker
def test_a_missing_tag_is_an_error(fresh, server):
    with pytest.raises(ImageError, match="not found"):
        fresh.pull("%s/app:nope" % server)
