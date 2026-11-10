"""Images: a config and a list of layers, kept in the store.

An image gets into the store in one of three ways: ``pull`` from a registry, ``load`` from the tar of ``docker save``, or ``import_rootfs``
from the tar of a root file system (what ``docker export`` writes).  The id of an image is the sha256 of its config, as in Docker.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import time
from typing import Callable, List, Optional

from .errors import ImageError, NoSuchImage
from .layers import LayerError, extract_layer
from .registry import Registry, RegistryError, VerifyingReader, goarch, parse_reference
from .store import Store

Progress = Optional[Callable[[str], None]]


class Image:
    def __init__(self, store: Store, data: dict) -> None:
        self.store = store
        self.data = data

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def short_id(self) -> str:
        return self.id.split(":")[-1][:12]

    @property
    def config(self) -> dict:
        return self.data["config"]

    @property
    def layers(self) -> List[str]:
        return self.data["layers"]

    @property
    def tags(self) -> List[str]:
        return self.data.get("tags", [])

    def layer_dirs(self) -> List[str]:
        """The directories of the layers, the topmost first (the order of ``lowerdir`` in an overlayfs mount)."""
        return [self.store.path("layers", d.split(":")[-1]) for d in reversed(self.layers)]

    def defaults(self) -> dict:
        """The ``Env``, ``Cmd``, ``Entrypoint``, ``WorkingDir`` and ``User`` that the image asks for."""
        c = self.config.get("config") or self.config.get("Config") or {}
        return {
            "env": list(c.get("Env") or []),
            "cmd": list(c.get("Cmd") or []),
            "entrypoint": list(c.get("Entrypoint") or []),
            "workdir": c.get("WorkingDir") or "/",
            "user": c.get("User") or "",
        }

    @property
    def size(self) -> int:
        return self.data.get("size", 0)


class ImageStore:
    def __init__(self, store: Store) -> None:
        self.store = store

    # -- bookkeeping

    def _image_path(self, image_id: str) -> str:
        return self.store.path("images", image_id.split(":")[-1] + ".json")

    def _save(self, data: dict) -> None:
        self.store.write_json(self._image_path(data["id"]), data)

    def all(self) -> List[Image]:
        out = []
        for name in sorted(os.listdir(self.store.path("images"))):
            if name.endswith(".json"):
                data = self.store.read_json(self.store.path("images", name))
                if data:
                    out.append(Image(self.store, data))
        return out

    def get(self, ref: str) -> Image:
        """An image by tag (``alpine``, ``alpine:3.20``) or by the beginning of its id."""
        images = self.all()
        wanted = ref.strip()
        try:
            name = parse_reference(wanted).name
        except ValueError:
            name = wanted
        for img in images:
            if name in img.tags or wanted in img.tags:
                return img
        hexpart = wanted.split(":")[-1].lower()
        matches = [i for i in images if len(hexpart) >= 4 and i.id.split(":")[-1].startswith(hexpart)]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ImageError("%r matches several images" % ref)
        raise NoSuchImage("no such image: %s" % ref)

    def _tag(self, data: dict, tags: List[str]) -> None:
        """Gives the tags to this image and takes them from the others (a tag names one image)."""
        for other in self.all():
            if other.id != data["id"] and any(t in other.tags for t in tags):
                other.data["tags"] = [t for t in other.tags if t not in tags]
                self._save(other.data)
        data["tags"] = sorted(set(data.get("tags", [])) | set(tags))

    def tag(self, ref: str, new: str) -> None:
        img = self.get(ref)
        self._tag(img.data, [parse_reference(new).name])
        self._save(img.data)

    def remove(self, ref: str) -> None:
        img = self.get(ref)
        try:
            name = parse_reference(ref).name
        except ValueError:
            name = ref
        if name in img.tags and len(img.tags) > 1:  # only the name goes
            img.data["tags"] = [t for t in img.tags if t != name]
            self._save(img.data)
            return
        os.unlink(self._image_path(img.id))
        still = {d for other in self.all() for d in other.layers}
        for d in img.layers:
            if d not in still:
                shutil.rmtree(self.store.path("layers", d.split(":")[-1]), ignore_errors=True)

    # -- layers

    def _have_layer(self, diff_id: str) -> bool:
        return os.path.isdir(self.store.path("layers", diff_id.split(":")[-1]))

    def _unpack_layer(self, fileobj, expected_diff: Optional[str]) -> str:
        """Unpacks into a temporary directory, checks the digest of the content, and moves it to its name (so a layer that is there is whole)."""
        tmp = self.store.path("layers", ".tmp-%d-%d" % (os.getpid(), time.time_ns()))
        try:
            info = extract_layer(fileobj, tmp)
            diff_id = str(info["diff_id"])
            if expected_diff and diff_id != expected_diff:
                raise ImageError("a layer has the digest %s, the image says %s" % (diff_id, expected_diff))
            final = self.store.path("layers", diff_id.split(":")[-1])
            if os.path.isdir(final):
                shutil.rmtree(tmp)
            else:
                os.rename(tmp, final)
            return diff_id
        except LayerError as e:
            shutil.rmtree(tmp, ignore_errors=True)
            raise ImageError(str(e)) from None
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise

    def _register(self, config_bytes: bytes, config: dict, layers: List[str], tags: List[str], sizes: int = 0) -> Image:
        image_id = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
        with self.store.lock():
            data = self.store.read_json(self._image_path(image_id)) or {"id": image_id, "config": config, "layers": layers, "tags": [], "size": sizes}
            data["created_at"] = int(time.time())
            self._tag(data, tags)
            self._save(data)
        return Image(self.store, data)

    # -- the three ways in

    def import_rootfs(self, tar_path: str, tag: Optional[str] = None, config: Optional[dict] = None) -> Image:
        """An image of one layer from the tar of a root file system."""
        with open(tar_path, "rb") as fh:
            diff_id = self._unpack_layer(fh, None)
        cfg = {
            "architecture": goarch(), "os": "linux", "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "config": dict(config or {"Cmd": ["/bin/sh"]}), "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        }
        raw = json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()
        name = parse_reference(tag).name if tag else None
        return self._register(raw, cfg, [diff_id], [name] if name else [], os.path.getsize(tar_path))

    def load(self, tar_path: str, progress: Progress = None) -> List[Image]:
        """The images of a tar made by ``docker save`` (a ``manifest.json``, the configs and the layers)."""
        out = []
        with tarfile.open(tar_path) as tar:
            try:
                manifest = json.load(tar.extractfile("manifest.json"))  # type: ignore[arg-type]
            except KeyError:
                raise ImageError("%s has no manifest.json: it is not the output of docker save" % tar_path) from None
            for entry in manifest:
                config_bytes = tar.extractfile(entry["Config"]).read()  # type: ignore[union-attr]
                config = json.loads(config_bytes)
                diff_ids = config["rootfs"]["diff_ids"]
                if len(diff_ids) != len(entry["Layers"]):
                    raise ImageError("the image has %d layers and %d diff ids" % (len(entry["Layers"]), len(diff_ids)))
                for member, diff_id in zip(entry["Layers"], diff_ids):
                    if self._have_layer(diff_id):
                        continue
                    if progress:
                        progress("unpacking %s" % diff_id[7:19])
                    self._unpack_layer(tar.extractfile(member), diff_id)  # type: ignore[arg-type]
                tags = []
                for t in entry.get("RepoTags") or []:
                    try:
                        tags.append(parse_reference(t).name)
                    except ValueError:
                        pass
                out.append(self._register(config_bytes, config, diff_ids, tags))
        return out

    def pull(self, ref_text: str, progress: Progress = None, registry: Optional[Registry] = None) -> Image:
        """Downloads an image for this machine's architecture from its registry and checks every digest."""
        ref = parse_reference(ref_text)
        reg = registry or Registry(ref)
        try:
            manifest, manifest_digest = reg.image_manifest()
            config_desc = manifest["config"]
            config_bytes = reg.blob_bytes(config_desc["digest"])
            config = json.loads(config_bytes)
            diff_ids = config["rootfs"]["diff_ids"]
            layers = manifest["layers"]
            if len(diff_ids) != len(layers):
                raise ImageError("the image has %d layers and %d diff ids" % (len(layers), len(diff_ids)))
            total = 0
            for desc, diff_id in zip(layers, diff_ids):
                total += desc.get("size", 0)
                if self._have_layer(diff_id):
                    if progress:
                        progress("%s: already here" % diff_id[7:19])
                    continue
                if progress:
                    progress("%s: pulling %d bytes" % (diff_id[7:19], desc.get("size", 0)))
                with reg.blob(desc["digest"]) as resp:
                    reader = VerifyingReader(resp, desc["digest"])
                    try:
                        self._unpack_layer(reader, diff_id)
                    except (LayerError, ImageError):
                        reader.verify()  # a damaged download is better explained by the digest than by the tar or gzip error
                        raise
                    reader.verify()
        except (RegistryError, LayerError) as e:
            raise ImageError(str(e)) from None
        tag = ref.name
        img = self._register(config_bytes, config, diff_ids, [tag], total)
        img.data["digest"] = manifest_digest
        self._save(img.data)
        return img
