"""A client of the Docker Registry HTTP API v2 (what ``docker pull`` talks to), for public images.

``GET /v2/<name>/manifests/<tag or digest>`` gives the manifest of an image (or an *index* of them, one per platform, from which the one
for this machine is chosen); it lists the digest of the config and of every layer; ``GET /v2/<name>/blobs/<digest>`` gives the bytes.  A
registry that wants a token answers 401 with ``WWW-Authenticate: Bearer realm=...,service=...,scope=...``; for a public image the token is
free (an anonymous request to the realm).  Every blob is checked against its digest when it has been read.
"""
from __future__ import annotations

import hashlib
import json
import platform
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import NamedTuple, Optional, Tuple

DOCKER_HUB = "registry-1.docker.io"

MANIFEST_TYPES = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
]
INDEX_TYPES = {MANIFEST_TYPES[0], MANIFEST_TYPES[1]}


class RegistryError(Exception):
    pass


class Reference(NamedTuple):
    registry: str
    repository: str
    tag: str
    digest: Optional[str]

    @property
    def name(self) -> str:
        """The name the way Docker prints it (``alpine:3.20``, ``myhost:5000/team/app:1``)."""
        repo = self.repository
        if self.registry == DOCKER_HUB:
            if repo.startswith("library/"):
                repo = repo[len("library/") :]
            base = repo
        else:
            base = self.registry + "/" + repo
        return base + ("@" + self.digest if self.digest else ":" + self.tag)


_DIGEST = re.compile(r"^(sha256|sha512):[0-9a-f]{32,128}$")


def parse_reference(text: str) -> Reference:
    """``alpine`` ``alpine:3.20`` ``user/app@sha256:...`` ``ghcr.io/org/app:v1`` ``localhost:5000/x``."""
    ref = text.strip()
    if not ref:
        raise ValueError("an empty image name")
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
        if not _DIGEST.match(digest):
            raise ValueError("%r is not a digest" % digest)
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = DOCKER_HUB, ref
    if registry in ("docker.io", "index.docker.io"):
        registry = DOCKER_HUB
    tag = "latest"
    last = path.rsplit("/", 1)[-1]
    if ":" in last:
        path, _, tag = path.rpartition(":")
        if not re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$", tag):
            raise ValueError("%r is not a valid tag" % tag)
    if not path or not re.match(r"^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$", path):
        raise ValueError("%r is not a valid image name (lower case letters, digits and . _ - / only)" % text)
    if registry == DOCKER_HUB and "/" not in path:
        path = "library/" + path
    return Reference(registry, path, tag, digest)


def goarch() -> str:
    """The name of this machine's architecture in the image world (``amd64``, ``arm64``)."""
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "arm", "i686": "386", "s390x": "s390x", "ppc64le": "ppc64le"}.get(
        platform.machine().lower(), platform.machine().lower()
    )


class _KeepHost(urllib.request.HTTPRedirectHandler):
    """A redirect to another host (the CDN that holds the blobs) must not get our token."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(req.full_url).netloc:
            new.headers.pop("Authorization", None)
            new.unredirected_hdrs.pop("Authorization", None)
        return new


_challenge = re.compile(r'(\w+)="([^"]*)"')


class Registry:
    def __init__(self, ref: Reference, timeout: float = 60.0, scheme: Optional[str] = None) -> None:
        self.ref = ref
        self.timeout = timeout
        host = ref.registry
        self.scheme = scheme or ("http" if host.startswith("localhost") or host.startswith("127.") else "https")
        self.base = "%s://%s/v2/%s" % (self.scheme, host, ref.repository)
        self.token: Optional[str] = None
        self.opener = urllib.request.build_opener(_KeepHost)

    # -- http

    def _open(self, url: str, accept: Optional[str] = None):
        for attempt in range(2):
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "kendi-konteyner/0.1")
            if accept:
                req.add_header("Accept", accept)
            if self.token:
                req.add_header("Authorization", "Bearer " + self.token)
            try:
                return self.opener.open(req, timeout=self.timeout)
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 0 and self._authenticate(e.headers.get("WWW-Authenticate", "")):
                    continue
                if e.code == 404:
                    raise RegistryError("%s: not found" % url) from None
                if e.code == 401 and attempt == 1:
                    raise RegistryError("%s: not found, or not allowed without a login (a private image)" % url) from None
                raise RegistryError("%s: HTTP %d %s" % (url, e.code, e.reason)) from None
            except urllib.error.URLError as e:
                raise RegistryError("%s: %s" % (url, e.reason)) from None
        raise RegistryError("%s: the registry refused the token" % url)

    def _authenticate(self, header: str) -> bool:
        if not header.lower().startswith("bearer "):
            return False
        fields = dict(_challenge.findall(header))
        realm = fields.get("realm")
        if not realm:
            return False
        params = {"service": fields.get("service", ""), "scope": fields.get("scope", "repository:%s:pull" % self.ref.repository)}
        url = realm + "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v})
        try:
            with self.opener.open(urllib.request.Request(url, headers={"User-Agent": "kendi-konteyner/0.1"}), timeout=self.timeout) as r:
                data = json.loads(r.read().decode())
        except (urllib.error.URLError, ValueError) as e:
            raise RegistryError("no token from %s: %s" % (realm, e)) from None
        self.token = data.get("token") or data.get("access_token")
        return bool(self.token)

    # -- the api

    def manifest(self, reference: str) -> Tuple[str, dict, str]:
        """(media type, the manifest as a dict, its digest) of a tag or a digest."""
        with self._open("%s/manifests/%s" % (self.base, reference), ", ".join(MANIFEST_TYPES)) as r:
            raw = r.read()
            media = r.headers.get("Content-Type", "").split(";")[0].strip()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if reference.startswith("sha256:") and reference != digest:
            raise RegistryError("the manifest %s has the digest %s" % (reference, digest))
        data = json.loads(raw.decode())
        return data.get("mediaType", media) or media, data, digest

    def image_manifest(self, os_name: str = "linux", arch: Optional[str] = None, variant: Optional[str] = None) -> Tuple[dict, str]:
        """The manifest of the image for a platform: follows an index to the entry for it."""
        arch = arch or goarch()
        media, manifest, digest = self.manifest(self.ref.digest or self.ref.tag)
        if media in INDEX_TYPES or "manifests" in manifest:
            candidates = [
                m for m in manifest.get("manifests", [])
                if m.get("platform", {}).get("os") == os_name and m.get("platform", {}).get("architecture") == arch
                and (variant is None or m["platform"].get("variant") in (None, variant))
            ]
            if not candidates:
                have = sorted({"%s/%s" % (m.get("platform", {}).get("os"), m.get("platform", {}).get("architecture")) for m in manifest.get("manifests", [])})
                raise RegistryError("no image for %s/%s (the index has %s)" % (os_name, arch, ", ".join(have)))
            media, manifest, digest = self.manifest(candidates[0]["digest"])
        if "layers" not in manifest:
            raise RegistryError("this is not an image manifest (media type %s)" % media)
        return manifest, digest

    def blob(self, digest: str):
        """An open response with the bytes of a blob (the caller checks the digest while reading: see ``VerifyingReader``)."""
        return self._open("%s/blobs/%s" % (self.base, digest))

    def blob_bytes(self, digest: str) -> bytes:
        with self.blob(digest) as r:
            data = r.read()
        algo, _, want = digest.partition(":")
        got = hashlib.new(algo, data).hexdigest()
        if got != want:
            raise RegistryError("the blob %s has the digest %s:%s" % (digest, algo, got))
        return data


class VerifyingReader:
    """Reads from a response and hashes what it reads; ``verify()`` compares the digest with the one that was promised."""

    def __init__(self, fileobj, digest: str) -> None:
        self.f = fileobj
        self.algo, _, self.want = digest.partition(":")
        self.h = hashlib.new(self.algo)
        self.size = 0

    def read(self, n: int = -1) -> bytes:
        data = self.f.read(n)
        self.h.update(data)
        self.size += len(data)
        return data

    def verify(self) -> None:
        while self.read(1 << 20):  # whatever the layer reader did not need (the end of the gzip stream)
            pass
        if self.h.hexdigest() != self.want:
            raise RegistryError("a layer has the digest %s:%s, not %s:%s" % (self.algo, self.h.hexdigest(), self.algo, self.want))
