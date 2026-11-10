"""The parts that need no kernel: parsers, tables, byte layouts.  They run anywhere."""
import struct

import pytest

from kendi_konteyner import linux, netlink, seccomp
from kendi_konteyner.cgroups import cpu_max, parse_size
from kendi_konteyner.layers import LayerError, normalize
from kendi_konteyner.registry import DOCKER_HUB, Reference, goarch, parse_reference
from kendi_konteyner.spec import Config, Volume, check_name, effective_caps, parse_env, parse_volume


def test_sizes_are_the_sizes_of_docker():
    assert parse_size("128m") == 128 * 1024 * 1024
    assert parse_size("1g") == 1 << 30
    assert parse_size("512K") == 512 * 1024
    assert parse_size("64mb") == 64 << 20
    assert parse_size("1.5g") == int(1.5 * (1 << 30))
    assert parse_size("1000") == 1000
    assert parse_size(" 2 t ") == 2 << 40
    for bad in ("", "m", "12x", "-5m", "1.2.3g"):
        with pytest.raises(ValueError):
            parse_size(bad)


def test_cpu_max_is_quota_and_period():
    assert cpu_max(0.5) == "50000 100000"
    assert cpu_max(2) == "200000 100000"
    assert cpu_max(1.5, 1000) == "1500 1000"
    with pytest.raises(ValueError):
        cpu_max(0)


@pytest.mark.parametrize(
    "text,registry,repo,tag,digest",
    [
        ("alpine", DOCKER_HUB, "library/alpine", "latest", None),
        ("alpine:3.20", DOCKER_HUB, "library/alpine", "3.20", None),
        ("library/alpine:edge", DOCKER_HUB, "library/alpine", "edge", None),
        ("user/app", DOCKER_HUB, "user/app", "latest", None),
        ("docker.io/user/app:v1", DOCKER_HUB, "user/app", "v1", None),
        ("index.docker.io/library/busybox", DOCKER_HUB, "library/busybox", "latest", None),
        ("ghcr.io/org/team/app:1.2", "ghcr.io", "org/team/app", "1.2", None),
        ("localhost:5000/x", "localhost:5000", "x", "latest", None),
        ("localhost/x:t", "localhost", "x", "t", None),
        ("myhost:5000/a/b:c", "myhost:5000", "a/b", "c", None),
        ("alpine@sha256:" + "a" * 64, DOCKER_HUB, "library/alpine", "latest", "sha256:" + "a" * 64),
        ("quay.io/prom/prometheus@sha256:" + "0" * 64, "quay.io", "prom/prometheus", "latest", "sha256:" + "0" * 64),
    ],
)
def test_image_references(text, registry, repo, tag, digest):
    assert parse_reference(text) == Reference(registry, repo, tag, digest)


def test_image_reference_names_and_errors():
    assert parse_reference("alpine").name == "alpine:latest"
    assert parse_reference("docker.io/library/alpine:3.20").name == "alpine:3.20"
    assert parse_reference("user/app:v1").name == "user/app:v1"
    assert parse_reference("ghcr.io/o/a").name == "ghcr.io/o/a:latest"
    for bad in ("", "Alpine", "alpine:", "a b", "-x", "alpine@sha256:xyz", "/x", "x//y"):
        with pytest.raises(ValueError):
            parse_reference(bad)
    assert goarch() in {"amd64", "arm64", "arm", "386", "s390x", "ppc64le"} or goarch()


def test_volumes_env_names():
    assert parse_volume("/a:/b") == Volume("/a", "/b", False)
    assert parse_volume("/a:/b:ro") == Volume("/a", "/b", True)
    assert parse_volume("/a:/b/../c:rw") == Volume("/a", "/c", False)
    for bad in ("/a", "a:/b", "/a:b", "/a:/b:xx", "/a:/b:ro:x", ":/b"):
        with pytest.raises(ValueError):
            parse_volume(bad)
    assert parse_env(["A=1", "B=", "C=x=y"]) == ["A=1", "B=", "C=x=y"]
    assert check_name("web-1") == "web-1" and check_name("") == ""
    for bad in ("-x", "a b", "a/b"):
        with pytest.raises(ValueError):
            check_name(bad)


def test_config_roundtrip():
    cfg = Config(id="a" * 64, image_id="sha256:1", image_name="alpine", argv=["sh"], volumes=[Volume("/a", "/b", True)], memory=1 << 20, cpus=0.5)
    again = Config.from_json(cfg.to_json())
    assert again == cfg and again.volumes[0].readonly


def test_default_capabilities_are_the_ones_of_docker():
    # CapEff of a container started by `docker run`, taken from /proc/self/status of one
    assert linux.mask(linux.DEFAULT_CAPS) == 0xA80425FB
    assert linux.names(0xA80425FB) == sorted(["CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID", "SETFCAP", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"], key=linux.CAPS.get)
    assert linux.mask(["CAP_NET_RAW", "chown"]) == (1 << 13) | 1
    with pytest.raises(ValueError):
        linux.mask(["NOPE"])
    base = Config(id="x", image_id="i", image_name="i", argv=["x"])
    assert effective_caps(base) == 0xA80425FB
    import dataclasses

    assert effective_caps(dataclasses.replace(base, cap_drop=["ALL"])) == 0
    assert effective_caps(dataclasses.replace(base, cap_drop=["ALL"], cap_add=["NET_BIND_SERVICE"])) == 1 << 10
    assert effective_caps(dataclasses.replace(base, cap_add=["SYS_ADMIN"])) == 0xA80425FB | 1 << 21
    assert effective_caps(dataclasses.replace(base, cap_drop=["NET_RAW"])) == 0xA80425FB & ~(1 << 13)
    assert effective_caps(dataclasses.replace(base, privileged=True)) >= (1 << 41) - 1


MOUNTINFO = r"""22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
36 35 0:30 /a\040b /mnt/a\040b ro,nosuid,nodev - tmpfs tmpfs rw,size=1k
37 22 0:31 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
"""


def test_mountinfo_parser():
    m = linux.parse_mountinfo(MOUNTINFO)
    assert [x.mount_point for x in m] == ["/", "/mnt/a b", "/proc"]
    assert m[0].fstype == "ext4" and m[0].source == "/dev/sda1" and m[0].options == "rw,relatime"
    assert m[1].root == "/a b" and m[1].options == "ro,nosuid,nodev" and m[1].super_options == "rw,size=1k"
    assert m[2].mount_id == 37 and m[2].parent_id == 22 and m[2].fields == ""


# ---------------------------------------------------------------------------------------------------------------- tar paths

def test_layer_paths_are_cleaned_and_refused():
    assert normalize("./a//b/") == ["a", "b"]
    assert normalize("/etc/passwd") == ["etc", "passwd"]
    assert normalize(".") == [] and normalize("") == []
    for bad in ("../x", "a/../../x", "a/..", "/../x"):
        with pytest.raises(LayerError):
            normalize(bad)


# ---------------------------------------------------------------------------------------------------------------- seccomp

def test_the_bpf_program_follows_the_rules():
    prog = seccomp.build_filter([100, 101], 56, 435, 0xC000003E, x32=True)
    arch = 0xC000003E
    ALLOW, EPERM, ENOSYS = seccomp.SECCOMP_RET_ALLOW, seccomp.SECCOMP_RET_ERRNO | 1, seccomp.SECCOMP_RET_ERRNO | 38
    assert seccomp.run(prog, 5, arch) == ALLOW
    assert seccomp.run(prog, 100, arch) == EPERM and seccomp.run(prog, 101, arch) == EPERM
    assert seccomp.run(prog, 5, 0x40000003) == EPERM  # another architecture
    assert seccomp.run(prog, 5 | seccomp.X32_BIT, arch) == EPERM  # the x32 ABI
    assert seccomp.run(prog, 435, arch) == ENOSYS
    assert seccomp.run(prog, 56, arch, [0x11]) == ALLOW  # plain clone
    for flag in (linux.CLONE_NEWNS, linux.CLONE_NEWUSER, linux.CLONE_NEWPID, linux.CLONE_NEWNET, linux.CLONE_NEWUTS, linux.CLONE_NEWIPC, linux.CLONE_NEWCGROUP):
        assert seccomp.run(prog, 56, arch, [0x11 | flag]) == EPERM
    assert len(prog) < 200 and all(0 <= jt < 256 and 0 <= jf < 256 for _, jt, jf, _ in prog)


def test_a_jump_that_does_not_fit_is_an_error():
    p = seccomp.Program()
    p.load(0)
    p.jump_eq(1, "far", None)
    for _ in range(300):
        p.ret(seccomp.SECCOMP_RET_ALLOW)
    p.label("far")
    p.ret(0)
    with pytest.raises(ValueError):
        p.assemble()


# ---------------------------------------------------------------------------------------------------------------- netlink bytes

def test_attributes_are_padded_to_four_bytes():
    a = netlink.attr(3, b"abc")
    assert a == struct.pack("=HH", 7, 3) + b"abc" + b"\0"
    assert len(netlink.attr_str(3, "eth0")) == 12  # 4 header + "eth0\0" 5 -> 9 -> 12
    assert netlink.attr_u32(10, 7) == struct.pack("=HHI", 8, 10, 7)
    parsed = netlink.parse_attrs(netlink.attr(1, b"x") + netlink.attr_str(3, "lo") + netlink.attr(0x8000 | 18, netlink.attr_u32(1, 5)))
    assert parsed[1] == b"x" and parsed[3] == b"lo\0" and netlink.parse_attrs(parsed[18])[1] == struct.pack("=I", 5)


def test_a_veth_request_nests_the_peer():
    nl = netlink.Netlink.__new__(netlink.Netlink)
    sent = []

    class Sock:
        def send(self, data):
            sent.append(data)
            raise RuntimeError("stop")

    nl.sock, nl.seq = Sock(), 0
    with pytest.raises(RuntimeError):
        nl.add_veth("kv1", "kp1")
    length, mtype, flags, seq, pid = struct.unpack_from("=IHHII", sent[0])
    assert length == len(sent[0]) and mtype == netlink.RTM_NEWLINK
    assert flags & netlink.NLM_F_CREATE and flags & netlink.NLM_F_EXCL and flags & netlink.NLM_F_REQUEST
    body = sent[0][16 + 16 :]
    top = netlink.parse_attrs(body)
    assert top[netlink.IFLA_IFNAME] == b"kv1\0"
    info = netlink.parse_attrs(top[netlink.IFLA_LINKINFO])
    assert info[netlink.IFLA_INFO_KIND] == b"veth\0"
    peer = netlink.parse_attrs(netlink.parse_attrs(info[netlink.IFLA_INFO_DATA])[netlink.VETH_INFO_PEER][16:])
    assert peer[netlink.IFLA_IFNAME] == b"kp1\0"
