"""The rtnetlink client against the kernel, read back with the real ``ip`` command."""
import json
import os
import subprocess
import sys

import pytest

from conftest import SRC, needs_root

pytestmark = needs_root

sys.path.insert(0, SRC)
from kendi_konteyner.netlink import Netlink, NetlinkError  # noqa: E402

NAMES = ("ktbr0", "ktv0", "ktp0", "ktren0")


def ip(*args, check=True):
    out = subprocess.run(["ip", *args], capture_output=True, text=True)
    if check:
        assert out.returncode == 0, out.stderr
    return out


def ip_json(*args):
    return json.loads(ip("-j", *args).stdout)


@pytest.fixture(autouse=True)
def clean():
    def wipe():
        for name in NAMES:
            ip("link", "del", name, check=False)

    wipe()
    yield
    wipe()


def test_a_bridge_is_a_bridge_with_a_mac_and_down():
    import time

    with Netlink() as nl:
        nl.add_bridge("ktbr0")
        # udev may give a new virtual device its "persistent" address a moment after it was made: read both until they settle
        for _ in range(50):
            link = nl.link("ktbr0")
            real = ip_json("-d", "link", "show", "ktbr0")[0]
            if link.mac == real["address"]:
                break
            time.sleep(0.05)
    assert real["linkinfo"]["info_kind"] == "bridge" and link.kind == "bridge"
    assert link.index == real["ifindex"] and link.mac == real["address"] and not link.up and "UP" not in real["flags"]


def test_up_and_down():
    with Netlink() as nl:
        nl.add_bridge("ktbr0")
        index = nl.index("ktbr0")
        nl.set_up(index)
        assert nl.link("ktbr0").up
        assert "UP" in ip_json("link", "show", "ktbr0")[0]["flags"]
        nl.set_up(index, False)
        assert not nl.link("ktbr0").up and "UP" not in ip_json("link", "show", "ktbr0")[0]["flags"]


def test_a_veth_pair_has_two_ends_that_know_each_other():
    with Netlink() as nl:
        nl.add_veth("ktv0", "ktp0")
        a, b = nl.link("ktv0"), nl.link("ktp0")
    assert a.kind == b.kind == "veth"
    real = ip_json("-d", "link", "show", "ktv0")[0]
    assert real["link"] == "ktp0" and real["linkinfo"]["info_kind"] == "veth"
    assert a.mac != b.mac


def test_master_rename_and_delete():
    with Netlink() as nl:
        nl.add_bridge("ktbr0")
        nl.add_veth("ktv0", "ktp0")
        nl.set_master(nl.index("ktv0"), nl.index("ktbr0"))
        assert nl.link("ktv0").master == nl.index("ktbr0")
        assert ip_json("link", "show", "ktv0")[0]["master"] == "ktbr0"
        nl.rename(nl.index("ktp0"), "ktren0")
        assert nl.link("ktp0") is None and nl.link("ktren0") is not None
        assert "ktren0" in [l["ifname"] for l in ip_json("link", "show")]
        nl.delete_link(nl.index("ktv0"))  # a veth pair goes with either end
        assert nl.link("ktv0") is None and nl.link("ktren0") is None
    assert ip("link", "show", "ktren0", check=False).returncode != 0


def test_addresses_are_read_and_written_the_way_ip_does():
    with Netlink() as nl:
        nl.add_bridge("ktbr0")
        index = nl.index("ktbr0")
        nl.add_address(index, "10.99.7.1/24")
        nl.add_address(index, "10.99.8.9/16")
        mine = sorted(a for i, a in nl.addresses() if i == index)
    real = sorted("%s/%d" % (a["local"], a["prefixlen"]) for a in ip_json("-4", "addr", "show", "ktbr0")[0]["addr_info"])
    assert mine == real == ["10.99.7.1/24", "10.99.8.9/16"]
    broadcast = {a["local"]: a.get("broadcast") for a in ip_json("-4", "addr", "show", "ktbr0")[0]["addr_info"]}
    assert broadcast == {"10.99.7.1": "10.99.7.255", "10.99.8.9": "10.99.255.255"}


def test_the_default_route_goes_through_the_gateway_in_a_network_namespace():
    """In a namespace of its own: the host's routing table is not touched."""
    ns = subprocess.Popen(["unshare", "--net", "sleep", "30"])
    try:
        for _ in range(100):  # until the namespace exists: it is a different one from ours
            if os.path.exists("/proc/%d/ns/net" % ns.pid) and os.readlink("/proc/%d/ns/net" % ns.pid) != os.readlink("/proc/self/ns/net"):
                break
            import time

            time.sleep(0.02)
        with Netlink() as nl:
            nl.add_veth("ktv0", "ktp0")
            nl.set_up(nl.index("ktv0"))  # the host end: without it the container's end has no carrier ("linkdown")
            nl.move_to_netns(nl.index("ktp0"), ns.pid)
            assert nl.link("ktp0") is None  # it left this namespace
        inside = lambda *a: subprocess.run(["nsenter", "-t", str(ns.pid), "-n", "ip", *a], capture_output=True, text=True, check=True).stdout
        assert "ktp0" in inside("-o", "link")
        # the same calls, made from inside the other namespace (what the init of a container does)
        code = (
            "import sys; sys.path.insert(0, %r)\n"
            "from kendi_konteyner.netlink import Netlink\n"
            "with Netlink() as nl:\n"
            "    i = nl.index('ktp0'); nl.rename(i, 'eth0'); nl.add_address(i, '10.77.0.2/24'); nl.set_up(i); nl.add_default_route('10.77.0.1', i)\n" % SRC
        )
        subprocess.run(["nsenter", "-t", str(ns.pid), "-n", sys.executable, "-c", code], check=True)
        assert "eth0" in inside("-o", "link") and "10.77.0.2/24" in inside("-4", "-o", "addr")
        assert inside("route").splitlines()[0] == "default via 10.77.0.1 dev eth0 "
    finally:
        ns.kill()
        ns.wait()


def test_errors_carry_the_errno_of_the_kernel():
    with Netlink() as nl:
        nl.add_bridge("ktbr0")
        with pytest.raises(NetlinkError) as e:
            nl.add_bridge("ktbr0")
        assert e.value.errno == 17  # EEXIST
        with pytest.raises(NetlinkError) as e:
            nl.index("ktdoesnotexist")
        assert e.value.errno == 19  # ENODEV
        with pytest.raises(NetlinkError) as e:
            nl.delete_link(999999)
        assert e.value.errno in (19, 2)
        index = nl.index("ktbr0")
        nl.add_address(index, "10.99.7.1/24")
        with pytest.raises(NetlinkError) as e:
            nl.add_address(index, "10.99.7.1/24")
        assert e.value.errno == 17
