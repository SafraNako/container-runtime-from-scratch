"""Networking of a container: none, host and the bridge with veth pairs; what the kernel was told, read back with the real ``ip``."""
import json
import os
import re
import socket
import subprocess
import time

import pytest

from conftest import IMAGE, needs_root

pytestmark = needs_root


def ip(*args):
    out = subprocess.run(["ip", *args], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return out.stdout


def internet() -> bool:
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=3).close()
        return True
    except OSError:
        return False


def ip_of(kk, name):
    """The address of a running container, as the container itself reports it."""
    out = kk("exec", name, "sh", "-c", "ip -4 -o addr show eth0").out
    return re.search(r"inet (10\.88\.\d+\.\d+)/16", out).group(1)


def test_none_has_only_the_loopback(kk, docker, image):
    script = "ip link | grep -E '^[0-9]+:' | sed 's/ mtu.*//'; ip route | wc -l; cat /proc/net/dev | tail -n +3 | cut -d: -f1 | tr -d ' '"
    mine = kk("run", "--rm", "--network", "none", IMAGE, "sh", "-c", script)
    theirs = docker("run", "--rm", "--network", "none", IMAGE, "sh", "-c", script)
    assert mine.out == theirs.out == "1: lo: <LOOPBACK,UP,LOWER_UP>\n0\nlo\n"


def test_host_shares_the_stack_of_the_host(kk, image):
    inside = kk("run", "--rm", "--network", "host", IMAGE, "readlink", "/proc/self/ns/net").out.strip()
    assert inside == os.readlink("/proc/self/ns/net")
    names = kk("run", "--rm", "--network", "host", IMAGE, "sh", "-c", "cat /proc/net/dev | tail -n +3 | cut -d: -f1 | tr -d ' '").out.split()
    assert "lo" in names and set(names) == set(os.listdir("/sys/class/net"))
    # the host name is still the container's own
    assert kk("run", "--rm", "--network", "host", "--hostname", "own", IMAGE, "hostname").out == "own\n"


def test_bridge_gives_each_container_an_address_and_a_route(kk, image):
    out = kk("run", "--rm", IMAGE, "sh", "-c", "ip addr show eth0; ip route; cat /etc/hosts | tail -1; cat /sys/class/net/eth0/mtu; cat /sys/class/net/eth0/operstate")
    assert out.code == 0, out.err
    assert re.search(r"inet 10\.88\.0\.\d+/16 brd 10\.88\.255\.255 scope global eth0", out.out)
    assert "default via 10.88.0.1 dev eth0" in out.out
    assert re.search(r"^10\.88\.0\.\d+\t[0-9a-f]{12}$", out.out, re.M)  # /etc/hosts has the address and the name
    assert out.out.strip().endswith("1500\nup")


def test_containers_reach_the_gateway_each_other_and_the_host(kk, image):
    kk("run", "-d", "--name", "server", IMAGE, "sh", "-c", "echo hello-from-server | nc -l -p 8080")
    time.sleep(0.8)
    server_ip = ip_of(kk, "server")
    out = kk("run", "--rm", IMAGE, "sh", "-c", "nc -w 3 %s 8080 2>&1; ping -c 1 -W 2 10.88.0.1 | tail -2 | head -1" % server_ip).out
    assert "hello-from-server" in out, out
    assert "1 packets received" in out or "1 received" in out


def test_the_host_can_connect_to_a_container(kk, image):
    kk("run", "-d", "--name", "web", IMAGE, "sh", "-c", "while true; do echo -e 'HTTP/1.0 200 OK\\r\\n\\r\\nserved by the container' | nc -l -p 80; done")
    time.sleep(0.8)
    s = socket.create_connection((ip_of(kk, "web"), 80), timeout=5)
    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    assert b"served by the container" in data


def test_each_container_has_its_own_address_and_it_is_given_back(kk, root, image):
    kk("run", "-d", "--name", "a", IMAGE, "sleep", "30")
    kk("run", "-d", "--name", "b", IMAGE, "sleep", "30")
    leases = json.load(open(os.path.join(root, "network", "leases.json")))
    assert sorted(leases.values()) == ["10.88.0.2/16", "10.88.0.3/16"]
    kk("rm", "-f", "a")
    kk("run", "-d", "--name", "c", IMAGE, "sleep", "30")
    leases = json.load(open(os.path.join(root, "network", "leases.json")))
    assert sorted(leases.values()) == ["10.88.0.2/16", "10.88.0.3/16"]  # the first one is free again
    kk("rm", "-f", "b", "c")
    assert json.load(open(os.path.join(root, "network", "leases.json"))) == {}


@pytest.mark.skipif(not internet(), reason="no internet")
def test_the_outside_world_is_reached_through_nat(kk, image):
    out = kk("run", "--rm", IMAGE, "sh", "-c", "ping -c 1 -W 3 1.1.1.1 | tail -2 | head -1; (printf 'GET / HTTP/1.0\\r\\n\\r\\n'; sleep 2) | nc 1.1.1.1 80 | head -1")
    assert "1 packets received" in out.out or "1 received" in out.out
    assert "HTTP/1." in out.out  # a web server of the internet answered through the NAT


def test_what_the_kernel_was_told(kk, image):
    """The bridge and the pair of veth devices as the real ip command sees them."""
    kk("run", "-d", "--name", "seen", IMAGE, "sleep", "30")
    links = json.loads(ip("-j", "-d", "link", "show"))
    bridge = [l for l in links if l["ifname"] == "kontbr0"][0]
    assert bridge["linkinfo"]["info_kind"] == "bridge" and "UP" in bridge["flags"]
    assert any(a["local"] == "10.88.0.1" and a["prefixlen"] == 16 for a in json.loads(ip("-j", "addr", "show", "kontbr0"))[0]["addr_info"])
    ends = [l for l in links if l["ifname"].startswith("kv")]
    assert len(ends) == 1
    assert ends[0]["linkinfo"]["info_kind"] == "veth" and ends[0]["master"] == "kontbr0" and "UP" in ends[0]["flags"]
    # and inside: the other end is eth0, up, with the address
    inside = kk("exec", "seen", "sh", "-c", "ip -o addr show eth0").out
    assert "10.88.0.2/16" in inside
    kk("rm", "-f", "seen")
    time.sleep(0.5)
    assert not [l for l in json.loads(ip("-j", "link", "show")) if l["ifname"].startswith("kv")]  # the host end went with the namespace


def test_the_forwarding_rules_are_there(kk, image):
    kk("run", "--rm", IMAGE, "true")
    rules = subprocess.run(["iptables", "-t", "nat", "-S", "POSTROUTING"], capture_output=True, text=True).stdout
    assert "-s 10.88.0.0/16" in rules and "MASQUERADE" in rules
    assert open("/proc/sys/net/ipv4/ip_forward").read().strip() == "1"
