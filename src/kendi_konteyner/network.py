"""The network of a container.

* ``none``: a new network namespace with only the loopback device (``lo``), brought up.
* ``host``: no new namespace; the container uses the host's network stack.
* ``bridge`` (the default): a bridge ``kontbr0`` on the host with the address 10.88.0.1/16, and for each container a pair of veth devices:
  one end in the bridge, the other in the container's network namespace as ``eth0`` with an address of 10.88.0.0/16 and a default route
  through the bridge.  Containers reach each other and the host through the bridge; for the outside world the host forwards (``ip_forward``)
  and rewrites the source address (an ``iptables`` rule, the only place where this module runs another program).

The addresses are kept in ``network/leases.json`` of the store.
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
from typing import Dict, Optional

from .errors import KonteynerError
from .netlink import Netlink, NetlinkError

BRIDGE = "kontbr0"
SUBNET = ipaddress.ip_network("10.88.0.0/16")
GATEWAY = "10.88.0.1"
PREFIX = SUBNET.prefixlen


def veth_names(cid: str) -> tuple:
    """The two ends: ``kv`` + 8 hex digits stays on the host, ``kp`` + 8 goes in the container (and is renamed ``eth0`` there)."""
    return "kv" + cid[:8], "kp" + cid[:8]


def _setup_loopback() -> None:
    """Brings ``lo`` up (a new network namespace has it down)."""
    import fcntl
    import socket
    import struct

    SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("16sH14x", b"lo", 0)
        flags = struct.unpack("16sH14x", fcntl.ioctl(s, SIOCGIFFLAGS, ifreq))[1]
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14x", b"lo", flags | IFF_UP))
    finally:
        s.close()


# ---------------------------------------------------------------------------------------------------------------- the addresses

def _leases(store) -> Dict[str, str]:
    return store.read_json(store.path("network", "leases.json"), {})


def allocate(store, cid: str) -> str:
    """The first free address of the subnet, as ``10.88.0.2/16``."""
    with store.lock("network.lock"):
        leases = _leases(store)
        if cid in leases:
            return leases[cid]
        used = {ip.split("/")[0] for ip in leases.values()} | {GATEWAY}
        for host in SUBNET.hosts():
            if str(host) not in used:
                leases[cid] = "%s/%d" % (host, PREFIX)
                store.write_json(store.path("network", "leases.json"), leases)
                return leases[cid]
    raise KonteynerError("no free address left in %s" % SUBNET)


def release(store, cid: str) -> None:
    with store.lock("network.lock"):
        leases = _leases(store)
        if leases.pop(cid, None) is not None:
            store.write_json(store.path("network", "leases.json"), leases)


# ---------------------------------------------------------------------------------------------------------------- the host side

def _iptables(*args: str) -> None:
    """Adds a rule if it is not there yet (``-C`` checks, ``-A``/``-I`` adds)."""
    binary = shutil.which("iptables")
    if binary is None:
        return
    table = ["-t", args[0]] if args[0] in ("nat", "filter") else []
    rule = args[1:] if table else args
    check = subprocess.run([binary, *table, "-C", *rule[1:]], capture_output=True)
    if check.returncode != 0:
        subprocess.run([binary, *table, rule[0], *rule[1:]], capture_output=True, check=False)


def ensure_bridge(nl: Netlink) -> int:
    """The bridge with the gateway address, and the rules that let the containers reach the outside."""
    link = nl.link(BRIDGE)
    if link is None:
        try:
            nl.add_bridge(BRIDGE)
        except NetlinkError as e:
            if e.errno != 17:  # EEXIST: made by another start at the same moment
                raise
        link = nl.link(BRIDGE)
        assert link is not None
        if not any(i == link.index for i, _ in nl.addresses()):
            try:
                nl.add_address(link.index, "%s/%d" % (GATEWAY, PREFIX))
            except NetlinkError as e:
                if e.errno != 17:
                    raise
    if not link.up:
        nl.set_up(link.index)
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
            fh.write("1")
    except OSError:
        pass
    _iptables("nat", "-A", "POSTROUTING", "-s", str(SUBNET), "!", "-o", BRIDGE, "-j", "MASQUERADE")
    _iptables("filter", "-I", "FORWARD", "-i", BRIDGE, "-j", "ACCEPT")
    _iptables("filter", "-I", "FORWARD", "-o", BRIDGE, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
    return link.index


def connect(store, cid: str, init_pid: int, ip: Optional[str]) -> None:
    """From the host: makes the veth pair, plugs one end into the bridge and puts the other in the container's network namespace."""
    host_end, peer = veth_names(cid)
    with store.lock("network.lock"), Netlink() as nl:
        bridge = ensure_bridge(nl)
        stale = nl.link(host_end)
        if stale is not None:  # left by a container that died in a way that left it
            nl.delete_link(stale.index)
        nl.add_veth(host_end, peer)
        host = nl.index(host_end)
        nl.set_master(host, bridge)
        nl.set_up(host)
        nl.move_to_netns(nl.index(peer), init_pid)


def setup_in_container(mode: str, ip: Optional[str], cid: str = "") -> None:
    """From the init, inside the new network namespace: ``lo`` up and, for a bridge, ``eth0`` with its address and route."""
    _setup_loopback()
    if mode != "bridge":
        return
    _, peer = veth_names(cid)
    with Netlink() as nl:
        index = nl.index(peer)
        nl.rename(index, "eth0")
        nl.add_address(index, ip)  # type: ignore[arg-type]
        nl.set_up(index)
        nl.add_default_route(GATEWAY, index)
