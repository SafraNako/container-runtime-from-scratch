"""Talking to the kernel's network stack over rtnetlink, without ``ip``.

A netlink message is a header (length, type, flags, sequence number, port id) and a payload that is a small fixed structure
(``ifinfomsg`` for a link, ``ifaddrmsg`` for an address, ``rtmsg`` for a route) followed by *attributes*: ``(length, type, value)`` records
padded to four bytes, which can hold other attributes (``IFLA_LINKINFO`` holds the kind of link and its data).  The kernel answers each request
with an ``NLMSG_ERROR`` message whose error is 0 when it worked (an acknowledgement) or a negative ``errno``.

This is enough for what a container needs: a bridge, a pair of virtual ethernet devices (veth) with one end in another network namespace, an
address on it, a route.  The tests read the result back with the real ``ip`` command.
"""
from __future__ import annotations

import errno
import os
import socket
import struct
import ipaddress
from typing import Dict, List, NamedTuple, Optional, Tuple

NETLINK_ROUTE = 0
NLMSG_ERROR, NLMSG_DONE = 2, 3
NLM_F_REQUEST, NLM_F_ACK, NLM_F_ROOT, NLM_F_MATCH, NLM_F_EXCL, NLM_F_CREATE = 1, 4, 0x100, 0x200, 0x200, 0x400
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK = 16, 17, 18
RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR = 20, 21, 22
RTM_NEWROUTE, RTM_DELROUTE = 24, 25

IFLA_ADDRESS, IFLA_IFNAME, IFLA_MASTER, IFLA_LINKINFO, IFLA_NET_NS_PID, IFLA_OPERSTATE = 1, 3, 10, 18, 19, 16
IFLA_INFO_KIND, IFLA_INFO_DATA = 1, 2
VETH_INFO_PEER = 1
IFA_ADDRESS, IFA_LOCAL, IFA_BROADCAST = 1, 2, 4
RTA_DST, RTA_OIF, RTA_GATEWAY = 1, 4, 5

IFF_UP = 1
RT_TABLE_MAIN, RTPROT_BOOT, RT_SCOPE_UNIVERSE, RTN_UNICAST = 254, 3, 0, 1

_NLMSG = struct.Struct("=IHHII")
_IFINFO = struct.Struct("=BxHiII")
_IFADDR = struct.Struct("=BBBBI")
_RTMSG = struct.Struct("=BBBBBBBBI")
_ATTR = struct.Struct("=HH")


class NetlinkError(OSError):
    pass


def _align(n: int) -> int:
    return (n + 3) & ~3


def attr(kind: int, value: bytes) -> bytes:
    """One attribute: length (header included), type, value, padding."""
    length = _ATTR.size + len(value)
    return _ATTR.pack(length, kind) + value + b"\0" * (_align(length) - length)


def attr_str(kind: int, text: str) -> bytes:
    return attr(kind, text.encode() + b"\0")


def attr_u32(kind: int, value: int) -> bytes:
    return attr(kind, struct.pack("=I", value))


def parse_attrs(data: bytes) -> Dict[int, bytes]:
    out: Dict[int, bytes] = {}
    pos = 0
    while pos + _ATTR.size <= len(data):
        length, kind = _ATTR.unpack_from(data, pos)
        if length < _ATTR.size:
            break
        out[kind & 0x3FFF] = data[pos + _ATTR.size : pos + length]
        pos += _align(length)
    return out


class Link(NamedTuple):
    index: int
    name: str
    flags: int
    kind: Optional[str]
    master: Optional[int]
    mac: Optional[str]

    @property
    def up(self) -> bool:
        return bool(self.flags & IFF_UP)


class Netlink:
    """A socket to the kernel's routing and link subsystem."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        self.sock.bind((0, 0))
        self.seq = 0

    def close(self) -> None:
        self.sock.close()

    def __enter__(self) -> "Netlink":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def request(self, mtype: int, flags: int, payload: bytes) -> List[Tuple[int, bytes]]:
        """Sends a request, returns the ``(type, payload)`` of the answers (a dump has many), raises ``NetlinkError`` on an error."""
        self.seq += 1
        msg = _NLMSG.pack(_NLMSG.size + len(payload), mtype, flags | NLM_F_REQUEST, self.seq, 0) + payload
        self.sock.send(msg)
        replies: List[Tuple[int, bytes]] = []
        while True:
            data = self.sock.recv(1 << 16)
            pos = 0
            while pos < len(data):
                length, rtype, rflags, seq, _ = _NLMSG.unpack_from(data, pos)
                body = data[pos + _NLMSG.size : pos + length]
                pos += _align(length)
                if rtype == NLMSG_ERROR:
                    (code,) = struct.unpack_from("=i", body)
                    if code:
                        raise NetlinkError(-code, "netlink: %s" % os.strerror(-code))
                    return replies
                if rtype == NLMSG_DONE:
                    return replies
                replies.append((rtype, body))
            if not (flags & NLM_F_ROOT):
                return replies

    # -- links

    def links(self) -> List[Link]:
        out = []
        for rtype, body in self.request(RTM_GETLINK, NLM_F_DUMP, _IFINFO.pack(socket.AF_UNSPEC, 0, 0, 0, 0)):
            if rtype != RTM_NEWLINK:
                continue
            _, _, index, flags, _ = _IFINFO.unpack_from(body)
            attrs = parse_attrs(body[_IFINFO.size :])
            info = parse_attrs(attrs.get(IFLA_LINKINFO, b""))
            kind = info.get(IFLA_INFO_KIND)
            master = attrs.get(IFLA_MASTER)
            mac = attrs.get(IFLA_ADDRESS)
            out.append(
                Link(
                    index, attrs.get(IFLA_IFNAME, b"").rstrip(b"\0").decode(), flags, kind.rstrip(b"\0").decode() if kind else None,
                    struct.unpack("=I", master)[0] if master else None, ":".join("%02x" % b for b in mac) if mac else None,
                )
            )
        return out

    def link(self, name: str) -> Optional[Link]:
        for link in self.links():
            if link.name == name:
                return link
        return None

    def index(self, name: str) -> int:
        link = self.link(name)
        if link is None:
            raise NetlinkError(errno.ENODEV, "no network interface called %s" % name)
        return link.index

    def _newlink(self, index: int, flags: int, change: int, attrs: bytes, extra: int = 0) -> None:
        self.request(RTM_NEWLINK, NLM_F_ACK | extra, _IFINFO.pack(socket.AF_UNSPEC, 0, index, flags, change) + attrs)

    def add_bridge(self, name: str) -> None:
        linkinfo = attr(IFLA_LINKINFO, attr_str(IFLA_INFO_KIND, "bridge"))
        self._newlink(0, 0, 0, attr_str(IFLA_IFNAME, name) + linkinfo, NLM_F_CREATE | NLM_F_EXCL)

    def add_veth(self, name: str, peer: str) -> None:
        """A pair of connected virtual ethernet devices: what goes in at one comes out at the other."""
        peer_info = _IFINFO.pack(socket.AF_UNSPEC, 0, 0, 0, 0) + attr_str(IFLA_IFNAME, peer)
        data = attr(IFLA_INFO_DATA, attr(VETH_INFO_PEER, peer_info))
        linkinfo = attr(IFLA_LINKINFO, attr_str(IFLA_INFO_KIND, "veth") + data)
        self._newlink(0, 0, 0, attr_str(IFLA_IFNAME, name) + linkinfo, NLM_F_CREATE | NLM_F_EXCL)

    def set_up(self, index: int, up: bool = True) -> None:
        self._newlink(index, IFF_UP if up else 0, IFF_UP, b"")

    def set_master(self, index: int, master: int) -> None:
        self._newlink(index, 0, 0, attr_u32(IFLA_MASTER, master))

    def rename(self, index: int, name: str) -> None:
        self._newlink(index, 0, 0, attr_str(IFLA_IFNAME, name))

    def move_to_netns(self, index: int, pid: int) -> None:
        """Puts the device in the network namespace of a process."""
        self._newlink(index, 0, 0, attr_u32(IFLA_NET_NS_PID, pid))

    def delete_link(self, index: int) -> None:
        self.request(RTM_DELLINK, NLM_F_ACK, _IFINFO.pack(socket.AF_UNSPEC, 0, index, 0, 0))

    # -- addresses and routes

    def add_address(self, index: int, cidr: str) -> None:
        iface = ipaddress.ip_interface(cidr)
        raw = iface.ip.packed
        attrs = attr(IFA_LOCAL, raw) + attr(IFA_ADDRESS, raw)
        if iface.version == 4:
            attrs += attr(IFA_BROADCAST, iface.network.broadcast_address.packed)
        family = socket.AF_INET if iface.version == 4 else socket.AF_INET6
        self.request(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, _IFADDR.pack(family, iface.network.prefixlen, 0, RT_SCOPE_UNIVERSE, index) + attrs)

    def addresses(self) -> List[Tuple[int, str]]:
        out = []
        for rtype, body in self.request(RTM_GETADDR, NLM_F_DUMP, _IFADDR.pack(socket.AF_UNSPEC, 0, 0, 0, 0)):
            if rtype != RTM_NEWADDR:
                continue
            family, prefix, _, _, index = _IFADDR.unpack_from(body)
            attrs = parse_attrs(body[_IFADDR.size :])
            raw = attrs.get(IFA_LOCAL) or attrs.get(IFA_ADDRESS)
            if raw:
                out.append((index, "%s/%d" % (ipaddress.ip_address(raw), prefix)))
        return out

    def add_default_route(self, gateway: str, index: int) -> None:
        gw = ipaddress.ip_address(gateway)
        family = socket.AF_INET if gw.version == 4 else socket.AF_INET6
        payload = _RTMSG.pack(family, 0, 0, 0, RT_TABLE_MAIN, RTPROT_BOOT, RT_SCOPE_UNIVERSE, RTN_UNICAST, 0) + attr(RTA_GATEWAY, gw.packed) + attr_u32(RTA_OIF, index)
        self.request(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, payload)
