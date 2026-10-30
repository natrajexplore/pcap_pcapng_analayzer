"""Live capture with raw sockets (standard library only).

* Linux: AF_PACKET — full Ethernet frames; needs root or CAP_NET_RAW.
* Windows: SIO_RCVALL on a raw IPv4 socket bound to one local address — IP packets only
  (no Ethernet header, no IPv6); needs Administrator.

Frames are written to pcapng (so they can be opened in Wireshark too) and can be analyzed immediately.
"""
from __future__ import annotations

import os
import socket
import struct
import time

from .reader import RawFrame, write_pcapng

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
ARPHRD_TO_LINKTYPE = {1: 1, 772: 1, 65534: 101, 776: 101, 778: 101, 768: 101}  # ether, loopback, none/tun, sit, gre
LINKTYPE_RAW = 101


class LiveCaptureError(Exception):
    pass


def interfaces() -> list[dict]:
    """Capturable interfaces: names on Linux, local IPv4 addresses on Windows."""
    if hasattr(socket, "AF_PACKET"):
        return [{"id": "any", "label": "all interfaces"}] + [{"id": n, "label": n} for _, n in socket.if_nameindex()]
    if os.name == "nt":
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)})
        return [{"id": ip, "label": f"{ip} (IPv4 only)"} for ip in ips]
    return []


def capture(interface: str = "any", duration: float | None = 10.0, count: int | None = None,
            snaplen: int = 262144, host: str | None = None, port: int | None = None,
            on_packet=None, stop=None) -> list[RawFrame]:
    """Capture frames until ``duration`` seconds, ``count`` frames or ``stop.is_set()`` (whichever first).

    Frames are returned only when there is no ``on_packet`` callback: a streaming caller owns the frames
    (and any memory cap), so they are not also accumulated here."""
    if hasattr(socket, "AF_PACKET"):
        sock, recv = _linux(interface)
    elif os.name == "nt" and hasattr(socket, "SIO_RCVALL"):
        sock, recv = _windows(interface)
    else:
        raise LiveCaptureError("live capture needs Linux AF_PACKET or Windows raw sockets")
    try:
        sock.settimeout(0.2)
        want_host = socket.inet_aton(host) if host else None
        frames: list[RawFrame] = []
        n = 0
        start = time.time()
        while not (stop is not None and stop.is_set()):
            if duration is not None and time.time() - start >= duration:
                break
            if count is not None and n >= count:
                break
            try:
                got = recv()
            except socket.timeout:
                continue
            if got is None:
                continue
            data, lt = got
            if (want_host or port) and not _match(data, lt, want_host, port):
                continue
            fr = RawFrame(time.time(), lt, data[:snaplen], len(data))
            n += 1
            if on_packet:
                on_packet(fr)
            else:
                frames.append(fr)
        return frames
    finally:
        if os.name == "nt" and hasattr(socket, "SIO_RCVALL"):
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        sock.close()


def _linux(interface):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError as exc:
        raise LiveCaptureError("live capture needs root or CAP_NET_RAW (try sudo)") from exc
    if interface and interface != "any":
        try:
            sock.bind((interface, 0))
        except OSError as exc:
            sock.close()
            raise LiveCaptureError(f"cannot capture on {interface}: {exc}") from exc

    def recv():
        data, addr = sock.recvfrom(65535)
        ifname, _proto, pkttype, hatype = addr[0], addr[1], addr[2], addr[3]
        if pkttype == PACKET_OUTGOING and ifname == "lo":
            return None                          # loopback delivers every packet twice
        return data, ARPHRD_TO_LINKTYPE.get(hatype, 1)
    return sock, recv


def _windows(interface):
    ip = interface if interface and interface != "any" else (interfaces() or [{"id": "127.0.0.1"}])[0]["id"]
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except OSError as exc:                                  # PermissionError is an OSError
        if sock is not None:
            sock.close()
        if isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 10013:
            raise LiveCaptureError("live capture on Windows needs an Administrator prompt") from exc
        raise LiveCaptureError(f"cannot capture on {ip}: {exc}") from exc
    return sock, lambda: (sock.recvfrom(65535)[0], LINKTYPE_RAW)


def _match(data: bytes, lt: int, host: bytes | None, port: int | None) -> bool:
    off = 0
    if lt == 1:
        if len(data) < 14:
            return False
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        if etype == 0x8100:
            etype = struct.unpack("!H", data[16:18])[0]
            off = 18
        if etype != 0x0800:
            return host is None and port is None
    ip = data[off:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return False
    if host and host not in (ip[12:16], ip[16:20]):
        return False
    if port:
        ihl = (ip[0] & 0xF) * 4
        if ip[9] not in (6, 17) or len(ip) < ihl + 4:
            return False
        sp, dp = struct.unpack("!HH", ip[ihl:ihl + 4])
        if port not in (sp, dp):
            return False
    return True


def save(frames: list[RawFrame], path: str, keylog: str | None = None) -> None:
    write_pcapng(path, [(f.ts, f.data, f.linktype, f.wirelen) for f in frames], keylog=keylog)
