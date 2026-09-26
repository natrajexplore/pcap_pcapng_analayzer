"""Live capture on Linux using an AF_PACKET raw socket (standard library only).

Requires root or CAP_NET_RAW. Frames are written to pcapng (so they can be opened
in Wireshark too) and can be analyzed immediately.
"""
from __future__ import annotations

import socket
import struct
import time

from .reader import RawFrame, write_pcapng

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
ARPHRD_TO_LINKTYPE = {1: 1, 772: 1, 65534: 101, 776: 101, 778: 101, 768: 101}  # ether, loopback, none/tun, sit, gre


class LiveCaptureError(Exception):
    pass


def capture(interface: str = "any", duration: float | None = 10.0, count: int | None = None,
            snaplen: int = 262144, host: str | None = None, port: int | None = None,
            on_packet=None) -> list[RawFrame]:
    """Capture frames until ``duration`` seconds or ``count`` frames (whichever first)."""
    if not hasattr(socket, "AF_PACKET"):
        raise LiveCaptureError("live capture needs Linux AF_PACKET sockets")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError as exc:
        raise LiveCaptureError("live capture needs root or CAP_NET_RAW (try sudo)") from exc
    try:
        if interface and interface != "any":
            sock.bind((interface, 0))
        sock.settimeout(0.2)
        want_host = socket.inet_aton(host) if host else None
        frames: list[RawFrame] = []
        start = time.time()
        while True:
            if duration is not None and time.time() - start >= duration:
                break
            if count is not None and len(frames) >= count:
                break
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            ifname, _proto, pkttype, hatype = addr[0], addr[1], addr[2], addr[3]
            if pkttype == PACKET_OUTGOING and ifname == "lo":
                continue                         # loopback delivers every packet twice
            lt = ARPHRD_TO_LINKTYPE.get(hatype, 1)
            if (want_host or port) and not _match(data, lt, want_host, port):
                continue
            fr = RawFrame(time.time(), lt, data[:snaplen], len(data))
            frames.append(fr)
            if on_packet:
                on_packet(fr)
        return frames
    finally:
        sock.close()


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
