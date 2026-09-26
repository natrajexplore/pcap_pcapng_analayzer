"""Pure-Python reader for libpcap (.pcap) and pcapng (.pcapng) capture files.

Yields ``RawFrame`` objects (timestamp, link type, captured bytes, original
length). No third-party dependencies are required.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_SHB = 0x0A0D0D0A


class CaptureFormatError(Exception):
    """Raised when a file is not a readable pcap/pcapng capture."""


@dataclass(slots=True)
class RawFrame:
    ts: float
    linktype: int
    data: bytes
    wirelen: int
    interface: int = 0


def open_capture(path_or_file) -> Iterator[RawFrame]:
    """Open a capture by path or binary file object and iterate its frames."""
    if isinstance(path_or_file, (str, bytes)) or hasattr(path_or_file, "__fspath__"):
        with open(path_or_file, "rb") as fh:
            yield from _iter_file(fh)
    else:
        yield from _iter_file(path_or_file)


def _iter_file(fh: BinaryIO) -> Iterator[RawFrame]:
    head = fh.read(4)
    if len(head) < 4:
        raise CaptureFormatError("File too small to be a capture")
    if head in PCAP_MAGICS:
        yield from _iter_pcap(fh, head)
    elif struct.unpack("<I", head)[0] == PCAPNG_SHB:
        yield from _iter_pcapng(fh, head)
    else:
        raise CaptureFormatError("Unknown capture format (not pcap or pcapng)")


def _iter_pcap(fh: BinaryIO, magic: bytes) -> Iterator[RawFrame]:
    endian, resolution = PCAP_MAGICS[magic]
    rest = fh.read(20)
    if len(rest) < 20:
        raise CaptureFormatError("Truncated pcap global header")
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", rest)
    linktype &= 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    while True:
        hdr = fh.read(16)
        if len(hdr) < 16:
            return
        sec, frac, incl, orig = rec.unpack(hdr)
        data = fh.read(incl)
        if len(data) < incl:
            return  # truncated final record
        yield RawFrame(sec + frac * resolution, linktype, data, orig)


def _iter_pcapng(fh: BinaryIO, first: bytes) -> Iterator[RawFrame]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, ts resolution)
    pending = first
    while True:
        head = pending + fh.read(8 - len(pending))
        pending = b""
        if len(head) < 8:
            return
        btype_le = struct.unpack("<I", head[:4])[0]
        if btype_le == PCAPNG_SHB:
            bom = fh.read(4)
            if len(bom) < 4:
                return
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", head[4:8])[0]
            body = fh.read(blen - 12)
            interfaces = []  # a new section resets interface ids
            continue
        btype, blen = struct.unpack(endian + "II", head)
        if blen < 12:
            raise CaptureFormatError("Corrupt pcapng block length")
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]  # trailing block length
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            interfaces.append((linktype, _if_tsresol(body[8:], endian)))
        elif btype == 6:  # Enhanced Packet Block
            iface, hi, lo, caplen, orig = struct.unpack(endian + "IIIII", body[:20])
            lt, res = interfaces[iface] if iface < len(interfaces) else (1, 1e-6)
            yield RawFrame(((hi << 32) | lo) * res, lt, body[20:20 + caplen], orig, iface)
        elif btype == 3:  # Simple Packet Block
            orig = struct.unpack(endian + "I", body[:4])[0]
            lt, _ = interfaces[0] if interfaces else (1, 1e-6)
            yield RawFrame(0.0, lt, body[4:4 + orig], orig)
        elif btype == 2:  # obsolete Packet Block
            iface, _drops, hi, lo, caplen, orig = struct.unpack(endian + "HHIIII", body[:20])
            lt, res = interfaces[iface] if iface < len(interfaces) else (1, 1e-6)
            yield RawFrame(((hi << 32) | lo) * res, lt, body[20:20 + caplen], orig, iface)
        # other blocks (name resolution, stats, custom...) are skipped


def _if_tsresol(options: bytes, endian: str) -> float:
    off = 0
    while off + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[off:off + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = options[off + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        off += 4 + ((length + 3) & ~3)
    return 1e-6


# ---------------------------------------------------------------- writers ---
# Minimal writers used by the demo/synthetic capture generator and tests.

def write_pcap(path, frames: list[tuple[float, bytes]], linktype: int = 1) -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        for ts, data in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            fh.write(data)


def write_pcapng(path, frames: list[tuple[float, bytes]], linktype: int = 1) -> None:
    def block(btype: int, body: bytes) -> bytes:
        body += b"\x00" * ((4 - len(body) % 4) % 4)
        blen = len(body) + 12
        return struct.pack("<II", btype, blen) + body + struct.pack("<I", blen)

    with open(path, "wb") as fh:
        fh.write(block(PCAPNG_SHB, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        fh.write(block(1, struct.pack("<HHI", linktype, 0, 262144)))
        for ts, data in frames:
            t = int(round(ts * 1e6))
            fh.write(block(6, struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(data), len(data)) + data))
