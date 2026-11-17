"""Bounded PNG RGB/RGBA LSB codec for fictitious laboratory data.

Uses only stdlib. PNG ancillary chunks are deliberately stripped on output.
The SHA-256 frame checksum detects accidental corruption, not malicious edits.
"""

import hashlib
import hmac
import struct
import zlib
from dataclasses import dataclass

SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAGIC = b"FSL1"
MAX_PNG_BYTES = 1024 * 1024
MAX_DIMENSION = 256
MAX_PIXELS = 65536
MAX_PAYLOAD = 8192
HEADER_SIZE = 40
PASSES = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
          (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2))


class SteganographyError(ValueError):
    """Invalid image, payload, frame or capacity; safe to show only generically."""


@dataclass
class Raster:
    width: int
    height: int
    depth: int
    color: int
    pixels: bytearray

    @property
    def pixel_bytes(self):
        return (3 if self.color == 2 else 4) * (self.depth // 8)


def _chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def _paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    return a if pa <= pb and pa <= pc else b if pb <= pc else c


def _size(n, start, step):
    return (n - start + step - 1) // step if n > start else 0


def decode_png(data: bytes) -> Raster:
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_PNG_BYTES or not data.startswith(SIGNATURE):
        raise SteganographyError("Invalid PNG")
    pos = len(SIGNATURE)
    ihdr = None
    idats = []
    seen_idat = False
    ended_idat = False
    ended = False
    seen_palette = False
    while pos < len(data):
        if len(data) - pos < 12:
            raise SteganographyError("Invalid PNG structure")
        length = struct.unpack_from(">I", data, pos)[0]
        end = pos + 12 + length
        if end > len(data):
            raise SteganographyError("Invalid PNG length")
        kind = data[pos + 4:pos + 8]
        payload = data[pos + 8:pos + 8 + length]
        crc = struct.unpack_from(">I", data, pos + 8 + length)[0]
        if zlib.crc32(kind + payload) & 0xFFFFFFFF != crc:
            raise SteganographyError("Invalid PNG checksum")
        if ihdr is None and kind != b"IHDR":
            raise SteganographyError("Missing PNG header")
        if kind == b"IHDR":
            if ihdr is not None or length != 13:
                raise SteganographyError("Invalid PNG header")
            ihdr = payload
        elif kind == b"IDAT":
            if ended_idat:
                raise SteganographyError("Invalid IDAT order")
            seen_idat = True
            idats.append(payload)
        elif kind == b"IEND":
            if length or not seen_idat or end != len(data):
                raise SteganographyError("Invalid PNG end")
            ended = True
            break
        elif kind == b"PLTE":
            if seen_idat or seen_palette or not 3 <= length <= 768 or length % 3:
                raise SteganographyError("Invalid PNG palette")
            seen_palette = True
        else:
            if seen_idat:
                ended_idat = True
            # Animated PNG and RGB tRNS transparency are not silently discarded.
            if kind in (b"acTL", b"fcTL", b"fdAT", b"tRNS") or not (kind[0] & 32):
                raise SteganographyError("Unsupported PNG feature")
        pos = end
    if not ended or ihdr is None:
        raise SteganographyError("Incomplete PNG")
    width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", ihdr)
    if (not 1 <= width <= MAX_DIMENSION or not 1 <= height <= MAX_DIMENSION
            or width * height > MAX_PIXELS or depth not in (8, 16) or color not in (2, 6)
            or compression != 0 or filtering != 0 or interlace not in (0, 1)):
        raise SteganographyError("Unsupported PNG dimensions or format")
    bpp = (3 if color == 2 else 4) * (depth // 8)
    passes = PASSES if interlace else ((0, 0, 1, 1),)
    expected = sum((1 + _size(width, x, dx) * bpp) * _size(height, y, dy)
                   for x, y, dx, dy in passes if _size(width, x, dx) and _size(height, y, dy))
    try:
        decompressor = zlib.decompressobj()
        raw = decompressor.decompress(b"".join(idats), expected + 1)
    except zlib.error as exc:
        raise SteganographyError("Invalid PNG compression") from exc
    if len(raw) != expected or not decompressor.eof or decompressor.unused_data or decompressor.unconsumed_tail:
        raise SteganographyError("Invalid PNG data size")
    pixels = bytearray(width * height * bpp)
    offset = 0
    for x0, y0, dx, dy in passes:
        pw, ph = _size(width, x0, dx), _size(height, y0, dy)
        if not pw or not ph:
            continue
        previous = bytearray(pw * bpp)
        for py in range(ph):
            filter_type = raw[offset]
            offset += 1
            if filter_type > 4:
                raise SteganographyError("Invalid PNG filter")
            row = bytearray(raw[offset:offset + pw * bpp])
            offset += len(row)
            for i, value in enumerate(row):
                a = row[i - bpp] if i >= bpp else 0
                b = previous[i]
                c = previous[i - bpp] if i >= bpp else 0
                predictor = (0, a, b, (a + b) // 2, _paeth(a, b, c))[filter_type]
                row[i] = (value + predictor) & 255
            for px in range(pw):
                target = ((y0 + py * dy) * width + x0 + px * dx) * bpp
                pixels[target:target + bpp] = row[px * bpp:(px + 1) * bpp]
            previous = row
    return Raster(width, height, depth, color, pixels)


def encode_png(raster: Raster) -> bytes:
    ihdr = struct.pack(">IIBBBBB", raster.width, raster.height, raster.depth, raster.color, 0, 0, 0)
    stride = raster.width * raster.pixel_bytes
    raw = b"".join(b"\0" + raster.pixels[y * stride:(y + 1) * stride] for y in range(raster.height))
    out = SIGNATURE + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(raw)) + _chunk(b"IEND", b"")
    if len(out) > MAX_PNG_BYTES:
        raise SteganographyError("Output PNG too large")
    return out


def _rgb_offsets(raster):
    step = raster.depth // 8
    for start in range(0, len(raster.pixels), raster.pixel_bytes):
        for channel in range(3):
            yield start + channel * step + step - 1


def embed(png: bytes, payload: bytes) -> bytes:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_PAYLOAD:
        raise SteganographyError("Invalid payload")
    raster = decode_png(png)
    frame = MAGIC + struct.pack(">I", len(payload)) + hashlib.sha256(payload).digest() + payload
    if len(frame) * 8 > raster.width * raster.height * 3:
        raise SteganographyError("Insufficient image capacity")
    offsets = _rgb_offsets(raster)
    for value in frame:
        for bit in range(7, -1, -1):
            index = next(offsets)
            raster.pixels[index] = (raster.pixels[index] & 0xFE) | ((value >> bit) & 1)
    return encode_png(raster)


def extract(png: bytes) -> bytes:
    raster = decode_png(png)
    available = raster.width * raster.height * 3
    if available < HEADER_SIZE * 8:
        raise SteganographyError("Image too small")
    offsets = iter(_rgb_offsets(raster))
    def read_bytes(count):
        result = bytearray()
        for _ in range(count):
            value = 0
            for _ in range(8):
                value = (value << 1) | (raster.pixels[next(offsets)] & 1)
            result.append(value)
        return bytes(result)
    header = read_bytes(HEADER_SIZE)
    length = struct.unpack(">I", header[4:8])[0]
    if header[:4] != MAGIC or not 1 <= length <= MAX_PAYLOAD or (HEADER_SIZE + length) * 8 > available:
        raise SteganographyError("Invalid hidden frame")
    payload = read_bytes(length)
    if not hmac.compare_digest(hashlib.sha256(payload).digest(), header[8:40]):
        raise SteganographyError("Invalid hidden payload checksum")
    return payload
