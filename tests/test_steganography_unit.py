"""PNG codec and LSB frame tests independent of the HTTP stack."""

import io
import struct
import unittest
import zlib

from app.crypto_lab.steganography import (
    HEADER_SIZE, MAX_PAYLOAD, MAX_PNG_BYTES, Raster, SteganographyError,
    decode_png, embed, encode_png, extract,
)


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)


def make_png(width, height, color=2, depth=8, interlace=False, pixels=None, filter_kind=0):
    bpp = (3 if color == 2 else 4) * (depth // 8)
    if pixels is None:
        pixels = bytes((i * 67 + 13) % 256 for i in range(width * height * bpp))
    passes = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
              (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)) if interlace else ((0, 0, 1, 1),)
    scanlines = bytearray()
    for x0, y0, dx, dy in passes:
        xs, ys = list(range(x0, width, dx)), list(range(y0, height, dy))
        if not xs or not ys:
            continue
        prev = bytes(len(xs) * bpp)
        for y in ys:
            row = b''.join(pixels[(y * width + x) * bpp:(y * width + x + 1) * bpp] for x in xs)
            filtered = bytearray()
            for i, value in enumerate(row):
                a, b = (row[i-bpp] if i >= bpp else 0), prev[i]
                c = prev[i-bpp] if i >= bpp else 0
                pp = a+b-c
                pa, pb, pc = abs(pp-a), abs(pp-b), abs(pp-c)
                predictors = (0, a, b, (a+b)//2, a if pa <= pb and pa <= pc else b if pb <= pc else c)
                filtered.append((value - predictors[filter_kind]) % 256)
            scanlines.extend(bytes([filter_kind]) + filtered)
            prev = row
    header = struct.pack(">IIBBBBB", width, height, depth, color, 0, 0, int(interlace))
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header) + chunk(b'IDAT', zlib.compress(scanlines)) + chunk(b'IEND', b'')


class SteganographyUnit(unittest.TestCase):
    def test_roundtrip_formats_and_alpha(self):
        for color in (2, 6):
            for depth in (8, 16):
                for interlace in (False, True):
                    for filter_kind in range(5):
                        with self.subTest(color=color, depth=depth, interlace=interlace, filter=filter_kind):
                            source = make_png(32, 32, color, depth, interlace, filter_kind=filter_kind)
                            before = decode_png(source)
                            result = embed(source, b'envelope ficticio')
                            after = decode_png(result)
                            self.assertEqual(extract(result), b'envelope ficticio')
                            self.assertEqual((after.color, after.depth), (color, depth))
                            if color == 6:
                                bpp, step = before.pixel_bytes, depth // 8
                                for pixel in range(before.width * before.height):
                                    i = pixel * bpp + 3 * step
                                    self.assertEqual(before.pixels[i:i+step], after.pixels[i:i+step])
                            step = depth // 8
                            for pixel in range(before.width * before.height):
                                for channel in range(3):
                                    i = pixel * before.pixel_bytes + channel * step + step - 1
                                    self.assertEqual(before.pixels[i] & 254, after.pixels[i] & 254)

    def test_pillow_can_open_output_if_available(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest('Pillow not installed; independent reader optional')
        for color, mode in ((2, 'RGB'), (6, 'RGBA')):
            png = embed(make_png(24, 24, color), b'a')
            with Image.open(io.BytesIO(png)) as image:
                image.load()
                self.assertEqual(image.mode, mode)
                self.assertEqual(image.size, (24, 24))

    def test_capacity_and_bad_images(self):
        with self.assertRaises(SteganographyError):
            embed(make_png(2, 2), b'a')
        for data in (b'', b'not a png', make_png(12, 12)[:-1], b'x' * (MAX_PNG_BYTES + 1)):
            with self.subTest(size=len(data)), self.assertRaises(SteganographyError):
                decode_png(data)
        with self.assertRaises(SteganographyError):
            embed(make_png(64, 64), b'x' * (MAX_PAYLOAD + 1))
        with self.assertRaises(SteganographyError):
            decode_png(make_png(257, 1))

    def test_corruption_and_no_hidden_payload(self):
        png = embed(make_png(32, 32), b'example payload')
        raster = decode_png(png)
        raster.pixels[(HEADER_SIZE * 8 + 2)] ^= 1
        with self.assertRaises(SteganographyError):
            extract(encode_png(raster))
        with self.assertRaises(SteganographyError):
            extract(make_png(32, 32))
        broken = bytearray(png)
        broken[30] ^= 1
        with self.assertRaises(SteganographyError):
            decode_png(bytes(broken))

    def test_unsupported_images_and_bad_zlib(self):
        bad_color = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(b'\0\0')) + chunk(b'IEND', b'')
        with self.assertRaises(SteganographyError):
            decode_png(bad_color)
        header = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
        corrupt = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header) + chunk(b'IDAT', b'wrong') + chunk(b'IEND', b'')
        with self.assertRaises(SteganographyError):
            decode_png(corrupt)


if __name__ == '__main__':
    unittest.main()
