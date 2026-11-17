"""Bit-flip comparison and independent-block propagation."""

from app.crypto_lab.toy_cipher import encrypt_block, generate_key
from .fixtures import BLOCKS, DISTINCT
from .results import Differences


def flip(data, bit):
    value = bytearray(data)
    value[bit // 8] ^= 1 << (7 - bit % 8)
    return bytes(value)


def plaintext_pairs(keys):
    result = Differences()
    for key in keys:
        for block in BLOCKS:
            baseline = encrypt_block(block, key)
            for bit in range(64):
                result.add(baseline, encrypt_block(flip(block, bit), key))
    return result.result()


def propagation(keys):
    # Indices -3..3 represent output-block position minus changed-block position.
    changed = [0] * 7
    denominators = [0] * 7
    for key in keys:
        baseline = [encrypt_block(b, key) for b in DISTINCT]
        for source in range(4):
            for bit in range(64):
                modified = encrypt_block(flip(DISTINCT[source], bit), key)
                for dest in range(4):
                    index = dest - source + 3
                    denominators[index] += 1
                    changed[index] += (modified if dest == source else baseline[dest]) != baseline[dest]
    return {"offsets": list(range(-3, 4)), "changed_blocks": changed, "comparisons": denominators,
            "data_blocks_per_message": 4, "padding_included": False}


def run():
    keys = [generate_key() for _ in range(32)]
    return {"keys": 32, "block_samples": 32, "plaintext_bit_flips": plaintext_pairs(keys),
            "propagation": propagation(keys)}
