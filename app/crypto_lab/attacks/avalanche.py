"""Avalanche statistics for plaintext and key bit changes."""

from app.crypto_lab.toy_cipher import encrypt_block, generate_key
from .fixtures import BLOCKS
from .differential import flip, plaintext_pairs, propagation
from .results import Differences


def run():
    keys = [generate_key() for _ in range(32)]
    plaintext = plaintext_pairs(keys)
    altered_key = Differences()
    for key in keys:
        for block in BLOCKS:
            baseline = encrypt_block(block, key)
            for bit in range(16):
                altered_key.add(baseline, encrypt_block(block, flip(key, bit)))
    return {"keys": 32, "block_samples": 32, "plaintext_bit_flips": plaintext,
            "key_bit_flips": altered_key.result(), "propagation": propagation(keys)}
