"""Exhaust the 16-bit teaching key space using two synthetic known pairs."""

from time import monotonic
from app.crypto_lab.toy_cipher import encrypt_block, generate_key
from .fixtures import DISTINCT


def run():
    target = generate_key()
    first, second = DISTINCT[:2]
    c1, c2 = encrypt_block(first, target), encrypt_block(second, target)
    start = monotonic()
    count1 = count2 = checks2 = 0
    found = False
    for value in range(65536):
        candidate = value.to_bytes(2, "big")
        if encrypt_block(first, candidate) == c1:
            count1 += 1
            found |= candidate == target
            checks2 += 1
            if encrypt_block(second, candidate) == c2:
                count2 += 1
    elapsed = monotonic() - start
    return {"attempts": 65536, "key_space": 65536, "duration_seconds": elapsed,
            "keys_per_second": 65536 / elapsed if elapsed > 0 else None,
            "first_pair_candidates": count1, "second_pair_checks": checks2,
            "second_pair_candidates": count2, "target_found": found}
