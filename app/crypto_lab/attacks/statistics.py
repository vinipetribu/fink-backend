"""Byte frequency and independent-block repetition metrics."""

from app.crypto_lab.toy_cipher import encrypt_block, generate_key
from .fixtures import BLOCKS, DISTINCT, REPEATED


def run():
    frequencies = [0] * 256
    groups = {name: [] for name in ("repeated", "distinct", "synthetic")}
    for _ in range(32):
        key = generate_key()
        for name, blocks in (("repeated", REPEATED), ("distinct", DISTINCT), ("synthetic", BLOCKS)):
            encrypted = [encrypt_block(b, key) for b in blocks]
            for block in encrypted:
                for value in block:
                    frequencies[value] += 1
            distinct = len(set(encrypted))
            groups[name].append({"total_blocks": len(blocks), "distinct_blocks": distinct,
                                 "repeated_excess": len(blocks) - distinct,
                                 "repeated_fraction": (len(blocks) - distinct) / len(blocks),
                                 "positions_equal_to_first": sum(b == encrypted[0] for b in encrypted)})
    total = sum(frequencies)
    summaries = {}
    for name, values in groups.items():
        fractions = [v["repeated_fraction"] for v in values]
        summaries[name] = {"per_key": values, "mean_repeated_fraction": sum(fractions) / len(fractions),
                           "min_repeated_fraction": min(fractions), "max_repeated_fraction": max(fractions)}
    return {"keys": 32, "byte_counts": frequencies, "byte_denominator": total,
            "byte_frequencies": [n / total for n in frequencies], "groups": summaries}
