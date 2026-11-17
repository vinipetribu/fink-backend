"""Aggregation of bit differences without retaining ciphertext."""

import math


class Differences:
    def __init__(self):
        self.histogram = [0] * 65
        self.bit_changes = [0] * 64
        self.count = 0

    def add(self, first, second):
        xor = int.from_bytes(first, "big") ^ int.from_bytes(second, "big")
        self.histogram[xor.bit_count()] += 1
        for i in range(64):
            self.bit_changes[i] += (xor >> (63 - i)) & 1
        self.count += 1

    def result(self):
        n = self.count
        if not n:
            raise ValueError("No observations")
        mean = sum(i * count for i, count in enumerate(self.histogram)) / n
        variance = sum(count * (i - mean) ** 2 for i, count in enumerate(self.histogram)) / n
        return {"pairs": n, "bits_per_pair": 64, "histogram_bits_changed": self.histogram,
                "output_bit_changed_counts": self.bit_changes, "output_bit_denominator": n,
                "mean_percent": mean * 100 / 64,
                "min_percent": next(i for i, v in enumerate(self.histogram) if v) * 100 / 64,
                "max_percent": next(i for i in range(64, -1, -1) if self.histogram[i]) * 100 / 64,
                "population_stddev_percent": math.sqrt(variance) * 100 / 64}
