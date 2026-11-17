"""Checks for synthetic experiments and bounded process execution."""
import asyncio
import unittest
from unittest.mock import patch

from app.crypto_lab.attacks import avalanche, brute_force, differential, fixtures, statistics
from app.crypto_lab.attacks.results import Differences
from app.crypto_lab.attacks.runner import Busy, Coordinator


class AttackMetricsTests(unittest.TestCase):
    def test_fixtures_and_differences(self):
        self.assertEqual(len(set(fixtures.BLOCKS)), 32)
        self.assertEqual(fixtures.BLOCKS[1], (1).to_bytes(8, "big"))
        self.assertEqual(differential.flip(bytes(8), 0), b"\x80" + bytes(7))
        d = Differences()
        d.add(bytes(8), b"\x80" + bytes(7))
        d.add(bytes(8), bytes(8))
        result = d.result()
        self.assertEqual(result["pairs"], 2)
        self.assertEqual(result["output_bit_denominator"], 2)
        self.assertEqual(result["output_bit_changed_counts"][0], 1)
        self.assertEqual(result["mean_percent"], 100 / 128)
        self.assertEqual(result["population_stddev_percent"], 100 / 128)

    def test_collision_accounting_and_full_space(self):
        # All keys collide on the first pair; only the original matches the second.
        def cipher(block, key):
            return bytes(8) if block == fixtures.DISTINCT[0] else key * 4
        with patch.object(brute_force, "generate_key", return_value=b"\xff\xff"), patch.object(brute_force, "encrypt_block", side_effect=cipher):
            result = brute_force.run()
        self.assertEqual(result["attempts"], 65536)
        self.assertEqual(result["first_pair_candidates"], 65536)
        self.assertEqual(result["second_pair_checks"], 65536)
        self.assertEqual(result["second_pair_candidates"], 1)
        self.assertTrue(result["target_found"])
        self.assertNotIn("key", result)

    def test_statistics_denominators(self):
        result = statistics.run()
        self.assertEqual(result["byte_denominator"], 32 * 40 * 8)
        self.assertEqual(sum(result["byte_counts"]), result["byte_denominator"])
        self.assertTrue(all(v["repeated_excess"] == 3 for v in result["groups"]["repeated"]["per_key"]))

    def test_differential_and_avalanche_counts(self):
        # Small catalogue and key count to check the algorithms without expensive runs.
        keys = [bytes(2)]
        with patch.object(differential, "BLOCKS", fixtures.BLOCKS[:2]):
            result = differential.plaintext_pairs(keys)
        self.assertEqual(result["pairs"], 128)
        self.assertEqual(sum(result["histogram_bits_changed"]), 128)
        prop = differential.propagation(keys)
        self.assertEqual(sum(prop["comparisons"]), 1024)
        self.assertEqual(sum(prop["changed_blocks"][i] for i in (0, 1, 2, 4, 5, 6)), 0)
        # Full avalanche path with cheap deterministic cipher; counts remain meaningful.
        with patch.object(avalanche, "generate_key", return_value=bytes(2)), \
             patch.object(avalanche, "encrypt_block", side_effect=lambda b, k: bytes(x ^ k[0] for x in b)), \
             patch.object(avalanche, "plaintext_pairs", return_value={"pairs": 65536}), \
             patch.object(avalanche, "propagation", return_value={}):
            result = avalanche.run()
        self.assertEqual(result["key_bit_flips"]["pairs"], 16384)
        self.assertEqual(sum(result["key_bit_flips"]["histogram_bits_changed"]), 16384)


class CoordinatorTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_experiments_complete(self):
        for experiment in ("brute_force", "differential", "avalanche"):
            c = Coordinator()
            started = c.start("owner", experiment, 120)
            await c.task
            result = c.get("owner", started["run_id"])
            self.assertEqual(result["status"], "completed", experiment)
            metrics = result["metrics"]
            if experiment == "brute_force":
                self.assertEqual(metrics["attempts"], 65536)
                self.assertTrue(metrics["target_found"])
            else:
                self.assertEqual(metrics["plaintext_bit_flips"]["pairs"], 65536)
                if experiment == "avalanche":
                    self.assertEqual(metrics["key_bit_flips"]["pairs"], 16384)

    async def test_subprocess_completion_and_owner(self):
        c = Coordinator()
        started = c.start("owner", "statistics", 30)
        with self.assertRaises(Busy):
            c.start("other", "statistics", 30)
        await c.task
        self.assertEqual(c.get("owner", started["run_id"])["status"], "completed")
        self.assertIsNone(c.get("other", started["run_id"]))
        self.assertIsNone(c.active)
        self.assertIsNone(c.process)

    async def test_timeout_and_cleanup(self):
        c = Coordinator()
        started = c.start("owner", "brute_force", .01)
        await c.task
        self.assertEqual(c.get("owner", started["run_id"])["status"], "timed_out")
        self.assertIsNone(c.active)
        self.assertIsNone(c.process)

    async def test_close_cleans_child(self):
        c = Coordinator()
        started = c.start("owner", "brute_force", 30)
        await asyncio.sleep(.1)
        await c.close()
        self.assertEqual(c.get("owner", started["run_id"])["status"], "failed")
        self.assertIsNone(c.process)


if __name__ == "__main__":
    unittest.main()
