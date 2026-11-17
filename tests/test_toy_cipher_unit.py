"""Pure unit/property checks for the deliberately insecure teaching cipher."""

import unittest
from unittest.mock import patch
from uuid import uuid4

from app.crypto_lab.errors import CapacityError, DecryptionError
from app.crypto_lab.key_store import KeyStore
from app.crypto_lab.metrics import Metrics
from app.crypto_lab.toy_cipher import (
    BLOCK_SIZE, INVERSE_SBOX, SBOX, ToyService, decrypt_block, decrypt_bytes, encrypt_block, encrypt_bytes, generate_key,
)


class ToyCipherProperties(unittest.TestCase):
    def test_sbox_is_bijective_and_nonlinear(self):
        self.assertEqual(sorted(SBOX), list(range(16)))
        self.assertEqual([INVERSE_SBOX[SBOX[n]] for n in range(16)], list(range(16)))
        self.assertNotEqual(SBOX[0] ^ SBOX[1], SBOX[2] ^ SBOX[3])

    def test_reversible_at_various_sizes(self):
        for size in (1, 7, 8, 9, 16, 17, 255, 4096):
            with self.subTest(size=size):
                data = bytes((i * 31) % 256 for i in range(size))
                self.assertEqual(decrypt_bytes(encrypt_bytes(data, b"\x12\x34"), b"\x12\x34"), data)

    def test_reversible_all_byte_values(self):
        for byte in range(256):
            block = bytes([byte]) * BLOCK_SIZE
            self.assertEqual(decrypt_block(encrypt_block(block, b"\x00\xff"), b"\x00\xff"), block)

    def test_key_and_input_affect_output(self):
        block = bytes(8)
        out = encrypt_block(block, b"\x00\x00")
        self.assertNotEqual(out, encrypt_block(block, b"\x00\x01"))
        changed = encrypt_block(bytes([1]) + bytes(7), b"\x00\x00")
        # Educational observation for one example, not a security or avalanche proof.
        self.assertGreater(sum(a != b for a, b in zip(out, changed)), 1)

    def test_equal_blocks_reveal_patterns(self):
        block = b"ABCD1234"
        ciphertext = encrypt_bytes(block * 2, b"\x12\x34")
        self.assertEqual(ciphertext[:8], ciphertext[8:16])

    def test_generation_uses_random_source(self):
        with patch("app.crypto_lab.toy_cipher.randbelow", side_effect=[1, 65535]) as rng:
            self.assertEqual(generate_key(), b"\x00\x01")
            self.assertEqual(generate_key(), b"\xff\xff")
            self.assertEqual(rng.call_count, 2)

    def test_invalid_lengths_and_key(self):
        for data in (b"", b"x" * 4097):
            with self.assertRaises(ValueError):
                encrypt_bytes(data, b"\0\0")
        for data in (b"", b"x", b"x" * 4105):
            with self.assertRaises(ValueError):
                decrypt_bytes(data, b"\0\0")
        with self.assertRaises(ValueError):
            encrypt_block(b"12345678", b"x")

    def test_invalid_padding(self):
        padded_with_invalid_byte = encrypt_block(b"1234567\x00", b"\0\0")
        with self.assertRaises(ValueError):
            decrypt_bytes(padded_with_invalid_byte, b"\0\0")

    def test_service_ownership_and_expiry(self):
        now = [0.0]
        store = KeyStore(capacity=1, ttl=60, clock=lambda: now[0])
        metrics = Metrics()
        service = ToyService(metrics, store)
        owner = uuid4()
        result = service.encrypt("texto fictício", owner)
        self.assertNotIn("key", result)
        self.assertEqual(service.decrypt(result["ciphertext"], result["key_id"], owner)["text"], "texto fictício")
        with self.assertRaises(DecryptionError):
            service.decrypt(result["ciphertext"], result["key_id"], uuid4())
        with self.assertRaises(CapacityError):
            service.encrypt("outro", owner)
        now[0] = 60
        with self.assertRaises(DecryptionError):
            service.decrypt(result["ciphertext"], result["key_id"], owner)
        self.assertEqual(metrics.summary()["counts"]["experimental_success"], 2)
        self.assertEqual(metrics.summary()["counts"]["experimental_failure"], 2)

    def test_capacity_and_rollback_after_failure(self):
        metrics = Metrics()
        service = ToyService(metrics)
        owner = uuid4()
        for _ in range(10):
            self.assertTrue(service.slots.acquire(blocking=False))
        with self.assertRaises(CapacityError):
            service.encrypt("fictício", owner)
        for _ in range(10):
            service.slots.release()
        with patch.object(metrics, "increment", side_effect=RuntimeError("erro simulado")):
            with self.assertRaises(RuntimeError):
                service.encrypt("fictício", owner)
        self.assertFalse(service.store._records)

    def test_key_generation_on_every_encryption(self):
        service = ToyService(Metrics())
        owner = uuid4()
        with patch("app.crypto_lab.toy_cipher.generate_key", side_effect=[b"\0\x01", b"\0\x02"]) as source:
            first = service.encrypt("mesma entrada", owner)
            second = service.encrypt("mesma entrada", owner)
        self.assertEqual(source.call_count, 2)
        self.assertNotEqual(first["key_id"], second["key_id"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])


if __name__ == "__main__":
    unittest.main()
