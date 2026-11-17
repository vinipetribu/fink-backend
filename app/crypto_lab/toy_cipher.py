"""Reversible educational block cipher. INSECURE: use fictitious data only.

Two-byte keys, deterministic independent blocks and no authentication make this
cipher unsuitable for protecting information. It is never used by AES-GCM.
"""

from hashlib import sha256
from secrets import randbelow
from threading import BoundedSemaphore
from uuid import UUID, uuid4

from app.crypto_lab.envelope import decode, encode
from app.crypto_lab.errors import CapacityError, DecryptionError
from app.crypto_lab.key_store import KeyStore
from app.crypto_lab.metrics import Metrics

BLOCK_SIZE = 8
ROUNDS = 4
SBOX = (12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2)
INVERSE_SBOX = tuple(SBOX.index(i) for i in range(16))
PERMUTATION = (2, 5, 0, 7, 4, 1, 6, 3)
WARNING = "Cifra didática insegura; use apenas dados fictícios."


def generate_key() -> bytes:
    """Generate a deliberately small random 16-bit key for demonstration."""
    return randbelow(1 << 16).to_bytes(2, "big")


def _round_keys(key: bytes) -> list[bytes]:
    if not isinstance(key, bytes) or len(key) != 2:
        raise ValueError("Invalid experimental key")
    return [sha256(b"FINK-TOY-V1" + key + bytes([r])).digest()[:BLOCK_SIZE] for r in range(ROUNDS)]


def _substitute(value: int, table: tuple[int, ...]) -> int:
    return (table[value >> 4] << 4) | table[value & 15]


def encrypt_block(block: bytes, key: bytes) -> bytes:
    """XOR, nibble substitution, byte permutation and reversible XOR mixing."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("Invalid block length")
    state = list(block)
    for round_key in _round_keys(key):
        state = [_substitute(value ^ round_key[i], SBOX) for i, value in enumerate(state)]
        state = [state[i] for i in PERMUTATION]
        for i in range(1, BLOCK_SIZE):
            state[i] ^= state[i - 1]
    return bytes(state)


def decrypt_block(block: bytes, key: bytes) -> bytes:
    """Reverse mixing, permutation, substitution and XOR in reverse round order."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("Invalid block length")
    state = list(block)
    for round_key in reversed(_round_keys(key)):
        for i in range(BLOCK_SIZE - 1, 0, -1):
            state[i] ^= state[i - 1]
        unpermuted = [0] * BLOCK_SIZE
        for i, original in enumerate(PERMUTATION):
            unpermuted[original] = state[i]
        state = [_substitute(value, INVERSE_SBOX) ^ round_key[i] for i, value in enumerate(unpermuted)]
    return bytes(state)


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    if not isinstance(data, bytes) or not 1 <= len(data) <= 4096:
        raise ValueError("Invalid plaintext length")
    pad = BLOCK_SIZE - len(data) % BLOCK_SIZE
    padded = data + bytes([pad]) * pad
    return b"".join(encrypt_block(padded[i:i + BLOCK_SIZE], key) for i in range(0, len(padded), BLOCK_SIZE))


def decrypt_bytes(data: bytes, key: bytes) -> bytes:
    if not isinstance(data, bytes) or not BLOCK_SIZE <= len(data) <= 4104 or len(data) % BLOCK_SIZE:
        raise ValueError("Invalid ciphertext length")
    padded = b"".join(decrypt_block(data[i:i + BLOCK_SIZE], key) for i in range(0, len(data), BLOCK_SIZE))
    pad = padded[-1]
    if not 1 <= pad <= BLOCK_SIZE or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid padding")
    data = padded[:-pad]
    if not 1 <= len(data) <= 4096:
        raise ValueError("Invalid plaintext length")
    return data


class ToyService:
    """Separate key store and execution budget; only metrics are shared with the lab."""

    def __init__(self, metrics: Metrics, store: KeyStore | None = None):
        self.metrics = metrics
        self.store = store if store is not None else KeyStore()
        self.slots = BoundedSemaphore(10)

    def encrypt(self, text: str, owner: UUID) -> dict:
        if not self.slots.acquire(blocking=False):
            raise CapacityError()
        try:
            key, key_id = generate_key(), uuid4()
            ciphertext = encode(encrypt_bytes(text.encode("utf-8"), key))
            result = {"operation_id": uuid4(), "algorithm": "TOY-V1-INSECURE", "key_id": key_id,
                      "ciphertext": ciphertext, "warning": WARNING}
            self.store.add(key_id, owner, key)
            try:
                self.metrics.increment("experimental_success")
            except Exception:
                self.store.discard(key_id, owner, key)
                raise
            return result
        finally:
            self.slots.release()

    def decrypt(self, ciphertext: str, key_id: UUID, owner: UUID) -> dict:
        if not self.slots.acquire(blocking=False):
            raise CapacityError()
        try:
            key = self.store.get(key_id, owner)
            try:
                if key is None:
                    raise ValueError("Key unavailable")
                text = decrypt_bytes(decode(ciphertext), key).decode("utf-8")
            except (ValueError, UnicodeError) as exc:
                self.metrics.increment("experimental_failure")
                raise DecryptionError() from exc
            self.metrics.increment("experimental_success")
            return {"operation_id": uuid4(), "algorithm": "TOY-V1-INSECURE", "text": text,
                    "warning": WARNING}
        finally:
            self.slots.release()
