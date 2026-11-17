"""AES-GCM operations with a fresh, single-use encryption key per message."""

import os
from threading import BoundedSemaphore
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.crypto_lab.envelope import decode, encode, make_aad
from app.crypto_lab.errors import CapacityError, DecryptionError
from app.crypto_lab.key_store import KeyStore
from app.crypto_lab.metrics import Metrics
from app.crypto_lab.schemas import CryptoEnvelope, DecryptResponse, EncryptResponse


class CryptoService:
    def __init__(self, store: KeyStore | None = None, metrics: Metrics | None = None):
        self.store = store if store is not None else KeyStore()
        self.metrics = metrics if metrics is not None else Metrics()
        self.slots = BoundedSemaphore(10)

    def encrypt(self, text: str, owner: UUID) -> EncryptResponse:
        if not self.slots.acquire(blocking=False):
            raise CapacityError()
        try:
            key, nonce, key_id = AESGCM.generate_key(bit_length=256), os.urandom(12), uuid4()
            aad = make_aad(1, "AES-256-GCM", key_id, owner)
            encrypted = AESGCM(key).encrypt(nonce, text.encode("utf-8"), aad)
            envelope = CryptoEnvelope(version=1, algorithm="AES-256-GCM", key_id=key_id,
                                      nonce=encode(nonce), ciphertext=encode(encrypted))
            result = EncryptResponse(operation_id=uuid4(), envelope=envelope)
            self.store.add(key_id, owner, key)
            try:
                self.metrics.increment("aes_encrypt_success")
            except Exception:
                self.store.discard(key_id, owner, key)
                raise
            return result
        finally:
            self.slots.release()

    def decrypt(self, envelope: CryptoEnvelope, owner: UUID) -> DecryptResponse:
        if not self.slots.acquire(blocking=False):
            raise CapacityError()
        try:
            key = self.store.get(envelope.key_id, owner)
            if key is None:
                self.metrics.increment("aes_decrypt_failure")
                raise DecryptionError()
            try:
                aad = make_aad(envelope.version, envelope.algorithm, envelope.key_id, owner)
                plaintext = AESGCM(key).decrypt(decode(envelope.nonce), decode(envelope.ciphertext), aad)
                text = plaintext.decode("utf-8")
            except (InvalidTag, UnicodeError, ValueError) as exc:
                self.metrics.increment("aes_decrypt_failure")
                raise DecryptionError() from exc
            result = DecryptResponse(operation_id=uuid4(), text=text)
            self.metrics.increment("aes_decrypt_success")
            return result
        finally:
            self.slots.release()


service = CryptoService()
