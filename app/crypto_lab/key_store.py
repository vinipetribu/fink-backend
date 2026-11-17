"""Bounded process-local key storage with atomic expiry and ownership checks."""

from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Callable
from uuid import UUID

from app.crypto_lab.errors import CapacityError


@dataclass(frozen=True, repr=False)
class KeyRecord:
    key: bytes
    owner: UUID
    expires_at: float


class KeyStore:
    def __init__(self, capacity: int = 500, ttl: float = 3600, clock: Callable[[], float] = monotonic):
        self._capacity = capacity
        self._ttl = ttl
        self._clock = clock
        self._records: dict[UUID, KeyRecord] = {}
        self._lock = Lock()

    def _purge(self, now: float) -> None:
        for key_id in [key_id for key_id, record in self._records.items() if record.expires_at <= now]:
            del self._records[key_id]

    def add(self, key_id: UUID, owner: UUID, key: bytes) -> None:
        with self._lock:
            now = self._clock()
            self._purge(now)
            if len(self._records) >= self._capacity:
                raise CapacityError()
            if key_id in self._records:
                raise ValueError("Identifier collision")
            self._records[key_id] = KeyRecord(key, owner, now + self._ttl)

    def get(self, key_id: UUID, owner: UUID) -> bytes | None:
        with self._lock:
            self._purge(self._clock())
            record = self._records.get(key_id)
            return record.key if record is not None and record.owner == owner else None

    def discard(self, key_id: UUID, owner: UUID, key: bytes) -> None:
        """Roll back only the exact record inserted by the current operation."""
        with self._lock:
            record = self._records.get(key_id)
            if record is not None and record.owner == owner and record.key == key:
                del self._records[key_id]
