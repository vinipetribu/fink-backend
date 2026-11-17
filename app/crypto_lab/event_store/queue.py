"""Bounded, non-blocking admission of sanitized laboratory events.

The queue is process-local and can lose events on shutdown or database failure.
Its lifecycle is deliberately independent of authentication and crypto services.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from queue import Empty, Full, Queue
from threading import Lock
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


EVENT_TYPES = frozenset({
    'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'ACCESS_DENIED', 'ADMIN_ACCESS',
    'AES_ENCRYPT', 'AES_DECRYPT', 'TOY_ENCRYPT', 'TOY_DECRYPT',
    'STEGO_EMBED', 'STEGO_EXTRACT', 'ATTACK_RUN', 'ANOMALY_RUN',
})
RESULTS = frozenset({'SUCCESS', 'FAILURE', 'DENIED', 'ALLOWED', 'TIMEOUT'})
ORIGINS = frozenset({'observed', 'synthetic'})
OPERATIONS = frozenset({
    '/api/v1/sessoes/login', '/api/v1/crypto-lab/encrypt',
    '/api/v1/crypto-lab/decrypt', '/api/v1/crypto-lab/experimental/run',
    '/api/v1/crypto-lab/steganography/embed', '/api/v1/crypto-lab/steganography/extract',
    '/api/v1/crypto-lab/attacks/runs', '/api/v1/crypto-lab/anomalies/runs',
    '<security-route>',
})


@dataclass(frozen=True)
class Event:
    origin: str
    event_type: str
    operation: str
    result: str
    occurred_at: datetime
    duration_ms: float | None = None


class EventQueue:
    """Collect only explicit, predefined fields with a bounded memory budget."""

    def __init__(self, capacity: int = 1000):
        self._queue: Queue[Event] = Queue(maxsize=capacity)
        self._lock = Lock()
        self._dropped = 0

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    def _discard(self, count: int) -> None:
        with self._lock:
            self._dropped += count

    def submit(self, event: Event) -> bool:
        if (event.origin not in ORIGINS or event.event_type not in EVENT_TYPES
                or event.operation not in OPERATIONS or event.result not in RESULTS
                or event.occurred_at.tzinfo is None
                or (event.duration_ms is not None and not 0 <= event.duration_ms <= 120000)):
            self._discard(1)
            return False
        try:
            self._queue.put_nowait(event)
        except Full:
            self._discard(1)
            return False
        return True

    async def flush(self, engine: AsyncEngine, *, batch_size: int = 100, timeout: float = 2.0) -> int:
        """Write a bounded batch; count failures without propagating database errors."""
        if not 1 <= batch_size <= 100 or not 0 < timeout <= 2:
            raise ValueError('Invalid batch limits')
        batch = []
        for _ in range(batch_size):
            try:
                event = self._queue.get_nowait()
            except Empty:
                break
            batch.append({
                'id': uuid4(), 'occurred_at': event.occurred_at.astimezone(timezone.utc),
                'origin': event.origin, 'event_type': event.event_type,
                'operation': event.operation, 'result': event.result,
                'duration_ms': event.duration_ms, 'run_id': None,
            })
        if not batch:
            return 0
        try:
            async with asyncio.timeout(timeout):
                async with engine.begin() as connection:
                    await connection.execute(text(
                        'INSERT INTO lab_events '
                        '(id, occurred_at, origin, event_type, operation, result, duration_ms, run_id) '
                        'VALUES (:id, :occurred_at, :origin, :event_type, :operation, :result, :duration_ms, :run_id)'
                    ), batch)
        except Exception:
            self._discard(len(batch))
            return 0
        return len(batch)
