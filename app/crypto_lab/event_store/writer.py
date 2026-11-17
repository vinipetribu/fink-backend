"""Lifecycle-managed writer for the bounded event queue."""
from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import AsyncEngine

from app.crypto_lab.event_store.queue import EventQueue


class EventWriter:
    """Flush one bounded batch per tick without blocking request handlers."""

    def __init__(self, queue: EventQueue, engine: AsyncEngine, interval: float = 0.5):
        if interval <= 0:
            raise ValueError('Invalid interval')
        self.queue = queue
        self.engine = engine
        self.interval = interval
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is not None:
            raise RuntimeError('Writer already started')
        self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        while not self._stop.is_set():
            await self.queue.flush(self.engine)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass
        # One final bounded flush; remaining queued events are lost on shutdown.
        await self.queue.flush(self.engine)

    async def close(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        await self._task
        self._task = None
