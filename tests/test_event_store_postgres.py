"""Isolated PostgreSQL integration; refuses any non-disposable database URL.

The test applies only the new migration via Alembic Operations on an empty,
private database. It never runs the earlier password transformation migration.
"""
import asyncio
import importlib
import os
import unittest
from datetime import datetime, timezone

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.crypto_lab.event_store.queue import Event, EventQueue
from app.crypto_lab.event_store.writer import EventWriter

TEST_URL = 'postgresql+asyncpg://labtest:labtest@lab-disposable:5432/lab_disposable'


class EventStorePostgres(unittest.IsolatedAsyncioTestCase):
    async def test_queue_writer_and_select(self):
        if os.environ.get('LAB_DISPOSABLE_DATABASE_URL') != TEST_URL:
            self.skipTest('Exact disposable database URL is required')
        engine = create_async_engine(TEST_URL)
        try:
            async with engine.begin() as connection:
                identity = (await connection.execute(text('SELECT current_database(), current_user'))).one()
                self.assertEqual(tuple(identity), ('lab_disposable', 'labtest'))
                existing = (await connection.execute(text("SELECT to_regclass('public.lab_events')"))).scalar()
                self.assertIsNone(existing, 'Disposable test database must be empty')

                def apply_migration(sync_connection):
                    migration = importlib.import_module('migrations.versions.20261117_secureai_events')
                    with Operations.context(MigrationContext.configure(sync_connection)):
                        migration.upgrade()

                await connection.run_sync(apply_migration)

            queue = EventQueue(capacity=2)
            writer = EventWriter(queue, engine, interval=0.05)
            writer.start()
            timestamp = datetime(2026, 11, 17, 12, tzinfo=timezone.utc)
            self.assertTrue(queue.submit(Event(
                origin='synthetic', event_type='AES_ENCRYPT',
                operation='/api/v1/crypto-lab/encrypt', result='SUCCESS',
                occurred_at=timestamp, duration_ms=12.5,
            )))
            row = None
            for _ in range(100):
                async with engine.connect() as connection:
                    row = (await connection.execute(text(
                        'SELECT origin, event_type, operation, result, occurred_at, duration_ms, run_id '
                        'FROM lab_events'
                    ))).mappings().first()
                if row:
                    break
                await asyncio.sleep(0.05)
            await writer.close()
            self.assertIsNotNone(row)
            self.assertEqual(dict(row), {
                'origin': 'synthetic', 'event_type': 'AES_ENCRYPT',
                'operation': '/api/v1/crypto-lab/encrypt', 'result': 'SUCCESS',
                'occurred_at': timestamp, 'duration_ms': 12.5, 'run_id': None,
            })
            self.assertEqual(queue.dropped, 0)
        finally:
            await engine.dispose()
