"""Disposable PostgreSQL only: ingestion, SQL summary and real AES event."""
import importlib
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID

import httpx
from alembic.migration import MigrationContext
from alembic.operations import Operations
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.deps import get_db, get_sessao_service
from app.core.settings import settings
from app.crypto_lab.event_store import emitter
from app.crypto_lab.event_store.ingestion import router as ingestion_router
from app.crypto_lab.event_store.queue import EventQueue
from app.crypto_lab.event_store.routes import router as event_router
from app.crypto_lab.event_store.writer import EventWriter
from app.crypto_lab.middleware import CryptoLabMiddleware
from app.crypto_lab.routes import router as crypto_router

URL = 'postgresql+asyncpg://labtest:labtest@lab-disposable:5432/lab_disposable'


class SyntheticIngestionIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_ingestion_and_real_crypto(self):
        if os.environ.get('LAB_DISPOSABLE_DATABASE_URL') != URL:
            self.skipTest('Exact disposable database URL required')
        engine = create_async_engine(URL)
        try:
            async with engine.begin() as conn:
                self.assertEqual(tuple((await conn.execute(text('SELECT current_database(), current_user'))).one()),
                                 ('lab_disposable', 'labtest'))
                self.assertIsNone((await conn.execute(text("SELECT to_regclass('public.lab_events')"))).scalar())
                def migrate(c):
                    with Operations.context(MigrationContext.configure(c)):
                        importlib.import_module('migrations.versions.20261117_secureai_events').upgrade()
                await conn.run_sync(migrate)
            maker = async_sessionmaker(engine, expire_on_commit=False)
            app = FastAPI()
            app.include_router(event_router)
            app.include_router(ingestion_router)
            app.include_router(crypto_router)
            app.add_middleware(CryptoLabMiddleware, settings=settings)
            async def db():
                async with maker() as session: yield session
            async def service():
                async def validate(token): return SimpleNamespace(fk_pessoa_id_pessoa=token)
                async def user(token): return SimpleNamespace(id_pessoa=UUID(int=1), admin=token == 'admin')
                return SimpleNamespace(validar=validate, pessoa_repo=SimpleNamespace(get_by_id=user))
            app.dependency_overrides[get_db] = db
            app.dependency_overrides[get_sessao_service] = service
            queue = EventQueue()
            patches = [patch.object(settings, 'crypto_lab_enabled', True),
                       patch.object(settings, 'crypto_lab_event_store_enabled', True),
                       patch.object(settings, 'environment', 'test'), patch.object(settings, 'debug', False),
                       patch.object(emitter, 'events', queue)]
            for item in patches: item.start()
            try:
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
                    path = '/api/v1/crypto-lab/events/synthetic-ingestions'
                    self.assertEqual((await client.post(path, json={'count': 1})).status_code, 401)
                    self.assertEqual((await client.post(path, json={'count': 1}, headers={'Authorization': 'Bearer user'})).status_code, 403)
                    admin = {'Authorization': 'Bearer admin'}
                    self.assertEqual((await client.post(path, json={'count': 10001}, headers=admin)).status_code, 422)
                    self.assertEqual((await client.post(path, json={'count': 1, 'plaintext': 'secret'}, headers=admin)).status_code, 422)
                    response = await client.post(path, json={'count': 600}, headers=admin)
                    self.assertEqual(response.status_code, 200, response.text)
                    report = response.json()
                    self.assertEqual((report['status'], report['requested'], report['generated'],
                                      report['persisted_confirmed'], report['failed_or_unconfirmed']),
                                     ('completed', 600, 600, 600, 0))
                    summary = await client.get('/api/v1/crypto-lab/events/summary', headers=admin, params={'origin': 'synthetic'})
                    self.assertEqual(summary.status_code, 200)
                    self.assertEqual(summary.json()['total'], 600)
                    self.assertEqual(summary.json()['by_type'], {'LOGIN_SUCCESS': 150, 'LOGIN_FAILURE': 150,
                                                                 'ACCESS_DENIED': 150, 'ADMIN_ACCESS': 150})
                    aes = await client.post('/api/v1/crypto-lab/encrypt', headers=admin, json={'text': 'fake-sensitive-marker'})
                    self.assertEqual(aes.status_code, 200, aes.text)
                    self.assertEqual(aes.json()['envelope']['algorithm'], 'AES-256-GCM')
                writer = EventWriter(queue, engine, interval=0.01)
                writer.start()
                await writer.close()
                # A fresh engine opens a new connection to confirm durability.
                fresh = create_async_engine(URL)
                try:
                    async with fresh.connect() as conn:
                        synthetic = (await conn.execute(text("SELECT count(*) FROM lab_events WHERE origin='synthetic'"))).scalar()
                        aes_rows = (await conn.execute(text("SELECT origin,event_type,operation,result FROM lab_events WHERE event_type='AES_ENCRYPT'"))).mappings().all()
                        leaked = (await conn.execute(text("SELECT count(*) FROM lab_events WHERE operation LIKE '%fake-sensitive-marker%'"))).scalar()
                    self.assertEqual(synthetic, 600)
                    self.assertEqual([dict(row) for row in aes_rows], [{'origin': 'observed', 'event_type': 'AES_ENCRYPT',
                                       'operation': '/api/v1/crypto-lab/encrypt', 'result': 'SUCCESS'}])
                    self.assertEqual(leaked, 0)
                finally:
                    await fresh.dispose()
            finally:
                for item in reversed(patches): item.stop()
        finally:
            await engine.dispose()
