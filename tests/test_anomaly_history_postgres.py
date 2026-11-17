"""History integration: only an explicitly identified disposable PostgreSQL."""
import asyncio
import importlib
import json
import os
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import UUID

import httpx
from alembic.migration import MigrationContext
from alembic.operations import Operations
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.deps import get_db, get_sessao_service
from app.core.settings import settings
from app.crypto_lab.anomaly_lab import history
from app.crypto_lab.anomaly_lab.routes import router
from app.crypto_lab.anomaly_lab.runner import Coordinator

URL = 'postgresql+asyncpg://labtest:labtest@lab-disposable:5432/lab_disposable'
PAYLOAD = {'profile': 'synthetic-security-v1', 'event_count': 21,
           'partition_sizes': {'train': 4, 'calibration': 2, 'validation': 2, 'test': 2},
           'library_versions': {'scikit_learn': 'test', 'numpy': 'test'},
           'model_parameters': {'n_estimators': 100},
           'baseline': {'center': 'median', 'scale': 'MAD'},
           'methods': {'isolation_forest': {'partitions': {'test': {'TP': 1, 'families': {
               'login_failures': {'support': 1, 'detected': 1}}}}}},
           'rows': [{'secret': 'must-not-persist'}]}


class HistoryIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        if os.environ.get('LAB_DISPOSABLE_DATABASE_URL') != URL:
            self.skipTest('Exact disposable database URL required')
        self.engine = create_async_engine(URL)
        async with self.engine.begin() as conn:
            self.assertEqual(tuple((await conn.execute(text('SELECT current_database(), current_user'))).one()),
                             ('lab_disposable', 'labtest'))
            self.assertIsNone((await conn.execute(text("SELECT to_regclass('public.lab_anomaly_runs')"))).scalar())
            def migrate(c):
                with Operations.context(MigrationContext.configure(c)):
                    importlib.import_module('migrations.versions.20261117_secureai_events').upgrade()
            await conn.run_sync(migrate)
        self.patches = [patch.object(settings, 'crypto_lab_enabled', True),
                        patch.object(settings, 'crypto_lab_anomaly_enabled', True),
                        patch.object(settings, 'crypto_lab_event_store_enabled', True),
                        patch.object(settings, 'environment', 'test'), patch.object(settings, 'debug', False),
                        patch.object(history, 'engine', self.engine)]
        for item in self.patches: item.start()
        self.maker = async_sessionmaker(self.engine, expire_on_commit=False)

    async def asyncTearDown(self):
        if hasattr(self, 'patches'):
            for item in reversed(self.patches): item.stop()
            await self.engine.dispose()

    def app(self):
        app = FastAPI()
        app.include_router(router)
        async def db():
            async with self.maker() as session: yield session
        async def service():
            async def validate(token): return SimpleNamespace(fk_pessoa_id_pessoa=token)
            async def user(token): return SimpleNamespace(id_pessoa=token, admin=token == 'admin')
            return SimpleNamespace(validar=validate, pessoa_repo=SimpleNamespace(get_by_id=user))
        app.dependency_overrides[get_db] = db
        app.dependency_overrides[get_sessao_service] = service
        return app

    async def test_terminal_persistence_http_and_restart(self):
        c = Coordinator()
        c.datasets['dataset'] = {'owner': 'owner', 'data': b'{}'}
        process = SimpleNamespace(returncode=0, communicate=AsyncMock(return_value=(json.dumps(PAYLOAD).encode(), b'')),
                                  wait=AsyncMock())
        with patch('app.crypto_lab.anomaly_lab.runner.sys.platform', 'linux'), \
             patch('app.crypto_lab.anomaly_lab.runner.os.path.exists', return_value=True), \
             patch('app.crypto_lab.anomaly_lab.runner.asyncio.create_subprocess_exec', new=AsyncMock(return_value=process)):
            job_id = c.start('owner', 'run', 20, 'dataset')['job_id']
            await c.task
            await c.close()
        job = c.jobs[job_id]
        self.assertEqual(job['status'], 'completed')
        self.assertIn(job['result_id'], c.results)
        async with self.engine.connect() as conn:
            row = (await conn.execute(text('SELECT * FROM lab_anomaly_runs WHERE id = :id'), {'id': UUID(job_id)})).mappings().one()
        self.assertEqual(row['state'], 'completed')
        self.assertEqual(row['processed_volume'], 10)
        self.assertEqual(row['metrics']['event_count'], 21)
        self.assertEqual(row['metrics']['methods']['isolation_forest']['partitions']['test']['TP'], 1)
        self.assertEqual(row['metrics']['methods']['isolation_forest']['partitions']['test']['families']['login_failures']['detected'], 1)
        self.assertNotIn('must-not-persist', str(row))
        self.assertTrue(await history.persist(job_id, 'completed', row['started_at'], row['finished_at'], PAYLOAD, db_engine=self.engine))
        async with self.engine.connect() as conn:
            self.assertEqual((await conn.execute(text('SELECT count(*) FROM lab_anomaly_runs'))).scalar(), 1)
        # New FastAPI instance and client, same database, as after application restart.
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app()), base_url='http://test') as client:
            path = '/api/v1/crypto-lab/anomalies/history'
            self.assertEqual((await client.get(path)).status_code, 401)
            self.assertEqual((await client.get(path, headers={'Authorization': 'Bearer user'})).status_code, 403)
            response = await client.get(path, headers={'Authorization': 'Bearer admin'}, params={'state': 'completed'})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()['items'][0]['id'], job_id)
            self.assertEqual(response.json()['items'][0]['metrics']['event_count'], 21)
            self.assertEqual((await client.get(path, headers={'Authorization': 'Bearer admin'}, params={'state': 'failed'})).json()['items'], [])
            with patch.object(settings, 'crypto_lab_event_store_enabled', False):
                self.assertEqual((await client.get(path, headers={'Authorization': 'Bearer admin'})).status_code, 503)
        broken = SimpleNamespace(begin=lambda: (_ for _ in ()).throw(RuntimeError('database offline')))
        self.assertFalse(await history.persist(job_id, 'completed', row['started_at'], row['finished_at'], PAYLOAD, db_engine=broken))
        self.assertEqual(c.results[job['result_id']]['result'], PAYLOAD)
        second = Coordinator()
        second.datasets['dataset'] = {'owner': 'owner', 'data': b'{}'}
        with patch.object(history, 'engine', broken), \
             patch('app.crypto_lab.anomaly_lab.runner.sys.platform', 'linux'), \
             patch('app.crypto_lab.anomaly_lab.runner.os.path.exists', return_value=True), \
             patch('app.crypto_lab.anomaly_lab.runner.asyncio.create_subprocess_exec', new=AsyncMock(return_value=process)):
            second_id = second.start('owner', 'run', 20, 'dataset')['job_id']
            await second.task
            await second.close()
        self.assertEqual(second.jobs[second_id]['status'], 'completed')
        self.assertEqual(second.results[second.jobs[second_id]['result_id']]['result'], PAYLOAD)
