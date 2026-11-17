"""HTTP query integration against a strictly identified disposable database."""
import importlib
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
from app.crypto_lab.event_store.routes import router

URL = 'postgresql+asyncpg://labtest:labtest@lab-disposable:5432/lab_disposable'


class EventQueryIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        if os.environ.get('LAB_DISPOSABLE_DATABASE_URL') != URL:
            self.skipTest('Exact disposable database URL required')
        self.engine = create_async_engine(URL)
        async with self.engine.begin() as conn:
            identity = (await conn.execute(text('SELECT current_database(), current_user'))).one()
            self.assertEqual(tuple(identity), ('lab_disposable', 'labtest'))
            self.assertIsNone((await conn.execute(text("SELECT to_regclass('public.lab_events')"))).scalar())
            def migrate(c):
                migration = importlib.import_module('migrations.versions.20261117_secureai_events')
                with Operations.context(MigrationContext.configure(c)):
                    migration.upgrade()
            await conn.run_sync(migrate)
            for i, origin, kind, result, day in [
                (1, 'observed', 'AES_ENCRYPT', 'SUCCESS', 1),
                (2, 'synthetic', 'ATTACK_RUN', 'FAILURE', 1),
                (3, 'observed', 'AES_ENCRYPT', 'FAILURE', 2),
                (4, 'observed', 'AES_ENCRYPT', 'SUCCESS', 2),
            ]:
                await conn.execute(text('INSERT INTO lab_events (id, occurred_at, origin, event_type, operation, result) '
                                        'VALUES (:id,:ts,:origin,:kind,:operation,:result)'),
                                   {'id': UUID(int=i), 'ts': datetime(2026, 1, day, tzinfo=timezone.utc),
                                    'origin': origin, 'kind': kind, 'operation': '/api/v1/crypto-lab/encrypt', 'result': result})
        self.app = FastAPI()
        self.app.include_router(router)
        maker = async_sessionmaker(self.engine, expire_on_commit=False)
        async def db():
            async with maker() as session:
                yield session
        async def service():
            async def validate(token):
                return SimpleNamespace(fk_pessoa_id_pessoa=token)
            async def user(token):
                return SimpleNamespace(id_pessoa=token, admin=(token == 'admin'))
            return SimpleNamespace(validar=validate, pessoa_repo=SimpleNamespace(get_by_id=user))
        self.app.dependency_overrides[get_db] = db
        self.app.dependency_overrides[get_sessao_service] = service
        self.flag = patch.object(settings, 'crypto_lab_event_store_enabled', True)
        self.flag.start()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url='http://test')
        self.params = {'start': '2026-01-01T00:00:00Z', 'end': '2026-01-04T00:00:00Z'}
        self.headers = {'Authorization': 'Bearer admin'}

    async def asyncTearDown(self):
        if hasattr(self, 'client'):
            await self.client.aclose()
            self.flag.stop()
            await self.engine.dispose()

    async def test_queries_and_auth(self):
        path = '/api/v1/crypto-lab/events'
        self.assertEqual((await self.client.get(path)).status_code, 401)
        self.assertEqual((await self.client.get(path, headers={'Authorization': 'Bearer user'})).status_code, 403)
        self.assertEqual((await self.client.get(path + '/summary')).status_code, 401)
        self.assertEqual((await self.client.get(path + '/summary', headers={'Authorization': 'Bearer user'})).status_code, 403)
        first = await self.client.get(path, headers=self.headers, params=dict(self.params, limit=2))
        self.assertEqual(first.status_code, 200, first.text)
        body = first.json()
        self.assertEqual([x['id'] for x in body['items']], [str(UUID(int=4)), str(UUID(int=3))])
        second = (await self.client.get(path, headers=self.headers, params=dict(self.params, limit=2, cursor=body['next_cursor']))).json()
        self.assertEqual([x['id'] for x in second['items']], [str(UUID(int=2)), str(UUID(int=1))])
        self.assertIsNone(second['next_cursor'])
        for key, value, count in [('origin', 'synthetic', 1), ('event_type', 'AES_ENCRYPT', 3), ('result', 'FAILURE', 2)]:
            params = dict(self.params, **{key: value})
            listing = (await self.client.get(path, headers=self.headers, params=params)).json()
            summary = (await self.client.get(path + '/summary', headers=self.headers, params=params)).json()
            self.assertEqual(len(listing['items']), count)
            self.assertEqual(summary['total'], count)
            self.assertEqual(sum(summary['by_day_utc'].values()), count)
        summary = (await self.client.get(path + '/summary', headers=self.headers, params=self.params)).json()
        self.assertEqual(summary['by_origin'], {'observed': 3, 'synthetic': 1})
        self.assertEqual(summary['by_result'], {'SUCCESS': 2, 'FAILURE': 2})
        self.assertEqual(summary['by_day_utc'], {'2026-01-01': 2, '2026-01-02': 2})
        one_day = {'start': '2026-01-02T00:00:00Z', 'end': '2026-01-03T00:00:00Z'}
        self.assertEqual((await self.client.get(path + '/summary', headers=self.headers, params=one_day)).json()['total'], 2)
        with patch.object(settings, 'crypto_lab_event_store_enabled', False):
            self.assertEqual((await self.client.get(path, headers=self.headers)).status_code, 503)
        for params in [dict(self.params, cursor='not-a-cursor'), dict(self.params, limit=101),
                       dict(self.params, origin='bad'), dict(self.params, event_type='bad'),
                       {'start': '2026-01-01T00:00:00', 'end': '2026-01-02T00:00:00Z'},
                       {'start': '2026-01-01T00:00:00Z', 'end': '2026-03-01T00:00:00Z'}]:
            self.assertEqual((await self.client.get(path, headers=self.headers, params=params)).status_code, 422)
        async def broken_db():
            yield SimpleNamespace(execute=AsyncMock(side_effect=RuntimeError('secret-database-password')))
        self.app.dependency_overrides[get_db] = broken_db
        response = await self.client.get(path, headers=self.headers, params=self.params)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('secret-database-password', response.text)
