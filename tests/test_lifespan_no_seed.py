import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.main import lifespan
from app.core.settings import settings


class LifespanNoSeedTest(unittest.IsolatedAsyncioTestCase):
    async def test_local_seed_disabled_writer_lifecycle(self):
        app = SimpleNamespace(state=SimpleNamespace())
        writer = SimpleNamespace(start=unittest.mock.Mock(), close=AsyncMock())
        with patch.object(settings, 'environment', 'development'), \
             patch.object(settings, 'disable_local_seed', True), \
             patch.object(settings, 'disable_local_create_all', True), \
             patch.object(settings, 'crypto_lab_enabled', True), \
             patch.object(settings, 'crypto_lab_event_store_enabled', True), \
             patch.object(settings, 'debug', False), \
             patch.object(settings, 'pluggy_enabled', False), \
             patch('app.main.init_db', new_callable=AsyncMock) as init_db, \
             patch('app.main.seed_db', new_callable=AsyncMock) as seed, \
             patch('app.crypto_lab.middleware.compatible_workers', return_value=True), \
             patch('app.crypto_lab.event_store.writer.EventWriter', return_value=writer):
            async with lifespan(app):
                init_db.assert_awaited_once_with(create_all=False)
                seed.assert_not_awaited()
                writer.start.assert_called_once()
                self.assertIs(app.state.lab_event_writer, writer)
            writer.close.assert_awaited_once()
