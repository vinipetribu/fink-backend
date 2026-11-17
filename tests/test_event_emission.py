"""Targeted checks for sanitized, optional event admission."""
import unittest
from types import SimpleNamespace
from datetime import datetime, timezone
from unittest.mock import patch
from starlette.requests import Request
from app.core import security_logging
from app.core.settings import settings
from app.crypto_lab.event_store import emitter
from app.crypto_lab.event_store.queue import Event, EventQueue
from app.crypto_lab.middleware import CryptoLabMiddleware
from app.crypto_lab.attacks.runner import Coordinator
from app.crypto_lab import routes
from app.crypto_lab.schemas import ToyEncryptRequest


class EventEmissionTests(unittest.TestCase):
    def test_security_event_preserves_existing_buffer_and_sanitizes(self):
        queue = EventQueue()
        request = Request({'type': 'http', 'method': 'POST', 'path': '/secret', 'headers': []})
        with patch.object(emitter, 'events', queue), patch.object(settings, 'crypto_lab_enabled', True), \
             patch.object(settings, 'crypto_lab_event_store_enabled', True), patch.object(settings, 'environment', 'test'), \
             patch.object(settings, 'debug', False):
            security_logging.log_security_event('LOGIN_FAILURE', 'FAILURE', request)
        event = queue._queue.get_nowait()
        self.assertEqual((event.event_type, event.operation, event.result),
                         ('LOGIN_FAILURE', '/api/v1/sessoes/login', 'FAILURE'))
        self.assertNotIn('/secret', repr(event))
        self.assertEqual(security_logging.get_security_logs()[0]['event'], 'LOGIN_FAILURE')

    def test_disabled_and_fail_open(self):
        queue = EventQueue()
        with patch.object(emitter, 'events', queue), patch.object(settings, 'crypto_lab_event_store_enabled', False):
            emitter.emit('AES_ENCRYPT', '/api/v1/crypto-lab/encrypt', 'SUCCESS')
        self.assertTrue(queue._queue.empty())
        with patch.object(emitter, 'events', queue), patch.object(settings, 'crypto_lab_enabled', True), \
             patch.object(settings, 'crypto_lab_event_store_enabled', True), patch.object(settings, 'environment', 'test'), \
             patch.object(settings, 'debug', False), patch.object(queue, 'submit', side_effect=RuntimeError):
            emitter.emit('AES_ENCRYPT', '/api/v1/crypto-lab/encrypt', 'SUCCESS')

    def test_capacity_drops(self):
        queue = EventQueue(capacity=1)
        event = Event('observed', 'AES_ENCRYPT', '/api/v1/crypto-lab/encrypt', 'SUCCESS', datetime.now(timezone.utc))
        self.assertTrue(queue.submit(event))
        self.assertFalse(queue.submit(event))
        self.assertEqual(queue.dropped, 1)

    def test_all_security_categories(self):
        queue = EventQueue()
        request = Request({'type': 'http', 'method': 'GET', 'path': '/private-value', 'headers': []})
        cases = [('LOGIN_SUCCESS', 'SUCCESS'), ('LOGIN_FAILURE', 'FAILURE'),
                 ('ACCESS_DENIED', 'DENIED'), ('ADMIN_ACCESS', 'ALLOWED')]
        with patch.object(emitter, 'events', queue), patch.object(settings, 'crypto_lab_enabled', True), \
             patch.object(settings, 'crypto_lab_event_store_enabled', True), patch.object(settings, 'environment', 'test'), \
             patch.object(settings, 'debug', False):
            for kind, result in cases:
                security_logging.log_security_event(kind, result, request, user_id='private-value')
        for kind, result in cases:
            event = queue._queue.get_nowait()
            self.assertEqual((event.event_type, event.result), (kind, result))
            self.assertNotIn('private-value', repr(event))


class OperationEmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_database_failure_counts_discard(self):
        queue = EventQueue()
        queue.submit(Event('observed', 'AES_ENCRYPT', '/api/v1/crypto-lab/encrypt',
                           'SUCCESS', datetime.now(timezone.utc)))
        engine = SimpleNamespace(begin=lambda: (_ for _ in ()).throw(RuntimeError('offline')))
        self.assertEqual(await queue.flush(engine), 0)
        self.assertEqual(queue.dropped, 1)

    async def test_crypto_http_outcomes(self):
        cases = [('encrypt', 'AES_ENCRYPT'), ('decrypt', 'AES_DECRYPT'),
                 ('steganography/embed', 'STEGO_EMBED'), ('steganography/extract', 'STEGO_EXTRACT')]
        for suffix, kind in cases:
            for status, result in ((200, 'SUCCESS'), (400, 'FAILURE')):
                async def app(scope, receive, send):
                    await send({'type': 'http.response.start', 'status': status, 'headers': []})
                    await send({'type': 'http.response.body', 'body': b'ok'})

                async def receive():
                    return {'type': 'http.request', 'body': b'{}'}

                sent = []
                async def send(message):
                    sent.append(message)

                path = '/api/v1/crypto-lab/' + suffix
                config = SimpleNamespace(environment='test', crypto_lab_enabled=True, debug=False,
                                         crypto_lab_workers=1, crypto_lab_instances=1)
                with patch.object(emitter, 'emit') as emit:
                    await CryptoLabMiddleware(app, config)({'type': 'http', 'method': 'POST', 'path': path}, receive, send)
                emit.assert_called_once_with(kind, path, result)
                self.assertEqual(sent[0]['status'], status)

    async def test_toy_operation_and_queue_failure(self):
        body = ToyEncryptRequest(action='encrypt', text='synthetic')
        user = SimpleNamespace(id_pessoa='synthetic-owner')
        with patch.object(settings, 'crypto_lab_experimental_enabled', True), \
             patch.object(routes.toy_service, 'encrypt', return_value={'ok': True}), \
             patch.object(emitter, 'emit') as emit:
            result = await routes.run_experiment(body, user)
        self.assertEqual(result, {'ok': True})
        emit.assert_called_once_with('TOY_ENCRYPT', '/api/v1/crypto-lab/experimental/run', 'SUCCESS')

    async def test_attack_start_and_cancelled_terminal(self):
        coordinator = Coordinator()
        with patch('app.crypto_lab.attacks.runner.sys.platform', 'linux'), patch.object(emitter, 'emit') as emit:
            coordinator.start('owner', 'statistics', 10)
            await coordinator.close()
        self.assertEqual([call.args[2] for call in emit.call_args_list], ['ALLOWED', 'FAILURE'])
        self.assertTrue(all(call.kwargs == {'origin': 'synthetic'} for call in emit.call_args_list))
