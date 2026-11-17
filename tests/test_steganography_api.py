"""HTTP authorization, limits, integration and regression for PNG steganography."""

import base64
import json
import os
import random
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from app.api import deps
from app.core.settings import settings
from app.crypto_lab import routes
from app.crypto_lab.aes_service import CryptoService
from app.crypto_lab.envelope import encode
from app.crypto_lab.steganography import decode_png, encode_png
from app.crypto_lab.toy_cipher import ToyService
from app.main import app
from tests.test_security_logs import FakeAuthService
from tests.test_steganography_unit import make_png

BASE = '/api/v1/crypto-lab'
USER = {'Authorization': 'Bearer local-user-token'}
ADMIN = {'Authorization': 'Bearer local-admin-token'}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, 'environment', 'development')
    monkeypatch.setattr(settings, 'debug', False)
    monkeypatch.setattr(settings, 'crypto_lab_enabled', True)
    monkeypatch.setattr(settings, 'crypto_lab_experimental_enabled', True)
    monkeypatch.setattr(settings, 'crypto_lab_workers', 1)
    monkeypatch.setattr(settings, 'crypto_lab_instances', 1)
    for name in ('WEB_CONCURRENCY', 'UVICORN_WORKERS', 'GUNICORN_CMD_ARGS'):
        monkeypatch.delenv(name, raising=False)
    aes = CryptoService()
    monkeypatch.setattr(routes, 'service', aes)
    monkeypatch.setattr(routes, 'toy_service', ToyService(aes.metrics))
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[deps.get_sessao_service] = lambda: FakeAuthService()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides = previous


def encrypted(client):
    response = client.post(BASE + '/encrypt', headers=USER, json={'text': 'despesa fictícia 💳'})
    assert response.status_code == 200
    return response.json()['envelope']


def embed_body(client, color=2):
    return {'image_png': encode(make_png(128, 128, color)), 'envelope': encrypted(client)}


@pytest.mark.parametrize('color', [2, 6])
def test_end_to_end_with_auth_and_image(client, color):
    data = embed_body(client, color)
    response = client.post(BASE + '/steganography/embed', headers=USER, json=data)
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    image = response.json()['image_png']
    assert 'despesa fictícia' not in response.text
    if color == 6:
        before, after = decode_png(base64.b64decode(data['image_png'])), decode_png(base64.b64decode(image))
        assert before.pixels[3::4] == after.pixels[3::4]
    recovered = client.post(BASE + '/steganography/extract', headers=USER, json={'image_png': image})
    assert recovered.status_code == 200
    assert recovered.headers['cache-control'] == 'no-store'
    assert recovered.json()['envelope'] == data['envelope']
    plain = client.post(BASE + '/decrypt', headers=USER, json=recovered.json())
    assert plain.status_code == 200
    assert plain.json()['text'] == 'despesa fictícia 💳'
    other = client.post(BASE + '/steganography/extract', headers=ADMIN, json={'image_png': image})
    assert other.status_code == 400
    assert 'envelope' not in other.json()
    assert client.post(BASE + '/steganography/embed', headers=ADMIN, json=data).status_code == 400


def test_auth_and_runtime_flags(client, monkeypatch):
    data = embed_body(client)
    assert client.post(BASE + '/steganography/embed', json=data).status_code == 401
    assert client.post(BASE + '/steganography/extract', json={'image_png': data['image_png']}).status_code == 401
    monkeypatch.setattr(settings, 'crypto_lab_enabled', False)
    assert client.post(BASE + '/steganography/embed', headers=USER, json=data).status_code == 503
    monkeypatch.setattr(settings, 'crypto_lab_enabled', True)
    monkeypatch.setattr(settings, 'environment', 'production')
    assert client.post(BASE + '/steganography/extract', headers=USER, json={'image_png': data['image_png']}).status_code == 404


def test_invalid_input_capacity_and_payload_tampering(client):
    data = embed_body(client)
    for image in ('@@@@', encode(b'not a png'), encode(make_png(2, 2)), encode(make_png(257, 1))):
        response = client.post(BASE + '/steganography/embed', headers=USER, json={**data, 'image_png': image})
        assert response.status_code in (400, 422)
        assert response.headers['cache-control'] == 'no-store'
    data['image_png'] = encode(make_png(128, 128))
    result = client.post(BASE + '/steganography/embed', headers=USER, json=data).json()
    raster = decode_png(base64.b64decode(result['image_png']))
    raster.pixels[400] ^= 1
    response = client.post(BASE + '/steganography/extract', headers=USER,
                           json={'image_png': encode(encode_png(raster))})
    assert response.status_code == 400
    assert response.headers['cache-control'] == 'no-store'


def test_body_limits_do_not_relax_other_endpoints(client):
    oversized = b'{"image_png":"' + b'A' * 1420000 + b'"}'
    assert client.post(BASE + '/steganography/extract', headers=USER, content=oversized).status_code == 413
    assert client.post(BASE + '/encrypt', headers=USER, content=b' ' * 16385).status_code == 413
    pixels = random.Random(42).randbytes(128 * 128 * 3)
    valid_but_large = {'image_png': encode(make_png(128, 128, pixels=pixels)), 'envelope': encrypted(client)}
    assert len(json.dumps(valid_but_large)) > 16384
    assert client.post(BASE + '/steganography/embed', headers=USER, json=valid_but_large).status_code == 200


def test_redacted_logs_and_validation(client, caplog):
    from app.core.security_logging import logger
    body = embed_body(client)
    logger.addHandler(caplog.handler)
    try:
        invalid = client.post(BASE + '/steganography/embed', headers=USER,
                              json={**body, 'secret_extra': 'extra-secret-abc'})
        result = client.post(BASE + '/steganography/embed', headers=USER, json=body)
    finally:
        logger.removeHandler(caplog.handler)
    assert invalid.status_code == 422 and result.status_code == 200
    for sensitive in ('extra-secret-abc', body['image_png'], body['envelope']['ciphertext'], 'local-user-token'):
        assert sensitive not in caplog.text + invalid.text


def test_toy_cipher_remains_independent(client):
    toy = client.post(BASE + '/experimental/run', headers=ADMIN, json={'action': 'encrypt', 'text': 'toy'})
    assert toy.status_code == 200
    toy = toy.json()
    body = embed_body(client)
    assert client.post(BASE + '/steganography/embed', headers=USER, json=body).status_code == 200
    decrypt = client.post(BASE + '/experimental/run', headers=ADMIN,
                          json={'action': 'decrypt', 'key_id': toy['key_id'], 'ciphertext': toy['ciphertext']})
    assert decrypt.status_code == 200 and decrypt.json()['text'] == 'toy'


def test_routes_not_registered_in_production():
    env = {**os.environ, 'ENVIRONMENT': 'production', 'DEBUG': 'false', 'CRYPTO_LAB_ENABLED': 'true'}
    code = "from app.main import app; assert not any('/steganography/' in r.path for r in app.routes)"
    result = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


@pytest.mark.asyncio
async def test_streamed_stego_body_without_content_length_is_limited():
    from types import SimpleNamespace
    from app.crypto_lab.middleware import CryptoLabMiddleware, MAX_STEGO_BODY

    async def inner(scope, receive, send):
        raise AssertionError('Oversized body reached the application')

    config = SimpleNamespace(environment='development', crypto_lab_enabled=True, debug=False,
                             crypto_lab_workers=1, crypto_lab_instances=1)
    boundary = CryptoLabMiddleware(inner, config)
    messages = iter([
        {'type': 'http.request', 'body': b'x' * 1000000, 'more_body': True},
        {'type': 'http.request', 'body': b'x' * (MAX_STEGO_BODY - 999999), 'more_body': False},
    ])
    sent = []
    async def receive():
        return next(messages)
    async def send(message):
        sent.append(message)
    await boundary({'type': 'http', 'path': BASE + '/steganography/extract', 'method': 'POST', 'headers': []},
                   receive, send)
    assert sent[0]['status'] == 413
    assert (b'cache-control', b'no-store') in sent[0]['headers']
