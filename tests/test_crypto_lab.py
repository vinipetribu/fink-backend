"""Local AES lab contracts, isolation and failure handling."""

import base64
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from app.api import deps
from app.core.settings import settings
from app.crypto_lab import aes_service
from app.crypto_lab.aes_service import CryptoService
from app.crypto_lab.envelope import make_aad
from app.crypto_lab.errors import CapacityError, DecryptionError
from app.crypto_lab.key_store import KeyStore
from app.main import app
from tests.test_security_logs import FakeAuthService
from tests.test_security_logging import ADMIN_ID, USER_ID

BASE = "/api/v1/crypto-lab"
USER = {"Authorization": "Bearer local-user-token"}
ADMIN = {"Authorization": "Bearer local-admin-token"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "debug", False)
    monkeypatch.setattr(settings, "crypto_lab_enabled", True)
    monkeypatch.setattr(settings, "crypto_lab_workers", 1)
    monkeypatch.setattr(settings, "crypto_lab_instances", 1)
    monkeypatch.setattr("app.crypto_lab.routes.service", CryptoService())
    for name in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_CMD_ARGS"):
        monkeypatch.delenv(name, raising=False)
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[deps.get_sessao_service] = lambda: FakeAuthService()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides = previous


def encrypt(client, text="Conta fictícia 💳"):
    response = client.post(BASE + "/encrypt", headers=USER, json={"text": text})
    assert response.status_code == 200, response.text
    return response.json()["envelope"]


def mutate_b64(value, index):
    raw = bytearray(base64.b64decode(value))
    raw[index] ^= 1
    return base64.b64encode(raw).decode()


@pytest.mark.parametrize("text", ["a", "Açaí e café 💳", " ", "😀" * 1024])
def test_round_trip(client, text):
    envelope = encrypt(client, text)
    response = client.post(BASE + "/decrypt", headers=USER, json={"envelope": envelope})
    assert response.status_code == 200
    assert response.json()["text"] == text
    assert response.headers["cache-control"] == "no-store"


def test_independent_keys_nonce_and_aad():
    service = CryptoService()
    first, second = (service.encrypt("abc", USER_ID).envelope for _ in range(2))
    key1, key2 = service.store.get(first.key_id, USER_ID), service.store.get(second.key_id, USER_ID)
    assert len(key1) == len(key2) == 32
    assert key1 != key2 and first.key_id != second.key_id
    assert len(base64.b64decode(first.nonce)) == 12
    aad = make_aad(1, "AES-256-GCM", first.key_id, USER_ID)
    assert AESGCM(key1).decrypt(base64.b64decode(first.nonce), base64.b64decode(first.ciphertext), aad) == b"abc"
    assert aad == (b"FINK-CRYPTO-V1" + b"\x00\x00\x00\x011" + b"\x00\x00\x00\x0bAES-256-GCM"
                   + b"\x00\x00\x00\x24" + str(first.key_id).encode()
                   + b"\x00\x00\x00\x24" + str(USER_ID).encode())


def test_known_aes_gcm_vector():
    cipher = AESGCM(bytes(32))
    assert cipher.encrypt(bytes(12), bytes(16), b"").hex() == (
        "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
    )


def test_expiry_and_capacity():
    now = [10.0]
    store = KeyStore(clock=lambda: now[0])
    ids = [uuid4() for _ in range(500)]
    for key_id in ids:
        store.add(key_id, USER_ID, b"x" * 32)
    with pytest.raises(CapacityError):
        store.add(uuid4(), USER_ID, b"y" * 32)
    assert store.get(ids[0], USER_ID) == b"x" * 32
    now[0] += 3599.999
    assert store.get(ids[0], USER_ID) is not None
    now[0] += .001
    assert store.get(ids[0], USER_ID) is None
    store.add(uuid4(), USER_ID, b"z" * 32)


def test_wrong_key_and_user():
    service = CryptoService()
    env = service.encrypt("fictício", USER_ID).envelope
    with pytest.raises(DecryptionError):
        service.decrypt(env, ADMIN_ID)
    service.store._records[env.key_id] = service.store._records[env.key_id].__class__(
        bytes(32), USER_ID, float("inf")
    )
    with pytest.raises(DecryptionError):
        service.decrypt(env, USER_ID)


@pytest.mark.parametrize("part", ["ciphertext", "tag", "nonce", "key_id", "other_user"])
def test_tampering_is_generic(client, part):
    envelope = encrypt(client)
    headers = USER
    if part == "ciphertext":
        envelope["ciphertext"] = mutate_b64(envelope["ciphertext"], 0)
    elif part == "tag":
        envelope["ciphertext"] = mutate_b64(envelope["ciphertext"], -1)
    elif part == "nonce":
        envelope["nonce"] = mutate_b64(envelope["nonce"], 0)
    elif part == "key_id":
        envelope["key_id"] = str(uuid4())
    else:
        headers = ADMIN
    response = client.post(BASE + "/decrypt", headers=headers, json={"envelope": envelope})
    assert response.status_code == 400
    assert response.json() == {"detail": "Não foi possível descriptografar o payload"}


def test_auth_and_metrics(client):
    assert client.post(BASE + "/encrypt", json={"text": "x"}).status_code == 401
    assert client.get(BASE + "/operations/summary", headers=USER).status_code == 403
    assert client.get(BASE + "/operations/summary", headers=ADMIN).status_code == 200
    assert client.post(BASE + "/encrypt", headers={"Authorization": "Bearer bad"}, json={"text": "x"}).status_code == 401


@pytest.mark.parametrize("data", [{"text": ""}, {"text": "😀" * 1025}, {"text": 1},
                                  {"text": "secret-plaintext", "extra": "secret-extra"}])
def test_invalid_text_is_sanitized(client, data):
    response = client.post(BASE + "/encrypt", headers=USER, json=data)
    assert response.status_code == 422
    assert "secret-plaintext" not in response.text and "secret-extra" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_body_limits_and_bad_json(client):
    exact = b'{"text":"x"}' + b" " * (16384 - len(b'{"text":"x"}'))
    assert client.post(BASE + "/encrypt", headers=USER, content=exact).status_code == 200
    assert client.post(BASE + "/encrypt", headers=USER, content=exact + b" ").status_code == 413
    assert client.post(BASE + "/encrypt", headers=USER, content=b"\xff").status_code == 400
    assert client.post(BASE + "/encrypt", headers=USER, content=b"{bad").status_code == 400


def test_bad_envelope_not_reflected(client):
    env = encrypt(client)
    env["nonce"] = "sensitive-nonce"
    response = client.post(BASE + "/decrypt", headers=USER, json={"envelope": env})
    assert response.status_code == 422
    assert "sensitive-nonce" not in response.text
    assert env["ciphertext"] not in response.text


def test_disabled_debug_workers_and_production(client, monkeypatch):
    monkeypatch.setattr(settings, "crypto_lab_enabled", False)
    assert client.post(BASE + "/encrypt", headers=USER, json={"text": "x"}).status_code == 503
    monkeypatch.setattr(settings, "crypto_lab_enabled", True)
    monkeypatch.setattr(settings, "debug", True)
    assert client.post(BASE + "/encrypt", headers=USER, json={"text": "x"}).status_code == 503
    monkeypatch.setattr(settings, "debug", False)
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    assert client.post(BASE + "/encrypt", headers=USER, json={"text": "x"}).status_code == 503
    monkeypatch.delenv("WEB_CONCURRENCY")
    monkeypatch.setattr(settings, "crypto_lab_instances", 2)
    assert client.post(BASE + "/encrypt", headers=USER, json={"text": "x"}).status_code == 503
    monkeypatch.setattr(settings, "environment", "production")
    assert client.post(BASE + "/encrypt", headers=USER, json={"text": "x"}).status_code == 404


def test_no_sensitive_data_in_logs_or_errors(client, caplog, monkeypatch):
    from app.core.security_logging import logger

    secret = "FICTITIOUS_PRIVATE_TEXT_943"
    logger.addHandler(caplog.handler)
    try:
        env = encrypt(client, secret)
        invalid = client.post(BASE + "/decrypt", headers=USER, json={"envelope": {**env, "nonce": "secret-invalid"}})
        report = client.get(BASE + "/operations/summary", headers=ADMIN)
    finally:
        logger.removeHandler(caplog.handler)
    observed = caplog.text + invalid.text + report.text
    for value in (secret, env["nonce"], env["ciphertext"], "local-user-token", "secret-invalid"):
        assert value not in observed


def test_concurrent_capacity_and_release(monkeypatch):
    store = KeyStore(capacity=7)
    def add_one(_):
        try:
            store.add(uuid4(), USER_ID, b"x" * 32)
            return True
        except CapacityError:
            return False
    with ThreadPoolExecutor(max_workers=20) as executor:
        assert sum(executor.map(add_one, range(40))) == 7
    service = CryptoService()
    for _ in range(10):
        assert service.slots.acquire(blocking=False)
    with pytest.raises(CapacityError):
        service.encrypt("x", USER_ID)
    for _ in range(10):
        service.slots.release()
    assert service.encrypt("x", USER_ID)


def test_partial_failure_and_collision(monkeypatch):
    service = CryptoService()
    fixed_id = uuid4()
    monkeypatch.setattr(aes_service, "uuid4", lambda: fixed_id)
    first = service.encrypt("x", USER_ID)
    before = service.store.get(fixed_id, USER_ID)
    with pytest.raises(ValueError):
        service.encrypt("x", USER_ID)
    assert service.store.get(fixed_id, USER_ID) == before
    assert service.decrypt(first.envelope, USER_ID).text == "x"
    assert service.slots.acquire(blocking=False)
    service.slots.release()


@pytest.mark.asyncio
async def test_streaming_body_without_content_length_is_bounded():
    from app.crypto_lab.middleware import CryptoLabMiddleware

    async def inner(scope, receive, send):
        raise AssertionError("Oversized body reached application")

    config = SimpleNamespace(environment="development", crypto_lab_enabled=True, debug=False,
                             crypto_lab_workers=1, crypto_lab_instances=1)
    boundary = CryptoLabMiddleware(inner, config)
    parts = iter([
        {"type": "http.request", "body": b"x" * 10000, "more_body": True},
        {"type": "http.request", "body": b"x" * 7000, "more_body": False},
    ])
    sent = []
    async def receive():
        return next(parts)
    async def send(message):
        sent.append(message)
    await boundary({"type": "http", "path": BASE + "/encrypt", "method": "POST", "headers": []}, receive, send)
    assert sent[0]["status"] == 413
    assert (b"cache-control", b"no-store") in sent[0]["headers"]


def test_failed_metrics_rolls_back_key(monkeypatch):
    service = CryptoService()
    monkeypatch.setattr(service.metrics, "increment", lambda _: (_ for _ in ()).throw(RuntimeError("failed")))
    with pytest.raises(RuntimeError):
        service.encrypt("fictício", USER_ID)
    assert not service.store._records


def test_unknown_or_expired_and_tampered_are_indistinguishable(client, monkeypatch):
    from app.crypto_lab import routes
    env = encrypt(client)
    fake = {**env, "key_id": str(uuid4())}
    altered = {**env, "ciphertext": mutate_b64(env["ciphertext"], -1)}
    a = client.post(BASE + "/decrypt", headers=USER, json={"envelope": fake})
    b = client.post(BASE + "/decrypt", headers=USER, json={"envelope": altered})
    assert a.status_code == b.status_code == 400
    assert a.content == b.content
    monkeypatch.setattr(routes.service.store, "_clock", lambda: float("inf"))
    c = client.post(BASE + "/decrypt", headers=USER, json={"envelope": env})
    assert c.status_code == 400 and c.content == a.content


@pytest.mark.parametrize("field,value", [
    ("version", 2), ("version", True), ("algorithm", "other"), ("key_id", "not-uuid"),
    ("nonce", "AAAA"), ("ciphertext", "***"),
])
def test_invalid_envelope_fields(client, field, value):
    env = encrypt(client)
    env[field] = value
    response = client.post(BASE + "/decrypt", headers=USER, json={"envelope": env})
    assert response.status_code == 422
    assert response.json() == {"detail": "Entrada invalida"}


def test_production_does_not_register_routes():
    env = {**os.environ, "ENVIRONMENT": "production", "DEBUG": "false", "CRYPTO_LAB_ENABLED": "true"}
    code = "from app.main import app; assert not any(r.path.startswith('/api/v1/crypto-lab') for r in app.routes)"
    result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_unexpected_error_is_generic(client, monkeypatch):
    from app.crypto_lab import routes

    def fail(*args):
        raise RuntimeError("sensitive-internal-details")
    monkeypatch.setattr(routes.service, "encrypt", fail)
    response = client.post(BASE + "/encrypt", headers=USER, json={"text": "sensitive-body"})
    assert response.status_code == 500
    assert "sensitive" not in response.text
    assert response.headers["cache-control"] == "no-store"
