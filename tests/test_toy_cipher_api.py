"""HTTP and isolation checks for the opt-in experimental cipher."""

import os
import subprocess
import sys
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from app.api import deps
from app.core.settings import settings
from app.crypto_lab import routes
from app.crypto_lab.aes_service import CryptoService
from app.crypto_lab.toy_cipher import ToyService
from app.main import app
from tests.test_security_logs import FakeAuthService
from tests.test_security_logging import ADMIN_ID, USER_ID

URL = "/api/v1/crypto-lab/experimental/run"
ADMIN = {"Authorization": "Bearer local-admin-token"}
USER = {"Authorization": "Bearer local-user-token"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "debug", False)
    monkeypatch.setattr(settings, "crypto_lab_enabled", True)
    monkeypatch.setattr(settings, "crypto_lab_experimental_enabled", True)
    monkeypatch.setattr(settings, "crypto_lab_workers", 1)
    monkeypatch.setattr(settings, "crypto_lab_instances", 1)
    for name in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_CMD_ARGS"):
        monkeypatch.delenv(name, raising=False)
    aes = CryptoService()
    monkeypatch.setattr(routes, "service", aes)
    monkeypatch.setattr(routes, "toy_service", ToyService(aes.metrics))
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[deps.get_sessao_service] = lambda: FakeAuthService()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides = previous


@pytest.mark.parametrize("text", ["x", "12345678", "blocos múltiplos com acento 💳", "😀" * 1024])
def test_admin_roundtrip(client, text):
    response = client.post(URL, headers=ADMIN, json={"action": "encrypt", "text": text})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"operation_id", "algorithm", "key_id", "ciphertext", "warning"}
    assert body["algorithm"] == "TOY-V1-INSECURE"
    assert "insegura" in body["warning"]
    decoded = client.post(URL, headers=ADMIN, json={"action": "decrypt", "key_id": body["key_id"],
                                                   "ciphertext": body["ciphertext"]})
    assert decoded.status_code == 200
    assert decoded.json()["text"] == text
    assert decoded.headers["cache-control"] == "no-store"


def test_permission_and_flags(client, monkeypatch):
    body = {"action": "encrypt", "text": "fictício"}
    assert client.post(URL, json=body).status_code == 401
    assert client.post(URL, headers=USER, json=body).status_code == 403
    monkeypatch.setattr(settings, "crypto_lab_experimental_enabled", False)
    assert client.post(URL, headers=ADMIN, json=body).status_code == 503
    monkeypatch.setattr(settings, "crypto_lab_experimental_enabled", True)
    monkeypatch.setattr(settings, "crypto_lab_enabled", False)
    assert client.post(URL, headers=ADMIN, json=body).status_code == 503
    monkeypatch.setattr(settings, "crypto_lab_enabled", True)
    monkeypatch.setattr(settings, "environment", "production")
    assert client.post(URL, headers=ADMIN, json=body).status_code == 404


def test_default_flag_off(monkeypatch):
    from app.core.settings import Settings
    monkeypatch.delenv("CRYPTO_LAB_EXPERIMENTAL_ENABLED", raising=False)
    assert Settings(_env_file=None).crypto_lab_experimental_enabled is False


@pytest.mark.parametrize("body", [
    {"action": "encrypt", "text": ""},
    {"action": "encrypt", "text": "😀" * 1025},
    {"action": "encrypt", "text": 3},
    {"action": "encrypt", "text": "SECRET-FICTION", "toy_key": 10},
    {"action": "decrypt", "key_id": str(uuid4()), "ciphertext": "AA=="},
    {"action": "decrypt", "key_id": str(uuid4()), "ciphertext": "####"},
    {"action": "invalid", "text": "SECRET-FICTION"},
])
def test_invalid_input_is_sanitized(client, body):
    response = client.post(URL, headers=ADMIN, json=body)
    assert response.status_code == 422
    assert "SECRET-FICTION" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_key_stores_and_owners_are_isolated(client):
    toy = client.post(URL, headers=ADMIN, json={"action": "encrypt", "text": "fictício"}).json()
    aes = client.post("/api/v1/crypto-lab/encrypt", headers=ADMIN, json={"text": "fictício"}).json()["envelope"]
    assert routes.toy_service.store.get(uuid4(), ADMIN_ID) is None
    assert routes.toy_service.store.get(toy_id := UUID(toy["key_id"]), USER_ID) is None
    assert routes.service.store.get(toy_id, ADMIN_ID) is None
    assert routes.toy_service.store.get(UUID(aes["key_id"]), ADMIN_ID) is None
    response = client.post(URL, headers=ADMIN, json={"action": "decrypt", "key_id": aes["key_id"],
                                                    "ciphertext": toy["ciphertext"]})
    assert response.status_code == 400
    aes_response = client.post("/api/v1/crypto-lab/decrypt", headers=ADMIN, json={"envelope": aes})
    assert aes_response.status_code == 200
    assert aes_response.json()["text"] == "fictício"


def test_no_secrets_in_logs_and_metrics(client, caplog):
    from app.core.security_logging import logger
    text = "FICTITIOUS-PRIVATE-CONTENT-836"
    logger.addHandler(caplog.handler)
    try:
        response = client.post(URL, headers=ADMIN, json={"action": "encrypt", "text": text})
        assert response.status_code == 200
        encrypted = response.json()
        assert "key" not in encrypted and "toy_key" not in encrypted and "text" not in encrypted
        wrong = client.post(URL, headers=ADMIN, json={"action": "decrypt", "key_id": str(uuid4()),
                                                     "ciphertext": encrypted["ciphertext"]})
        metrics = client.get("/api/v1/crypto-lab/operations/summary", headers=ADMIN)
    finally:
        logger.removeHandler(caplog.handler)
    assert wrong.status_code == 400
    assert metrics.json()["counts"]["experimental_success"] == 1
    assert metrics.json()["counts"]["experimental_failure"] == 1
    observed = caplog.text + wrong.text + metrics.text
    for value in (text, encrypted["ciphertext"], "local-admin-token"):
        assert value not in observed


def test_production_has_no_route():
    env = {**os.environ, "ENVIRONMENT": "production", "DEBUG": "false", "CRYPTO_LAB_ENABLED": "true",
           "CRYPTO_LAB_EXPERIMENTAL_ENABLED": "true"}
    code = "from app.main import app; assert not any(r.path.startswith('/api/v1/crypto-lab') for r in app.routes)"
    result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
