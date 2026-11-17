"""HTTP contract and access checks without a real database."""
import pytest
import httpx
from app.api import deps
from app.core.settings import settings
from app.crypto_lab.attacks import routes
from app.crypto_lab.attacks.runner import Coordinator
from app.main import app
from tests.test_security_logs import FakeAuthService

URL = "/api/v1/crypto-lab/attacks/runs"
ADMIN = {"Authorization": "Bearer local-admin-token"}
USER = {"Authorization": "Bearer local-user-token"}


@pytest.mark.asyncio
async def test_http_contract_and_isolation(monkeypatch):
    for name in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_CMD_ARGS"):
        monkeypatch.delenv(name, raising=False)
    for name in ("crypto_lab_enabled", "crypto_lab_experimental_enabled", "crypto_lab_attacks_enabled"):
        monkeypatch.setattr(settings, name, True)
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "debug", False)
    monkeypatch.setattr(settings, "crypto_lab_workers", 1)
    monkeypatch.setattr(settings, "crypto_lab_instances", 1)
    coordinator = Coordinator()
    monkeypatch.setattr(routes, "coordinator", coordinator)
    old = app.dependency_overrides.copy()
    app.dependency_overrides[deps.get_sessao_service] = lambda: FakeAuthService()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            body = {"experiment": "statistics"}
            assert (await client.post(URL, json=body)).status_code == 401
            assert (await client.post(URL, headers=USER, json=body)).status_code == 403
            bad = await client.post(URL, headers=ADMIN, json={**body, "plaintext": "sensitive-marker"})
            assert bad.status_code == 422 and "sensitive-marker" not in bad.text
            assert (await client.post(URL, headers=ADMIN, content=b"{" )).status_code == 400
            assert (await client.post(URL, headers=ADMIN, content=b"x" * 1025)).status_code == 413
            monkeypatch.setattr(settings, "crypto_lab_attacks_enabled", False)
            assert (await client.post(URL, headers=ADMIN, json=body)).status_code == 503
            monkeypatch.setattr(settings, "crypto_lab_attacks_enabled", True)
            response = await client.post(URL, headers=ADMIN, json=body)
            assert response.status_code == 202
            assert response.headers["cache-control"] == "no-store"
            run_id = response.json()["run_id"]
            assert (await client.post(URL, headers=ADMIN, json=body)).status_code == 503
            await coordinator.task
            result = await client.get(f"{URL}/{run_id}", headers=ADMIN)
            assert result.status_code == 200 and result.json()["status"] == "completed"
            assert result.json()["metrics"]["byte_denominator"] == 10240
            assert '"key":' not in result.text.lower()
            assert '"plaintext":' not in result.text.lower()
            assert '"ciphertext":' not in result.text.lower()
            assert result.headers["cache-control"] == "no-store"
            assert (await client.post(URL, headers=ADMIN, json=body)).status_code == 429
            monkeypatch.setattr(settings, "environment", "production")
            assert (await client.get(f"{URL}/{run_id}", headers=ADMIN)).status_code == 404
    finally:
        await coordinator.close()
        app.dependency_overrides = old
