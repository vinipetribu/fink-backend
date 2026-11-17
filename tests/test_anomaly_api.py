"""ASGI authentication and validation checks for the synthetic lab."""
import pytest
import httpx
from app.api import deps
from app.core.settings import settings
from app.crypto_lab.anomaly_lab import routes
from app.crypto_lab.anomaly_lab.runner import Coordinator
from app.main import app
from tests.test_security_logs import FakeAuthService

URL = '/api/v1/crypto-lab/anomalies/datasets'
ADMIN = {'Authorization': 'Bearer local-admin-token'}
USER = {'Authorization': 'Bearer local-user-token'}


@pytest.mark.asyncio
async def test_access_and_validation(monkeypatch):
    for name in ('WEB_CONCURRENCY', 'UVICORN_WORKERS', 'GUNICORN_CMD_ARGS'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(settings, 'environment', 'development')
    monkeypatch.setattr(settings, 'debug', False)
    monkeypatch.setattr(settings, 'crypto_lab_enabled', True)
    monkeypatch.setattr(settings, 'crypto_lab_anomaly_enabled', True)
    monkeypatch.setattr(settings, 'crypto_lab_workers', 1)
    monkeypatch.setattr(settings, 'crypto_lab_instances', 1)
    coordinator = Coordinator()
    monkeypatch.setattr(routes, 'coordinator', coordinator)
    old = app.dependency_overrides.copy()
    app.dependency_overrides[deps.get_sessao_service] = lambda: FakeAuthService()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://localhost') as client:
            body = {'profile': 'synthetic-security-v1'}
            assert (await client.post(URL, json=body)).status_code == 401
            assert (await client.post(URL, headers=USER, json=body)).status_code == 403
            invalid = await client.post(URL, headers=ADMIN, json={**body, 'secret': 'marker'})
            assert invalid.status_code == 422 and 'marker' not in invalid.text
            assert (await client.post(URL, headers=ADMIN, content=b'x' * 1025)).status_code == 413
            monkeypatch.setattr(settings, 'crypto_lab_anomaly_enabled', False)
            assert (await client.post(URL, headers=ADMIN, json=body)).status_code == 503
            monkeypatch.setattr(settings, 'crypto_lab_anomaly_enabled', True)
            response = await client.post(URL, headers=ADMIN, json=body)
            assert response.status_code == 202 and response.headers['cache-control'] == 'no-store'
            assert (await client.post(URL, headers=ADMIN, json=body)).status_code == 503
            await coordinator.task
            job = await client.get('/api/v1/crypto-lab/anomalies/jobs/' + response.json()['job_id'], headers=ADMIN)
            assert job.status_code == 200 and job.json()['status'] == 'completed'
            # Simulate expiry of the per-admin cooldown without a minute-long test.
            coordinator.user_starts.clear()
            run = await client.post('/api/v1/crypto-lab/anomalies/runs', headers=ADMIN,
                                    json={'dataset_id': job.json()['dataset_id']})
            assert run.status_code == 202
            await coordinator.task
            finished = await client.get('/api/v1/crypto-lab/anomalies/jobs/' + run.json()['job_id'], headers=ADMIN)
            assert finished.status_code == 200 and finished.json()['status'] == 'completed'
            result = await client.get('/api/v1/crypto-lab/anomalies/results/' + finished.json()['result_id'],
                                      headers=ADMIN)
            assert result.status_code == 200 and result.headers['cache-control'] == 'no-store'
            assert result.json()['result']['scope'] == 'synthetic_only'
    finally:
        await coordinator.close()
        app.dependency_overrides = old
