"""Security-log access, bounded retention and redaction through the real API guards."""

from collections import deque
from collections.abc import Iterator
import json
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.api import deps as api_deps
from app.core import security_logging
from app.identidade.api import pessoa_routes
from app.main import app
from tests.test_security_logging import (
    ADMIN_ID,
    LOGIN_EMAIL,
    LOGIN_PASSWORD,
    LOGIN_TOKEN,
    USER_ID,
    EmptyPessoaService,
    FakeLoginService,
)


class FakeAuthService(FakeLoginService):
    """Replace only storage; keep HTTPBearer, get_current_user and require_admin real."""

    def __init__(self) -> None:
        super().__init__()
        self.pessoa_repo = self

    async def validar(self, token: str) -> SimpleNamespace:
        """Resolve fictitious Bearer tokens without any database access."""
        ids = {"local-user-token": USER_ID, "local-admin-token": ADMIN_ID}
        if token not in ids:
            raise ValueError("Token inválido ou expirado")
        return SimpleNamespace(fk_pessoa_id_pessoa=ids[token])

    async def get_by_id(self, user_id: UUID) -> SimpleNamespace:
        """Provide the existing boolean ADMIN flag."""
        return SimpleNamespace(id_pessoa=user_id, admin=user_id == ADMIN_ID)


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """Isolate the buffer and fake storage while retaining the real app middleware."""
    monkeypatch.setattr(
        security_logging,
        "_security_events",
        deque(maxlen=security_logging.SECURITY_LOG_LIMIT),
    )
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[api_deps.get_sessao_service] = lambda: FakeAuthService()
    app.dependency_overrides[pessoa_routes.get_pessoa_service] = lambda: EmptyPessoaService()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides = previous


ADMIN_HEADERS = {"Authorization": "Bearer local-admin-token"}
LOGS_URL = "/api/v1/security-logs/"


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [
        pytest.param({}, 401, id="anonymous-401"),
        pytest.param({"Authorization": "Bearer invalid-token"}, 401, id="invalid-token-401"),
        pytest.param({"Authorization": "Bearer local-user-token"}, 403, id="user-403"),
        pytest.param(ADMIN_HEADERS, 200, id="admin-200"),
    ],
)
def test_security_logs_access_matrix(
    client: TestClient,
    headers: dict[str, str],
    expected_status: int,
) -> None:
    """The backend enforces authentication and the central ADMIN guard."""
    response = client.get(LOGS_URL, headers=headers)
    assert response.status_code == expected_status, response.text
    if expected_status == 200:
        assert response.json() == []
        assert response.headers["Cache-Control"] == "no-store"
    else:
        assert "detail" in response.json()
        events = security_logging.get_security_logs()
        assert events[0]["event"] == "ACCESS_DENIED"
        assert events[0]["route"] == LOGS_URL
        if expected_status == 401:
            assert response.headers["WWW-Authenticate"] == "Bearer"


def test_buffer_keeps_only_latest_200_events(client: TestClient) -> None:
    """Overflow discards the oldest events and the API returns newest first."""
    request = Request({"type": "http", "method": "POST"})
    for index in range(205):
        security_logging.log_security_event(
            "LOGIN_SUCCESS", "SUCCESS", request, user_id=UUID(int=index + 1)
        )
    response = client.get(LOGS_URL, headers=ADMIN_HEADERS)
    assert response.status_code == 200
    assert len(response.json()) == 200
    assert [event["user_id"] for event in response.json()] == [
        str(UUID(int=index + 1)) for index in reversed(range(5, 205))
    ]


def test_all_events_match_stdout_without_secrets_or_refresh_pollution(
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Reuse all four existing producers and preserve their structured stdout events."""
    security_logging.logger.addHandler(caplog.handler)
    try:
        app.dependency_overrides[api_deps.get_sessao_service] = lambda: FakeLoginService(fail=True)
        assert client.post(
            "/api/v1/sessoes/login",
            json={"email": LOGIN_EMAIL, "senha": LOGIN_PASSWORD},
        ).status_code == 401

        app.dependency_overrides[api_deps.get_sessao_service] = lambda: FakeAuthService()
        assert client.post(
            "/api/v1/sessoes/login",
            headers={"Authorization": f"Bearer {LOGIN_TOKEN}"},
            json={"email": LOGIN_EMAIL, "senha": LOGIN_PASSWORD},
        ).status_code == 201
        assert client.get(
            f"/api/v1/pessoas/{USER_ID}?token={LOGIN_TOKEN}"
        ).status_code == 401
        assert client.get("/api/v1/pessoas/", headers=ADMIN_HEADERS).status_code == 200

        stdout_events = [
            json.loads(record.getMessage())
            for record in caplog.records
            if record.name == "fink.security"
        ]
        assert [event["event"] for event in stdout_events] == [
            "LOGIN_FAILURE", "LOGIN_SUCCESS", "ACCESS_DENIED", "ADMIN_ACCESS"
        ]
        for _ in range(3):
            response = client.request(
                "GET",
                f"{LOGS_URL}?token={LOGIN_TOKEN}",
                headers=ADMIN_HEADERS,
                json={"senha": LOGIN_PASSWORD, "body": "never-log-this-body"},
            )
            assert response.status_code == 200
            assert response.json() == list(reversed(stdout_events))
            assert all(set(event) <= security_logging.SECURITY_LOG_FIELDS for event in response.json())
            for secret in (
                LOGIN_PASSWORD, LOGIN_TOKEN, LOGIN_EMAIL,
                "Bearer", "local-admin-token", "never-log-this-body", "local-hash-not-emitted",
            ):
                assert secret not in response.text
        assert len([record for record in caplog.records if record.name == "fink.security"]) == 4
    finally:
        security_logging.logger.removeHandler(caplog.handler)


def test_response_allowlist_filters_unexpected_fields(client: TestClient) -> None:
    """Even an accidentally added internal field must not reach the endpoint."""
    security_logging.log_security_event(
        "LOGIN_FAILURE", "FAILURE", Request({"type": "http", "method": "POST"})
    )
    security_logging._security_events[0].update(
        password=LOGIN_PASSWORD, token=LOGIN_TOKEN, body="never-log-this-body"
    )
    response = client.get(LOGS_URL, headers=ADMIN_HEADERS)
    assert response.status_code == 200
    assert set(response.json()[0]) == security_logging.SECURITY_LOG_FIELDS - {"user_id"}


def test_snapshot_cannot_mutate_buffer(client: TestClient) -> None:
    """Returned events are copies, so a caller cannot change the retained events."""
    security_logging.log_security_event(
        "LOGIN_FAILURE", "FAILURE", Request({"type": "http", "method": "POST"})
    )
    snapshot = security_logging.get_security_logs()
    snapshot[0]["event"] = "changed"
    snapshot.clear()
    assert client.get(LOGS_URL, headers=ADMIN_HEADERS).json()[0]["event"] == "LOGIN_FAILURE"
