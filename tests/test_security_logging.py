"""Tests for the minimal structured SB-05 security log."""

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import date, datetime, timedelta
import json
from uuid import UUID

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.api import deps as api_deps
from app.core.security_logging import logger as security_logger
from app.identidade.api import pessoa_routes
from app.identidade.domain.sessao import Sessao
from app.main import app


USER_ID = UUID("10000000-0000-4000-8000-000000000001")
ADMIN_ID = UUID("20000000-0000-4000-8000-000000000002")
LOGIN_EMAIL = "security-user@example.com"
LOGIN_PASSWORD = "never-log-this-password"
LOGIN_TOKEN = "never-log-this-token"


class FakeLoginService:
    """Return local login results without database or network access."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    async def criar_por_email_senha(self, email: str, senha: str) -> tuple[Sessao, str]:
        """Accept or reject the fictitious credentials deterministically."""
        assert email == LOGIN_EMAIL
        assert senha == LOGIN_PASSWORD
        if self.fail:
            raise ValueError("Credenciais inválidas")

        today = date(2026, 1, 1)
        return (
            Sessao(
                id_sessao=1,
                fk_pessoa_id_pessoa=USER_ID,
                token_hash="local-hash-not-emitted",
                criada_em=today,
                expira_em=today + timedelta(days=1),
            ),
            LOGIN_TOKEN,
        )


class EmptyPessoaService:
    """Avoid database access while exercising the administrative route."""

    @staticmethod
    async def listar() -> list[object]:
        """Return no local people."""
        return []


@dataclass
class FakeAdmin:
    """Minimal local principal accepted by require_admin."""

    id_pessoa: UUID = ADMIN_ID
    admin: bool = True


@pytest.fixture(autouse=True)
def preserve_dependency_overrides() -> Iterator[None]:
    """Restore global FastAPI overrides after every test."""
    previous = app.dependency_overrides.copy()
    try:
        yield
    finally:
        app.dependency_overrides = previous


@pytest.fixture
def client() -> TestClient:
    """Return a local in-process API client without running the lifespan."""
    return TestClient(app)


@pytest.fixture
def security_log(caplog: pytest.LogCaptureFixture) -> Iterator[pytest.LogCaptureFixture]:
    """Attach pytest's in-memory handler to the non-propagating security logger."""
    security_logger.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        security_logger.removeHandler(caplog.handler)


def _events(caplog: pytest.LogCaptureFixture) -> tuple[list[dict[str, str]], str]:
    output = "\n".join(record.getMessage() for record in caplog.records)
    events = []
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("event"):
            events.append(item)
    return events, output


def _assert_fields(event: dict[str, str], *, includes_user: bool) -> None:
    expected = {"timestamp", "event", "result", "method", "route"}
    if includes_user:
        expected.add("user_id")
    assert set(event) == expected
    datetime.fromisoformat(event["timestamp"])


def test_login_success_is_structured_and_redacted(
    client: TestClient,
    security_log: pytest.LogCaptureFixture,
) -> None:
    """LOGIN_SUCCESS contains only allowlisted fields and no credentials."""
    app.dependency_overrides[api_deps.get_sessao_service] = lambda: FakeLoginService()

    response = client.post(
        "/api/v1/sessoes/login",
        json={"email": LOGIN_EMAIL, "senha": LOGIN_PASSWORD},
    )
    events, output = _events(security_log)

    assert response.status_code == 201
    assert len(events) == 1
    _assert_fields(events[0], includes_user=True)
    assert events == [
        {
            "timestamp": events[0]["timestamp"],
            "event": "LOGIN_SUCCESS",
            "result": "SUCCESS",
            "method": "POST",
            "route": "/api/v1/sessoes/login",
            "user_id": str(USER_ID),
        }
    ]
    assert LOGIN_EMAIL not in output
    assert LOGIN_PASSWORD not in output
    assert LOGIN_TOKEN not in output
    assert "local-hash-not-emitted" not in output


def test_login_failure_is_structured_and_redacted(
    client: TestClient,
    security_log: pytest.LogCaptureFixture,
) -> None:
    """LOGIN_FAILURE omits the submitted identity and credential."""
    app.dependency_overrides[api_deps.get_sessao_service] = lambda: FakeLoginService(fail=True)

    response = client.post(
        "/api/v1/sessoes/login",
        json={"email": LOGIN_EMAIL, "senha": LOGIN_PASSWORD},
    )
    events, output = _events(security_log)

    assert response.status_code == 401
    assert len(events) == 1
    _assert_fields(events[0], includes_user=False)
    assert events[0]["event"] == "LOGIN_FAILURE"
    assert events[0]["result"] == "FAILURE"
    assert events[0]["method"] == "POST"
    assert events[0]["route"] == "/api/v1/sessoes/login"
    assert "user_id" not in events[0]
    assert LOGIN_EMAIL not in output
    assert LOGIN_PASSWORD not in output
    assert LOGIN_TOKEN not in output


def test_access_denied_event_is_emitted_for_anonymous_request(
    client: TestClient,
    security_log: pytest.LogCaptureFixture,
) -> None:
    """ACCESS_DENIED records the route template without request contents."""
    app.dependency_overrides[pessoa_routes.get_pessoa_service] = lambda: EmptyPessoaService()

    response = client.get(f"/api/v1/pessoas/{USER_ID}")
    events, output = _events(security_log)

    assert response.status_code == 401
    assert len(events) == 1
    _assert_fields(events[0], includes_user=False)
    assert events[0]["event"] == "ACCESS_DENIED"
    assert events[0]["result"] == "DENIED"
    assert events[0]["method"] == "GET"
    assert events[0]["route"] == "/api/v1/pessoas/{id_pessoa}"
    assert "user_id" not in events[0]
    assert LOGIN_PASSWORD not in output
    assert LOGIN_TOKEN not in output


def test_admin_access_event_contains_only_admin_id_and_route(
    client: TestClient,
    security_log: pytest.LogCaptureFixture,
) -> None:
    """ADMIN_ACCESS records a successful central admin authorization."""

    async def get_fake_admin(request: Request) -> FakeAdmin:
        request.state.security_user_id = ADMIN_ID
        return FakeAdmin()

    app.dependency_overrides[api_deps.get_current_user] = get_fake_admin
    app.dependency_overrides[pessoa_routes.get_pessoa_service] = lambda: EmptyPessoaService()

    response = client.get("/api/v1/pessoas/")
    events, output = _events(security_log)

    assert response.status_code == 200
    assert len(events) == 1
    _assert_fields(events[0], includes_user=True)
    assert events[0]["event"] == "ADMIN_ACCESS"
    assert events[0]["result"] == "ALLOWED"
    assert events[0]["method"] == "GET"
    assert events[0]["route"] == "/api/v1/pessoas/"
    assert events[0]["user_id"] == str(ADMIN_ID)
    assert LOGIN_PASSWORD not in output
    assert LOGIN_TOKEN not in output
