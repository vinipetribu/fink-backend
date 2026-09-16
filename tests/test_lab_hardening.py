"""Minimal regression tests for the audit closeout in the local laboratory."""

from collections.abc import Iterator
from dataclasses import dataclass
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app import main
from app.api import deps
from app.comercial.api.solicitacao_pagamento_routes import get_solicitacao_pagamento_service
from app.core.settings import Settings, settings


@dataclass
class LocalPrincipal:
    """Fictitious principal used without a database or external services."""

    id_pessoa: UUID = UUID("10000000-0000-4000-8000-000000000001")
    admin: bool = False


@pytest.fixture(autouse=True)
def restore_overrides() -> Iterator[None]:
    """Preserve application state and dependency overrides between tests."""
    previous = main.app.dependency_overrides.copy()
    previous_client = getattr(main.app.state, "pluggy_client", None)
    try:
        yield
    finally:
        main.app.dependency_overrides = previous
        main.app.state.pluggy_client = previous_client


def test_pluggy_is_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """The application default remains disabled without environment overrides."""
    monkeypatch.delenv("PLUGGY_ENABLED", raising=False)

    assert Settings(_env_file=None).pluggy_enabled is False


@pytest.mark.asyncio
async def test_disabled_pluggy_lifespan_never_initializes_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Startup cannot create or authenticate a Pluggy client when disabled."""
    monkeypatch.setattr(settings, "pluggy_enabled", False)
    monkeypatch.setattr(main, "init_db", AsyncMock())
    monkeypatch.setattr(main, "seed_db", AsyncMock())

    def forbidden_client(**kwargs: object) -> None:
        raise AssertionError("Disabled Pluggy must not initialize a client")

    monkeypatch.setattr(main, "PluggyClient", forbidden_client)

    async with main.lifespan(main.app):
        assert main.app.state.pluggy_client is None


@pytest.mark.parametrize(
    "path",
    [
        "/connect-token",
        "/accounts/local-item",
        "/transactions/local-account",
        "/accounts/local-account/balance",
        "/accounts/local-account/summary",
        "/_debug-auth",
    ],
)
def test_disabled_pluggy_routes_never_use_a_client(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    """All integration routes reject requests even if a stale client exists."""
    monkeypatch.setattr(settings, "pluggy_enabled", False)
    main.app.state.pluggy_client = object()
    main.app.dependency_overrides[deps.get_current_user] = lambda: LocalPrincipal(admin=True)

    response = TestClient(main.app).get(f"/api/v1/pluggy{path}")

    assert response.status_code == 503


@pytest.mark.parametrize("actor", ["ANONYMOUS", "USER"])
@pytest.mark.parametrize(
    ("method", "path"),
    [("POST", "/"), ("GET", "/"), ("GET", "/1"), ("DELETE", "/1")],
)
def test_payment_requests_deny_anonymous_and_user(method: str, path: str, actor: str) -> None:
    """Payment administration cannot be reached by anonymous callers or USER."""
    main.app.dependency_overrides[get_solicitacao_pagamento_service] = lambda: object()
    if actor == "USER":
        main.app.dependency_overrides[deps.get_current_user] = lambda: LocalPrincipal()

    response = TestClient(main.app).request(
        method,
        f"/api/v1/solicitacoes-pagamento{path}",
        json={"fk_tipo_pagamento_id_pagamento": 1, "fk_assinatura_id_assinatura": 1},
    )

    assert response.status_code == (401 if actor == "ANONYMOUS" else 403)
