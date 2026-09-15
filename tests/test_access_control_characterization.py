"""Characterization tests for the current SB-02 and SB-03 behavior."""

from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import date, timedelta
from typing import Literal
from uuid import UUID

import pytest
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from fastapi.security import HTTPBearer
from fastapi.testclient import TestClient

from app.api import deps as api_deps
from app.identidade.api import pessoa_routes, sessao_routes
from app.identidade.domain.sessao import Sessao
from app.main import app


Actor = Literal["ANONYMOUS", "USER", "ADMIN"]

USER_ID = UUID("10000000-0000-4000-8000-000000000001")
ADMIN_ID = UUID("20000000-0000-4000-8000-000000000002")
OTHER_USER_ID = UUID("30000000-0000-4000-8000-000000000003")
LOCAL_PASSWORD = "fictitious-local-password"
LOCAL_TOKENS = {
    "local-user-token": USER_ID,
    "local-admin-token": ADMIN_ID,
}
PUBLIC_ENDPOINTS = frozenset(
    {
        ("GET", "/"),
        ("GET", "/health"),
        ("GET", "/api/v1/health"),
        ("GET", "/api/v1/info"),
        ("POST", "/api/v1/pessoas/"),
        ("POST", "/api/v1/sessoes/login"),
        ("GET", "/api/v1/planos/"),
        ("GET", "/api/v1/planos/{id_plano}"),
    }
)
CATALOG_ADMIN_ENDPOINTS = frozenset(
    {
        ("POST", "/api/v1/planos/"),
        ("PATCH", "/api/v1/planos/{id_plano}"),
        ("DELETE", "/api/v1/planos/{id_plano}"),
        ("PUT", "/api/v1/planos/{id_plano}/ativar"),
        ("PUT", "/api/v1/planos/{id_plano}/desativar"),
        ("POST", "/api/v1/tipos-pagamento/"),
        ("PATCH", "/api/v1/tipos-pagamento/{id_pagamento}"),
        ("DELETE", "/api/v1/tipos-pagamento/{id_pagamento}"),
    }
)


@dataclass
class FakePessoa:
    """Fictitious local person returned by the in-memory service."""

    id_pessoa: UUID
    email: str
    nome: str
    data_nascimento: date
    telefone: str
    genero: str
    estado: str
    cidade: str
    rua: str
    numero: str
    cep: str
    data_criacao: date
    admin: bool


def _fake_pessoa(id_pessoa: UUID, email: str, *, admin: bool = False) -> FakePessoa:
    return FakePessoa(
        id_pessoa=id_pessoa,
        email=email,
        nome="Pessoa Fictícia",
        data_nascimento=date(1990, 1, 1),
        telefone="81999999999",
        genero="nao_informado",
        estado="PE",
        cidade="Recife",
        rua="Rua Local",
        numero="123",
        cep="50000000",
        data_criacao=date(2026, 1, 1),
        admin=admin,
    )


class FakePessoaService:
    """Serve only fictitious in-memory people; it performs no database access."""

    def __init__(self) -> None:
        self.pessoas = {
            USER_ID: _fake_pessoa(USER_ID, "user@example.com"),
            ADMIN_ID: _fake_pessoa(ADMIN_ID, "admin@example.com", admin=True),
            OTHER_USER_ID: _fake_pessoa(OTHER_USER_ID, "other@example.com"),
        }

    async def buscar_por_id(self, id_pessoa: UUID) -> FakePessoa:
        """Return one fictitious person."""
        return self.pessoas[id_pessoa]

    async def listar(self) -> list[FakePessoa]:
        """Return all fictitious people."""
        return list(self.pessoas.values())

    @staticmethod
    def to_dict(pessoa: FakePessoa) -> dict[str, object]:
        """Serialize the fake with the same public shape as PessoaService."""
        return asdict(pessoa)


class FakeSessaoService:
    """Authenticates two local fake tokens and never contacts external services."""

    def __init__(self, pessoas: dict[UUID, FakePessoa]) -> None:
        self.pessoas = pessoas
        self.pessoa_repo = self

    @staticmethod
    def _sessao(id_pessoa: UUID) -> Sessao:
        today = date(2026, 1, 1)
        return Sessao(
            id_sessao=1,
            fk_pessoa_id_pessoa=id_pessoa,
            token_hash="fictitious-token-hash",
            criada_em=today,
            expira_em=today + timedelta(days=1),
        )

    async def criar_por_email_senha(
        self,
        email: str,
        senha: str,
    ) -> tuple[Sessao, str]:
        """Return a deterministic local session for the public-login probe."""
        assert email == "user@example.com"
        assert senha == LOCAL_PASSWORD
        return self._sessao(USER_ID), "fictitious-login-token"

    async def validar(self, token: str) -> Sessao:
        """Resolve a fictitious USER or ADMIN bearer token."""
        try:
            id_pessoa = LOCAL_TOKENS[token]
        except KeyError as exc:
            raise ValueError("Token inválido ou expirado") from exc
        return self._sessao(id_pessoa)

    async def get_by_id(self, id_pessoa: UUID) -> FakePessoa | None:
        """Support get_current_user with the in-memory person collection."""
        return self.pessoas.get(id_pessoa)


def _headers(actor: Actor) -> dict[str, str]:
    if actor == "USER":
        return {"Authorization": "Bearer local-user-token"}
    if actor == "ADMIN":
        return {"Authorization": "Bearer local-admin-token"}
    return {}


def _dependency_calls(dependant: Dependant) -> list[object]:
    calls: list[object] = []
    for dependency in dependant.dependencies:
        calls.append(dependency.call)
        calls.extend(_dependency_calls(dependency))
    return calls


def _route(method: str, path: str) -> APIRoute:
    matches = [
        route
        for route in app.routes
        if isinstance(route, APIRoute)
        and route.path == path
        and method in route.methods
    ]
    assert len(matches) == 1, f"Expected one route for {method} {path}"
    return matches[0]


def _has_authentication_guard(route: APIRoute) -> bool:
    return any(
        call
        in {
            api_deps.get_current_user,
            api_deps.get_current_user_id,
            api_deps.require_admin,
        }
        or isinstance(call, HTTPBearer)
        for call in _dependency_calls(route.dependant)
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Build a client whose auth and person services are entirely in memory."""
    previous_overrides = app.dependency_overrides.copy()
    pessoa_service = FakePessoaService()
    auth_service = FakeSessaoService(pessoa_service.pessoas)

    app.dependency_overrides[api_deps.get_sessao_service] = lambda: auth_service
    app.dependency_overrides[sessao_routes.get_sessao_service] = lambda: auth_service
    app.dependency_overrides[pessoa_routes.get_pessoa_service] = lambda: pessoa_service

    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides = previous_overrides


def test_only_documented_public_endpoints_lack_authentication() -> None:
    """Keep the complete public allowlist small without calling any handler."""
    actual_public = {
        (method, route.path)
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in route.methods
        if not _has_authentication_guard(route)
    }
    assert actual_public == PUBLIC_ENDPOINTS


def test_catalog_mutations_use_the_central_admin_guard() -> None:
    """All plan and payment-type mutations must require ADMIN."""
    for method, path in CATALOG_ADMIN_ENDPOINTS:
        calls = _dependency_calls(_route(method, path).dependant)
        assert api_deps.require_admin in calls


@pytest.mark.parametrize("actor", ["ANONYMOUS", "USER", "ADMIN"])
def test_public_login_is_accessible_to_every_actor(
    client: TestClient,
    actor: Actor,
) -> None:
    """Login remains public, regardless of whether a bearer header is present."""
    response = client.post(
        "/api/v1/sessoes/login",
        headers=_headers(actor),
        json={"email": "user@example.com", "senha": LOCAL_PASSWORD},
    )

    assert response.status_code == 201, response.text


@pytest.mark.parametrize(
    ("actor", "id_pessoa", "expected_status"),
    [
        ("ANONYMOUS", USER_ID, 401),
        ("USER", USER_ID, 200),
        ("ADMIN", ADMIN_ID, 200),
    ],
)
def test_own_profile_matches_secureai_matrix(
    client: TestClient,
    actor: Actor,
    id_pessoa: UUID,
    expected_status: int,
) -> None:
    """Anonymous access is denied while authenticated actors read themselves."""
    response = client.get(
        f"/api/v1/pessoas/{id_pessoa}",
        headers=_headers(actor),
    )

    assert response.status_code == expected_status, response.text


@pytest.mark.parametrize(
    ("actor", "expected_status"),
    [
        ("ANONYMOUS", 401),
        ("USER", 403),
        ("ADMIN", 200),
    ],
)
def test_other_users_profile_matches_secureai_matrix(
    client: TestClient,
    actor: Actor,
    expected_status: int,
) -> None:
    """USER must not read another profile; the matrix permits ADMIN access."""
    response = client.get(
        f"/api/v1/pessoas/{OTHER_USER_ID}",
        headers=_headers(actor),
    )

    assert response.status_code == expected_status, response.text


@pytest.mark.parametrize(
    ("actor", "expected_status"),
    [
        ("ANONYMOUS", 401),
        ("USER", 403),
        ("ADMIN", 200),
    ],
)
def test_administrative_people_list_matches_secureai_matrix(
    client: TestClient,
    actor: Actor,
    expected_status: int,
) -> None:
    """Only ADMIN should reach the representative administrative route."""
    response = client.get("/api/v1/pessoas/", headers=_headers(actor))

    assert response.status_code == expected_status, response.text
