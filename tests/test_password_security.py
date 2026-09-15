"""Security tests for password hashing and public registration."""

from collections.abc import Iterator
from datetime import date
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.passwords import verify_password
from app.identidade.api.pessoa_routes import get_pessoa_service
from app.identidade.persistence.pessoa_orm import PessoaORM
from app.identidade.persistence.sessao_orm import SessaoORM
from app.identidade.services.pessoa_service import PessoaService
from app.identidade.services.sessao_service import SessaoService
from app.main import app


PLAIN_PASSWORD = "same-local-test-password"


def pessoa_payload(email: str) -> dict[str, Any]:
    """Return fictitious registration data for a test account."""
    return {
        "email": email,
        "senha": PLAIN_PASSWORD,
        "nome": "Pessoa de Teste",
        "data_nascimento": date(1990, 1, 1),
        "telefone": "81999999999",
        "genero": "nao_informado",
        "estado": "PE",
        "cidade": "Recife",
        "rua": "Rua de Teste",
        "numero": "123",
        "cep": "50000000",
    }


class FakePessoaRepository:
    """In-memory repository that exposes the value handed to persistence."""

    def __init__(self) -> None:
        self.pessoas: dict[UUID, PessoaORM] = {}

    async def create(self, pessoa: PessoaORM) -> PessoaORM:
        pessoa.id_pessoa = pessoa.id_pessoa or uuid4()
        pessoa.data_criacao = pessoa.data_criacao or date.today()
        self.pessoas[pessoa.id_pessoa] = pessoa
        return pessoa

    async def list_all(self) -> list[PessoaORM]:
        return list(self.pessoas.values())

    async def get_by_id(self, id_pessoa: UUID) -> PessoaORM | None:
        return self.pessoas.get(id_pessoa)

    async def get_by_email(self, email: str) -> PessoaORM | None:
        return next((pessoa for pessoa in self.pessoas.values() if pessoa.email == email), None)

    async def update(self, pessoa: PessoaORM) -> PessoaORM:
        self.pessoas[pessoa.id_pessoa] = pessoa
        return pessoa

    async def delete(self, id_pessoa: UUID) -> None:
        self.pessoas.pop(id_pessoa, None)


class FakeSessaoRepository:
    """Minimal in-memory session repository for login tests."""

    def __init__(self) -> None:
        self.sessoes: list[SessaoORM] = []

    async def create(self, sessao: SessaoORM) -> SessaoORM:
        sessao.id_sessao = len(self.sessoes) + 1
        self.sessoes.append(sessao)
        return sessao


@pytest.fixture
def pessoa_repo() -> FakePessoaRepository:
    return FakePessoaRepository()


@pytest.fixture
def pessoa_service(pessoa_repo: FakePessoaRepository) -> PessoaService:
    return PessoaService(pessoa_repo)


@pytest.fixture
def api_client(pessoa_service: PessoaService) -> Iterator[TestClient]:
    app.dependency_overrides[get_pessoa_service] = lambda: pessoa_service
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_persisted_password_differs_from_plaintext(
    pessoa_service: PessoaService,
    pessoa_repo: FakePessoaRepository,
) -> None:
    """Persistence never receives the plaintext credential."""
    await pessoa_service.criar(pessoa_payload("different@example.com"))

    persisted = next(iter(pessoa_repo.pessoas.values()))
    assert persisted.senha_hash != PLAIN_PASSWORD


@pytest.mark.asyncio
async def test_persisted_password_uses_argon2id_format(
    pessoa_service: PessoaService,
    pessoa_repo: FakePessoaRepository,
) -> None:
    """Persistence receives an Argon2id encoded hash."""
    await pessoa_service.criar(pessoa_payload("argon2id@example.com"))

    persisted = next(iter(pessoa_repo.pessoas.values()))
    assert persisted.senha_hash.startswith("$argon2id$")
    assert verify_password(persisted.senha_hash, PLAIN_PASSWORD)


@pytest.mark.asyncio
async def test_same_password_receives_distinct_salted_hashes(
    pessoa_service: PessoaService,
    pessoa_repo: FakePessoaRepository,
) -> None:
    """A unique salt makes equal passwords produce different hashes."""
    await pessoa_service.criar(pessoa_payload("first@example.com"))
    await pessoa_service.criar(pessoa_payload("second@example.com"))

    first, second = pessoa_repo.pessoas.values()
    assert first.senha_hash != second.senha_hash


@pytest.mark.asyncio
async def test_login_accepts_correct_password(
    pessoa_service: PessoaService,
    pessoa_repo: FakePessoaRepository,
) -> None:
    """Login verifies the Argon2id hash and preserves the Bearer-token flow."""
    pessoa = await pessoa_service.criar(pessoa_payload("login@example.com"))
    sessao_repo = FakeSessaoRepository()
    service = SessaoService(sessao_repo, pessoa_repo)

    sessao, token = await service.criar_por_email_senha(
        pessoa.email,
        PLAIN_PASSWORD,
    )

    assert token
    assert sessao.fk_pessoa_id_pessoa == pessoa.id_pessoa


@pytest.mark.asyncio
async def test_login_rejects_incorrect_password(
    pessoa_service: PessoaService,
    pessoa_repo: FakePessoaRepository,
) -> None:
    """Login rejects a password that does not match the persisted hash."""
    pessoa = await pessoa_service.criar(pessoa_payload("wrong-password@example.com"))
    service = SessaoService(FakeSessaoRepository(), pessoa_repo)

    with pytest.raises(ValueError, match="Credenciais inválidas"):
        await service.criar_por_email_senha(pessoa.email, "incorrect-password")


def test_registration_response_never_contains_password_hash(
    api_client: TestClient,
    pessoa_repo: FakePessoaRepository,
) -> None:
    """The public API response omits plaintext and persisted credential fields."""
    response = api_client.post(
        "/api/v1/pessoas/",
        json={
            **pessoa_payload("response@example.com"),
            "data_nascimento": "1990-01-01",
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    persisted = next(iter(pessoa_repo.pessoas.values()))
    assert "senha" not in body
    assert "senha_hash" not in body
    assert persisted.senha_hash not in response.text
    assert PLAIN_PASSWORD not in response.text


def test_public_registration_rejects_admin_field(api_client: TestClient) -> None:
    """A public caller cannot select the administrative role."""
    response = api_client.post(
        "/api/v1/pessoas/",
        json={
            **pessoa_payload("admin-attempt@example.com"),
            "data_nascimento": "1990-01-01",
            "admin": True,
        },
    )

    assert response.status_code == 422
