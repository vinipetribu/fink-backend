from __future__ import annotations

import hashlib
import secrets
from datetime import date, timedelta
from typing import Any, Sequence
from uuid import UUID

from app.identidade.domain.sessao import Sessao as SessaoDomain
from app.identidade.mappers.sessao_mapper import orm_to_model, model_to_orm_new
from app.identidade.persistence.sessao_orm import SessaoORM
from app.identidade.repositories.sessao_repository import SessaoRepository
from app.identidade.repositories.pessoa_repository import PessoaRepository
from app.core.passwords import verify_password


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SessaoService:
    """Regras de negócio de Sessão, aderente ao schema de banco atual."""

    def __init__(self, sessao_repo: SessaoRepository, pessoa_repo: PessoaRepository) -> None:
        self.sessao_repo = sessao_repo
        self.pessoa_repo = pessoa_repo

    async def criar_por_email_senha(self, email: str, senha: str, *, dias_validez: int = 1) -> tuple[SessaoDomain, str]:
        """Autentica por email/senha, cria sessão e retorna (SessaoDomain, token_claro)."""
        pessoa = await self.pessoa_repo.get_by_email(email)
        if not pessoa or not verify_password(pessoa.senha_hash, senha):
            raise ValueError("Credenciais inválidas")

        token_claro = secrets.token_urlsafe(48)
        token_hash = _sha256(token_claro)

        hoje = date.today()
        expira = hoje + timedelta(days=dias_validez)

        dom = SessaoDomain(
            id_sessao=None,
            fk_pessoa_id_pessoa=pessoa.id_pessoa,
            token_hash=token_hash,
            criada_em=hoje,
            expira_em=expira,
        )
        orm = model_to_orm_new(dom)
        created = await self.sessao_repo.create(orm)
        return orm_to_model(created), token_claro

    async def validar(self, token_claro: str) -> SessaoDomain:
        """Valida o token: existe e não expirou."""
        await self.sessao_repo.purge_expired()
        token_hash = _sha256(token_claro)
        sessao = await self.sessao_repo.get_by_token_hash(token_hash)
        if not sessao:
            raise ValueError("Sessão inválida")
        if sessao.expira_em < date.today():
            await self.sessao_repo.delete_by_token_hash(token_hash)
            raise ValueError("Sessão expirada")
        return orm_to_model(sessao)

    async def encerrar_por_token(self, token_claro: str) -> None:
        token_hash = _sha256(token_claro)
        await self.sessao_repo.delete_by_token_hash(token_hash)

    async def encerrar_por_id(self, id_sessao: int) -> None:
        await self.sessao_repo.delete_by_id(id_sessao)

    async def encerrar_todas_de_pessoa(self, id_pessoa: UUID) -> int:
        return await self.sessao_repo.delete_all_for_pessoa(id_pessoa)

    async def listar_por_pessoa(self, id_pessoa: UUID) -> list[SessaoDomain]:
        itens = await self.sessao_repo.list_by_pessoa(id_pessoa)
        return [orm_to_model(i) for i in itens]

    # Utilitários compatíveis com PessoaService
    @staticmethod
    def to_dict(s: SessaoORM) -> dict[str, Any]:
        return {
            "id_sessao": s.id_sessao,
            "fk_pessoa_id_pessoa": s.fk_pessoa_id_pessoa,
            "criada_em": s.criada_em,
            "expira_em": s.expira_em,
        }

    @classmethod
    def list_to_dict(cls, sessoes: Sequence[SessaoORM]) -> list[dict[str, Any]]:
        return [cls.to_dict(x) for x in sessoes]
