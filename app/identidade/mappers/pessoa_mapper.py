"""Mapper para conversão entre Pessoa (domain) e PessoaORM (persistence)."""

from __future__ import annotations

from app.identidade.domain.pessoa import Pessoa
from app.identidade.persistence.pessoa_orm import PessoaORM


def orm_to_model(orm: PessoaORM) -> Pessoa:
    """Converte PessoaORM (persistence) para Pessoa (domain)."""
    return Pessoa(
        id_pessoa=orm.id_pessoa,
        email=orm.email,
        senha_hash=orm.senha_hash,
        nome=orm.nome,
        data_nascimento=orm.data_nascimento,
        telefone=orm.telefone,
        genero=orm.genero,
        estado=orm.estado,
        cidade=orm.cidade,
        rua=orm.rua,
        numero=orm.numero,
        cep=orm.cep,
        data_criacao=orm.data_criacao,
        admin=orm.admin,
    )


def model_to_orm_new(model: Pessoa) -> PessoaORM:
    """Converte Pessoa (domain) para novo PessoaORM (persistence)."""
    return PessoaORM(
        email=model.email,
        senha_hash=model.senha_hash,
        nome=model.nome,
        data_nascimento=model.data_nascimento,
        telefone=model.telefone,
        genero=model.genero,
        estado=model.estado,
        cidade=model.cidade,
        rua=model.rua,
        numero=model.numero,
        cep=model.cep,
        admin=model.admin,
    )
