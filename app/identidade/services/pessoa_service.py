from datetime import date
from typing import Sequence, Any
from uuid import UUID

from app.identidade.domain.pessoa import Pessoa
from app.core.passwords import hash_password
from app.identidade.persistence.pessoa_orm import PessoaORM
from app.identidade.repositories.pessoa_repository import PessoaRepository
from app.identidade.mappers.pessoa_mapper import orm_to_model, model_to_orm_new


class PessoaService:
    """Camada de regras de negócio de Pessoa."""

    def __init__(self, repo: PessoaRepository):
        self.repo = repo

    async def criar(self, pessoa_data: dict[str, Any]) -> Pessoa:
        """Cria uma nova pessoa."""
        try:
            # Remove campos que não devem ser fornecidos no create
            pessoa_data.pop("id_pessoa", None)
            pessoa_data.pop("data_criacao", None)
            pessoa_data.pop("admin", None)
            pessoa_data.pop("senha_hash", None)

            senha = pessoa_data.pop("senha")

            # Create domain model with defaults
            pessoa = Pessoa(
                id_pessoa=None,
                data_criacao=date.today(),
                admin=False,
                senha_hash=hash_password(senha),
                **pessoa_data,
            )

            # Verificar se já existe pessoa com este email
            existing = await self.repo.get_by_email(pessoa.email)
            if existing:
                raise ValueError("Email já cadastrado")

            # Convert to ORM and save
            pessoa_orm = model_to_orm_new(pessoa)
            created_orm = await self.repo.create(pessoa_orm)

            # Convert back to domain model
            return orm_to_model(created_orm)
        except Exception as e:
            raise ValueError(f"Erro ao criar pessoa: {str(e)}")

    async def listar(self) -> list[Pessoa]:
        """Lista todas as pessoas cadastradas."""
        pessoas_orm = await self.repo.list_all()
        return [orm_to_model(p) for p in pessoas_orm] if pessoas_orm else []

    async def buscar_por_id(self, id_pessoa: UUID) -> Pessoa:
        """Busca uma pessoa por ID."""
        pessoa_orm = await self.repo.get_by_id(id_pessoa)
        if not pessoa_orm:
            raise ValueError("Pessoa não encontrada.")
        return orm_to_model(pessoa_orm)

    async def buscar_por_email(self, email: str) -> Pessoa:
        """Busca uma pessoa por email."""
        pessoa_orm = await self.repo.get_by_email(email)
        if not pessoa_orm:
            raise ValueError("Nenhum cadastro encontrado para esse e-mail.")
        return orm_to_model(pessoa_orm)

    async def atualizar(self, id_pessoa: UUID, pessoa_data: dict[str, Any]) -> Pessoa:
        """Atualiza uma pessoa existente."""
        try:
            # Verifica se a pessoa existe
            pessoa_atual = await self.repo.get_by_id(id_pessoa)
            if not pessoa_atual:
                raise ValueError("Pessoa não encontrada")

            # Campos que não podem ser modificados
            campos_protegidos = {
                "id_pessoa",
                "data_criacao",
                "nome",
                "data_nascimento",
                "genero",
                "admin",
                "senha_hash",
            }
            campos_invalidos = campos_protegidos.intersection(pessoa_data.keys())
            if campos_invalidos:
                raise ValueError(f"Não é permitido modificar os seguintes campos: {', '.join(campos_invalidos)}")

            # Atualiza apenas os campos fornecidos
            for key, value in pessoa_data.items():
                if value is not None:
                    if key == "senha":
                        pessoa_atual.senha_hash = hash_password(value)
                    else:
                        setattr(pessoa_atual, key, value)

            # Atualiza no banco
            updated_orm = await self.repo.update(pessoa_atual)
            return orm_to_model(updated_orm)
        except Exception as e:
            raise ValueError(f"Erro ao atualizar pessoa: {str(e)}")

    async def remover(self, id_pessoa: UUID) -> None:
        """Remove uma pessoa existente."""
        pessoa = await self.repo.get_by_id(id_pessoa)
        if not pessoa:
            raise ValueError("Pessoa não encontrada")
        await self.repo.delete(id_pessoa)

    @staticmethod
    def to_dict(p: Pessoa | PessoaORM) -> dict[str, Any]:
        """Converte uma pessoa para um dicionário seguro para respostas da API."""
        return {
            "id_pessoa": p.id_pessoa,
            "email": p.email,
            "nome": p.nome,
            "data_nascimento": p.data_nascimento,
            "telefone": p.telefone,
            "genero": p.genero,
            "estado": p.estado,
            "cidade": p.cidade,
            "rua": p.rua,
            "numero": p.numero,
            "cep": p.cep,
            "data_criacao": p.data_criacao,
            "admin": p.admin,
        }

    @classmethod
    def list_to_dict(cls, pessoas: Sequence[PessoaORM]) -> list[dict[str, Any]]:
        """Converte uma lista de PessoaORM para lista de dicionários."""
        return [cls.to_dict(p) for p in pessoas]
