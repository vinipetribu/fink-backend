from __future__ import annotations

from datetime import date
from uuid import UUID, uuid4

from sqlalchemy import Boolean, Date, String, func
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.shared.database import Base


class PessoaORM(Base):
    __tablename__ = "pessoa"

    id_pessoa: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    email: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    senha_hash: Mapped[str] = mapped_column(String, nullable=False)
    nome: Mapped[str] = mapped_column(String, nullable=False)
    data_nascimento: Mapped[date] = mapped_column(Date, nullable=False)
    telefone: Mapped[str] = mapped_column(String, nullable=False)
    genero: Mapped[str] = mapped_column(String, nullable=False)
    estado: Mapped[str] = mapped_column(String, nullable=False)
    cidade: Mapped[str] = mapped_column(String, nullable=False)
    rua: Mapped[str] = mapped_column(String, nullable=False)
    numero: Mapped[str] = mapped_column(String, nullable=False)
    cep: Mapped[str] = mapped_column(String, nullable=False)
    data_criacao: Mapped[date] = mapped_column(Date, nullable=False, server_default=func.current_date())
    admin: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="0")

    # 1 Pessoa -> N Sessões / Metas / Alertas / Assinaturas
    sessoes: Mapped[list["SessaoORM"]] = relationship(
        "SessaoORM",
        back_populates="pessoa",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    metas: Mapped[list["MetaORM"]] = relationship(
        "MetaORM",
        back_populates="pessoa",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    alertas: Mapped[list["AlertaORM"]] = relationship(
        "AlertaORM",
        back_populates="pessoa",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    assinaturas: Mapped[list["AssinaturaORM"]] = relationship(
        "AssinaturaORM",
        back_populates="pessoa",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<PessoaORM id={self.id_pessoa} email={self.email}>"
