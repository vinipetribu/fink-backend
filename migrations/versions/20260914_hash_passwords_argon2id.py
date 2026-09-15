"""rename password column and hash existing passwords with Argon2id

Revision ID: 20260914_argon2id
Revises: 20250116_refactor_alerta
Create Date: 2026-09-14 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op
from argon2 import PasswordHasher
from argon2.low_level import Type
import sqlalchemy as sa


revision: str = "20260914_argon2id"
down_revision: str | Sequence[str] | None = "20250116_refactor_alerta"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Rename the credential column and hash every legacy plaintext value."""
    op.alter_column(
        "pessoa",
        "senha",
        new_column_name="senha_hash",
        existing_type=sa.String(),
        existing_nullable=False,
    )

    connection = op.get_bind()
    password_hasher = PasswordHasher(type=Type.ID)
    pessoas = connection.execute(sa.text("SELECT id_pessoa, senha_hash FROM pessoa")).mappings()

    for pessoa in pessoas:
        current_value = pessoa["senha_hash"]
        if not current_value.startswith("$argon2id$"):
            connection.execute(
                sa.text("UPDATE pessoa " "SET senha_hash = :senha_hash " "WHERE id_pessoa = :id_pessoa"),
                {
                    "senha_hash": password_hasher.hash(current_value),
                    "id_pessoa": pessoa["id_pessoa"],
                },
            )


def downgrade() -> None:
    """Restore the old column name without attempting to recover plaintext."""
    op.alter_column(
        "pessoa",
        "senha_hash",
        new_column_name="senha",
        existing_type=sa.String(),
        existing_nullable=False,
    )
