from pydantic import BaseModel, EmailStr, Field, ConfigDict
from datetime import date
from typing import Optional
from uuid import UUID


class PessoaBase(BaseModel):
    email: EmailStr
    nome: str
    data_nascimento: date
    telefone: str
    genero: str
    estado: str
    cidade: str
    rua: str
    numero: str
    cep: str


class PessoaCreate(PessoaBase):
    senha: str

    model_config = ConfigDict(extra="forbid")


class PessoaUpdate(BaseModel):
    email: Optional[EmailStr] = None
    telefone: Optional[str] = None
    estado: Optional[str] = None
    cidade: Optional[str] = None
    rua: Optional[str] = None
    numero: Optional[str] = None
    cep: Optional[str] = None
    senha: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class PessoaResponse(PessoaBase):
    id_pessoa: UUID = Field(..., description="ID único da pessoa (UUID)", examples=["550e8400-e29b-41d4-a716-446655440000"])
    data_criacao: date
    admin: bool = False

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id_pessoa": "550e8400-e29b-41d4-a716-446655440000",
                "email": "usuario@example.com",
                "nome": "João Silva",
                "data_nascimento": "1990-01-01",
                "telefone": "81999999999",
                "genero": "masculino",
                "estado": "PE",
                "cidade": "Recife",
                "rua": "Rua Exemplo",
                "numero": "123",
                "cep": "50000000",
                "data_criacao": "2025-01-01",
                "admin": False
            }
        }
    )
