from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from uuid import UUID


@dataclass
class Pessoa:
    id_pessoa: UUID | None
    email: str
    senha_hash: str = field(repr=False)
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

    def __post_init__(self) -> None:
        for field_name, value in [
            ("email", self.email),
            ("senha_hash", self.senha_hash),
            ("nome", self.nome),
            ("telefone", self.telefone),
            ("genero", self.genero),
            ("estado", self.estado),
            ("cidade", self.cidade),
            ("rua", self.rua),
            ("numero", self.numero),
            ("cep", self.cep),
        ]:
            if value is None or (isinstance(value, str) and value.strip() == ""):
                raise ValueError(f"{field_name} é obrigatório")
