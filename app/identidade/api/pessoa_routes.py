from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user_id
from ..services.pessoa_service import PessoaService
from ..repositories.pessoa_repository_impl import PessoaRepositoryImpl
from .pessoa_schema import PessoaCreate, PessoaResponse, PessoaUpdate

router = APIRouter(tags=["pessoas"])


async def get_pessoa_service(session: AsyncSession = Depends(get_db)) -> PessoaService:
    repository = PessoaRepositoryImpl(session)
    return PessoaService(repository)


@router.post("/", response_model=PessoaResponse, status_code=status.HTTP_201_CREATED)
async def create_pessoa(
    pessoa: PessoaCreate,
    service: PessoaService = Depends(get_pessoa_service),
) -> PessoaResponse:
    """Cria uma nova pessoa (cadastro)."""
    try:
        pessoa_dict = pessoa.model_dump()
        created = await service.criar(pessoa_dict)
        return PessoaResponse.model_validate(service.to_dict(created))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/", response_model=List[PessoaResponse])
async def list_pessoas(
    service: PessoaService = Depends(get_pessoa_service),
) -> List[PessoaResponse]:
    """Lista todas as pessoas (uso administrativo)."""
    try:
        pessoas = await service.listar()
        return [PessoaResponse.model_validate(service.to_dict(p)) for p in pessoas]
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/{id_pessoa}", response_model=PessoaResponse)
async def get_pessoa(
    id_pessoa: UUID = Path(..., description="ID único da pessoa (UUID)", example="550e8400-e29b-41d4-a716-446655440000"),
    service: PessoaService = Depends(get_pessoa_service),
    user_id: UUID = Depends(get_current_user_id),
) -> PessoaResponse:
    """
    Busca uma pessoa por ID.

    Só permite acessar os dados se o ID da rota for o mesmo ID do usuário autenticado.
    """
    if id_pessoa != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para acessar estes dados",
        )

    try:
        pessoa = await service.buscar_por_id(id_pessoa)
        return PessoaResponse.model_validate(service.to_dict(pessoa))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/by-email/{email}", response_model=PessoaResponse)
async def get_pessoa_by_email(
    email: str,
    service: PessoaService = Depends(get_pessoa_service),
) -> PessoaResponse:
    """Busca uma pessoa por email."""
    try:
        pessoa = await service.buscar_por_email(email)
        return PessoaResponse.model_validate(service.to_dict(pessoa))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.patch("/{id_pessoa}", response_model=PessoaResponse)
async def update_pessoa(
    id_pessoa: UUID = Path(..., description="ID único da pessoa (UUID)", example="550e8400-e29b-41d4-a716-446655440000"),
    pessoa: PessoaUpdate = ...,
    service: PessoaService = Depends(get_pessoa_service),
    user_id: UUID = Depends(get_current_user_id),
) -> PessoaResponse:
    """
    Atualiza parcialmente uma pessoa existente.

    Só permite atualizar se o ID da rota for o mesmo ID do usuário autenticado.
    """
    if id_pessoa != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para atualizar estes dados",
        )

    try:
        updated = await service.atualizar(id_pessoa, pessoa.model_dump(exclude_unset=True))
        return PessoaResponse.model_validate(service.to_dict(updated))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete("/{id_pessoa}")
async def delete_pessoa(
    id_pessoa: UUID = Path(..., description="ID único da pessoa (UUID)", example="550e8400-e29b-41d4-a716-446655440000"),
    service: PessoaService = Depends(get_pessoa_service),
    user_id: UUID = Depends(get_current_user_id),
):
    """
    Remove uma pessoa.

    Só permite remover se o ID da rota for o mesmo ID do usuário autenticado.
    """
    if id_pessoa != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para remover este cadastro",
        )

    try:
        await service.remover(id_pessoa)
        return {"message": "Pessoa removida com sucesso"}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
