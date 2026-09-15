from typing import List, AsyncGenerator
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.database import async_session_maker
from app.comercial.repositories.assinatura_repository_impl import AssinaturaRepositoryImpl
from app.comercial.services.assinatura_service import AssinaturaService
from app.api.deps import get_current_user_id  # <-- NOVO: pega o id do usuário autenticado
from .assinatura_schema import (
    AssinaturaCreate,
    AssinaturaResponse,
    AssinaturaUpdate,
)

router = APIRouter(tags=["assinaturas"])


# -------------------------------------------------------------------------
# Dependências
# -------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_assinatura_service(
    session: AsyncSession = Depends(get_db),
) -> AssinaturaService:
    repo = AssinaturaRepositoryImpl(session)
    return AssinaturaService(repo)


# -------------------------------------------------------------------------
# Endpoints CRUD
# -------------------------------------------------------------------------

@router.post(
    "/",
    response_model=AssinaturaResponse,
    status_code=status.HTTP_201_CREATED,
)
async def criar_assinatura(
    assinatura: AssinaturaCreate,
    service: AssinaturaService = Depends(get_assinatura_service),
    user_id: UUID = Depends(get_current_user_id),  # <-- NOVO
) -> AssinaturaResponse:
    """Cria uma nova assinatura para o usuário autenticado."""
    try:
        dados = assinatura.model_dump()
        # Garante que a assinatura pertence ao usuário logado
        dados["fk_pessoa_id_pessoa"] = user_id  # <-- NOVO

        criada = await service.criar(dados)
        return AssinaturaResponse.model_validate(criada.__dict__)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/", response_model=List[AssinaturaResponse])
async def listar_assinaturas(
    service: AssinaturaService = Depends(get_assinatura_service),
    user_id: UUID = Depends(get_current_user_id),
) -> List[AssinaturaResponse]:
    """Lista as assinaturas do usuário autenticado."""
    try:
        assinaturas = await service.listar_por_pessoa(user_id)
        return [AssinaturaResponse.model_validate(a.__dict__) for a in assinaturas]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get(
    "/{id_assinatura}",
    response_model=AssinaturaResponse,
)
async def buscar_assinatura(
    id_assinatura: int,
    service: AssinaturaService = Depends(get_assinatura_service),
    user_id: UUID = Depends(get_current_user_id),  # <-- NOVO
) -> AssinaturaResponse:
    """Busca uma assinatura por ID, apenas se pertencer ao usuário autenticado."""
    try:
        assinatura = await service.buscar_por_id(id_assinatura)

        # Verifica se a assinatura pertence ao usuário logado  <-- NOVO
        if assinatura.fk_pessoa_id_pessoa != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Você não tem permissão para acessar esta assinatura",
            )

        return AssinaturaResponse.model_validate(assinatura.__dict__)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.patch(
    "/{id_assinatura}",
    response_model=AssinaturaResponse,
)
async def atualizar_assinatura(
    id_assinatura: int,
    assinatura: AssinaturaUpdate,
    service: AssinaturaService = Depends(get_assinatura_service),
    user_id: UUID = Depends(get_current_user_id),  # <-- NOVO
) -> AssinaturaResponse:
    """Atualiza parcialmente uma assinatura existente do usuário autenticado."""
    try:
        # Verifica se a assinatura pertence ao usuário antes de atualizar  <-- NOVO
        assinatura_atual = await service.buscar_por_id(id_assinatura)
        if assinatura_atual.fk_pessoa_id_pessoa != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Você não tem permissão para atualizar esta assinatura",
            )

        dados = assinatura.model_dump(exclude_unset=True)
        atualizada = await service.atualizar(id_assinatura, dados)
        return AssinaturaResponse.model_validate(atualizada.__dict__)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.delete("/{id_assinatura}")
async def remover_assinatura(
    id_assinatura: int,
    service: AssinaturaService = Depends(get_assinatura_service),
    user_id: UUID = Depends(get_current_user_id),  # <-- NOVO
):
    """Remove uma assinatura do usuário autenticado."""
    try:
        # Verifica se a assinatura pertence ao usuário antes de remover  <-- NOVO
        assinatura_atual = await service.buscar_por_id(id_assinatura)
        if assinatura_atual.fk_pessoa_id_pessoa != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Você não tem permissão para remover esta assinatura",
            )

        await service.remover(id_assinatura)
        return {"message": "Assinatura removida com sucesso"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


# -------------------------------------------------------------------------
# Regras adicionais: renovar / cancelar
# -------------------------------------------------------------------------

@router.post(
    "/{id_assinatura}/renovar",
    response_model=AssinaturaResponse,
)
async def renovar_assinatura(
    id_assinatura: int,
    meses: int = 1,
    service: AssinaturaService = Depends(get_assinatura_service),
    user_id: UUID = Depends(get_current_user_id),  # <-- NOVO
) -> AssinaturaResponse:
    """Renova uma assinatura existente do usuário autenticado."""
    try:
        # Verifica se a assinatura pertence ao usuário antes de renovar  <-- NOVO
        assinatura_atual = await service.buscar_por_id(id_assinatura)
        if assinatura_atual.fk_pessoa_id_pessoa != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Você não tem permissão para renovar esta assinatura",
            )

        renovada = await service.renovar(id_assinatura, meses)
        return AssinaturaResponse.model_validate(renovada.__dict__)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.put(
    "/{id_assinatura}/cancelar",
    response_model=AssinaturaResponse,
)
async def cancelar_assinatura(
    id_assinatura: int,
    service: AssinaturaService = Depends(get_assinatura_service),
    user_id: UUID = Depends(get_current_user_id),  # <-- NOVO
) -> AssinaturaResponse:
    """Cancela uma assinatura (status='cancelada') do usuário autenticado."""
    try:
        # Verifica se a assinatura pertence ao usuário antes de cancelar  <-- NOVO
        assinatura_atual = await service.buscar_por_id(id_assinatura)
        if assinatura_atual.fk_pessoa_id_pessoa != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Você não tem permissão para cancelar esta assinatura",
            )

        cancelada = await service.cancelar(id_assinatura)
        return AssinaturaResponse.model_validate(cancelada.__dict__)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
