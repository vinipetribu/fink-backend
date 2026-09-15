from __future__ import annotations

from typing import List, AsyncGenerator
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.comercial.repositories.tipo_pagamento_repository_impl import TipoPagamentoRepositoryImpl
from app.comercial.services.tipo_pagamento_service import TipoPagamentoService
from app.identidade.persistence.pessoa_orm import PessoaORM
from app.shared.database import async_session_maker
from .tipo_pagamento_schema import (
    TipoPagamentoCreate,
    TipoPagamentoResponse,
    TipoPagamentoUpdate,
)

router = APIRouter(tags=["tipos-pagamento"])


# DB session
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


# Service DI
async def get_service(session: AsyncSession = Depends(get_db)) -> TipoPagamentoService:
    return TipoPagamentoService(TipoPagamentoRepositoryImpl(session))


@router.post("/", response_model=TipoPagamentoResponse, status_code=status.HTTP_201_CREATED)
async def create_tipo_pagamento(
    payload: TipoPagamentoCreate,
    service: TipoPagamentoService = Depends(get_service),
    _: PessoaORM = Depends(require_admin),
) -> TipoPagamentoResponse:
    try:
        created = await service.criar(payload.model_dump())
        return TipoPagamentoResponse.model_validate(created.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/", response_model=List[TipoPagamentoResponse])
async def list_tipos(
    service: TipoPagamentoService = Depends(get_service),
    _: PessoaORM = Depends(get_current_user),
) -> List[TipoPagamentoResponse]:
    try:
        itens = await service.listar()
        return [TipoPagamentoResponse.model_validate(i.__dict__) for i in itens]
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/{id_pagamento}", response_model=TipoPagamentoResponse)
async def get_by_id(
    id_pagamento: int,
    service: TipoPagamentoService = Depends(get_service),
    _: PessoaORM = Depends(get_current_user),
) -> TipoPagamentoResponse:
    try:
        item = await service.buscar_por_id(id_pagamento)
        return TipoPagamentoResponse.model_validate(item.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/by-tipo/{tipo}", response_model=TipoPagamentoResponse)
async def get_by_tipo(
    tipo: str,
    service: TipoPagamentoService = Depends(get_service),
    _: PessoaORM = Depends(get_current_user),
) -> TipoPagamentoResponse:
    try:
        item = await service.buscar_por_tipo(tipo)
        return TipoPagamentoResponse.model_validate(item.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.patch("/{id_pagamento}", response_model=TipoPagamentoResponse)
async def update_tipo(
    id_pagamento: int,
    payload: TipoPagamentoUpdate,
    service: TipoPagamentoService = Depends(get_service),
    _: PessoaORM = Depends(require_admin),
) -> TipoPagamentoResponse:
    try:
        updated = await service.atualizar(id_pagamento, payload.model_dump(exclude_unset=True))
        return TipoPagamentoResponse.model_validate(updated.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/{id_pagamento}")
async def delete_tipo(
    id_pagamento: int,
    service: TipoPagamentoService = Depends(get_service),
    _: PessoaORM = Depends(require_admin),
):
    try:
        await service.remover(id_pagamento)
        return {"message": "Tipo de pagamento removido com sucesso"}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
