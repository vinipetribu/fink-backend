from typing import List, AsyncGenerator
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.identidade.persistence.pessoa_orm import PessoaORM
from app.shared.database import async_session_maker
from ..repositories.solicitacao_pagamento_repository_impl import SolicitacaoPagamentoRepositoryImpl
from ..services.solicitacao_pagamento_service import SolicitacaoPagamentoService
from .solicitacao_pagamento_schema import (
    SolicitacaoPagamentoCreate,
    SolicitacaoPagamentoResponse,
)

router = APIRouter(tags=["solicitacoes_pagamento"])


# -------------------------------------------------------------------------
# Dependências de injeção
# -------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_solicitacao_pagamento_service(
    session: AsyncSession = Depends(get_db),
) -> SolicitacaoPagamentoService:
    repo = SolicitacaoPagamentoRepositoryImpl(session)
    return SolicitacaoPagamentoService(repo)


# -------------------------------------------------------------------------
# Endpoints CRUD
# -------------------------------------------------------------------------

@router.post(
    "/",
    response_model=SolicitacaoPagamentoResponse,
    status_code=status.HTTP_201_CREATED,
)
async def criar_solicitacao_pagamento(
    solicitacao: SolicitacaoPagamentoCreate,
    service: SolicitacaoPagamentoService = Depends(get_solicitacao_pagamento_service),
    _: PessoaORM = Depends(require_admin),
) -> SolicitacaoPagamentoResponse:
    """Cria uma nova solicitação de pagamento."""
    try:
        dados = solicitacao.model_dump()
        criada = await service.criar(dados)
        return SolicitacaoPagamentoResponse.model_validate(criada.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/", response_model=List[SolicitacaoPagamentoResponse])
async def listar_solicitacoes_pagamento(
    service: SolicitacaoPagamentoService = Depends(get_solicitacao_pagamento_service),
    _: PessoaORM = Depends(require_admin),
) -> List[SolicitacaoPagamentoResponse]:
    """Lista todas as solicitações de pagamento."""
    try:
        solicitacoes = await service.listar_todas()
        return [SolicitacaoPagamentoResponse.model_validate(s.__dict__) for s in solicitacoes]
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/{id_solicitacao}", response_model=SolicitacaoPagamentoResponse)
async def buscar_solicitacao_pagamento(
    id_solicitacao: int,
    service: SolicitacaoPagamentoService = Depends(get_solicitacao_pagamento_service),
    _: PessoaORM = Depends(require_admin),
) -> SolicitacaoPagamentoResponse:
    """Busca uma solicitação de pagamento por ID."""
    try:
        solicitacao = await service.buscar_por_id(id_solicitacao)
        return SolicitacaoPagamentoResponse.model_validate(solicitacao.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete("/{id_solicitacao}")
async def remover_solicitacao_pagamento(
    id_solicitacao: int,
    service: SolicitacaoPagamentoService = Depends(get_solicitacao_pagamento_service),
    _: PessoaORM = Depends(require_admin),
):
    """Remove uma solicitação de pagamento existente."""
    try:
        await service.remover(id_solicitacao)
        return {"message": "Solicitação de pagamento removida com sucesso"}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
