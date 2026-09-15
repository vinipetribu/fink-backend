from typing import List, AsyncGenerator
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.identidade.persistence.pessoa_orm import PessoaORM
from app.shared.database import async_session_maker
from ..repositories.plano_repository_impl import PlanoRepositoryImpl
from ..services.plano_service import PlanoService
from .plano_schema import PlanoCreate, PlanoResponse, PlanoUpdate


router = APIRouter(tags=["planos"])


# -------------------------------------------------------------------------
# Dependências de injeção
# -------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_plano_service(session: AsyncSession = Depends(get_db)) -> PlanoService:
    repo = PlanoRepositoryImpl(session)
    return PlanoService(repo)


# -------------------------------------------------------------------------
# Endpoints
# -------------------------------------------------------------------------

@router.post("/", response_model=PlanoResponse, status_code=status.HTTP_201_CREATED)
async def criar_plano(
    plano: PlanoCreate,
    service: PlanoService = Depends(get_plano_service),
    _: PessoaORM = Depends(require_admin),
) -> PlanoResponse:
    """Cria um novo plano"""
    try:
        plano_dict = plano.model_dump()
        criado = await service.criar(plano_dict)
        return PlanoResponse.model_validate(criado.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/", response_model=List[PlanoResponse])
async def listar_planos(service: PlanoService = Depends(get_plano_service)) -> List[PlanoResponse]:
    """Lista todos os planos"""
    try:
        planos = await service.listar_todos()
        return [PlanoResponse.model_validate(p.__dict__) for p in planos]
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/{id_plano}", response_model=PlanoResponse)
async def buscar_plano(id_plano: int, service: PlanoService = Depends(get_plano_service)) -> PlanoResponse:
    """Busca um plano por ID"""
    try:
        plano = await service.buscar_por_id(id_plano)
        return PlanoResponse.model_validate(plano.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.patch("/{id_plano}", response_model=PlanoResponse)
async def atualizar_plano(
    id_plano: int,
    plano: PlanoUpdate,
    service: PlanoService = Depends(get_plano_service),
    _: PessoaORM = Depends(require_admin),
) -> PlanoResponse:
    """Atualiza parcialmente um plano"""
    try:
        atualizado = await service.atualizar(id_plano, plano.model_dump(exclude_unset=True))
        return PlanoResponse.model_validate(atualizado.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete("/{id_plano}")
async def remover_plano(
    id_plano: int,
    service: PlanoService = Depends(get_plano_service),
    _: PessoaORM = Depends(require_admin),
):
    """Remove um plano existente"""
    try:
        await service.remover(id_plano)
        return {"message": "Plano removido com sucesso"}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.put("/{id_plano}/ativar", response_model=PlanoResponse)
async def ativar_plano(
    id_plano: int,
    service: PlanoService = Depends(get_plano_service),
    _: PessoaORM = Depends(require_admin),
) -> PlanoResponse:
    """Ativa um plano existente"""
    try:
        plano = await service.ativar(id_plano)
        return PlanoResponse.model_validate(plano.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.put("/{id_plano}/desativar", response_model=PlanoResponse)
async def desativar_plano(
    id_plano: int,
    service: PlanoService = Depends(get_plano_service),
    _: PessoaORM = Depends(require_admin),
) -> PlanoResponse:
    """Desativa um plano existente"""
    try:
        plano = await service.desativar(id_plano)
        return PlanoResponse.model_validate(plano.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
