from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.api.deps import get_current_user, get_sessao_service
from app.identidade.persistence.pessoa_orm import PessoaORM
from app.identidade.services.sessao_service import SessaoService
from .sessao_schema import LoginRequest, SessaoCriadaResponse, SessaoResponse

router = APIRouter(tags=["sessoes"])
security = HTTPBearer(auto_error=False)  # faz o Swagger exibir o cadeado "Authorize"

@router.post("/login", response_model=SessaoCriadaResponse, status_code=status.HTTP_201_CREATED)
async def login(payload: LoginRequest, service: SessaoService = Depends(get_sessao_service)) -> SessaoCriadaResponse:
    """Autentica, cria sessão e retorna o token em claro uma única vez."""
    try:
        sessao, token = await service.criar_por_email_senha(payload.email, payload.senha)
        data = {
            "id_sessao": sessao.id_sessao,
            "fk_pessoa_id_pessoa": sessao.fk_pessoa_id_pessoa,
            "token": token,
            "criada_em": sessao.criada_em,
            "expira_em": sessao.expira_em,
        }
        return SessaoCriadaResponse.model_validate(data)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/validar", response_model=SessaoResponse)
async def validar(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    service: SessaoService = Depends(get_sessao_service),
) -> SessaoResponse:
    """Valida um Bearer token e retorna dados da sessão (sem o token)."""
    try:
        if not credentials or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token ausente")
        token = credentials.credentials
        sessao = await service.validar(token)
        return SessaoResponse.model_validate(sessao.__dict__)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.delete("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    service: SessaoService = Depends(get_sessao_service),
):
    """Remove a sessão associada ao Bearer token."""
    try:
        if not credentials or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token ausente")
        token = credentials.credentials
        await service.encerrar_por_token(token)
        return
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/pessoa/{id_pessoa}", response_model=List[SessaoResponse])
async def listar_por_pessoa(
    id_pessoa: UUID = Path(..., description="ID único da pessoa (UUID)", example="550e8400-e29b-41d4-a716-446655440000"),
    service: SessaoService = Depends(get_sessao_service),
    current_user: PessoaORM = Depends(get_current_user),
) -> List[SessaoResponse]:
    """Lista sessões da pessoa."""
    if id_pessoa != current_user.id_pessoa and not current_user.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para acessar estas sessões",
        )
    try:
        itens = await service.listar_por_pessoa(id_pessoa)
        return [SessaoResponse.model_validate(i.__dict__) for i in itens]
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.delete("/pessoa/{id_pessoa}/todas", status_code=status.HTTP_200_OK)
async def encerrar_todas(
    id_pessoa: UUID = Path(..., description="ID único da pessoa (UUID)", example="550e8400-e29b-41d4-a716-446655440000"),
    service: SessaoService = Depends(get_sessao_service),
    current_user: PessoaORM = Depends(get_current_user),
):
    """Remove todas as sessões da pessoa."""
    if id_pessoa != current_user.id_pessoa and not current_user.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para encerrar estas sessões",
        )
    try:
        count = await service.encerrar_todas_de_pessoa(id_pessoa)
        return {"removidas": count}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
