"""Dependências compartilhadas da API."""
from typing import AsyncGenerator
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.identidade.persistence.pessoa_orm import PessoaORM
from app.identidade.repositories.pessoa_repository_impl import PessoaRepositoryImpl
from app.identidade.repositories.sessao_repository_impl import SessaoRepositoryImpl
from app.identidade.services.sessao_service import SessaoService
from app.core.security_logging import log_security_event
from app.shared.database import async_session_maker


security = HTTPBearer(auto_error=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Fornece uma sessão de banco de dados assíncrona."""
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_sessao_service(session: AsyncSession = Depends(get_db)) -> SessaoService:
    """Fornece o serviço de sessão/autenticação."""
    return SessaoService(SessaoRepositoryImpl(session), PessoaRepositoryImpl(session))


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    sessao_service: SessaoService = Depends(get_sessao_service),
) -> PessoaORM:
    """Validate the Bearer session and return its current local user."""
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token ausente ou inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        sessao = await sessao_service.validar(credentials.credentials)
        pessoa = await sessao_service.pessoa_repo.get_by_id(sessao.fk_pessoa_id_pessoa)
        if not pessoa:
            raise ValueError("Usuário da sessão não encontrado")
        request.state.security_user_id = pessoa.id_pessoa
        return pessoa
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user_id(current_user: PessoaORM = Depends(get_current_user)) -> UUID:
    """Return the authenticated user's identifier for ownership checks."""
    return current_user.id_pessoa


async def require_admin(
    request: Request,
    current_user: PessoaORM = Depends(get_current_user),
) -> PessoaORM:
    """Require the authenticated user to have the existing admin flag."""
    if not current_user.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso exclusivo para administradores",
        )
    log_security_event(
        "ADMIN_ACCESS",
        "ALLOWED",
        request,
        user_id=current_user.id_pessoa,
    )
    return current_user
