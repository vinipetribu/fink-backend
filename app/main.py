"""FastAPI application entrypoint: sets up lifespan, CORS, and API v1 routes."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.routes import api_router
from app.api.csv_upload_routes import router as csv_upload_router
from app.api.security_log_routes import router as security_logs_router
from app.core.security_logging import log_security_event
from app.core.settings import settings
from app.shared.database import init_db
from app.shared.seed import seed_db


from app.providers.pluggy_client import PluggyClient
from app.api.pluggy_routes import router as pluggy_router

from app.alertas.api.routes import router as alertas_router
from app.identidade.api.pessoa_routes import router as pessoas_router
from app.metas.api.routes import router as metas_router
from app.comercial.api.plano_routes import router as planos_router
from app.identidade.api.sessao_routes import router as sessoes_router
from app.comercial.api.assinatura_routes import router as assinaturas_router
from app.comercial.api.tipo_pagamento_routes import router as tipos_pagamento_router
from app.comercial.api.solicitacao_pagamento_routes import (
    router as solicitacoes_pagamento_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # DB
    await init_db(create_all=(settings.environment != "production"))
    # Seed (sugiro rodar só fora de produção)
    if settings.environment != "production":
        await seed_db()

    # Disabled by default: do not instantiate or authenticate an external client.
    app.state.pluggy_client = None
    if settings.pluggy_enabled:
        app.state.pluggy_client = PluggyClient(
            base_url=settings.pluggy_base_url,
            client_id=settings.pluggy_client_id,
            client_secret=settings.pluggy_client_secret,
        )

    try:
        yield
    finally:
        client = getattr(app.state, "pluggy_client", None)
        if client:
            await client.close()



app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    debug=settings.debug,
    lifespan=lifespan,
)

security = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_access_denied(request: Request, call_next):
    """Emit one minimal event for denied non-login requests."""
    response = await call_next(request)
    if response.status_code in {401, 403} and request.url.path != "/api/v1/sessoes/login":
        log_security_event(
            "ACCESS_DENIED",
            "DENIED",
            request,
            user_id=getattr(request.state, "security_user_id", None),
        )
    return response

app.include_router(api_router, prefix="/api/v1")
app.include_router(security_logs_router, prefix="/api/v1/security-logs")
app.include_router(pessoas_router, prefix="/api/v1/pessoas")
app.include_router(alertas_router, prefix="/api/v1/alertas")
app.include_router(metas_router, prefix="/api/v1/metas")
app.include_router(planos_router, prefix="/api/v1/planos")
app.include_router(sessoes_router, prefix="/api/v1/sessoes")
app.include_router(assinaturas_router, prefix="/api/v1/assinaturas")
app.include_router(tipos_pagamento_router, prefix="/api/v1/tipos-pagamento")
app.include_router(solicitacoes_pagamento_router, prefix="/api/v1/solicitacoes-pagamento")
app.include_router(pluggy_router)
app.include_router(csv_upload_router)



@app.get("/")
async def root() -> dict[str, Any]:
    """Return basic app metadata for quick inspection."""
    return {
        "message": f"Welcome to {settings.app_name}",
        "version": settings.app_version,
        "environment": settings.environment,
    }


@app.get("/health")
async def health_check() -> dict[str, Any]:
    """Liveness probe endpoint used by containers and load balancers."""
    return {"status": "healthy", "service": settings.app_name}
