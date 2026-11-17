"""ADMIN-only API for bounded synthetic experiments."""
from typing import Literal
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from app.api.deps import require_admin
from app.core.settings import settings
from .runner import Busy, RateLimited, coordinator

router = APIRouter(prefix="/api/v1/crypto-lab/attacks", tags=["crypto-lab-attacks"])


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    experiment: Literal["brute_force", "statistics", "differential", "avalanche"]


def enabled():
    if not settings.crypto_lab_experimental_enabled or not settings.crypto_lab_attacks_enabled:
        raise HTTPException(503, "Laboratório indisponível")


@router.post("/runs", status_code=202)
async def start_run(body: RunRequest, user=Depends(require_admin)):
    enabled()
    try:
        return coordinator.start(str(user.id_pessoa), body.experiment, settings.crypto_lab_attacks_timeout_seconds)
    except Busy:
        raise HTTPException(503, "Laboratório indisponível") from None
    except RateLimited:
        raise HTTPException(429, "Limite de requisições excedido") from None


@router.get("/runs/{run_id}")
async def get_run(run_id: UUID, user=Depends(require_admin)):
    enabled()
    try:
        result = coordinator.get(str(user.id_pessoa), str(run_id))
    except RateLimited:
        raise HTTPException(429, "Limite de requisições excedido") from None
    if result is None:
        raise HTTPException(404, "Não encontrado")
    return result
