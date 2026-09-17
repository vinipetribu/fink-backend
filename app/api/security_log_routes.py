"""Administrative access to recent in-memory security events."""

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel

from app.api.deps import require_admin
from app.core.security_logging import SecurityEvent, SecurityResult, get_security_logs
from app.identidade.persistence.pessoa_orm import PessoaORM

router = APIRouter(tags=["security-logs"])


class SecurityLogResponse(BaseModel):
    """Only the public allowlist of security-event fields."""

    timestamp: str
    event: SecurityEvent
    result: SecurityResult
    method: str
    route: str
    user_id: str | None = None


@router.get("/", response_model=list[SecurityLogResponse], response_model_exclude_none=True)
async def list_security_logs(
    response: Response,
    _: PessoaORM = Depends(require_admin),
) -> list[dict[str, str]]:
    """Read the last 200 events, newest first, after central ADMIN authorization."""
    response.headers["Cache-Control"] = "no-store"
    return get_security_logs()
