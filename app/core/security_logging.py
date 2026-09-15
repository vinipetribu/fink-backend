"""Minimal structured security events written to stdout."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from fastapi import Request


SecurityEvent = Literal[
    "LOGIN_SUCCESS",
    "LOGIN_FAILURE",
    "ACCESS_DENIED",
    "ADMIN_ACCESS",
]
SecurityResult = Literal["SUCCESS", "FAILURE", "DENIED", "ALLOWED"]

logger = logging.getLogger("fink.security")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


def log_security_event(
    event: SecurityEvent,
    result: SecurityResult,
    request: Request,
    *,
    user_id: UUID | str | None = None,
) -> None:
    """Emit an allowlisted JSON event without request data or credentials."""
    route = request.scope.get("route")
    route_template = getattr(route, "path", "<unresolved>")
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        "result": result,
        "method": request.method,
        "route": route_template,
    }
    if user_id is not None:
        payload["user_id"] = str(user_id)

    logger.info(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
