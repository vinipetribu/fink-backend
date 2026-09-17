"""Minimal structured security events written to stdout and a bounded memory buffer."""

from __future__ import annotations

import json
import logging
import sys
from collections import deque
from datetime import datetime, timezone
from threading import Lock
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

SECURITY_LOG_LIMIT = 200
SECURITY_LOG_FIELDS = frozenset({"timestamp", "event", "result", "method", "route", "user_id"})
_security_events: deque[dict[str, str]] = deque(maxlen=SECURITY_LOG_LIMIT)
_security_events_lock = Lock()

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

    with _security_events_lock:
        _security_events.append(payload)

    logger.info(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


def get_security_logs() -> list[dict[str, str]]:
    """Return an allowlisted snapshot, newest first, without exposing the buffer."""
    with _security_events_lock:
        return [
            {key: value for key, value in payload.items() if key in SECURITY_LOG_FIELDS}
            for payload in reversed(_security_events)
        ]
