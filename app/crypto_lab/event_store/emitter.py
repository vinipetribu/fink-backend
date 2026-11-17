"""Fail-open admission of allowlisted metadata to the local queue."""
from datetime import datetime, timezone
from app.core.settings import settings
from app.crypto_lab.event_store import events
from app.crypto_lab.event_store.queue import Event


def emit(event_type: str, operation: str, result: str, *, origin: str = 'observed') -> None:
    try:
        if not (settings.crypto_lab_enabled and settings.crypto_lab_event_store_enabled
                and not settings.debug and settings.environment.strip().lower() in {'development', 'test', 'testing', 'local'}):
            return
        events.submit(Event(origin=origin, event_type=event_type, operation=operation,
                            result=result, occurred_at=datetime.now(timezone.utc)))
    except Exception:
        # The application operation must not depend on the telemetry path.
        return
