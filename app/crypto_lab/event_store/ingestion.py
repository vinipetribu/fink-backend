"""Small, controlled synthetic event ingestion, independent of the live queue."""
import asyncio
import time
from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_admin
from app.core.settings import settings

router = APIRouter(prefix='/api/v1/crypto-lab/events', tags=['crypto-lab-events'])
MAX_EVENTS = 10000
BATCH_SIZE = 250
BATCH_TIMEOUT = 3
TOTAL_TIMEOUT = 20
_slot = Lock()
# Fixed metadata only; no request data is accepted.
CATEGORIES = (
    ('LOGIN_SUCCESS', '/api/v1/sessoes/login', 'SUCCESS'),
    ('LOGIN_FAILURE', '/api/v1/sessoes/login', 'FAILURE'),
    ('ACCESS_DENIED', '<security-route>', 'DENIED'),
    ('ADMIN_ACCESS', '<security-route>', 'ALLOWED'),
)


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    count: int = Field(ge=1, le=MAX_EVENTS)


@router.post('/synthetic-ingestions')
async def ingest(body: IngestRequest, _=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if not settings.crypto_lab_event_store_enabled:
        raise HTTPException(503, 'Armazenamento do laboratório indisponível')
    if not _slot.acquire(blocking=False):
        raise HTTPException(503, 'Ingestão indisponível')
    start = time.monotonic()
    run_id = uuid4()
    requested = body.count
    generated = persisted = unconfirmed = 0
    status = 'completed'
    try:
        while generated < requested:
            remaining = TOTAL_TIMEOUT - (time.monotonic() - start)
            if remaining <= 0:
                status = 'partial'
                break
            count = min(BATCH_SIZE, requested - generated)
            timestamp = datetime.now(timezone.utc)
            batch = []
            for i in range(generated, generated + count):
                kind, operation, result = CATEGORIES[i % len(CATEGORIES)]
                batch.append({'id': uuid4(), 'occurred_at': timestamp, 'origin': 'synthetic',
                              'event_type': kind, 'operation': operation, 'result': result,
                              'duration_ms': None, 'run_id': run_id})
            generated += count
            try:
                async with asyncio.timeout(min(BATCH_TIMEOUT, remaining)):
                    await db.execute(text('''INSERT INTO lab_events
                        (id, occurred_at, origin, event_type, operation, result, duration_ms, run_id)
                        VALUES (:id, :occurred_at, :origin, :event_type, :operation, :result, :duration_ms, :run_id)'''), batch)
                    await db.commit()
                persisted += count
            except Exception:
                # A lost connection during COMMIT makes the batch outcome uncertain.
                unconfirmed += count
                status = 'partial'
                break
        return {'schema_version': 1, 'run_id': run_id, 'status': status, 'requested': requested,
                'generated': generated, 'persisted_confirmed': persisted, 'failed_or_unconfirmed': unconfirmed,
                'not_generated': requested - generated, 'duration_seconds': time.monotonic() - start,
                'batch_size': BATCH_SIZE, 'max_events': MAX_EVENTS}
    finally:
        _slot.release()
