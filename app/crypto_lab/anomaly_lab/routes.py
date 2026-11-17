"""Local ADMIN-only synthetic anomaly experiments."""
from uuid import UUID
from datetime import datetime
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import require_admin, get_db
from app.core.settings import settings
from app.crypto_lab.event_store.routes import filters, decode_cursor, encode_cursor, execute
from .runner import Busy, NotFound, RateLimited, coordinator
from .schemas import DatasetRequest, RunRequest

router = APIRouter(prefix='/api/v1/crypto-lab/anomalies', tags=['crypto-lab-anomalies'])


def enabled():
    if not settings.crypto_lab_anomaly_enabled:
        raise HTTPException(503, 'Laboratório indisponível')


def handle(error):
    if isinstance(error, Busy): raise HTTPException(503, 'Laboratório indisponível') from None
    if isinstance(error, RateLimited): raise HTTPException(429, 'Limite de requisições excedido') from None
    raise HTTPException(404, 'Não encontrado') from None


def history_filters(start: datetime | None = None, end: datetime | None = None,
                    state: Literal['completed', 'failed', 'timed_out'] | None = None):
    enabled()
    values = filters(start=start, end=end, origin=None, event_type=None, result=None)
    return {'start': values['start'], 'end': values['end'], 'state': state}


@router.get('/history')
async def history(_=Depends(require_admin), f=Depends(history_filters), db: AsyncSession = Depends(get_db),
                  limit: int = Query(10, ge=1, le=20), cursor: str | None = Query(None, max_length=256)):
    params = dict(f, limit=limit + 1)
    cursor_clause = ''
    if cursor:
        stamp, identifier = decode_cursor(cursor)
        if not f['start'] <= stamp < f['end']:
            raise HTTPException(422, 'Cursor fora do período')
        params.update(cursor_time=stamp, cursor_id=identifier)
        cursor_clause = 'AND (finished_at, id) < (:cursor_time, :cursor_id)'
    rows = (await execute(db, f'''SELECT id, origin, catalog, model_versions, state, started_at, finished_at,
        processed_volume, metrics_version, metrics FROM lab_anomaly_runs
        WHERE finished_at >= :start AND finished_at < :end
        AND (CAST(:state AS text) IS NULL OR state = :state) {cursor_clause}
        ORDER BY finished_at DESC, id DESC LIMIT :limit''', params)).mappings().all()
    items = [dict(row) for row in rows[:limit]]
    next_cursor = encode_cursor(items[-1]['finished_at'], items[-1]['id']) if len(rows) > limit else None
    return {'schema_version': 1, 'period': {'start': f['start'], 'end_exclusive': f['end']},
            'state': f['state'], 'items': items, 'next_cursor': next_cursor, 'limit': limit}


@router.post('/datasets', status_code=202)
async def create_dataset(body: DatasetRequest, user=Depends(require_admin)):
    enabled()
    try: return coordinator.start(str(user.id_pessoa), 'dataset', settings.crypto_lab_anomaly_timeout_seconds)
    except (Busy, RateLimited, NotFound) as error: handle(error)


@router.post('/runs', status_code=202)
async def create_run(body: RunRequest, user=Depends(require_admin)):
    enabled()
    try: return coordinator.start(str(user.id_pessoa), 'run', settings.crypto_lab_anomaly_timeout_seconds, str(body.dataset_id))
    except (Busy, RateLimited, NotFound) as error: handle(error)


@router.get('/jobs/{job_id}')
async def get_job(job_id: UUID, user=Depends(require_admin)):
    enabled()
    try: return coordinator.read(str(user.id_pessoa), coordinator.jobs, str(job_id))
    except (RateLimited, NotFound) as error: handle(error)


@router.get('/results/{result_id}')
async def get_result(result_id: UUID, user=Depends(require_admin)):
    enabled()
    try: return coordinator.read(str(user.id_pessoa), coordinator.results, str(result_id))
    except (RateLimited, NotFound) as error: handle(error)
