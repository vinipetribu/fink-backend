"""Bounded ADMIN queries over sanitized SecureAI Lab events."""
import asyncio
import base64
import binascii
import json
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_admin
from app.core.settings import settings
from app.crypto_lab.event_store.queue import EVENT_TYPES, RESULTS

router = APIRouter(prefix='/api/v1/crypto-lab/events', tags=['crypto-lab-events'])
MAX_DAYS = 31
MAX_LIMIT = 100


def filters(start: datetime | None = None, end: datetime | None = None,
            origin: Literal['observed', 'synthetic'] | None = None,
            event_type: str | None = Query(None, max_length=64),
            result: str | None = Query(None, max_length=32)):
    if not settings.crypto_lab_event_store_enabled:
        raise HTTPException(503, 'Armazenamento do laboratório indisponível')
    now = datetime.now(timezone.utc)
    if start is None and end is None:
        end = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        start = end - timedelta(days=7)
    elif start is None:
        if end.tzinfo is None or end.utcoffset() is None:
            raise HTTPException(422, 'Datas devem incluir fuso horário')
        start = end - timedelta(days=7)
    elif end is None:
        if start.tzinfo is None or start.utcoffset() is None:
            raise HTTPException(422, 'Datas devem incluir fuso horário')
        end = start + timedelta(days=7)
    if start.tzinfo is None or end.tzinfo is None or start.utcoffset() is None or end.utcoffset() is None:
        raise HTTPException(422, 'Datas devem incluir fuso horário')
    start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
    if end <= start or end - start > timedelta(days=MAX_DAYS):
        raise HTTPException(422, 'Período inválido ou superior a 31 dias')
    if event_type is not None and event_type not in EVENT_TYPES or result is not None and result not in RESULTS:
        raise HTTPException(422, 'Filtro inválido')
    return {'start': start, 'end': end, 'origin': origin, 'event_type': event_type, 'result': result}


WHERE = '''occurred_at >= :start AND occurred_at < :end
    AND (CAST(:origin AS text) IS NULL OR origin = :origin)
    AND (CAST(:event_type AS text) IS NULL OR event_type = :event_type)
    AND (CAST(:result AS text) IS NULL OR result = :result)'''


def encode_cursor(timestamp, identifier):
    raw = json.dumps([timestamp.isoformat(), str(identifier)], separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def decode_cursor(cursor):
    try:
        raw = base64.b64decode(cursor + '=' * (-len(cursor) % 4), altchars=b'-_', validate=True)
        value = json.loads(raw)
        if not isinstance(value, list) or len(value) != 2 or not all(isinstance(x, str) for x in value):
            raise ValueError()
        stamp = datetime.fromisoformat(value[0])
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError()
        return stamp.astimezone(timezone.utc), UUID(value[1])
    except (ValueError, TypeError, UnicodeDecodeError, binascii.Error, OverflowError):
        raise HTTPException(422, 'Cursor inválido') from None


async def execute(db, statement, params):
    try:
        async with asyncio.timeout(5):
            return await db.execute(text(statement), params)
    except Exception:
        raise HTTPException(503, 'Consulta de eventos indisponível') from None


@router.get('/summary')
async def summary(_=Depends(require_admin), f=Depends(filters), db: AsyncSession = Depends(get_db)):
    statement = f'''WITH filtered AS (SELECT origin, event_type, result, occurred_at FROM lab_events WHERE {WHERE})
        SELECT 'origin' AS category, origin AS value, COUNT(*) AS count FROM filtered GROUP BY origin
        UNION ALL SELECT 'type', event_type, COUNT(*) FROM filtered GROUP BY event_type
        UNION ALL SELECT 'result', result, COUNT(*) FROM filtered GROUP BY result
        UNION ALL SELECT 'day', to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD'), COUNT(*)
            FROM filtered GROUP BY 2
        UNION ALL SELECT 'total', '', COUNT(*) FROM filtered'''
    rows = (await execute(db, statement, f)).mappings().all()
    groups = {'origin': {}, 'type': {}, 'result': {}, 'day': {}}
    total = 0
    for row in rows:
        if row['category'] == 'total':
            total = row['count']
        else:
            groups[row['category']][row['value']] = row['count']
    return {'schema_version': 1, 'period': {'start': f['start'], 'end_exclusive': f['end']},
            'filters': {k: f[k] for k in ('origin', 'event_type', 'result')},
            'limits': {'max_period_days': MAX_DAYS, 'query_timeout_seconds': 5},
            'total': total, 'by_origin': groups['origin'], 'by_type': groups['type'],
            'by_result': groups['result'], 'by_day_utc': dict(sorted(groups['day'].items()))}


@router.get('')
async def list_events(_=Depends(require_admin), f=Depends(filters), db: AsyncSession = Depends(get_db),
                      limit: int = Query(50, ge=1, le=MAX_LIMIT), cursor: str | None = Query(None, max_length=256)):
    params = dict(f, limit=limit + 1)
    cursor_clause = ''
    if cursor:
        stamp, identifier = decode_cursor(cursor)
        if not f['start'] <= stamp < f['end']:
            raise HTTPException(422, 'Cursor fora do período')
        params.update(cursor_time=stamp, cursor_id=identifier)
        cursor_clause = 'AND (occurred_at, id) < (:cursor_time, :cursor_id)'
    rows = (await execute(db, f'''SELECT id, occurred_at, origin, event_type, operation, result, duration_ms, run_id
        FROM lab_events WHERE {WHERE} {cursor_clause} ORDER BY occurred_at DESC, id DESC LIMIT :limit''', params)).mappings().all()
    more = len(rows) > limit
    items = [dict(row) for row in rows[:limit]]
    next_cursor = encode_cursor(items[-1]['occurred_at'], items[-1]['id']) if more else None
    return {'schema_version': 1, 'period': {'start': f['start'], 'end_exclusive': f['end']},
            'items': items, 'next_cursor': next_cursor, 'limit': limit}
