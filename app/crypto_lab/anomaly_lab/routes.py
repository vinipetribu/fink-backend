"""Local ADMIN-only synthetic anomaly experiments."""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from app.api.deps import require_admin
from app.core.settings import settings
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
