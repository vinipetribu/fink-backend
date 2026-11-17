"""Authenticated endpoints for the local AES demonstration."""

from typing import Annotated
from threading import BoundedSemaphore

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from app.api.deps import get_current_user, require_admin
from app.crypto_lab.aes_service import service
from app.crypto_lab.errors import CapacityError, DecryptionError
from app.crypto_lab.schemas import (
    DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, OperationsSummaryResponse,
    ToyDecryptRequest, ToyDecryptResponse, ToyEncryptRequest, ToyEncryptResponse,
    CryptoEnvelope, StegoEmbedRequest, StegoEmbedResponse, StegoExtractRequest, StegoExtractResponse,
)
from app.crypto_lab.envelope import decode, encode
from app.crypto_lab.steganography import SteganographyError, embed, extract
from app.crypto_lab.toy_cipher import ToyService
from app.core.settings import settings
from app.identidade.persistence.pessoa_orm import PessoaORM

router = APIRouter(prefix="/api/v1/crypto-lab", tags=["crypto-lab"])
toy_service = ToyService(service.metrics)
stego_slots = BoundedSemaphore(2)


def _stego_embed(image: str, envelope: CryptoEnvelope, owner) -> dict:
    if not stego_slots.acquire(blocking=False):
        raise CapacityError()
    try:
        service.decrypt(envelope, owner)  # Authenticate ownership; never return or log the plaintext.
        png = embed(decode(image), envelope.model_dump_json().encode("utf-8"))
        return {"image_png": encode(png)}
    finally:
        stego_slots.release()


def _stego_extract(image: str, owner) -> dict:
    if not stego_slots.acquire(blocking=False):
        raise CapacityError()
    try:
        try:
            envelope = CryptoEnvelope.model_validate_json(extract(decode(image)))
        except (ValidationError, ValueError) as exc:
            raise SteganographyError("Invalid hidden envelope") from exc
        service.decrypt(envelope, owner)  # Authenticate before exposing the envelope.
        return {"envelope": envelope}
    finally:
        stego_slots.release()


@router.post("/steganography/embed", response_model=StegoEmbedResponse)
async def embed_envelope(body: StegoEmbedRequest, user: PessoaORM = Depends(get_current_user)) -> dict:
    try:
        return await run_in_threadpool(_stego_embed, body.image_png, body.envelope, user.id_pessoa)
    except CapacityError:
        raise HTTPException(status_code=503, detail="Laboratório indisponível") from None
    except (SteganographyError, DecryptionError):
        raise HTTPException(status_code=400, detail="Não foi possível processar a imagem ou o envelope") from None


@router.post("/steganography/extract", response_model=StegoExtractResponse)
async def extract_envelope(body: StegoExtractRequest, user: PessoaORM = Depends(get_current_user)) -> dict:
    try:
        return await run_in_threadpool(_stego_extract, body.image_png, user.id_pessoa)
    except CapacityError:
        raise HTTPException(status_code=503, detail="Laboratório indisponível") from None
    except (SteganographyError, DecryptionError):
        raise HTTPException(status_code=400, detail="Não foi possível processar a imagem ou o envelope") from None


@router.post("/encrypt", response_model=EncryptResponse)
async def encrypt(body: EncryptRequest, user: PessoaORM = Depends(get_current_user)) -> EncryptResponse:
    try:
        return await run_in_threadpool(service.encrypt, body.text, user.id_pessoa)
    except CapacityError:
        raise HTTPException(status_code=503, detail="Laboratório indisponível") from None


@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt(body: DecryptRequest, user: PessoaORM = Depends(get_current_user)) -> DecryptResponse:
    try:
        return await run_in_threadpool(service.decrypt, body.envelope, user.id_pessoa)
    except CapacityError:
        raise HTTPException(status_code=503, detail="Laboratório indisponível") from None
    except DecryptionError:
        raise HTTPException(status_code=400, detail="Não foi possível descriptografar o payload") from None


@router.get("/operations/summary", response_model=OperationsSummaryResponse)
async def summary(_: PessoaORM = Depends(require_admin)) -> dict:
    return service.metrics.summary()


@router.post("/experimental/run", response_model=ToyEncryptResponse | ToyDecryptResponse)
async def run_experiment(
    body: Annotated[ToyEncryptRequest | ToyDecryptRequest, Body(discriminator="action")],
    user: PessoaORM = Depends(require_admin),
) -> dict:
    """Run the insecure educational cipher only when explicitly enabled for admins."""
    if not settings.crypto_lab_experimental_enabled:
        raise HTTPException(status_code=503, detail="Laboratório experimental indisponível")
    from app.crypto_lab.event_store.emitter import emit
    event_type = 'TOY_ENCRYPT' if isinstance(body, ToyEncryptRequest) else 'TOY_DECRYPT'
    try:
        if isinstance(body, ToyEncryptRequest):
            result = await run_in_threadpool(toy_service.encrypt, body.text, user.id_pessoa)
        else:
            result = await run_in_threadpool(toy_service.decrypt, body.ciphertext, body.key_id, user.id_pessoa)
        emit(event_type, '/api/v1/crypto-lab/experimental/run', 'SUCCESS')
        return result
    except CapacityError:
        emit(event_type, '/api/v1/crypto-lab/experimental/run', 'FAILURE')
        raise HTTPException(status_code=503, detail="Laboratório indisponível") from None
    except DecryptionError:
        emit(event_type, '/api/v1/crypto-lab/experimental/run', 'FAILURE')
        raise HTTPException(status_code=400, detail="Não foi possível descriptografar o payload") from None
