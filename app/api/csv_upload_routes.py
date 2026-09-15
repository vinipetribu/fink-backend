"""Authenticated, in-memory CSV upload endpoint."""

from __future__ import annotations

import csv
import hashlib
import io
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.identidade.persistence.pessoa_orm import PessoaORM


MAX_CSV_BYTES = 1024 * 1024
MAX_CSV_RECORDS = 1000
CSV_PREVIEW_RECORDS = 5
REQUIRED_COLUMNS = {"data", "descricao", "valor"}

router = APIRouter(prefix="/api/v1/uploads", tags=["uploads"])


class CSVPreviewRow(BaseModel):
    """One validated row exposed in the small response preview."""

    data: date
    descricao: str
    valor: str


class CSVUploadResponse(BaseModel):
    """Metadata returned after validating an in-memory CSV upload."""

    nome_original: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    quantidade_registros: int = Field(ge=1, le=MAX_CSV_RECORDS)
    previa: list[CSVPreviewRow] = Field(max_length=CSV_PREVIEW_RECORDS)


async def _read_limited(arquivo: UploadFile) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while chunk := await arquivo.read(64 * 1024):
        total += len(chunk)
        if total > MAX_CSV_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="O arquivo CSV deve ter no máximo 1 MB",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_date(value: str, line_number: int) -> date:
    if len(value) != 10 or value[4] != "-" or value[7] != "-":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Linha {line_number}: data inválida; use YYYY-MM-DD",
        )
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Linha {line_number}: data inválida; use YYYY-MM-DD",
        ) from exc


def _parse_description(value: str, line_number: int) -> str:
    description = value.strip()
    if not description or len(description) > 255:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Linha {line_number}: descrição deve conter de 1 a 255 caracteres",
        )
    return description


def _parse_value(value: str, line_number: int) -> str:
    try:
        amount = Decimal(value.strip())
    except InvalidOperation as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Linha {line_number}: valor inválido",
        ) from exc
    if not amount.is_finite() or amount.as_tuple().exponent < -2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Linha {line_number}: valor deve ser decimal finito com até duas casas",
        )
    return format(amount, "f")


def _parse_csv(content: str) -> tuple[int, list[CSVPreviewRow]]:
    try:
        reader = csv.DictReader(io.StringIO(content, newline=""), strict=True)
        headers = reader.fieldnames
        if (
            headers is None
            or len(headers) != len(set(headers))
            or not REQUIRED_COLUMNS.issubset(headers)
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="O CSV deve conter as colunas data, descricao e valor",
            )

        preview: list[CSVPreviewRow] = []
        record_count = 0
        for row in reader:
            record_count += 1
            if record_count > MAX_CSV_RECORDS:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="O CSV deve conter no máximo 1.000 registros",
                )
            if None in row or any(row.get(column) is None for column in REQUIRED_COLUMNS):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Linha {reader.line_num}: quantidade de campos inválida",
                )

            parsed = CSVPreviewRow(
                data=_parse_date(row["data"].strip(), reader.line_num),
                descricao=_parse_description(row["descricao"], reader.line_num),
                valor=_parse_value(row["valor"], reader.line_num),
            )
            if len(preview) < CSV_PREVIEW_RECORDS:
                preview.append(parsed)
    except csv.Error as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="CSV malformado",
        ) from exc

    if record_count == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="O CSV deve conter ao menos um registro",
        )
    return record_count, preview


@router.post("/csv", response_model=CSVUploadResponse)
async def upload_csv(
    _: Annotated[PessoaORM, Depends(get_current_user)],
    arquivo: Annotated[UploadFile, File(description="Arquivo CSV de até 1 MB")],
) -> CSVUploadResponse:
    """Validate a CSV in memory and return its digest and a small preview."""
    try:
        original_name = arquivo.filename or ""
        if not original_name.lower().endswith(".csv"):
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Somente arquivos com extensão .csv são aceitos",
            )

        raw_content = await _read_limited(arquivo)
        try:
            text_content = raw_content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="O arquivo deve usar codificação UTF-8",
            ) from exc

        record_count, preview = _parse_csv(text_content)
        return CSVUploadResponse(
            nome_original=original_name,
            sha256=hashlib.sha256(raw_content).hexdigest(),
            quantidade_registros=record_count,
            previa=preview,
        )
    finally:
        await arquivo.close()
