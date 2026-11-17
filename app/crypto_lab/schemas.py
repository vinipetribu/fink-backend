"""Strict public request and response models."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator

from app.crypto_lab.envelope import decode


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CryptoEnvelope(Model):
    version: StrictInt
    algorithm: Literal["AES-256-GCM"]
    key_id: UUID
    nonce: StrictStr = Field(max_length=16)
    ciphertext: StrictStr = Field(max_length=5484)

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError("Unsupported version")
        return value

    @field_validator("nonce")
    @classmethod
    def valid_nonce(cls, value: str) -> str:
        if len(decode(value)) != 12:
            raise ValueError("Invalid nonce")
        return value

    @field_validator("ciphertext")
    @classmethod
    def valid_ciphertext(cls, value: str) -> str:
        if not 17 <= len(decode(value)) <= 4112:
            raise ValueError("Invalid ciphertext length")
        return value


class EncryptRequest(Model):
    text: StrictStr

    @field_validator("text")
    @classmethod
    def valid_text(cls, value: str) -> str:
        try:
            size = len(value.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValueError("Invalid text") from exc
        if not 1 <= size <= 4096:
            raise ValueError("Invalid text length")
        return value


class EncryptResponse(Model):
    operation_id: UUID
    envelope: CryptoEnvelope


class DecryptRequest(Model):
    envelope: CryptoEnvelope


class DecryptResponse(Model):
    operation_id: UUID
    text: StrictStr


class StegoImage(Model):
    image_png: StrictStr = Field(max_length=1398104)

    @field_validator("image_png")
    @classmethod
    def valid_image_encoding(cls, value: str) -> str:
        if not 1 <= len(decode(value)) <= 1048576:
            raise ValueError("Invalid PNG length")
        return value


class StegoEmbedRequest(StegoImage):
    envelope: CryptoEnvelope


class StegoExtractRequest(StegoImage):
    pass


class StegoEmbedResponse(Model):
    image_png: StrictStr


class StegoExtractResponse(Model):
    envelope: CryptoEnvelope


class ToyEncryptRequest(EncryptRequest):
    action: Literal["encrypt"]


class ToyDecryptRequest(Model):
    action: Literal["decrypt"]
    key_id: UUID
    ciphertext: StrictStr = Field(max_length=5472)

    @field_validator("ciphertext")
    @classmethod
    def valid_ciphertext(cls, value: str) -> str:
        raw = decode(value)
        if not 8 <= len(raw) <= 4104 or len(raw) % 8:
            raise ValueError("Invalid experimental ciphertext")
        return value


class ToyEncryptResponse(Model):
    operation_id: UUID
    algorithm: Literal["TOY-V1-INSECURE"]
    key_id: UUID
    ciphertext: StrictStr
    warning: Literal["Cifra didática insegura; use apenas dados fictícios."]


class ToyDecryptResponse(Model):
    operation_id: UUID
    algorithm: Literal["TOY-V1-INSECURE"]
    text: StrictStr
    warning: Literal["Cifra didática insegura; use apenas dados fictícios."]


class Counts(Model):
    aes_encrypt_success: int
    aes_decrypt_success: int
    aes_decrypt_failure: int
    experimental_success: int = 0
    experimental_failure: int = 0


class OperationsSummaryResponse(Model):
    scope: Literal["current_process"]
    since: datetime
    counts: Counts
