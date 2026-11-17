"""Canonical envelope encoding and versioned authenticated metadata."""

import base64
import binascii
from uuid import UUID


def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode(value: str) -> bytes:
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise ValueError("Invalid encoding") from exc
    if encode(raw) != value:
        raise ValueError("Noncanonical encoding")
    return raw


def make_aad(version: int, algorithm: str, key_id: UUID, owner: UUID) -> bytes:
    """Prefix then four big-endian uint32-length-prefixed UTF-8 fields."""
    values = (str(version), algorithm, str(key_id), str(owner))
    fields = [value.encode("utf-8") for value in values]
    return b"FINK-CRYPTO-V1" + b"".join(len(field).to_bytes(4, "big") + field for field in fields)
