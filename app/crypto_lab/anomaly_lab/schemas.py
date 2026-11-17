"""Strict requests for the synthetic anomaly lab."""
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict


class DatasetRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    profile: Literal['synthetic-security-v1']


class RunRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    dataset_id: UUID
