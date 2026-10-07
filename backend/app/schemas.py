from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class TargetCreate(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    name: str = Field(min_length=1, max_length=100)
    endpoint: HttpUrl


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    endpoint: HttpUrl
    created_at: datetime


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: UUID


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    target_id: UUID
    status: Literal["created"]
    created_at: datetime