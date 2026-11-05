from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl, SecretStr, model_validator


class TargetConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str | None = Field(default=None, min_length=1, max_length=120, pattern=r"^[a-zA-Z0-9_./:-]+$")
    timeout_seconds: int = Field(default=30, ge=1, le=120)
    prompt_field: str = Field(default="prompt", pattern=r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")
    response_field: str = Field(default="response", pattern=r"^[a-zA-Z_][a-zA-Z0-9_.]{0,127}$")
    static_body: dict[str, str | int | bool] = Field(default_factory=dict, max_length=20)


class ScanConfigurationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    engines: list[Literal["library", "pyrit", "garak"]] = Field(default_factory=lambda: ["pyrit", "garak"], min_length=1, max_length=3)
    attack_ids: list[str] = Field(default_factory=list, max_length=17)

    @model_validator(mode="after")
    def unique_selections(self):
        if len(set(self.engines)) != len(self.engines) or len(set(self.attack_ids)) != len(self.attack_ids):
            raise ValueError("Duplicate engines or attacks are not allowed")
        return self


class TargetCreate(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    name: str = Field(min_length=1, max_length=100)
    endpoint: HttpUrl
    target_type: Literal["local", "ollama", "rest"] = "ollama"
    configuration: TargetConfiguration = Field(default_factory=TargetConfiguration)
    authorized: bool = False

    @model_validator(mode="after")
    def validate_configuration(self):
        from ..services.target_adapters import canonical_endpoint
        canonical_endpoint(self.endpoint)
        config = self.configuration
        if self.target_type != "rest" and (config.prompt_field != "prompt" or config.response_field != "response" or config.static_body):
            raise ValueError("REST settings require a REST target")
        if self.target_type == "rest" and config.model is not None:
            raise ValueError("REST model settings belong in the static request body")
        if config.prompt_field in config.static_body:
            raise ValueError("Static body cannot override the prompt field")
        if any(key.lower() in {"password", "token", "api_key", "authorization", "secret"} for key in config.static_body):
            raise ValueError("Do not store credentials in target configuration")
        return self


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    endpoint: HttpUrl
    created_at: datetime
    target_type: Literal["local", "ollama", "rest"]
    configuration: dict
    authorized: bool
    owner_id: UUID | None
    validation_status: str
    validated_at: datetime | None


class TargetValidationRead(BaseModel):
    target_id: UUID
    status: Literal["valid", "invalid"]
    message: str
    latency_ms: int | None = None
    checked_at: datetime


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: UUID
    configuration: ScanConfigurationCreate = Field(default_factory=ScanConfigurationCreate)
    auto_start: bool = False


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    target_id: UUID
    status: Literal["created", "queued", "running", "completed", "failed", "cancelled"]
    created_at: datetime
    owner_id: UUID | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_code: str | None = None
    configuration: "ScanConfigurationRead | None" = None


class ScanConfigurationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    pipeline: str
    engines: list[str]
    attack_ids: list[str]


ScanRead.model_rebuild()

class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: SecretStr = Field(min_length=12, max_length=128)


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
