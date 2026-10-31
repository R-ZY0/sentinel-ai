from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint,JSON
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(100))
    endpoint: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    target_id: Mapped[UUID] = mapped_column(ForeignKey("targets.id"))
    status: Mapped[str] = mapped_column(String(30), default="created")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

class AttackAttempt(Base):
    __tablename__ = "attack_attempts"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scans.id"),
        index=True,
    )
    attack_case_id: Mapped[str | None] = mapped_column(
        String(100), nullable=True, index=True
    )
    category: Mapped[str] = mapped_column(String(100))
    payload: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="created")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )


class Response(Base):
    __tablename__ = "responses"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    attack_attempt_id: Mapped[UUID] = mapped_column(
        ForeignKey("attack_attempts.id"),
        index=True,
    )
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    response_id: Mapped[UUID] = mapped_column(
        ForeignKey("responses.id"),
        index=True,
    )
    category: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(
        String(30),
        default="unassessed",
    )
    status: Mapped[str] = mapped_column(
        String(30),
        default="suspected",
    )
    evidence: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

class ResponseEvaluation(Base):
    __tablename__ = "response_evaluations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    response_id: Mapped[UUID] = mapped_column(
        ForeignKey("responses.id"),
        unique=True,
    )
    baseline_results: Mapped[dict] = mapped_column(JSON)
    security_result: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )