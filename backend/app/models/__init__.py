from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base


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
    target_type: Mapped[str] = mapped_column(String(30), default="ollama")
    configuration: Mapped[dict] = mapped_column(JSON, default=dict)
    owner_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), index=True)
    authorized: Mapped[bool] = mapped_column(Boolean, default=True)
    validation_status: Mapped[str] = mapped_column(String(30), default="not_validated")
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    owner: Mapped["User | None"] = relationship()
    scans: Mapped[list["Scan"]] = relationship(back_populates="target")
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
    owner_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(80))
    task_id: Mapped[str | None] = mapped_column(String(36))
    target: Mapped["Target"] = relationship(back_populates="scans")
    owner: Mapped["User | None"] = relationship()
    configuration: Mapped["ScanConfiguration | None"] = relationship(back_populates="scan", uselist=False)
    attempts: Mapped[list["AttackAttempt"]] = relationship(back_populates="scan")


class Attack(Base):
    __tablename__ = "attacks"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    category: Mapped[str] = mapped_column(String(100))
    engine: Mapped[str] = mapped_column(String(30), index=True)
    payload: Mapped[str] = mapped_column(Text)
    strategy: Mapped[str] = mapped_column(Text)
    expected_behavior: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class ScanConfiguration(Base):
    __tablename__ = "scan_configurations"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id"), unique=True)
    pipeline: Mapped[str] = mapped_column(String(30), default="week2")
    engines: Mapped[list] = mapped_column(JSON)
    target_snapshot: Mapped[dict] = mapped_column(JSON)
    scan: Mapped["Scan"] = relationship(back_populates="configuration")
    selections: Mapped[list["ScanAttack"]] = relationship(back_populates="configuration")

    @property
    def attack_ids(self):
        return [item.attack_id for item in sorted(self.selections, key=lambda item: item.position)]


class ScanAttack(Base):
    __tablename__ = "scan_attacks"
    configuration_id: Mapped[UUID] = mapped_column(ForeignKey("scan_configurations.id"), primary_key=True)
    attack_id: Mapped[str] = mapped_column(ForeignKey("attacks.id"), primary_key=True)
    position: Mapped[int] = mapped_column()
    definition: Mapped[dict] = mapped_column(JSON)
    configuration: Mapped["ScanConfiguration"] = relationship(back_populates="selections")
    attack: Mapped["Attack"] = relationship()

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
    attack_id: Mapped[str | None] = mapped_column(ForeignKey("attacks.id"), index=True)
    test_case_id: Mapped[str | None] = mapped_column(String(30), index=True)
    execution_metadata: Mapped[dict | None] = mapped_column(JSON)
    scan: Mapped["Scan"] = relationship(back_populates="attempts")
    attack: Mapped["Attack | None"] = relationship()
    responses: Mapped[list["Response"]] = relationship(back_populates="attempt")
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
    attempt: Mapped["AttackAttempt"] = relationship(back_populates="responses")
    findings: Mapped[list["Finding"]] = relationship(back_populates="response")
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
    response: Mapped["Response"] = relationship(back_populates="findings")
    evidence_records: Mapped[list["Evidence"]] = relationship(back_populates="finding")
    mappings: Mapped[list["VulnerabilityMapping"]] = relationship(back_populates="finding")
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


class EvidenceReceipt(Base):
    """Backend envelope around the security team's unchanged signed receipt."""
    __tablename__ = "evidence_receipts"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    response_id: Mapped[UUID] = mapped_column(ForeignKey("responses.id"), unique=True)
    key_id: Mapped[str] = mapped_column(String(32))
    receipt: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id"), index=True)
    response_id: Mapped[UUID] = mapped_column(ForeignKey("responses.id"), index=True)
    evidence_type: Mapped[str] = mapped_column(String(40))
    description: Mapped[str] = mapped_column(Text)
    validated: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    finding: Mapped["Finding"] = relationship(back_populates="evidence_records")
    response: Mapped["Response"] = relationship()


class VulnerabilityMapping(Base):
    __tablename__ = "vulnerability_mappings"
    __table_args__ = (UniqueConstraint("finding_id", "taxonomy", "reference_id"),)
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id"), index=True)
    taxonomy: Mapped[str] = mapped_column(String(30))
    reference_id: Mapped[str] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(Text)
    finding: Mapped["Finding"] = relationship(back_populates="mappings")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    actor_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), index=True)
    scan_id: Mapped[UUID | None] = mapped_column(ForeignKey("scans.id"), index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    resource_id: Mapped[str] = mapped_column(String(100))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    actor: Mapped["User | None"] = relationship()
    scan: Mapped["Scan | None"] = relationship()
