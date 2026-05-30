import uuid
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Boolean, Float, Integer, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from constants import ScanStatus, ComponentType, Severity, AttackDomain

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all Sentinel AI database models."""

    pass


class Client(Base):
    """
    Represents an authorized client organization that has engaged Sentinel AI
    for infrastructure security testing.
    """

    __tablename__ = "clients"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    company: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    scans: Mapped[list["Scan"]] = relationship(back_populates="client")
    consents: Mapped[list["Consent"]] = relationship(back_populates="client")

    def __repr__(self) -> str:
        """Return a debug representation of this client record."""
        return f"<Client id={self.id} company={self.company} email={self.email}>"


class Consent(Base):
    """
    Records the signed authorization from a client before any scan begins.
    A scan MUST NOT start without a valid Consent record. This is a
    non-negotiable security requirement of the platform.
    """

    __tablename__ = "consents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    client_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("clients.id"), nullable=False
    )
    signed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    scope: Mapped[dict] = mapped_column(JSON, nullable=False)
    signed_by_email: Mapped[str] = mapped_column(String(255), nullable=False)

    client: Mapped["Client"] = relationship(back_populates="consents")
    scans: Mapped[list["Scan"]] = relationship(back_populates="consent")

    def __repr__(self) -> str:
        """Return a debug representation of this consent record."""
        return f"<Consent id={self.id} client_id={self.client_id} signed_at={self.signed_at}>"


class Scan(Base):
    """
    Represents a single authorized security scan session against a client's
    AI infrastructure. Links to the Consent that authorized it.
    Status must always be managed via ScanStatus constants — never raw strings.
    """

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    client_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("clients.id"), nullable=False
    )
    consent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("consents.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=ScanStatus.PENDING
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    component_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    client: Mapped["Client"] = relationship(back_populates="scans")
    consent: Mapped["Consent"] = relationship(back_populates="scans")
    components: Mapped[list["Component"]] = relationship(back_populates="scan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="scan")

    def __repr__(self) -> str:
        """Return a debug representation of this scan record."""
        return f"<Scan id={self.id} client_id={self.client_id} status={self.status}>"


class Component(Base):
    """
    Represents a single infrastructure component discovered by the ReconAgent
    within a scan. Each component is independently attacked across its
    applicable attack domains.
    """

    __tablename__ = "components"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False
    )
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(500), nullable=False)
    framework: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    priority_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")

    scan: Mapped["Scan"] = relationship(back_populates="components")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="component"
    )

    def __repr__(self) -> str:
        """Return a debug representation of this component record."""
        return f"<Component id={self.id} type={self.type} endpoint={self.endpoint}>"


class Vulnerability(Base):
    """
    Records a confirmed vulnerability finding from the AttackAgent or
    MutationAgent. Each record maps to a specific component, attack domain,
    and severity level with both Sentinel score and CVSS score.
    Also tracks autopatch status for findings that have been remediated.
    """

    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False
    )
    component_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("components.id"), nullable=False
    )
    domain: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    sentinel_score: Mapped[float] = mapped_column(Float, nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    found_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    patched_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    patch_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    pr_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="vulnerabilities")
    component: Mapped["Component"] = relationship(back_populates="vulnerabilities")

    def __repr__(self) -> str:
        """Return a debug representation of this vulnerability record."""
        return (
            f"<Vulnerability id={self.id} domain={self.domain} "
            f"severity={self.severity} score={self.sentinel_score}>"
        )
