"""SQLAlchemy ORM models for Sentinel AI PostgreSQL persistence."""

import uuid
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Boolean, Integer, Float, DateTime, ForeignKey, JSON, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from constants import ScanStatus

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy ORM models."""


class Client(Base):
    """Represents a customer organization using Sentinel AI security scans."""

    __tablename__ = "clients"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    company: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    consents: Mapped[list["Consent"]] = relationship("Consent", back_populates="client")
    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="client")

    def __repr__(self) -> str:
        """Return a concise developer-facing model representation."""
        return f"<Client id={self.id}>"


class Consent(Base):
    """Represents signed scope authorization for security testing activities."""

    __tablename__ = "consents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    client_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("clients.id"), nullable=False)
    signed_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    scope: Mapped[dict] = mapped_column(JSON, nullable=False)
    signed_by_email: Mapped[str] = mapped_column(String(255), nullable=False)

    client: Mapped["Client"] = relationship("Client", back_populates="consents")
    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="consent")

    def __repr__(self) -> str:
        """Return a concise developer-facing model representation."""
        return f"<Consent id={self.id}>"


class Scan(Base):
    """Represents a single autonomous security scan execution for a client."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    client_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("clients.id"), nullable=False)
    consent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("consents.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default=ScanStatus.PENDING, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    component_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    client: Mapped["Client"] = relationship("Client", back_populates="scans")
    consent: Mapped["Consent"] = relationship("Consent", back_populates="scans")
    components: Mapped[list["Component"]] = relationship("Component", back_populates="scan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship("Vulnerability", back_populates="scan")

    def __repr__(self) -> str:
        """Return a concise developer-facing model representation."""
        return f"<Scan id={self.id}>"


class Component(Base):
    """Represents a discovered attack surface component within a scan."""

    __tablename__ = "components"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    type: Mapped[str] = mapped_column(String(100), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(500), nullable=False)
    framework: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    priority_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default=ScanStatus.PENDING, nullable=False)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="components")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship("Vulnerability", back_populates="component")

    def __repr__(self) -> str:
        """Return a concise developer-facing model representation."""
        return f"<Component id={self.id}>"


class Vulnerability(Base):
    """Represents a discovered vulnerability associated with a scan component."""

    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    component_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("components.id"), nullable=False)
    domain: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    sentinel_score: Mapped[float] = mapped_column(Float, nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    found_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="vulnerabilities")
    component: Mapped["Component"] = relationship("Component", back_populates="vulnerabilities")

    def __repr__(self) -> str:
        """Return a concise developer-facing model representation."""
        return f"<Vulnerability id={self.id}>"
