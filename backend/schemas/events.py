"""Pydantic v2 schemas for WebSocket event payloads in Sentinel AI."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from constants import WSEvent


class BaseWSEventSchema(BaseModel):
    """Base fields shared by all WebSocket event schemas."""

    scan_id: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    event_type: str


class AgentStartedEvent(BaseWSEventSchema):
    """Event emitted when an agent begins work on a scan phase."""

    event_type: str = WSEvent.AGENT_STARTED
    agent_name: str
    phase: str


class AttackExecutedEvent(BaseWSEventSchema):
    """Event emitted when an attack attempt is executed against a component."""

    event_type: str = WSEvent.ATTACK_EXECUTED
    component_id: str
    domain: str
    payload_preview: str
    response_preview: str
    score: float


class MutationOccurredEvent(BaseWSEventSchema):
    """Event emitted when a mutation is generated from a parent attack."""

    event_type: str = WSEvent.MUTATION_OCCURRED
    parent_attack_id: str
    child_attack_id: str
    strategy: str


class VulnerabilityFoundEvent(BaseWSEventSchema):
    """Event emitted when a vulnerability is confirmed during a scan."""

    event_type: str = WSEvent.VULNERABILITY_FOUND
    component_id: str
    domain: str
    severity: str
    description: str


class ComponentCompleteEvent(BaseWSEventSchema):
    """Event emitted when testing completes for a single component."""

    event_type: str = WSEvent.COMPONENT_COMPLETE
    component_id: str
    domains_tested: int
    findings_count: int


class ScanCompleteEvent(BaseWSEventSchema):
    """Event emitted when an entire scan finishes."""

    event_type: str = WSEvent.SCAN_COMPLETE
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    report_path: Optional[str] = None


class CriticalHaltEvent(BaseWSEventSchema):
    """Event emitted when a scan is halted due to a critical finding."""

    event_type: str = WSEvent.CRITICAL_HALT
    component_id: str
    domain: str
    score: float
    reason: str


class ProgressUpdateEvent(BaseWSEventSchema):
    """Event emitted to report incremental scan progress."""

    event_type: str = WSEvent.PROGRESS_UPDATE
    component_id: str
    current_domain: str
    iteration: int
    total_iterations: int
    message: str
