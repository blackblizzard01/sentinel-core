from datetime import datetime
from typing import Optional, Any

from pydantic import BaseModel, ConfigDict

from constants import WSEvent


class BaseEvent(BaseModel):
    """Base schema for all Sentinel AI WebSocket events.

    All events broadcast over /ws/scan/{scan_id} inherit from this.
    """

    model_config = ConfigDict(from_attributes=True)

    scan_id: str
    timestamp: str
    event_type: str


class AgentStartedEvent(BaseEvent):
    """Emitted when an agent begins its phase."""

    event_type: str = WSEvent.AGENT_STARTED
    agent_name: str
    phase: str


class AttackExecutedEvent(BaseEvent):
    """Emitted after each individual attack attempt."""

    event_type: str = WSEvent.ATTACK_EXECUTED
    component_id: str
    domain: str
    payload_preview: str
    response_preview: str
    score: float


class MutationOccurredEvent(BaseEvent):
    """Emitted when MutationAgent produces a new attack variant."""

    event_type: str = WSEvent.MUTATION_OCCURRED
    parent_attack_id: str
    child_attack_id: str
    strategy: str


class VulnerabilityFoundEvent(BaseEvent):
    """Emitted when a vulnerability is confirmed and logged."""

    event_type: str = WSEvent.VULNERABILITY_FOUND
    component_id: str
    domain: str
    severity: str
    description: str


class ComponentCompleteEvent(BaseEvent):
    """Emitted when all domains for a component have been tested."""

    event_type: str = WSEvent.COMPONENT_COMPLETE
    component_id: str
    domains_tested: list[str]
    findings_count: int


class ScanCompleteEvent(BaseEvent):
    """Emitted when the full scan finishes and report is ready."""

    event_type: str = WSEvent.SCAN_COMPLETE
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    report_path: str


class CriticalHaltEvent(BaseEvent):
    """Emitted when a CRITICAL_THRESHOLD score triggers an immediate halt."""

    event_type: str = WSEvent.CRITICAL_HALT
    component_id: str
    domain: str
    score: float
    reason: str


AnyEvent = (
    AgentStartedEvent
    | AttackExecutedEvent
    | MutationOccurredEvent
    | VulnerabilityFoundEvent
    | ComponentCompleteEvent
    | ScanCompleteEvent
    | CriticalHaltEvent
)
