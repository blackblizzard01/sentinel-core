"""LangGraph orchestrator state machine for Sentinel AI scan lifecycle."""

import logging
import uuid
from typing import Any, Optional, TypedDict

from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from sqlalchemy import select

from backend.database import AsyncSessionLocal
from backend.models import Scan
from backend.schemas.events import (
    AgentStartedEvent,
    AttackExecutedEvent,
    MutationOccurredEvent,
    VulnerabilityFoundEvent,
    ComponentCompleteEvent,
    ScanCompleteEvent,
    CriticalHaltEvent,
)
from backend.websocket.connection_manager import manager
from knowledge_base import KnowledgeBase
from constants import (
    AttackDomain,
    ComponentType,
    ScanPhase,
    ScanStatus,
    AgentName,
    WSEvent,
    MAX_ITERATIONS,
    CRITICAL_THRESHOLD,
    PARTIAL_THRESHOLD,
)

load_dotenv()

logger = logging.getLogger(__name__)


class ScanState(TypedDict):
    """LangGraph state passed between orchestrator nodes."""

    client_id: str
    scan_id: str
    current_component_index: int
    current_component: dict
    current_domain_index: int
    current_domain: str
    attack_results: list
    iteration: int
    phase: str
    logs: list
    critical_halt: bool
    components: list
    approved_findings: list
    report_path: str
    report_json: dict


class SentinelOrchestrator:
    """
    LangGraph state machine orchestrator for Sentinel AI.
    Controls the full scan lifecycle: recon → attack → mutation →
    report → autopatch. Agents communicate only through state and ChromaDB.
    """

    def __init__(self) -> None:
        """Initialize orchestrator and compile the LangGraph state machine."""
        self.kb: KnowledgeBase = KnowledgeBase()
        self.graph: Any = self._build_graph()
        self.logger = logging.getLogger(__name__)
        logger.info("SentinelOrchestrator initialized")

    def _build_graph(self) -> Any:
        """
        Build and compile the LangGraph state machine.
        Defines all nodes and edges for the scan workflow.
        Returns the compiled graph.
        """
        graph: StateGraph = StateGraph(ScanState)

        graph.add_node("recon", self._recon_node)
        graph.add_node("attack", self._attack_node)
        graph.add_node("mutation", self._mutation_node)
        graph.add_node("report", self._report_node)
        graph.add_node("autopatch", self._autopatch_node)

        graph.set_entry_point("recon")

        graph.add_edge("recon", "attack")
        graph.add_conditional_edges(
            "attack",
            self._after_attack_router,
            {
                "mutation": "mutation",
                "report": "report",
                "attack": "attack",
            },
        )
        graph.add_edge("mutation", "attack")
        graph.add_edge("report", "autopatch")
        graph.add_edge("autopatch", END)

        return graph.compile()

    def _after_attack_router(self, state: ScanState) -> str:
        """
        Conditional edge router for LangGraph orchestrator.
        critical_halt is checked first — legal requirement for authorized red-teaming.
        A confirmed CRITICAL finding (score >= CRITICAL_THRESHOLD) must halt
        all further attacks and route directly to report generation.
        """
        # Legal safety gate — must be first
        if state.get("critical_halt", False):
            return "report"
        if state["iteration"] >= MAX_ITERATIONS:
            return "report"
        if self._all_components_done(state):
            return "report"

        has_partial_success: bool = any(
            result.get("score", 0) >= PARTIAL_THRESHOLD for result in state["attack_results"]
        )
        if (
            state["iteration"] < MAX_ITERATIONS
            and not state["critical_halt"]
            and has_partial_success
        ):
            return "mutation"

        return "attack"

    def _all_components_done(self, state: ScanState) -> bool:
        """Return True when all components in the scan have been processed."""
        if not state["components"]:
            return False
        return state["current_component_index"] >= len(state["components"])

    async def _update_scan_status(self, scan_id: str, status: str) -> None:
        """Update scan status in PostgreSQL for the given scan_id."""
        try:
            scan_uuid = uuid.UUID(scan_id)
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(Scan).where(Scan.id == scan_uuid))
                scan: Optional[Scan] = result.scalar_one_or_none()
                if scan is None:
                    logger.error("Scan not found for status update: %s", scan_id)
                    return
                scan.status = status
                await session.commit()
        except Exception:
            logger.exception("Failed to update scan status for scan %s", scan_id)

    async def _recon_node(self, state: ScanState) -> dict:
        """
        Recon node stub. Week 2 will call ReconAgent.run(state).
        Returns partial state update dict — does not mutate input state.
        """
        logger.info("Recon node executing")
        updates: dict = {}
        updates["phase"] = ScanPhase.RECON
        updates["logs"] = state.get("logs", []) + ["Recon node entered — stub"]

        agent_started_event = AgentStartedEvent(
            scan_id=state["scan_id"],
            event_type=WSEvent.AGENT_STARTED,
            agent_name=AgentName.RECON,
            phase=ScanPhase.RECON,
        )
        await manager.broadcast_to_scan(state["scan_id"], agent_started_event.model_dump())

        components = [
            {
                "component_id": "stub-component-001",
                "type": ComponentType.LLM_MODEL,
                "endpoint": "http://localhost:9999/stub",
                "framework": "stub",
                "priority_score": 5.0,
            }
        ]
        updates["components"] = components
        updates["current_component_index"] = 0
        updates["current_component"] = components[0]

        try:
            await self._update_scan_status(state["scan_id"], ScanStatus.ACTIVE)
        except Exception:
            logger.exception("DB update failed during recon; continuing scan")

        return updates

    async def _attack_node(self, state: ScanState) -> dict:
        """
        Attack node stub. Week 2 will call AttackAgent.run(state).
        Returns partial state update dict — does not mutate input state.
        """
        logger.info("Attack node executing")
        updates: dict = {}
        updates["phase"] = ScanPhase.ATTACKING
        updates["logs"] = state.get("logs", []) + [f"Attack phase — iteration {state['iteration']}"]

        attack_executed_event = AttackExecutedEvent(
            scan_id=state["scan_id"],
            event_type=WSEvent.ATTACK_EXECUTED,
            component_id=state.get("current_component", {}).get("component_id", "stub-component-001"),
            domain=state.get("current_domain", AttackDomain.PROMPT_INJECTION),
            payload_preview="[stub — Week 2 AttackAgent will populate]",
            response_preview="[stub — Week 2 AttackAgent will populate]",
            score=0.0,
        )
        await manager.broadcast_to_scan(state["scan_id"], attack_executed_event.model_dump())

        # Scoring stub — Week 2: AttackAgent replaces this with judge-model scoring
        # Judge Model concept: second LLM scores attack success without white-box
        # access to target. Reference: UJA paper (ICLR 2026) — AI Security Lead owns impl.
        # TODO Week 2: score = await attack_agent.score_response(payload, response)
        stub_score = 0.5

        updates["attack_results"] = state.get("attack_results", []) + [
            {
                "component_id": state.get("current_component", {}).get("id", "stub"),
                "domain": state.get("current_domain", AttackDomain.PROMPT_INJECTION),
                "score": stub_score,
                "iteration": state.get("iteration", 0),
            }
        ]

        # Critical halt check — AI Security Lead wires real score here in Week 2
        if stub_score >= CRITICAL_THRESHOLD:
            updates["critical_halt"] = True
            logger.warning(
                "CRITICAL score %.2f on component %s — halting scan",
                stub_score,
                state.get("current_component", {}).get("id", "unknown"),
            )
            critical_halt_event = CriticalHaltEvent(
                scan_id=state["scan_id"],
                event_type=WSEvent.CRITICAL_HALT,
                component_id=state.get("current_component", {}).get("component_id", "stub-component-001"),
                domain=state.get("current_domain", AttackDomain.PROMPT_INJECTION),
                score=stub_score,
                reason="[stub — Week 2 AttackAgent will populate]",
            )
            await manager.broadcast_to_scan(state["scan_id"], critical_halt_event.model_dump())
        else:
            updates["critical_halt"] = state.get("critical_halt", False)

        # Advance domain index — Week 2: replace stub domains with DOMAIN_COMPONENT_MAP lookup
        # TODO Week 2: domains = DOMAIN_COMPONENT_MAP.get(state["current_component"].get("type"), [])
        stub_domains = [AttackDomain.PROMPT_INJECTION]  # Single domain stub for Week 2
        current_domain_idx = state.get("current_domain_index", 0)
        current_comp_idx = state.get("current_component_index", 0)
        components = state.get("components", [])

        if current_domain_idx < len(stub_domains) - 1:
            # More domains remain for this component
            updates["current_domain_index"] = current_domain_idx + 1
            updates["current_domain"] = stub_domains[updates["current_domain_index"]]
        else:
            # All domains for this component done — advance to next component
            updates["current_domain_index"] = 0
            updates["current_component_index"] = current_comp_idx + 1
            if current_comp_idx + 1 < len(components):
                updates["current_component"] = components[current_comp_idx + 1]
            updates["current_domain"] = stub_domains[0]

        updates["iteration"] = state["iteration"] + 1
        return updates

    async def _mutation_node(self, state: ScanState) -> dict:
        """
        Mutation node stub. Week 3 will call MutationAgent.run(state).
        Returns partial state update dict — does not mutate input state.
        """
        logger.info("Mutation node executing")
        updates: dict = {}
        updates["phase"] = ScanPhase.MUTATING
        updates["logs"] = state.get("logs", []) + ["Mutation node entered — stub"]

        mutation_event = MutationOccurredEvent(
            scan_id=state["scan_id"],
            event_type=WSEvent.MUTATION_OCCURRED,
            parent_attack_id="[stub — Week 2 AttackAgent will populate]",
            child_attack_id="[stub — Week 2 AttackAgent will populate]",
            strategy="[stub — Week 2 AttackAgent will populate]",
        )
        await manager.broadcast_to_scan(state["scan_id"], mutation_event.model_dump())

        return updates

    async def _report_node(self, state: ScanState) -> dict:
        """
        Report node stub. Week 5 will call ReportAgent.run(state).
        Returns partial state update dict — does not mutate input state.
        """
        logger.info("Report node executing")
        updates: dict = {}
        updates["phase"] = ScanPhase.REPORTING
        updates["logs"] = state.get("logs", []) + ["Report node entered — stub"]

        scan_complete_event = ScanCompleteEvent(
            scan_id=state["scan_id"],
            event_type=WSEvent.SCAN_COMPLETE,
            total_vulnerabilities=len(state["attack_results"]),
            critical_count=0,
            high_count=0,
            report_path=f"reports/{state['scan_id']}_report.pdf",
        )
        await manager.broadcast_to_scan(state["scan_id"], scan_complete_event.model_dump())

        updates["report_path"] = f"reports/{state['scan_id']}_report.pdf"
        updates["report_json"] = {"status": "stub", "findings": []}

        try:
            await self._update_scan_status(state["scan_id"], ScanStatus.COMPLETED)
        except Exception:
            logger.exception("DB update failed during report; continuing scan")

        return updates

    async def _autopatch_node(self, state: ScanState) -> dict:
        """
        Autopatch node stub. Week 6 will call AutopatchAgent.run(state).
        Returns partial state update dict — does not mutate input state.
        """
        logger.info("Autopatch node executing")
        updates: dict = {}
        updates["phase"] = ScanPhase.PATCHING
        updates["logs"] = state.get("logs", []) + ["Autopatch node entered — stub"]

        self.logger.info("Autopatch stub — no approved findings to process")

        updates["phase"] = ScanPhase.DONE
        return updates

    async def run_scan(self, client_id: str, scan_id: str) -> dict:
        """
        Entry point to start a full scan.
        Builds initial state and streams through the LangGraph graph.
        Returns the final state dict when scan completes.
        """
        initial_state: ScanState = {
            "client_id": client_id,
            "scan_id": scan_id,
            "current_component_index": 0,
            "current_component": {},
            "current_domain_index": 0,
            "current_domain": AttackDomain.PROMPT_INJECTION,
            "attack_results": [],
            "iteration": 0,
            "phase": ScanPhase.RECON,
            "logs": [],
            "critical_halt": False,
            "components": [],
            "approved_findings": [],
            "report_path": "",
            "report_json": {},
        }

        try:
            logger.info("Starting scan %s for client %s", scan_id, client_id)
            final_state: dict = await self.graph.ainvoke(initial_state)
            logger.info(
                "Scan %s completed. Phase: %s",
                scan_id,
                final_state["phase"],
            )
            return final_state
        except Exception:
            logger.exception("Scan %s failed", scan_id)
            raise
