import asyncio
import logging
from datetime import datetime, timezone
from typing import TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph

from agents.attack_agent import AttackAgent
from agents.recon_agent import ReconAgent
from constants import MAX_ITERATIONS, AgentName, ScanPhase, WSEvent

load_dotenv()

logger = logging.getLogger("orchestrator")


async def _broadcast(scan_id: str, event_type: str, payload: dict) -> None:
    """
    Broadcasts a WebSocket event to all clients watching this scan.
    Uses lazy import of backend.main.manager to avoid circular imports.
    Never raises — a broadcast failure must never crash a scan node.

    Args:
        scan_id: Routes the event to the right connected clients.
        event_type: A WSEvent constant string.
        payload: Additional event fields merged into the broadcast message.
    """
    try:
        from backend.main import manager

        message = {
            "event_type": event_type,
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        await manager.broadcast(scan_id, message)
    except Exception as e:
        logger.warning("WebSocket broadcast failed (non-fatal): %s", e)


class ScanState(TypedDict):
    """LangGraph state for a single Sentinel AI scan orchestration run."""

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
    manifest: dict
    approved_findings: list
    report_path: str
    report_json: dict
    out_of_components: bool


async def recon_node(state: ScanState) -> dict:
    """
    Runs ReconAgent to map the client's full AI attack surface.
    Broadcasts AgentStartedEvent before running.
    Sets the first component and domain on state after recon completes.

    Args:
        state: Current LangGraph ScanState.

    Returns:
        Dict of state updates merged into ScanState by LangGraph.
    """
    scan_id = state["scan_id"]
    client_id = state["client_id"]

    await _broadcast(scan_id, WSEvent.AGENT_STARTED, {
        "agent_name": AgentName.RECON,
        "phase": ScanPhase.RECON,
    })

    logger.info("recon_node | scan_id=%s | phase=%s", scan_id, ScanPhase.RECON)

    agent = ReconAgent(client_id=client_id, scan_id=scan_id)
    updated_state = await agent.run(dict(state))

    components = updated_state.get("components", [])
    if components:
        first_component = components[0]
        domains = first_component.get("estimated_attack_domains", [])
        updated_state["current_component"] = first_component
        updated_state["current_component_index"] = 0
        updated_state["current_domain"] = domains[0] if domains else ""
        updated_state["current_domain_index"] = 0

    # Ensure out_of_components is initialized
    updated_state["out_of_components"] = len(components) == 0

    logs = list(state.get("logs", []))
    logs.append(f"recon_node: mapped {len(components)} components")
    updated_state["logs"] = logs
    updated_state["phase"] = ScanPhase.ATTACKING

    logger.info(
        "recon_node complete | scan_id=%s | components=%s",
        scan_id, len(components),
    )
    return updated_state


async def attack_node(state: ScanState) -> dict:
    """
    Runs AttackAgent against the current component and domain.
    Broadcasts AgentStartedEvent before and AttackExecutedEvent after.
    Handles critical halt detection and broadcasts CriticalHaltEvent if triggered.
    Does NOT increment iteration — mutation_node owns that counter.

    Args:
        state: Current LangGraph ScanState.

    Returns:
        Dict of state updates merged into ScanState by LangGraph.
    """
    scan_id = state["scan_id"]
    client_id = state["client_id"]
    current_domain = state.get("current_domain", "")
    current_component = state.get("current_component", {})
    component_id = current_component.get("component_id", "unknown")

    await _broadcast(scan_id, WSEvent.AGENT_STARTED, {
        "agent_name": AgentName.ATTACK,
        "phase": ScanPhase.ATTACKING,
        "component_id": component_id,
        "domain": current_domain,
    })

    logger.info(
        "attack_node | scan_id=%s | component=%s | domain=%s",
        scan_id, component_id, current_domain,
    )

    agent = AttackAgent(client_id=client_id, scan_id=scan_id)
    updated_state = await agent.run(dict(state))

    attack_results = updated_state.get("attack_results", [])
    high_score = max((r.get("score", 0.0) for r in attack_results), default=0.0)

    await _broadcast(scan_id, WSEvent.ATTACK_EXECUTED, {
        "component_id": component_id,
        "domain": current_domain,
        "payload_preview": attack_results[0].get("payload", "")[:100] if attack_results else "",
        "response_preview": attack_results[0].get("response_text", "")[:100] if attack_results else "",
        "score": high_score,
    })

    if updated_state.get("critical_halt"):
        await _broadcast(scan_id, WSEvent.CRITICAL_HALT, {
            "component_id": component_id,
            "domain": current_domain,
            "score": high_score,
            "reason": "Score exceeded CRITICAL_THRESHOLD",
        })
        logger.warning(
            "CRITICAL HALT | scan_id=%s | component=%s | domain=%s | score=%.2f",
            scan_id, component_id, current_domain, high_score,
        )

    iteration = state.get("iteration", 0) + 1
    updated_state["iteration"] = iteration

    if iteration >= MAX_ITERATIONS and not updated_state.get("critical_halt"):
        components = updated_state.get("components", state.get("components", []))
        c_idx = updated_state.get("current_component_index", state.get("current_component_index", 0))
        d_idx = updated_state.get("current_domain_index", state.get("current_domain_index", 0))

        if c_idx < len(components):
            current_comp = components[c_idx]
            domains = current_comp.get("estimated_attack_domains", [])
            if d_idx + 1 < len(domains):
                updated_state["current_domain_index"] = d_idx + 1
                updated_state["current_domain"] = domains[d_idx + 1]
                updated_state["iteration"] = 0
                updated_state["attack_results"] = []
            else:
                next_c = c_idx + 1
                updated_state["current_component_index"] = next_c
                updated_state["current_domain_index"] = 0
                updated_state["iteration"] = 0
                updated_state["attack_results"] = []
                if next_c < len(components):
                    next_comp = components[next_c]
                    next_domains = next_comp.get("estimated_attack_domains", [])
                    updated_state["current_component"] = next_comp
                    updated_state["current_domain"] = next_domains[0] if next_domains else ""
                else:
                    updated_state["out_of_components"] = True

    logs = list(state.get("logs", []))
    logs.append(
        f"attack_node: {len(attack_results)} attempts on {component_id}/{current_domain} "
        f"high_score={high_score:.2f}"
    )
    updated_state["logs"] = logs

    logger.info(
        "attack_node complete | scan_id=%s | attempts=%s | high_score=%.2f",
        scan_id, len(attack_results), high_score,
    )
    return updated_state


async def mutation_node(state: ScanState) -> dict:
    """Generate mutated attack variants from successful attack results."""
    logger.info(
        "mutation_node | scan_id=%s | phase=%s", state["scan_id"], state["phase"]
    )
    logs = list(state["logs"])
    logs.append("mutation_node: mutation generation (skeleton)")

    updates = {
        "phase": ScanPhase.MUTATING,
        "logs": logs,
    }

    return updates


async def report_node(state: ScanState) -> dict:
    """Compile findings into a client-facing security report."""
    logger.info(
        "report_node | scan_id=%s | phase=%s", state["scan_id"], state["phase"]
    )
    logs = list(state["logs"])
    logs.append("report_node: report generation (skeleton)")
    return {"phase": ScanPhase.REPORTING, "logs": logs}


async def autopatch_node(state: ScanState) -> dict:
    """Generate remediation patches and pull requests for approved findings."""
    logger.info(
        "autopatch_node | scan_id=%s | phase=%s", state["scan_id"], state["phase"]
    )
    logs = list(state["logs"])
    logs.append("autopatch_node: autopatch generation (skeleton)")
    return {"phase": ScanPhase.PATCHING, "logs": logs}


def route_after_attack(state: ScanState) -> str:
    """
    Determines next node after attack_node.

    Priority order:
    1. critical_halt or out_of_components → report_node
    2. iteration == 0 → attack_node (we just advanced to a new domain)
    3. iteration > 0 → mutation_node (keep mutating until max iterations)

    Args:
        state: Current LangGraph ScanState.

    Returns:
        Node name: "mutation_node", "attack_node", or "report_node".
    """
    if state.get("critical_halt"):
        logger.info("route_after_attack → report_node (critical_halt)")
        return "report_node"
        
    if state.get("out_of_components"):
        logger.info("route_after_attack → report_node (out_of_components)")
        return "report_node"

    iteration = state.get("iteration", 0)
    if iteration == 0:
        logger.info("route_after_attack → attack_node (advanced to new domain)")
        return "attack_node"
    
    logger.info("route_after_attack → mutation_node (iteration=%s)", iteration)
    return "mutation_node"


def build_graph() -> StateGraph:
    """Construct and compile the LangGraph scan orchestration workflow."""
    graph = StateGraph(ScanState)
    graph.add_node("recon_node", recon_node)
    graph.add_node("attack_node", attack_node)
    graph.add_node("mutation_node", mutation_node)
    graph.add_node("report_node", report_node)
    graph.add_node("autopatch_node", autopatch_node)
    graph.set_entry_point("recon_node")
    graph.add_edge("recon_node", "attack_node")
    graph.add_conditional_edges(
        "attack_node",
        route_after_attack,
        {"mutation_node": "mutation_node", "report_node": "report_node"},
    )
    graph.add_edge("mutation_node", "attack_node")
    graph.add_edge("report_node", "autopatch_node")
    graph.add_edge("autopatch_node", END)
    return graph.compile()


async def run_scan(client_id: str, scan_id: str) -> ScanState:
    """Run the full scan orchestration graph and return the final state."""
    app = build_graph()
    initial_state: ScanState = {
        "client_id": client_id,
        "scan_id": scan_id,
        "current_component_index": 0,
        "current_component": {},
        "current_domain_index": 0,
        "current_domain": "",
        "attack_results": [],
        "iteration": 0,
        "phase": ScanPhase.RECON,
        "logs": [],
        "critical_halt": False,
        "components": [],
        "manifest": {"components": []},
        "approved_findings": [],
        "report_path": "",
        "report_json": {},
        "out_of_components": False,
    }
    logger.info("Starting scan %s for client %s", scan_id, client_id)
    final_state: ScanState = await app.ainvoke(initial_state)
    logger.info(
        "Scan %s complete | phase=%s | logs=%s",
        scan_id,
        final_state["phase"],
        final_state["logs"],
    )

    await _broadcast(scan_id, WSEvent.SCAN_COMPLETE, {
        "total_vulnerabilities": sum(
            1 for r in final_state.get("attack_results", [])
            if r.get("score", 0.0) >= 0.7
        ),
        "critical_count": sum(
            1 for r in final_state.get("attack_results", [])
            if r.get("score", 0.0) >= 0.9
        ),
        "high_count": sum(
            1 for r in final_state.get("attack_results", [])
            if 0.7 <= r.get("score", 0.0) < 0.9
        ),
        "report_path": final_state.get("report_path", ""),
    })

    return final_state


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    async def _main() -> None:
        """Run a local skeleton scan for development smoke testing."""
        final = await run_scan("test-client-001", "test-scan-001")
        print(final["phase"])
        print(final["logs"])

    asyncio.run(_main())
