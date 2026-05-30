import asyncio
import logging
from typing import TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph

from constants import MAX_ITERATIONS, AgentName, ScanPhase

load_dotenv()

logger = logging.getLogger("orchestrator")


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
    approved_findings: list
    report_path: str
    report_json: dict


async def recon_node(state: ScanState) -> dict:
    """Discover infrastructure components and populate the scan component list."""
    logger.info(
        "recon_node | scan_id=%s | phase=%s", state["scan_id"], state["phase"]
    )
    logs = list(state["logs"])
    logs.append("recon_node: infrastructure discovery (skeleton)")
    return {"phase": ScanPhase.RECON, "logs": logs}


async def attack_node(state: ScanState) -> dict:
    """Execute attack payloads against the current component and domain."""
    logger.info(
        "attack_node | scan_id=%s | phase=%s", state["scan_id"], state["phase"]
    )
    logs = list(state["logs"])
    logs.append("attack_node: attack execution (skeleton)")
    return {"phase": ScanPhase.ATTACKING, "logs": logs}


async def mutation_node(state: ScanState) -> dict:
    """Generate mutated attack variants from successful attack results."""
    logger.info(
        "mutation_node | scan_id=%s | phase=%s", state["scan_id"], state["phase"]
    )
    logs = list(state["logs"])
    logs.append("mutation_node: mutation generation (skeleton)")
    return {
        "phase": ScanPhase.MUTATING,
        "iteration": state["iteration"] + 1,
        "logs": logs,
    }


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
    """Route to mutation loop or report based on critical halt and iteration count."""
    if state["critical_halt"]:
        logger.warning("Critical halt on scan %s", state["scan_id"])
        return "report_node"
    if state["iteration"] < MAX_ITERATIONS:
        return "mutation_node"
    return "report_node"


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
        "approved_findings": [],
        "report_path": "",
        "report_json": {},
    }
    logger.info("Starting scan %s for client %s", scan_id, client_id)
    final_state: ScanState = await app.ainvoke(initial_state)
    logger.info(
        "Scan %s complete | phase=%s | logs=%s",
        scan_id,
        final_state["phase"],
        final_state["logs"],
    )
    return final_state


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    async def _main() -> None:
        """Run a local skeleton scan for development smoke testing."""
        final = await run_scan("test-client-001", "test-scan-001")
        print(final["phase"])
        print(final["logs"])

    asyncio.run(_main())
