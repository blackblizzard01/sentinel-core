import asyncio
import logging
from datetime import datetime, timezone
from typing import TypedDict

from dotenv import load_dotenv
from langgraph.graph import END, StateGraph

from agents.attack_agent import AttackAgent
from agents.recon_agent import ReconAgent
from agents.mutation_agent import MutationAgent
from agents.report_agent import ReportAgent
from knowledge_base.knowledge_base import KnowledgeBase
from domains.domain_library import DomainLibrary
from constants import CRITICAL_THRESHOLD, MAX_ITERATIONS, SUCCESS_THRESHOLD, TOP_K_RETRIEVAL, AgentName, ScanPhase, WSEvent

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
    previous_batch_avg_score: float
    domains_tested: list
    findings_count: int


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

    if high_score >= CRITICAL_THRESHOLD:
        updated_state["critical_halt"] = True

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

    current_batch_avg: float = (
        sum(r.get("score", 0.0) for r in attack_results) / len(attack_results)
        if attack_results else 0.0
    )

    iteration = state.get("iteration", 0) + 1
    updated_state["iteration"] = iteration

    # Check for no improvement stopping condition:
    # We only check this if iteration > 1 (meaning this is a mutated batch, not the initial one)
    no_improvement = False
    if iteration > 1:
        parent_avg = state.get("previous_batch_avg_score", 0.0)
        if current_batch_avg <= parent_avg:
            no_improvement = True
            logger.info(
                "No improvement detected: current_avg=%.2f <= parent_avg=%.2f. Skipping remaining iterations.",
                current_batch_avg, parent_avg
            )

    updated_state["previous_batch_avg_score"] = current_batch_avg

    # <-- CHANGE: Use updated_state (not state) to accumulate all attack results
    if "all_attack_results" not in updated_state:
        updated_state["all_attack_results"] = []
    updated_state["all_attack_results"].extend(attack_results)

    should_advance = (iteration >= MAX_ITERATIONS) or no_improvement

    if should_advance and not updated_state.get("critical_halt"):
        components = updated_state.get("components", state.get("components", []))
        c_idx = updated_state.get("current_component_index", state.get("current_component_index", 0))
        d_idx = updated_state.get("current_domain_index", state.get("current_domain_index", 0))

        if c_idx < len(components):
            current_comp = components[c_idx]
            domains = current_comp.get("estimated_attack_domains", [])
            if d_idx + 1 < len(domains):
                updated_state["current_domain_index"] = d_idx + 1
                updated_state["current_domain"] = domains[d_idx + 1]
                domains_tested = list(updated_state.get("domains_tested",
                    state.get("domains_tested", [])))
                domains_tested.append(current_domain)
                updated_state["domains_tested"] = domains_tested
                updated_state["iteration"] = 0
                updated_state["previous_batch_avg_score"] = 0.0
                updated_state["attack_results"] = []
            else:
                next_c = c_idx + 1
                findings = [
                    r for r in updated_state.get("all_attack_results", [])
                    if float(r.get("score", 0.0)) >= SUCCESS_THRESHOLD
                    and r.get("component_id") == component_id
                ]
                await _broadcast(scan_id, WSEvent.COMPONENT_COMPLETE, {
                    "component_id": component_id,
                    "domains_tested": list(updated_state.get("domains_tested", [])),
                    "findings_count": len(findings),
                })
                updated_state["current_component_index"] = next_c
                updated_state["current_domain_index"] = 0
                updated_state["domains_tested"] = []
                updated_state["findings_count"] = 0
                updated_state["iteration"] = 0
                updated_state["previous_batch_avg_score"] = 0.0
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
    """
    Full mutation loop node. Runs after attack_node when iteration > 0
    and before the next attack cycle.

    Steps:
    1. Read current domain and component from state.
    2. Instantiate KnowledgeBase and retrieve top-5 successful attacks
       from ChromaDB for the current domain + component_type via
       kb.get_top_attacks(domain, component_type, k=TOP_K_RETRIEVAL).
    3. If KB returns nothing, fall back to state["attack_results"] filtered
       by score >= SUCCESS_THRESHOLD.
    4. If still no attacks, log a warning and return early with iteration=0.
    5. For each parent attack, call
       MutationAgent.generate_variants(parent_payload, n=10) to produce
       10 mutated variants.
    6. For each variant, call kb.log_mutation() to persist lineage.
       Collect the returned mutation_id string.
    7. Broadcast WSEvent.MUTATION_OCCURRED via _broadcast() per variant
       with fields: parent_attack_id, child_attack_id, strategy,
       component_id, domain.
    8. Inject all variants into a new attack_results list as dicts with
       keys: payload, strategy, parent_score, domain, component_id,
       component_type, score (set to 0.0 — not yet executed).
    9. Reset iteration to 0 so the next attack_node cycle starts fresh.
    10. Set phase to ScanPhase.MUTATING.
    11. Never raises — wrap each variant in try/except, log errors with
        logger.error(), and continue. One variant failure must never
        abort the node.

    Args:
        state: Current LangGraph ScanState.

    Returns:
        Dict of state updates: attack_results, iteration, phase, logs.
    """
    scan_id: str = state["scan_id"]
    client_id: str = state["client_id"]
    current_domain: str = state.get("current_domain", "")
    current_component: dict = state.get("current_component", {})
    component_id: str = current_component.get("component_id", "unknown")
    component_type: str = current_component.get("component_type", "unknown")

    await _broadcast(scan_id, WSEvent.AGENT_STARTED, {
        "agent_name": AgentName.MUTATION,
        "phase": ScanPhase.MUTATING,
        "component_id": component_id,
        "domain": current_domain,
    })

    logger.info(
        "mutation_node | scan_id=%s | component=%s | domain=%s",
        scan_id, component_id, current_domain,
    )

    kb = KnowledgeBase(client_id=client_id, scan_id=scan_id)
    top_attacks: list[dict] = []
    try:
        top_attacks = await kb.get_top_attacks(
            domain=current_domain,
            component_type=component_type,
            k=TOP_K_RETRIEVAL,
        )
    except Exception as e:
        logger.error("mutation_node: get_top_attacks failed: %s", e)

    if not top_attacks:
        logger.warning(
            "mutation_node: no KB results, falling back to state attack_results"
        )
        top_attacks = [
            r for r in state.get("attack_results", [])
            if float(r.get("score", 0.0)) >= SUCCESS_THRESHOLD
        ]

    if not top_attacks:
        logger.warning(
            "mutation_node: no successful attacks found — skipping mutation "
            "for component=%s domain=%s", component_id, current_domain,
        )
        logs = list(state.get("logs", []))
        logs.append(
            f"mutation_node: skipped — no successful attacks for "
            f"{component_id}/{current_domain}"
        )
        return {
            "phase": ScanPhase.MUTATING,
            "logs": logs,
        }

    mutation_agent = MutationAgent(client_id=client_id, scan_id=scan_id)
    injected_payloads: list[dict] = []
    total_variants: int = 0

    for parent_attack in top_attacks:
        parent_payload: str = parent_attack.get("payload", "")
        parent_score: float = float(parent_attack.get("score", 0.0))
        parent_attack_id: str = parent_attack.get("attack_id", "unknown")

        try:
            variants = await mutation_agent.generate_variants(parent_payload, n=10)
            for variant in variants:
                try:
                    child_payload = variant.get("payload", "")
                    strategy = variant.get("strategy", "unknown")

                    mutation_id = await kb.log_mutation(
                        parent_attack_id=parent_attack_id,
                        child_payload=child_payload,
                        strategy=strategy,
                        child_score=0.0,
                        generation=1,
                    )

                    await _broadcast(scan_id, WSEvent.MUTATION_OCCURRED, {
                        "parent_attack_id": parent_attack_id,
                        "child_attack_id": mutation_id,
                        "strategy": strategy,
                        "component_id": component_id,
                        "domain": current_domain,
                    })

                    injected_payloads.append({
                        "payload": child_payload,
                        "strategy": strategy,
                        "parent_score": parent_score,
                        "domain": current_domain,
                        "component_id": component_id,
                        "component_type": component_type,
                        "score": 0.0,
                    })
                    total_variants += 1
                except Exception as e:
                    logger.error("mutation_node: failed to process variant: %s", e)
        except Exception as e:
            logger.error("mutation_node: failed to generate variants: %s", e)

    logs = list(state.get("logs", []))
    logs.append(f"mutation_node: generated {total_variants} variants")

    return {
        "attack_results": injected_payloads,
        "phase": ScanPhase.MUTATING,
        "logs": logs,
    }


async def report_node(state: ScanState) -> dict:
    """Compile findings into a client-facing security report."""
    scan_id = state["scan_id"]
    client_id = state["client_id"]

    await _broadcast(scan_id, WSEvent.AGENT_STARTED, {
        "agent_name": AgentName.REPORT,
        "phase": ScanPhase.REPORTING,
    })

    logger.info(
        "report_node | scan_id=%s | phase=%s", scan_id, state["phase"]
    )

    agent = ReportAgent(client_id=client_id, scan_id=scan_id)
    updated_state = await agent.run(dict(state))

    logger.info(
        "report_node complete | scan_id=%s | report_path=%s",
        scan_id, updated_state.get("report_path", ""),
    )
    return updated_state


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


def route_after_mutation(state: ScanState) -> str:
    """
    Determines next node after mutation_node.

    Stopping condition priority order:
    1. critical_halt → report_node (safety escape hatch, checked first always)
    2. out_of_components → report_node
    3. iteration >= MAX_ITERATIONS → advance domain:
           - If next domain exists on current component: reset iteration=0,
             update current_domain and current_domain_index, return "attack_node"
           - If no next domain: advance to next component, reset iteration=0,
             update current_component, current_domain, indices, return "attack_node"
           - If no next component: set out_of_components=True, return "report_node"
    4. No improvement: if state["previous_batch_avg_score"] == 0.0 and
       iteration > 0, that means the last attack batch scored zero on average —
       treat as no improvement and advance to next domain using the same
       domain/component advance logic as condition 3.
       If previous_batch_avg_score > 0.0, continue to attack_node.
    5. Default → attack_node (keep iterating)

    Note: This router cannot mutate state directly in LangGraph — it can only
    return a node name string. Domain/component advancement that requires state
    mutation must be handled in attack_node (which already does this when
    iteration >= MAX_ITERATIONS). This router's job is purely to decide the
    routing string. The actual state mutations for domain advancement already
    live in attack_node and will execute on the next attack_node call when
    iteration is at the boundary.

    Args:
        state: Current LangGraph ScanState.

    Returns:
        Node name: "attack_node" or "report_node".
    """
    if state.get("critical_halt"):
        logger.info("route_after_mutation → report_node (critical_halt)")
        return "report_node"

    if state.get("out_of_components"):
        logger.info("route_after_mutation → report_node (out_of_components)")
        return "report_node"

    iteration: int = state.get("iteration", 0)

    if iteration >= MAX_ITERATIONS:
        logger.info(
            "route_after_mutation → attack_node (max_iterations=%s reached, "
            "attack_node will advance domain)", iteration,
        )
        return "attack_node"

    prev_avg: float = float(state.get("previous_batch_avg_score", 0.0))
    if prev_avg == 0.0 and iteration > 0:
        logger.info(
            "route_after_mutation → attack_node (no improvement, prev_avg=%.2f, "
            "attack_node will advance domain)", prev_avg,
        )
        return "attack_node"

    logger.info(
        "route_after_mutation → attack_node (iteration=%s, prev_avg=%.2f)",
        iteration, prev_avg,
    )
    return "attack_node"


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
        {
            "attack_node": "attack_node",
            "mutation_node": "mutation_node",
            "report_node": "report_node"
        }
    )
    graph.add_conditional_edges(
        "mutation_node",
        route_after_mutation,
        {
            "attack_node": "attack_node",
            "report_node": "report_node",
        }
    )
    graph.add_edge("report_node", "autopatch_node")
    graph.add_edge("autopatch_node", END)
    return graph.compile()


async def run_scan(client_id: str, scan_id: str, manifest: dict | None = None) -> ScanState:
    """Run the full scan orchestration graph and return the final state.
    
    Args:
        client_id: The authorized client's ID.
        scan_id: The current scan session ID.
        manifest: Optional infrastructure manifest with component endpoints.
                 If not provided, defaults to empty manifest (scan will have nothing to test).
                 Format: {"components": [{"endpoint": str, "type": str, "framework": str}]}
    
    Returns:
        Final ScanState after orchestration completes.
    """
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
        "manifest": manifest if manifest is not None else {"components": []},
        "approved_findings": [],
        "report_path": "",
        "report_json": {},
        "out_of_components": False,
        "previous_batch_avg_score": 0.0,
        "domains_tested": [],
        "findings_count": 0,
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
