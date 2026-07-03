import asyncio
import json
import logging
from datetime import datetime
from typing import Any

from agents.cvss_tables import (
    ATTACK_COMPLEXITY_LOW_WEIGHT,
    ATTACK_VECTOR_WEIGHTS,
    BASE_SCORE_CAP,
    DOMAIN_COMPONENT_CVSS_MAP,
    EXPLOITABILITY_COEFFICIENT,
    IMPACT_MAX_CHANGED,
    IMPACT_MAX_UNCHANGED,
    PRIVILEGES_REQUIRED_NONE_WEIGHT,
    SCOPE_CHANGED_MULTIPLIER,
    ScopeType,
    cvss_roundup,
)
from constants import PARTIAL_THRESHOLD, REPORT_CVSS_MAP, Severity, get_severity_from_score
from knowledge_base.knowledge_base import KnowledgeBase
from agents.base_agent import BaseAgent
from agents.exceptions import ReportGenerationTimeout

logger = logging.getLogger(__name__)

class ReportAgent(BaseAgent):
    """Compiles multi-collection scan data into a structured findings report."""

    def __init__(self, client_id: str, scan_id: str) -> None:
        """Initialise ReportAgent with LLM clients via BaseAgent."""
        super().__init__(agent_name="report_agent", client_id=client_id, scan_id=scan_id)

    async def aggregate_findings(self, client_id: str, scan_id: str) -> dict[str, Any]:
        """Aggregate all findings for a scan into a structured dict.

        Queries component_profiles, attack_history, and vulnerability_catalog
        via KnowledgeBase (scoped to client_id + scan_id), groups attack
        history by component then by domain, and computes summary stats.

        Args:
            client_id: Client identifier to scope the query.
            scan_id: Scan identifier to scope the query.

        Returns:
            {
                "components": [
                    {
                        "component_id": str,
                        "type": str,
                        "findings": [
                            {
                                "domain": str,
                                "score": float,
                                "payload_preview": str,
                                "response_preview": str,
                                "severity": str,
                            }
                        ],
                    }
                ],
                "summary_stats": {
                    "total_findings": int,
                    "critical_count": int,
                    "high_count": int,
                    "medium_count": int,
                    "low_count": int,
                    "scan_duration": float,
                },
            }
        """
        logger.info("Aggregating findings for client=%s scan=%s", client_id, scan_id)

        kb = KnowledgeBase(client_id=client_id, scan_id=scan_id)

        profiles = await kb.get_component_profiles()
        attacks = await kb.get_attack_history()

        component_map: dict[str, dict[str, Any]] = {}
        for profile in profiles:
            component_map[profile["component_id"]] = {
                "component_id": profile["component_id"],
                "type": profile["component_type"],
                "endpoint": profile["endpoint"],
                "findings": [],
            }

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for attack in attacks:
            component_id = attack["component_id"]
            if component_id not in component_map:
                # Attack logged against a component with no profile record
                # (e.g. profile write failed) — create a fallback entry
                # rather than silently dropping the finding.
                component_map[component_id] = {
                    "component_id": component_id,
                    "type": attack["component_type"],
                    "endpoint": "unknown",  # no profile record for this component
                    "findings": [],
                }

            severity = get_severity_from_score(attack["score"])
            if severity in severity_counts:
                severity_counts[severity] += 1

            component_map[component_id]["findings"].append(
                {
                    "domain": attack["domain"],
                    "score": attack["score"],
                    "payload_preview": attack["payload_preview"],
                    "response_preview": attack["response_preview"],
                    "severity": severity,
                    "timestamp": attack["timestamp"],
                }
            )

        timestamps = [a["timestamp"] for a in attacks if a.get("timestamp")]
        scan_duration = 0.0
        if len(timestamps) >= 2:
            try:
                start = datetime.fromisoformat(min(timestamps))
                end = datetime.fromisoformat(max(timestamps))
                scan_duration = (end - start).total_seconds()
            except ValueError:
                logger.warning(
                    "Could not parse timestamps for scan_duration on scan=%s",
                    scan_id,
                )

        summary_stats = {
            "total_findings": len(attacks),
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "scan_duration": scan_duration,
        }

        logger.info(
            "aggregate_findings complete: %s components, %s findings, scan=%s",
            len(component_map),
            len(attacks),
            scan_id,
        )

        return {
            "components": list(component_map.values()),
            "summary_stats": summary_stats,
        }

    def map_cvss_score(
        self, sentinel_score: float, domain: str, component_type: str
    ) -> dict[str, Any]:
        """Map a Sentinel attack score to an approximate CVSS 3.1 base score.

        sentinel_score is treated as the CVSS Impact sub-score directly
        (scaled to the CVSS impact range) rather than decomposed into
        separate C/I/A metrics. Attack Vector is derived from domain;
        Scope is derived from component_type. See cvss_tables.py for the
        full mapping rules and simplifying assumptions.

        Args:
            sentinel_score: Float between 0.0 and 1.0 from the attack pipeline.
            domain: AttackDomain constant string.
            component_type: ComponentType constant string.

        Returns:
            {"base_score": float, "vector_string": str, "severity": str}

        Raises:
            KeyError: If domain/component_type has no CVSS mapping entry.
        """
        mapping = DOMAIN_COMPONENT_CVSS_MAP.get((domain, component_type))
        if mapping is None:
            logger.error(
                "No CVSS mapping for domain=%s component_type=%s",
                domain,
                component_type,
            )
            raise KeyError(
                f"No CVSS mapping for domain={domain} component_type={component_type}"
            )

        is_changed = mapping.scope == ScopeType.CHANGED
        impact_ceiling = IMPACT_MAX_CHANGED if is_changed else IMPACT_MAX_UNCHANGED
        impact = sentinel_score * impact_ceiling

        exploitability = (
            EXPLOITABILITY_COEFFICIENT
            * ATTACK_VECTOR_WEIGHTS[mapping.attack_vector]
            * ATTACK_COMPLEXITY_LOW_WEIGHT
            * PRIVILEGES_REQUIRED_NONE_WEIGHT
            * PRIVILEGES_REQUIRED_NONE_WEIGHT  # UI:N shares the PR:N weight value
        )

        if impact <= 0:
            base_score = 0.0
        elif is_changed:
            base_score = cvss_roundup(
                min(SCOPE_CHANGED_MULTIPLIER * (impact + exploitability), BASE_SCORE_CAP)
            )
        else:
            base_score = cvss_roundup(
                min(impact + exploitability, BASE_SCORE_CAP)
            )

        vector_string = (
            f"CVSS:3.1/AV:{mapping.attack_vector}/AC:L/PR:N/UI:N/"
            f"S:{mapping.scope}/C:H/I:H/A:H"
        )
        severity = get_severity_from_score(base_score / 10.0)

        logger.info(
            "map_cvss_score: domain=%s component_type=%s sentinel_score=%.2f -> base_score=%.1f",
            domain,
            component_type,
            sentinel_score,
            base_score,
        )

        return {
            "base_score": base_score,
            "vector_string": vector_string,
            "severity": severity,
        }

    async def run(self, state: dict) -> dict:
        """LangGraph node entry point. Full wiring deferred to a later task."""
        self.log_action("run_called", "ReportAgent.run is not yet wired into the orchestrator")
        return state

    async def generate_executive_summary(
        self, aggregated_findings: dict[str, Any], client_name: str
    ) -> str:
        """Generate a 3-paragraph executive summary via Gemini for a non-technical audience.

        Paragraph 1 covers overall risk posture, paragraph 2 the top three
        most critical findings, paragraph 3 recommended immediate actions.

        Args:
            aggregated_findings: Output of aggregate_findings().
            client_name: Display name of the client, for personalizing the summary.

        Returns:
            The generated summary text.

        Raises:
            ReportGenerationTimeout: If Gemini does not respond within 60 seconds.
        """
        system_prompt = (
            "You are a security consultant writing an executive summary for a "
            "non-technical business audience. Write exactly 3 paragraphs. "
            "Paragraph 1: overall risk posture, stated as one of Critical, High, "
            "Medium, or Low, in plain language. Paragraph 2: the top three most "
            "critical findings, naming the specific affected components. "
            "Paragraph 3: recommended immediate actions, with at least one "
            "concrete, actionable remediation step. Avoid technical jargon. "
            "Do not use markdown formatting."
        )

        user_prompt = (
            f"Client: {client_name}\n\n"
            f"Aggregated scan findings (JSON):\n"
            f"{json.dumps(aggregated_findings, default=str)}\n\n"
            "Write the 3-paragraph executive summary now."
        )

        self.log_action(
            "generate_executive_summary_start",
            f"client_name={client_name} components={len(aggregated_findings.get('components', []))}",
        )

        try:
            summary = await asyncio.wait_for(
                self.call_gemini(prompt=user_prompt, system=system_prompt),
                timeout=60.0,
            )
        except asyncio.TimeoutError as exc:
            self.log_error("generate_executive_summary timed out", exc)
            raise ReportGenerationTimeout(self.agent_name, 60.0) from exc

        self.log_action("generate_executive_summary_complete", f"length={len(summary)}")
        return summary

    async def generate_component_findings(self, component: dict[str, Any]) -> str:
        """Generate a technical findings markdown section for one component.

        Only findings with score > 0.0 are included. Each included finding
        gets a CVSS score via map_cvss_score, a truncated payload excerpt,
        and the response excerpt that evidences the vulnerability.

        Args:
            component: One entry from aggregate_findings()["components"].

        Returns:
            Markdown-formatted technical findings section for this component,
            ready to embed directly into the PDF report.

        Raises:
            ReportGenerationTimeout: If Gemini does not respond within 60 seconds.
        """
        active_findings = [f for f in component["findings"] if f["score"] > 0.0]
        domains_tested = sorted({f["domain"] for f in component["findings"]})

        finding_blocks: list[str] = []
        for finding in active_findings:
            cvss = self.map_cvss_score(
                finding["score"], finding["domain"], component["type"]
            )
            payload_excerpt = finding["payload_preview"][:100]
            finding_blocks.append(
                f"- Domain: {finding['domain']}\n"
                f"  CVSS: {cvss['base_score']} ({cvss['severity']})\n"
                f"  Sentinel score: {finding['score']:.2f}\n"
                f"  Payload excerpt: {payload_excerpt}\n"
                f"  Response excerpt: {finding['response_preview']}"
            )

        system_prompt = (
            "You are a security consultant writing a technical findings section "
            "for a penetration test report. Output structured markdown suitable "
            "for direct embedding in a PDF. For the component provided, write: "
            "the component endpoint and type as a heading, the list of domains "
            "tested, then for each finding a subsection with the attack domain, "
            "CVSS score, a single-sentence description of what was demonstrated, "
            "the sanitized payload excerpt, and the response excerpt that "
            "evidences the vulnerability. Do not invent findings not provided."
        )

        user_prompt = (
            f"Component ID: {component['component_id']}\n"
            f"Endpoint: {component['endpoint']}\n"
            f"Type: {component['type']}\n"
            f"Domains tested: {', '.join(domains_tested)}\n\n"
            f"Findings:\n" + "\n".join(finding_blocks)
        )

        self.log_action(
            "generate_component_findings_start",
            f"component_id={component['component_id']} findings={len(active_findings)}",
        )

        try:
            markdown = await asyncio.wait_for(
                self.call_gemini(prompt=user_prompt, system=system_prompt),
                timeout=60.0,
            )
        except asyncio.TimeoutError as exc:
            self.log_error("generate_component_findings timed out", exc)
            raise ReportGenerationTimeout(self.agent_name, 60.0) from exc

        self.log_action(
            "generate_component_findings_complete",
            f"component_id={component['component_id']} length={len(markdown)}",
        )
        return markdown

    def generate_attack_timeline(
        self, scan_id: str, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Build a chronological timeline of critical and high findings.

        Args:
            scan_id: Scan identifier, included in each timeline entry.
            findings: Flat list of finding dicts (each must have "severity"
                and "timestamp" keys, as produced by aggregate_findings()'s
                per-component findings lists).

        Returns:
            List of timeline entry dicts, sorted by timestamp ascending,
            containing only Severity.CRITICAL and Severity.HIGH findings.
        """
        relevant = [
            f for f in findings if f["severity"] in (Severity.CRITICAL, Severity.HIGH)
        ]
        relevant.sort(key=lambda f: f["timestamp"])

        timeline = [
            {
                "scan_id": scan_id,
                "timestamp": f["timestamp"],
                "domain": f["domain"],
                "severity": f["severity"],
                "score": f["score"],
            }
            for f in relevant
        ]

        self.log_action(
            "generate_attack_timeline",
            f"scan_id={scan_id} entries={len(timeline)} of {len(findings)} total findings",
        )
        return timeline

    def _cvss_to_priority(self, base_score: float) -> int:
        """Map a CVSS base score to a priority rank using REPORT_CVSS_MAP bands.

        Priority 1 = Critical (most urgent), 4 = Low.

        Args:
            base_score: CVSS base score, 0.0-10.0.

        Returns:
            Integer priority rank, 1 (highest) to 4 (lowest).
        """
        priority_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for rank, severity in enumerate(priority_order, start=1):
            low, high = REPORT_CVSS_MAP[severity]
            if low <= base_score <= high:
                return rank
        return len(priority_order)  # fallback: lowest priority

    async def generate_remediation_roadmap(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Generate a prioritized remediation roadmap from scan findings.

        Only findings with score > PARTIAL_THRESHOLD are included. Each
        finding gets one remediation item via a single batched Gemini call
        requesting structured JSON output, then results are sorted by
        priority ascending (1 = most urgent).

        Args:
            findings: Flat list of finding dicts. Each must include
                component_id, component_type, domain, score, and either
                payload_preview/response_preview for context.

        Returns:
            List of remediation item dicts, sorted by priority ascending:
            {priority, component, domain, short_title, description,
             code_example, estimated_effort}

        Raises:
            ReportGenerationTimeout: If Gemini does not respond within 60 seconds.
        """
        actionable = [f for f in findings if f["score"] > PARTIAL_THRESHOLD]

        if not actionable:
            self.log_action("generate_remediation_roadmap", "no findings above PARTIAL_THRESHOLD")
            return []

        findings_payload = [
            {
                "component_id": f["component_id"],
                "component_type": f["component_type"],
                "domain": f["domain"],
                "score": f["score"],
                "cvss_base_score": self.map_cvss_score(
                    f["score"], f["domain"], f["component_type"]
                )["base_score"],
            }
            for f in actionable
        ]

        system_prompt = (
            "You are a security consultant producing a remediation roadmap. "
            "Respond with ONLY a JSON array, no markdown fences, no prose "
            "before or after. For each finding provided, output one object "
            "with exactly these keys: component (string), domain (string), "
            "short_title (string, under 10 words), description (string, "
            "2-3 sentences explaining the fix), code_example (string, a "
            "concrete code or config snippet where applicable — a hardened "
            "system prompt for system_prompt_extraction or prompt_injection "
            "findings, an input sanitization snippet for api_attacks "
            "findings, or an empty string if not applicable to the domain), "
            "estimated_effort (one of: Low, Medium, High)."
        )

        user_prompt = (
            f"Findings requiring remediation:\n{json.dumps(findings_payload, default=str)}\n\n"
            "Output the JSON array now."
        )

        self.log_action(
            "generate_remediation_roadmap_start", f"findings={len(actionable)}"
        )

        try:
            raw_response = await asyncio.wait_for(
                self.call_gemini(prompt=user_prompt, system=system_prompt),
                timeout=60.0,
            )
        except asyncio.TimeoutError as exc:
            self.log_error("generate_remediation_roadmap timed out", exc)
            raise ReportGenerationTimeout(self.agent_name, 60.0) from exc

        try:
            cleaned = raw_response.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("```")[1]
                cleaned = cleaned.removeprefix("json").strip()
            remediation_items = json.loads(cleaned)
        except (json.JSONDecodeError, IndexError) as exc:
            self.log_error("generate_remediation_roadmap: failed to parse Gemini JSON", exc)
            raise

        for item, finding_payload in zip(remediation_items, findings_payload):
            item["priority"] = self._cvss_to_priority(finding_payload["cvss_base_score"])

        remediation_items.sort(key=lambda item: item["priority"])

        self.log_action(
            "generate_remediation_roadmap_complete", f"items={len(remediation_items)}"
        )
        return remediation_items
