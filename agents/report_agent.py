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
from constants import get_severity_from_score
from knowledge_base.knowledge_base import KnowledgeBase

logger = logging.getLogger(__name__)

class ReportAgent:
    """Compiles multi-collection scan data into a structured findings report."""

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
