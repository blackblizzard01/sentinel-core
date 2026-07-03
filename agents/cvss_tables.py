"""CVSS v3.1 scoring constants and domain/component lookup tables.

Simplified CVSS v3.1 approximation: sentinel_score maps directly to the
CVSS Impact sub-score (rather than decomposing into separate
Confidentiality/Integrity/Availability metrics), per W5-TEAM-02 spec.
Exploitability sub-score uses fixed Attack Complexity: Low, Privileges
Required: None, User Interaction: None — reasonable defaults for
automated AI red-team attacks where the agent has no special access
and no human is in the loop.
"""

import math
from typing import NamedTuple

from constants import AttackDomain, ComponentType


class AttackVector:
    """CVSS 3.1 Attack Vector metric values and weights."""
    NETWORK = "N"
    ADJACENT = "A"


ATTACK_VECTOR_WEIGHTS: dict[str, float] = {
    AttackVector.NETWORK: 0.85,
    AttackVector.ADJACENT: 0.62,
}

# Fixed sub-metric weights (CVSS 3.1 spec values for AC:L, PR:N, UI:N)
ATTACK_COMPLEXITY_LOW_WEIGHT = 0.77
PRIVILEGES_REQUIRED_NONE_WEIGHT = 0.85
USER_INTERACTION_NONE_WEIGHT = 0.85

EXPLOITABILITY_COEFFICIENT = 8.22
IMPACT_MAX_UNCHANGED = 6.42
IMPACT_MAX_CHANGED = 7.52
SCOPE_CHANGED_MULTIPLIER = 1.08

BASE_SCORE_CAP = 10.0


class ScopeType:
    UNCHANGED = "U"
    CHANGED = "C"


class CvssMapping(NamedTuple):
    """Lookup entry: which Attack Vector and Scope apply to a domain/component pair."""
    attack_vector: str
    scope: str


# Domain -> default Attack Vector (per W5-TEAM-02 spec mapping rule 2)
DOMAIN_ATTACK_VECTOR: dict[str, str] = {
    AttackDomain.PROMPT_INJECTION: AttackVector.NETWORK,
    AttackDomain.RAG_POISONING: AttackVector.NETWORK,
    AttackDomain.SYSTEM_PROMPT_EXTRACT: AttackVector.NETWORK,
    AttackDomain.API_ATTACKS: AttackVector.NETWORK,
    AttackDomain.INDIRECT_INJECTION: AttackVector.ADJACENT,
    AttackDomain.INTER_AGENT_TRUST: AttackVector.ADJACENT,
}

# Component types that flip Scope to Changed (per spec mapping rule 3)
SCOPE_CHANGED_COMPONENT_TYPES: set[str] = {
    ComponentType.BACKEND,
    ComponentType.DATABASE,
}

# Full domain x component_type lookup table.
# Built from DOMAIN_ATTACK_VECTOR + SCOPE_CHANGED_COMPONENT_TYPES rather than
# hand-enumerated, so it can never drift out of sync with the two rules above.
DOMAIN_COMPONENT_CVSS_MAP: dict[tuple[str, str], CvssMapping] = {}
for _domain, _av in DOMAIN_ATTACK_VECTOR.items():
    for _component_type in vars(ComponentType).values():
        if not isinstance(_component_type, str):
            continue
        _scope = (
            ScopeType.CHANGED
            if _component_type in SCOPE_CHANGED_COMPONENT_TYPES
            else ScopeType.UNCHANGED
        )
        DOMAIN_COMPONENT_CVSS_MAP[(_domain, _component_type)] = CvssMapping(
            attack_vector=_av, scope=_scope
        )


def cvss_roundup(value: float) -> float:
    """Round up to the nearest 0.1, per official CVSS 3.1 Roundup(x) spec.

    Args:
        value: Raw computed CVSS score component.

    Returns:
        Value rounded up to one decimal place.
    """
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10
