"""
domain_library.py — DomainLibrary for loading and serving attack templates.

Templates are stored as JSON in domains/templates/*.json.
The AI Security Lead populates template content in Week 2 and Week 4.
The AttackAgent calls get_templates() to retrieve templates for a domain.
"""
import json
import logging
from pathlib import Path
from typing import Optional
from constants import AttackDomain

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Map domain string to JSON filename
DOMAIN_FILE_MAP: dict[str, str] = {
    AttackDomain.PROMPT_INJECTION: "prompt_injection.json",
    AttackDomain.RAG_POISONING: "rag_poisoning.json",
    AttackDomain.API_ATTACKS: "api_attacks.json",
    AttackDomain.INDIRECT_INJECTION: "indirect_injection.json",
    AttackDomain.SYSTEM_PROMPT_EXTRACT: "system_prompt_extraction.json",
}


class DomainLibrary:
    """
    Loads and serves attack templates from the domains/templates/ directory.
    
    Usage:
        library = DomainLibrary()
        templates = library.get_templates(AttackDomain.PROMPT_INJECTION)
    """

    def __init__(self) -> None:
        """Initialize DomainLibrary and validate template files exist."""
        self._cache: dict[str, list[dict]] = {}
        for domain, filename in DOMAIN_FILE_MAP.items():
            path = TEMPLATES_DIR / filename
            if not path.exists():
                logger.warning(
                    "Template file missing for domain '%s': %s", domain, path
                )

    def get_templates(
        self,
        domain: str,
        severity_filter: Optional[str] = None,
    ) -> list[dict]:
        """
        Retrieve attack templates for a given domain.
        
        Args:
            domain: AttackDomain constant string.
            severity_filter: Optional — filter by 'critical', 'high', 'medium'.
        
        Returns:
            List of template dicts. Empty list if domain has no templates yet.
        
        # TODO Week 2: AI Security Lead populates template JSON files.
        # Until then, returns empty list — AttackAgent must handle gracefully.
        """
        if domain in self._cache:
            templates = self._cache[domain]
        else:
            filename = DOMAIN_FILE_MAP.get(domain)
            if not filename:
                logger.error("Unknown domain: %s", domain)
                return []
            path = TEMPLATES_DIR / filename
            try:
                with open(path) as f:
                    data = json.load(f)
                templates = data.get("templates", [])
                self._cache[domain] = templates
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.error("Failed to load templates for domain %s: %s", domain, e)
                return []

        if severity_filter:
            templates = [
                t for t in templates
                if t.get("severity_potential") == severity_filter
            ]
        return templates

    def get_domain_count(self, domain: str) -> int:
        """Return number of templates available for a domain."""
        return len(self.get_templates(domain))
