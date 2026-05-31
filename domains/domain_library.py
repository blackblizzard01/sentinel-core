# stdlib
import json
import logging
from pathlib import Path

# local
from constants import AttackDomain, ComponentType, DOMAIN_COMPONENT_MAP


class DomainLibrary:
    """
    Loads and serves attack template JSON files for each attack domain.
    Maps component types to their applicable attack domains using
    DOMAIN_COMPONENT_MAP from constants.py.
    Templates are loaded lazily and cached after first load.
    """

    def __init__(self) -> None:
        """Initializes DomainLibrary with templates directory path and empty cache."""
        self.templates_dir = Path(__file__).parent / "templates"
        self.logger = logging.getLogger("sentinel.domain_library")
        self._cache: dict[str, list[dict]] = {}

    def load_domain(self, domain: str) -> list[dict]:
        """
        Loads all templates for a given attack domain from its JSON file.
        Caches results after first load.

        Args:
            domain: An AttackDomain constant string.

        Returns:
            List of template dicts. Empty list if file missing or parse error.
        """
        if domain in self._cache:
            return self._cache[domain]

        path = self.templates_dir / f"{domain}.json"
        if not path.exists():
            self.logger.warning(f"Template file not found for domain: {domain}")
            return []

        try:
            with open(path, "r", encoding="utf-8") as f:
                templates = json.load(f)
            self._cache[domain] = templates
            self.logger.info(f"Loaded {len(templates)} templates for domain: {domain}")
            return templates
        except (json.JSONDecodeError, OSError) as e:
            self.logger.error(f"Failed to load templates for domain {domain}: {e}")
            return []

    def get_templates_for_component(self, component_type: str) -> list[str]:
        """
        Returns applicable attack domain strings for a given component type.
        Uses DOMAIN_COMPONENT_MAP from constants.py.

        Args:
            component_type: A ComponentType constant string.

        Returns:
            List of AttackDomain constant strings. Defaults to
            [AttackDomain.API_ATTACKS] for unknown component types.
        """
        domains = DOMAIN_COMPONENT_MAP.get(component_type, [AttackDomain.API_ATTACKS])
        self.logger.debug(f"Component {component_type} → domains: {domains}")
        return domains

    def get_all_templates_for_component(self, component_type: str) -> list[dict]:
        """
        Returns all template dicts across every domain applicable to a component type.

        Args:
            component_type: A ComponentType constant string.

        Returns:
            Flat list of all template dicts for all applicable domains.
        """
        domains = self.get_templates_for_component(component_type)
        results: list[dict] = []
        for domain in domains:
            results.extend(self.load_domain(domain))
        return results
