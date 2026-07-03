from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional, TYPE_CHECKING

import httpx
from pydantic import BaseModel

from agents.base_agent import BaseAgent
from constants import (
    AgentName,
    AttackDomain,
    ChromaCollection,
    ComponentType,
    ScanPhase,
)
from knowledge_base.knowledge_base import KnowledgeBase

if TYPE_CHECKING:
    from agents.orchestrator import ScanState

logger = logging.getLogger(__name__)

FINGERPRINT_HTTP_TIMEOUT: float = 10.0
FINGERPRINT_CALIBRATION_PROMPT: str = (
    "What is 2+2? Answer in exactly one word."
)
FINGERPRINT_PAYLOAD_MESSAGES: dict[str, Any] = {
    "messages": [{"role": "user", "content": FINGERPRINT_CALIBRATION_PROMPT}],
}
FINGERPRINT_PAYLOAD_COMPLETION: dict[str, Any] = {
    "prompt": FINGERPRINT_CALIBRATION_PROMPT,
    "max_tokens": 10,
}
COMPONENT_TYPE_EMBEDDING: str = "embedding_model"

COMMON_ROUTES: list[str] = [
    "/health",
    "/api/",
    "/v1/chat/completions",
    "/chat",
    "/complete",
    "/generate",
    "/rag/query",
    "/embed",
    "/infer",
    "/predict",
    "/v1/completions",
    "/v1/embeddings",
]

FRAMEWORK_SIGNATURES: dict[str, list[str]] = {
    ComponentType.LLM_MODEL: [
        "x-openai",
        "openai",
        "llama",
        "mistral",
        "claude",
        "gemini",
        "gpt",
    ],
    "fastapi": ["fastapi", "uvicorn", "starlette"],
    "flask": ["werkzeug", "flask"],
    "django": ["django", "wsgi"],
}

HTTP_TIMEOUT: float = 10.0
PROBE_USER_AGENT: str = "SentinelAI-Recon/1.0"


class ComponentProfileSchema(BaseModel):
    """Validated schema for a single component profile entry."""

    component_id: str
    type: str
    endpoint: str
    framework: str
    priority_score: int
    estimated_attack_domains: list[str]


class ReconAgent(BaseAgent):
    """Maps a client's full AI attack surface by probing endpoints, enumerating
    routes, and detecting frameworks. Stores results in ChromaDB
    component_profiles collection. Inherits BaseAgent for LLM calls and
    structured logging."""

    def __init__(
        self,
        client_id: str,
        scan_id: str,
        kb: Optional[KnowledgeBase] = None,
    ) -> None:
        """Initialise ReconAgent with optional shared KnowledgeBase instance."""
        super().__init__(AgentName.RECON, client_id, scan_id)
        self.knowledge_base = kb or KnowledgeBase(client_id=client_id, scan_id=scan_id)
        self.kb = self.knowledge_base
        self.http_client: Optional[httpx.AsyncClient] = None

    def _available_domains(self, candidate_domains: list[str]) -> list[str]:
        """Return only domains that have a template file in domains/templates/."""
        from pathlib import Path
        templates_dir = Path(__file__).parent.parent / "domains" / "templates"
        return [d for d in candidate_domains if (templates_dir / f"{d}.json").exists()]

    def _estimated_attack_domains(self, component_type: str) -> list[str]:
        """Map component type to attack domains using DOMAIN_COMPONENT_MAP
        from constants.py, filtered to only domains with existing template files."""
        from constants import DOMAIN_COMPONENT_MAP
        candidates = DOMAIN_COMPONENT_MAP.get(
            component_type, [AttackDomain.PROMPT_INJECTION]
        )
        return self._available_domains(candidates)

    async def _summarize_probe(
        self, endpoint: str
    ) -> tuple[bool, str, int]:
        """Derive reachability, framework, and priority from probe_endpoint results."""
        probe_result = await self.probe_endpoint(endpoint)
        framework = self.detect_framework(
            probe_result["headers"],
            probe_result["body_preview"],
        )
        is_reachable = probe_result.get("get_status") not in (-1, 0)
        priority_score = self.assign_priority(probe_result, framework, [])
        return is_reachable, framework, priority_score

    def _classify_fingerprint_body(self, body: Any) -> str:
        """Classify component type from a fingerprint HTTP response body."""
        if isinstance(body, list) and body and all(
            isinstance(item, (int, float)) for item in body
        ):
            logger.warning(
                "Fingerprint detected embedding_model at endpoint — not in attack scope"
            )
            return COMPONENT_TYPE_EMBEDDING

        if isinstance(body, dict):
            if self._body_has_embedding_keys(body):
                logger.warning(
                    "Fingerprint detected embedding_model at endpoint — not in attack scope"
                )
                return COMPONENT_TYPE_EMBEDDING

            if "label" in body or "labels" in body:
                return "classifier"

            text_value = self._extract_text_from_body(body)
            if text_value.strip():
                return ComponentType.LLM_MODEL

        return ComponentType.LLM_MODEL

    def _body_has_embedding_keys(self, body: Any) -> bool:
        """Return True if the response body contains embedding or vector fields."""
        if isinstance(body, dict):
            for key in body:
                if key in ("embedding", "vector", "embeddings"):
                    return True
                if self._body_has_embedding_keys(body[key]):
                    return True
        elif isinstance(body, list):
            return any(self._body_has_embedding_keys(item) for item in body)
        return False

    def _extract_text_from_body(self, body: dict[str, Any]) -> str:
        """Extract a text answer from common LLM JSON response shapes."""
        if "text" in body and isinstance(body["text"], str):
            return body["text"]

        choices = body.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message")
                if isinstance(message, dict) and isinstance(message.get("content"), str):
                    return message["content"]
                if isinstance(first.get("text"), str):
                    return first["text"]

        message = body.get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"]

        return ""

    async def fingerprint_model(self, endpoint: str) -> str:
        """
        Sends a calibration prompt to a detected LLM endpoint and classifies
        the response style as a ComponentType constant.

        Sends exactly: "What is 2+2? Answer in exactly one word."

        Classification logic:
        - If response is a short single token / numeric → ComponentType.LLM_MODEL
        - If response is a probability distribution or label → "classifier"
        - If response is a vector / list of floats → "embedding_model"
        - If endpoint does not respond or errors → ComponentType.LLM_MODEL as safe default

        Args:
            endpoint: The full URL of the LLM endpoint to fingerprint.

        Returns:
            A ComponentType constant string: ComponentType.LLM_MODEL, "classifier",
            or "embedding_model".
        """
        payloads = (FINGERPRINT_PAYLOAD_MESSAGES, FINGERPRINT_PAYLOAD_COMPLETION)
        request_headers = {"User-Agent": PROBE_USER_AGENT}

        async with httpx.AsyncClient(timeout=FINGERPRINT_HTTP_TIMEOUT) as client:
            for payload in payloads:
                try:
                    response = await client.post(
                        endpoint,
                        json=payload,
                        headers=request_headers,
                    )
                    response.raise_for_status()
                    body = response.json()
                    result = self._classify_fingerprint_body(body)
                    logger.info("Fingerprinted %s as %s", endpoint, result)
                    return result
                except httpx.TimeoutException as exc:
                    self.log_error(
                        f"fingerprint_model timeout for {endpoint}",
                        exc,
                    )
                except httpx.HTTPStatusError as exc:
                    self.log_error(
                        f"fingerprint_model HTTP {exc.response.status_code} for {endpoint}",
                        exc,
                    )
                except Exception as exc:
                    self.log_error("fingerprint_model failed", exc)

        logger.info(
            "Fingerprinted %s as %s (default)",
            endpoint,
            ComponentType.LLM_MODEL,
        )
        return ComponentType.LLM_MODEL

    async def build_component_map(self, manifest: dict) -> list[dict]:
        """Assembles the full component map from a client infrastructure manifest."""
        components: list[dict] = []
        manifest_components = manifest.get("components", [])

        for index, entry in enumerate(manifest_components):
            endpoint = entry["endpoint"]
            _is_reachable, probed_framework, priority_score = await self._summarize_probe(
                endpoint
            )

            resolved_type = entry.get("type")
            if not resolved_type:
                resolved_type = await self.fingerprint_model(endpoint)

            framework = entry.get("framework") or probed_framework or "unknown"

            component_dict = {
                "component_id": f"{self.scan_id}_{index}",
                "type": resolved_type,
                "endpoint": endpoint,
                "framework": framework,
                "priority_score": priority_score,
                "estimated_attack_domains": self._estimated_attack_domains(
                    resolved_type
                ),
            }
            validated = ComponentProfileSchema(**component_dict).model_dump()
            components.append(validated)

        logger.info("Built component map: %s components", len(components))
        return components

    async def probe_endpoint(self, url: str) -> dict:
        """Send GET and POST requests to a single URL. Capture status codes,
        response headers, content type, response time, and a truncated
        response body preview. Returns a structured probe_result dict."""
        empty_result: dict = {
            "url": url,
            "get_status": -1,
            "post_status": -1,
            "headers": {},
            "content_type": "",
            "response_time_ms": -1.0,
            "body_preview": "",
            "post_body_preview": "",
            "probed_at": datetime.now(timezone.utc).isoformat(),
        }

        get_status = -1
        post_status = -1
        headers: dict = {}
        content_type = ""
        response_time_ms = -1.0
        body_preview = ""
        post_body_preview = ""

        try:
            request_headers = {"User-Agent": PROBE_USER_AGENT}
            async with httpx.AsyncClient(
                timeout=HTTP_TIMEOUT, follow_redirects=True
            ) as client:
                try:
                    start_time = time.monotonic()
                    get_response = await client.get(url, headers=request_headers)
                    response_time_ms = round(
                        (time.monotonic() - start_time) * 1000, 2
                    )
                    get_status = get_response.status_code
                    headers = dict(get_response.headers)
                    content_type = get_response.headers.get("content-type", "")
                    body_preview = get_response.text[:500]
                except (httpx.RequestError, httpx.TimeoutException):
                    get_status = -1
                    headers = {}
                    content_type = ""
                    response_time_ms = -1.0
                    body_preview = ""

                try:
                    post_response = await client.post(
                        url, headers=request_headers, json={}
                    )
                    post_status = post_response.status_code
                    post_body_preview = post_response.text[:500]
                except (httpx.RequestError, httpx.TimeoutException):
                    post_status = -1
                    post_body_preview = ""

            result = {
                "url": url,
                "get_status": get_status,
                "post_status": post_status,
                "headers": headers,
                "content_type": content_type,
                "response_time_ms": response_time_ms,
                "body_preview": body_preview,
                "post_body_preview": post_body_preview,
                "probed_at": datetime.now(timezone.utc).isoformat(),
            }
            self.log_action(
                "probe_endpoint",
                f"url={url} get={get_status} post={post_status}",
            )
            return result
        except Exception as e:
            self.log_error("probe_endpoint failed", e)
            return empty_result

    async def enumerate_routes(self, base_url: str) -> list[str]:
        """Attempt every path in COMMON_ROUTES against base_url concurrently.
        Return the list of full URLs that responded with a non-(-1) GET status."""
        base_url = base_url.rstrip("/")
        full_urls = [base_url + route for route in COMMON_ROUTES]

        results = await asyncio.gather(
            *[self.probe_endpoint(url) for url in full_urls],
            return_exceptions=True,
        )

        live_routes: list[str] = []
        for url, result in zip(full_urls, results):
            if isinstance(result, dict) and result.get("get_status") not in (-1, 0):
                live_routes.append(url)

        self.log_action(
            "enumerate_routes",
            f"base={base_url} found={len(live_routes)}/{len(COMMON_ROUTES)}",
        )
        return live_routes

    def detect_framework(self, headers: dict, response_body: str) -> str:
        """Identify the server framework from response headers and body text.
        Returns one of: 'fastapi', 'flask', 'django', 'llm_endpoint', or 'unknown'."""
        header_parts = [
            f"{k} {v}" for k, v in headers.items()
        ]
        combined = (
            " ".join(header_parts).lower() + " " + response_body.lower()
        )

        if any(
            token in combined
            for token in FRAMEWORK_SIGNATURES[ComponentType.LLM_MODEL]
        ):
            return "llm_endpoint"
        if any(token in combined for token in FRAMEWORK_SIGNATURES["fastapi"]):
            return "fastapi"
        if any(token in combined for token in FRAMEWORK_SIGNATURES["flask"]):
            return "flask"
        if any(token in combined for token in FRAMEWORK_SIGNATURES["django"]):
            return "django"
        return "unknown"

    def assign_priority(
        self, probe_result: dict, framework: str, live_routes: list[str]
    ) -> int:
        """Score this component 1–10 based on recon findings.
        Higher = more attack surface. Used to order AttackAgent work."""
        score = 1

        if probe_result.get("get_status") in (200, 201):
            score += 2
        if probe_result.get("post_status") in (200, 201):
            score += 2
        if framework == "llm_endpoint":
            score += 3
        if framework in ("fastapi", "flask"):
            score += 1
        if len(live_routes) >= 3:
            score += 1
        if probe_result.get("response_time_ms", -1) < 500:
            score += 1

        return max(1, min(10, score))

    async def build_component_profile(
        self,
        endpoint: str,
        component_type: str,
    ) -> dict:
        """Run the full recon pipeline for one endpoint: probe → enumerate →
        detect → score → use Groq to summarise findings.
        Returns the complete component profile dict."""
        probe_result = await self.probe_endpoint(endpoint)
        live_routes = await self.enumerate_routes(endpoint)
        framework = self.detect_framework(
            probe_result["headers"],
            probe_result["body_preview"],
        )
        priority = self.assign_priority(probe_result, framework, live_routes)

        prompt = f"""
       You are a security analyst reviewing recon data for an AI system component.
       Endpoint: {endpoint}
       Component type: {component_type}
       Framework detected: {framework}
       Priority score: {priority}/10
       Live routes found: {live_routes}
       HTTP GET status: {probe_result['get_status']}
       HTTP POST status: {probe_result['post_status']}
       Response headers: {json.dumps(probe_result['headers'], indent=2)}
       Body preview: {probe_result['body_preview'][:300]}

       Write 2–3 sentences summarising the attack surface of this component.
       Be specific and technical. Focus on what an attacker could exploit.
       """
        summary = await self.call_groq(prompt, temperature=0.3)

        return {
            "client_id": self.client_id,
            "scan_id": self.scan_id,
            "endpoint": endpoint,
            "component_type": component_type,
            "framework": framework,
            "priority_score": priority,
            "live_routes": live_routes,
            "probe_result": probe_result,
            "llm_summary": summary,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    async def run(self, state: ScanState) -> ScanState:
        """Main entry point. Drives all recon steps, writes component map to ChromaDB, updates state."""
        self.log_action("run", f"Starting ReconAgent for scan {self.scan_id}")

        manifest = state["manifest"]
        component_map = await self.build_component_map(manifest)

        for component in component_map:
            try:
                await self.knowledge_base.log_component_profile(
                    component_id=component["component_id"],
                    component_type=component.get("type", "unknown"),
                    endpoint=component.get("endpoint", "unknown"),
                    framework=component.get("framework", "unknown"),
                    priority_score=component.get("priority_score", 0.0),
                )
            except Exception as exc:
                self.log_error("Component profile write failed", exc)

        state["components"] = component_map
        state["phase"] = ScanPhase.RECON
        logs = list(state["logs"])
        logs.append(
            f"ReconAgent complete: {len(component_map)} components mapped"
        )
        state["logs"] = logs
        return state
