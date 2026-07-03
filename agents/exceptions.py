"""Custom exceptions for Sentinel AI agents."""


class ReportGenerationTimeout(Exception):
    """Raised when LLM report generation exceeds the allotted timeout."""

    def __init__(self, agent_name: str, timeout_seconds: float) -> None:
        self.agent_name = agent_name
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"{agent_name} report generation exceeded {timeout_seconds}s timeout"
        )
