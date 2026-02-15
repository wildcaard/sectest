from abc import ABC, abstractmethod
from typing import Optional
import asyncio

from security_agent.models.vulnerability import Vulnerability, Severity, VulnerabilityCategory


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

    def __init__(self, http_client, config: dict):
        self.http_client = http_client
        self.config = config
        self.vulnerabilities: list[Vulnerability] = []

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner display name."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Scanner description."""
        ...

    @property
    @abstractmethod
    def phase(self) -> int:
        """Scan phase (1=recon, 2=passive, 3=active)."""
        ...

    @abstractmethod
    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Execute the scan and return vulnerabilities found."""
        ...

    def add_vulnerability(self, vuln: Vulnerability):
        """Add a discovered vulnerability to the results."""
        vuln.scanner_name = self.name
        self.vulnerabilities.append(vuln)

    def is_enabled(self) -> bool:
        """Check if this scanner is enabled in config."""
        scanner_key = self.__class__.__module__.split(".")[-1]
        scanner_conf = self.config.get("scanners", {}).get(scanner_key, {})
        return scanner_conf.get("enabled", True)
