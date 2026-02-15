"""Directory and path discovery scanner."""

import asyncio
from urllib.parse import urlparse, urljoin

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


class DirectoryScanner(BaseScanner):
    """Scanner that discovers directories and paths by probing common endpoints."""

    # (path, description, is_sensitive)
    COMMON_PATHS: list[tuple[str, str, bool]] = [
        ("/admin", "Admin panel", True),
        ("/administrator", "Administrator panel", True),
        ("/login", "Login page", False),
        ("/wp-admin", "WordPress admin", True),
        ("/wp-login.php", "WordPress login", True),
        ("/dashboard", "Dashboard", True),
        ("/panel", "Control panel", True),
        ("/console", "Console", True),
        ("/phpmyadmin", "phpMyAdmin", True),
        ("/api", "API endpoint", False),
        ("/api/v1", "API v1 endpoint", False),
        ("/swagger", "Swagger documentation", True),
        ("/docs", "Documentation", False),
        ("/graphql", "GraphQL endpoint", True),
        ("/.well-known", "Well-Known URIs", False),
        ("/backup", "Backup files", True),
        ("/config", "Configuration", True),
        ("/debug", "Debug endpoint", True),
        ("/test", "Test page", True),
        ("/status", "Status page", False),
        ("/health", "Health check", False),
        ("/metrics", "Metrics endpoint", True),
        ("/info", "Info endpoint", False),
    ]

    @property
    def name(self) -> str:
        return "Directory Scanner"

    @property
    def description(self) -> str:
        return "Discovers directories and paths by probing common endpoints"

    @property
    def phase(self) -> int:
        return 3

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Execute directory discovery scan."""
        self.vulnerabilities = []

        try:
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for path, desc, is_sensitive in self.COMMON_PATHS:
                try:
                    full_url = urljoin(base_url, path)
                    await self._probe_path(full_url, path, desc, is_sensitive)
                except Exception:
                    continue

        except Exception:
            pass

        return self.vulnerabilities

    async def _probe_path(
        self,
        full_url: str,
        path: str,
        description: str,
        is_sensitive: bool,
    ) -> None:
        """Probe a single path using HEAD first, then GET if interesting."""
        try:
            # Start with HEAD request to minimize bandwidth
            response = await self.http_client.head(full_url)
            if response is None:
                return

            status_code: int = response.status_code

            # Skip 404, 403 can be interesting (path exists but access denied)
            if status_code == 404:
                return

            # For interesting status codes, do a GET to get more info
            body: str = ""
            content_length: int = 0
            if status_code in (200, 301, 302, 403):
                if status_code in (200, 403):
                    get_response = await self.http_client.get(full_url)
                    if get_response is not None:
                        body = get_response.text
                        content_length = len(body)
                        status_code = get_response.status_code

                self._report_finding(full_url, path, description, is_sensitive, status_code, content_length)

        except Exception:
            pass

    def _report_finding(
        self,
        full_url: str,
        path: str,
        description: str,
        is_sensitive: bool,
        status_code: int,
        content_length: int,
    ) -> None:
        """Report a discovered path as a vulnerability finding."""
        try:
            if status_code == 403:
                severity = Severity.INFO
                title = f"Path Exists (Forbidden): {path}"
                desc = (
                    f"The path '{path}' ({description}) exists but returned 403 Forbidden. "
                    "The resource exists but access is currently denied."
                )
            elif status_code in (301, 302):
                severity = Severity.INFO
                title = f"Path Redirects: {path}"
                desc = (
                    f"The path '{path}' ({description}) returned a redirect ({status_code}). "
                    "The resource may have moved or may require authentication."
                )
            elif status_code == 200:
                severity = Severity.MEDIUM if is_sensitive else Severity.INFO
                title = f"Path Discovered: {path}"
                desc = (
                    f"The path '{path}' ({description}) is accessible and returned HTTP 200. "
                )
                if is_sensitive:
                    desc += "This is a sensitive path that should not be publicly accessible."
                else:
                    desc += "Review this endpoint for proper access controls."
            else:
                severity = Severity.INFO
                title = f"Path Responded: {path} (HTTP {status_code})"
                desc = (
                    f"The path '{path}' ({description}) returned HTTP {status_code}."
                )

            evidence = f"HTTP {status_code} - {full_url}"
            if content_length > 0:
                evidence += f" (Content-Length: {content_length})"

            self.add_vulnerability(Vulnerability(
                title=title,
                severity=severity,
                category=VulnerabilityCategory.SECURITY_MISCONFIG,
                description=desc,
                evidence=evidence,
                url=full_url,
                remediation=(
                    "Restrict access to sensitive paths using authentication and authorization. "
                    "Remove or disable unnecessary endpoints in production."
                ),
                cwe_id="CWE-538",
                false_positive_likelihood="low" if status_code == 200 else "medium",
            ))
        except Exception:
            pass
