"""API security scanner."""

import re
import json
from typing import Optional
from urllib.parse import urlparse, urljoin

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


class APISecurityScanner(BaseScanner):
    """Scanner that checks API endpoints for security issues."""

    API_ENDPOINTS: list[tuple[str, str]] = [
        ("/api", "API root"),
        ("/api/v1", "API v1"),
        ("/api/v2", "API v2"),
        ("/graphql", "GraphQL endpoint"),
        ("/swagger.json", "Swagger/OpenAPI spec (JSON)"),
        ("/openapi.json", "OpenAPI spec (JSON)"),
        ("/api-docs", "API documentation"),
        ("/swagger-ui", "Swagger UI"),
        ("/swagger", "Swagger"),
        ("/api/swagger.json", "API Swagger spec"),
        ("/api/health", "API health check"),
        ("/api/version", "API version endpoint"),
    ]

    @property
    def name(self) -> str:
        return "API Security Scanner"

    @property
    def description(self) -> str:
        return "Checks API endpoints for authentication, CORS, and information disclosure issues"

    @property
    def phase(self) -> int:
        return 3

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Execute API security scan."""
        self.vulnerabilities = []

        try:
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for path, desc in self.API_ENDPOINTS:
                try:
                    full_url = urljoin(base_url, path)
                    await self._check_api_endpoint(full_url, path, desc)
                except Exception:
                    continue

        except Exception:
            pass

        return self.vulnerabilities

    async def _check_api_endpoint(self, full_url: str, path: str, description: str) -> None:
        """Check a single API endpoint for security issues."""
        try:
            response = await self.http_client.get(full_url)
            if response is None:
                return

            status_code: int = response.status_code

            if status_code == 404:
                return

            body: str = response.text
            content_type: str = response.headers.get("content-type", "")

            # Check if endpoint returns data without authentication
            if status_code == 200:
                self._check_unauthenticated_access(full_url, path, description, body, content_type)
                self._check_api_spec_exposure(full_url, path, body, content_type)
                self._check_version_info(full_url, path, body, content_type)

            # Check for verbose error messages
            if status_code >= 400:
                self._check_verbose_errors(full_url, path, body, status_code)

            # Check CORS configuration
            await self._check_cors(full_url, path)

        except Exception:
            pass

    def _check_unauthenticated_access(
        self,
        full_url: str,
        path: str,
        description: str,
        body: str,
        content_type: str,
    ) -> None:
        """Check if an API endpoint returns data without authentication."""
        try:
            is_json = "json" in content_type.lower() or "javascript" in content_type.lower()
            has_data = False

            if is_json:
                try:
                    data = json.loads(body)
                    # Check if response contains meaningful data (not just a status message)
                    if isinstance(data, dict):
                        non_meta_keys = [
                            k for k in data.keys()
                            if k.lower() not in ("status", "message", "error", "ok", "version", "name")
                        ]
                        has_data = len(non_meta_keys) > 0 and len(body) > 50
                    elif isinstance(data, list) and len(data) > 0:
                        has_data = True
                except (json.JSONDecodeError, ValueError):
                    pass

            if has_data:
                self.add_vulnerability(Vulnerability(
                    title=f"Unauthenticated API Data Access: {path}",
                    severity=Severity.HIGH,
                    category=VulnerabilityCategory.BROKEN_AUTH,
                    description=(
                        f"The API endpoint '{path}' ({description}) returns data without requiring "
                        "authentication. This may expose sensitive information to unauthorized users."
                    ),
                    evidence=f"HTTP 200 - Content-Type: {content_type}\nResponse preview: {body[:300]}",
                    url=full_url,
                    remediation=(
                        "Require authentication for all API endpoints that return sensitive data. "
                        "Implement proper authorization checks."
                    ),
                    cwe_id="CWE-306",
                    owasp_category="A07:2021 Identification and Authentication Failures",
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass

    def _check_api_spec_exposure(
        self,
        full_url: str,
        path: str,
        body: str,
        content_type: str,
    ) -> None:
        """Check if API specification documents are publicly accessible."""
        try:
            spec_indicators = [
                "swagger" in path.lower(),
                "openapi" in path.lower(),
                "api-docs" in path.lower(),
            ]

            if not any(spec_indicators):
                return

            is_spec = False
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    is_spec = any(
                        key in data
                        for key in ("swagger", "openapi", "paths", "definitions", "components")
                    )
            except (json.JSONDecodeError, ValueError):
                pass

            if is_spec:
                self.add_vulnerability(Vulnerability(
                    title=f"API Specification Publicly Accessible: {path}",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        f"The API specification at '{path}' is publicly accessible. "
                        "This reveals all API endpoints, parameters, and data models to attackers."
                    ),
                    evidence=f"API spec found at {full_url}\nPreview: {body[:300]}",
                    url=full_url,
                    remediation="Restrict access to API documentation to authenticated users only.",
                    cwe_id="CWE-200",
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _check_version_info(
        self,
        full_url: str,
        path: str,
        body: str,
        content_type: str,
    ) -> None:
        """Check if API returns version information."""
        try:
            if "json" not in content_type.lower():
                return

            try:
                data = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return

            if not isinstance(data, dict):
                return

            version_keys = ["version", "api_version", "apiVersion", "build", "revision"]
            found_versions: list[str] = []

            for key in version_keys:
                if key in data:
                    found_versions.append(f"{key}: {data[key]}")

            if found_versions:
                self.add_vulnerability(Vulnerability(
                    title=f"API Version Information Disclosed: {path}",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        f"The API endpoint '{path}' discloses version information. "
                        "This helps attackers identify specific software versions with known vulnerabilities."
                    ),
                    evidence="\n".join(found_versions),
                    url=full_url,
                    remediation="Remove version information from API responses in production.",
                    cwe_id="CWE-200",
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _check_verbose_errors(
        self,
        full_url: str,
        path: str,
        body: str,
        status_code: int,
    ) -> None:
        """Check for verbose error messages from the API."""
        try:
            verbose_indicators: list[tuple[str, str]] = [
                (r"stack\s*trace", "stack trace"),
                (r"traceback", "traceback"),
                (r"exception", "exception details"),
                (r"at\s+\w+\.\w+\(", "code location"),
                (r"line\s+\d+", "line number"),
                (r"file\s+[\"']?/", "file path"),
                (r"debug", "debug information"),
            ]

            found_indicators: list[str] = []
            for pattern, desc in verbose_indicators:
                if re.search(pattern, body, re.IGNORECASE):
                    found_indicators.append(desc)

            if found_indicators:
                self.add_vulnerability(Vulnerability(
                    title=f"Verbose API Error Response: {path}",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        f"The API endpoint '{path}' returned a verbose error (HTTP {status_code}) "
                        "that may leak implementation details."
                    ),
                    evidence=(
                        f"HTTP {status_code}\n"
                        f"Verbose indicators: {', '.join(found_indicators)}\n"
                        f"Response preview: {body[:300]}"
                    ),
                    url=full_url,
                    remediation=(
                        "Return generic error messages in production. "
                        "Log detailed errors server-side only."
                    ),
                    cwe_id="CWE-209",
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    async def _check_cors(self, full_url: str, path: str) -> None:
        """Check CORS configuration on API endpoints."""
        try:
            response = await self.http_client.options(
                full_url,
                headers={"Origin": "https://evil.example.com"},
            )
            if response is None:
                return

            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                self.add_vulnerability(Vulnerability(
                    title=f"Permissive CORS Policy on API: {path}",
                    severity=severity,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        f"The API endpoint '{path}' has a permissive CORS policy (Access-Control-Allow-Origin: *). "
                        "This allows any website to make cross-origin requests to this API."
                    ),
                    evidence=(
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    url=full_url,
                    remediation=(
                        "Restrict CORS to specific trusted origins. "
                        "Never use wildcard (*) with credentials."
                    ),
                    cwe_id="CWE-942",
                    false_positive_likelihood="low",
                ))
            elif "evil.example.com" in acao:
                self.add_vulnerability(Vulnerability(
                    title=f"CORS Reflects Arbitrary Origin on API: {path}",
                    severity=Severity.HIGH,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        f"The API endpoint '{path}' reflects the Origin header in "
                        "Access-Control-Allow-Origin, allowing any domain to access the API."
                    ),
                    evidence=(
                        f"Request Origin: https://evil.example.com\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    url=full_url,
                    remediation="Validate Origin headers against a whitelist of trusted domains.",
                    cwe_id="CWE-942",
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass
