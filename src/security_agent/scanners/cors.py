"""CORS Misconfiguration Scanner.

Tests for overly permissive Cross-Origin Resource Sharing configurations
that could allow unauthorised cross-origin access to sensitive data.
"""

from urllib.parse import urlparse
from typing import Optional

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


class CorsScanner(BaseScanner):
    """Scans for CORS misconfigurations on the target."""

    @property
    def name(self) -> str:
        return "CORS Misconfiguration"

    @property
    def description(self) -> str:
        return "Tests for insecure Cross-Origin Resource Sharing configurations"

    @property
    def phase(self) -> int:
        return 2

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Run CORS misconfiguration tests against *target_url*."""
        self.vulnerabilities = []

        parsed = urlparse(target_url)
        target_domain = parsed.hostname or ""

        await self._test_evil_origin(target_url)
        await self._test_null_origin(target_url)
        await self._test_subdomain_trick(target_url, target_domain)
        await self._test_preflight(target_url)

        return self.vulnerabilities

    # ------------------------------------------------------------------
    # Test helpers
    # ------------------------------------------------------------------

    async def _test_evil_origin(self, url: str) -> None:
        """Send a request with Origin: https://evil.com and check reflection."""
        try:
            evil_origin = "https://evil.com"
            response = await self.http_client.get(
                url, headers={"Origin": evil_origin}
            )
            if response is None:
                return

            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "").lower()

            if acao == evil_origin:
                severity = Severity.CRITICAL if acac == "true" else Severity.HIGH
                self.add_vulnerability(Vulnerability(
                    title="CORS Allows Arbitrary Origin",
                    severity=severity,
                    category=VulnerabilityCategory.BROKEN_ACCESS,
                    description=(
                        "The server reflects an arbitrary Origin header in "
                        "Access-Control-Allow-Origin. "
                        + (
                            "Combined with Access-Control-Allow-Credentials: true, "
                            "this allows any website to make authenticated cross-origin "
                            "requests and read responses."
                            if acac == "true"
                            else "An attacker's site can read cross-origin responses."
                        )
                    ),
                    evidence=(
                        f"Request Origin: {evil_origin}\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac or 'not set'}"
                    ),
                    url=url,
                    remediation=(
                        "Validate the Origin header against a strict allowlist. "
                        "Never reflect arbitrary origins, especially with credentials."
                    ),
                    cvss_score=9.1 if acac == "true" else 7.4,
                    cwe_id="CWE-942",
                    owasp_category="A01:2021 Broken Access Control",
                    references=[
                        "https://portswigger.net/web-security/cors"
                    ],
                    false_positive_likelihood="low",
                ))
            elif acao == "*":
                self._flag_wildcard(url, acac)
        except Exception:
            pass

    async def _test_null_origin(self, url: str) -> None:
        """Test with Origin: null (sandboxed iframes, data URIs)."""
        try:
            response = await self.http_client.get(
                url, headers={"Origin": "null"}
            )
            if response is None:
                return

            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "").lower()

            if acao == "null":
                self.add_vulnerability(Vulnerability(
                    title="CORS Allows Null Origin",
                    severity=Severity.HIGH,
                    category=VulnerabilityCategory.BROKEN_ACCESS,
                    description=(
                        "The server allows Origin: null in Access-Control-Allow-Origin. "
                        "Sandboxed iframes and data-URI pages send a null origin, "
                        "making this exploitable."
                    ),
                    evidence=(
                        f"Request Origin: null\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac or 'not set'}"
                    ),
                    url=url,
                    remediation=(
                        "Do not allow 'null' as a valid origin. Validate origins "
                        "against a strict allowlist."
                    ),
                    cvss_score=7.4,
                    cwe_id="CWE-942",
                    owasp_category="A01:2021 Broken Access Control",
                    references=[
                        "https://portswigger.net/web-security/cors"
                    ],
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    async def _test_subdomain_trick(self, url: str, target_domain: str) -> None:
        """Test with Origin that embeds the target domain as a subdomain of evil.com."""
        try:
            trick_origin = f"https://{target_domain}.evil.com"
            response = await self.http_client.get(
                url, headers={"Origin": trick_origin}
            )
            if response is None:
                return

            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "").lower()

            if acao == trick_origin:
                self.add_vulnerability(Vulnerability(
                    title="CORS Origin Validation Bypass via Subdomain Trick",
                    severity=Severity.HIGH,
                    category=VulnerabilityCategory.BROKEN_ACCESS,
                    description=(
                        f"The server accepted '{trick_origin}' as a valid origin, "
                        "suggesting origin validation uses a prefix/substring check "
                        "rather than exact matching."
                    ),
                    evidence=(
                        f"Request Origin: {trick_origin}\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac or 'not set'}"
                    ),
                    url=url,
                    remediation=(
                        "Use exact string matching or proper domain comparison "
                        "when validating the Origin header. Do not rely on "
                        "substring or regex prefix matching."
                    ),
                    cvss_score=7.4,
                    cwe_id="CWE-942",
                    owasp_category="A01:2021 Broken Access Control",
                    references=[
                        "https://portswigger.net/web-security/cors"
                    ],
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    async def _test_preflight(self, url: str) -> None:
        """Send a preflight OPTIONS request and analyse the response."""
        try:
            response = await self.http_client.options(
                url,
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "X-Custom-Header",
                },
            )
            if response is None:
                return

            acao = response.headers.get("access-control-allow-origin", "")
            acam = response.headers.get("access-control-allow-methods", "")
            acah = response.headers.get("access-control-allow-headers", "")

            if acao in ("*", "https://evil.com"):
                issues: list[str] = []
                if acao == "https://evil.com":
                    issues.append("Reflects arbitrary origin in preflight response")
                if acam and "*" in acam:
                    issues.append("Allows all HTTP methods via wildcard")
                if acah and "*" in acah:
                    issues.append("Allows all headers via wildcard")

                if issues:
                    self.add_vulnerability(Vulnerability(
                        title="Permissive CORS Preflight Response",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.BROKEN_ACCESS,
                        description=(
                            "The preflight (OPTIONS) response has permissive CORS "
                            "settings. " + "; ".join(issues) + "."
                        ),
                        evidence=(
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Methods: {acam or 'not set'}\n"
                            f"Access-Control-Allow-Headers: {acah or 'not set'}"
                        ),
                        url=url,
                        remediation=(
                            "Restrict allowed origins, methods, and headers in "
                            "preflight responses to only those that are required."
                        ),
                        cvss_score=5.3,
                        cwe_id="CWE-942",
                        owasp_category="A01:2021 Broken Access Control",
                        references=[
                            "https://portswigger.net/web-security/cors"
                        ],
                        false_positive_likelihood="low",
                    ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Wildcard helper
    # ------------------------------------------------------------------

    def _flag_wildcard(self, url: str, acac: str) -> None:
        """Flag wildcard ACAO, escalate to CRITICAL if combined with credentials."""
        try:
            if acac == "true":
                # Browsers actually block this combination, but the server
                # config itself is dangerously wrong.
                self.add_vulnerability(Vulnerability(
                    title="CORS Wildcard Origin with Credentials",
                    severity=Severity.CRITICAL,
                    category=VulnerabilityCategory.BROKEN_ACCESS,
                    description=(
                        "The server sends Access-Control-Allow-Origin: * together "
                        "with Access-Control-Allow-Credentials: true. While modern "
                        "browsers block this combination, the configuration "
                        "indicates a fundamental misunderstanding of CORS that may "
                        "lead to further vulnerabilities."
                    ),
                    evidence=(
                        "Access-Control-Allow-Origin: *\n"
                        "Access-Control-Allow-Credentials: true"
                    ),
                    url=url,
                    remediation=(
                        "Never combine wildcard origin with credentials. Use a "
                        "strict origin allowlist and reflect only validated origins."
                    ),
                    cvss_score=9.1,
                    cwe_id="CWE-942",
                    owasp_category="A01:2021 Broken Access Control",
                    references=[
                        "https://portswigger.net/web-security/cors"
                    ],
                    false_positive_likelihood="low",
                ))
            else:
                self.add_vulnerability(Vulnerability(
                    title="CORS Allows Any Origin via Wildcard",
                    severity=Severity.LOW,
                    category=VulnerabilityCategory.BROKEN_ACCESS,
                    description=(
                        "The server returns Access-Control-Allow-Origin: *. "
                        "Any website can read cross-origin responses. This is "
                        "acceptable for truly public APIs but inappropriate if "
                        "the endpoint returns sensitive data."
                    ),
                    evidence="Access-Control-Allow-Origin: *",
                    url=url,
                    remediation=(
                        "If the endpoint serves sensitive data, replace the "
                        "wildcard with an explicit origin allowlist."
                    ),
                    cvss_score=3.7,
                    cwe_id="CWE-942",
                    owasp_category="A01:2021 Broken Access Control",
                    references=[
                        "https://portswigger.net/web-security/cors"
                    ],
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass
