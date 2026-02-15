"""HTTP Security Headers Scanner.

Checks for the presence and correct configuration of security-related HTTP
response headers such as HSTS, CSP, X-Content-Type-Options, and others.
"""

import re
from typing import Optional

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


class HeadersScanner(BaseScanner):
    """Scans HTTP response headers for security misconfigurations."""

    @property
    def name(self) -> str:
        return "HTTP Security Headers"

    @property
    def description(self) -> str:
        return "Checks for missing or misconfigured HTTP security headers"

    @property
    def phase(self) -> int:
        return 2

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Fetch the target URL and analyse all security-relevant headers."""
        self.vulnerabilities = []

        response = await self.http_client.get(target_url)
        if response is None:
            return self.vulnerabilities

        headers = response.headers

        self._check_hsts(headers, target_url)
        self._check_csp(headers, target_url)
        self._check_content_type_options(headers, target_url)
        self._check_frame_options(headers, target_url)
        self._check_xss_protection(headers, target_url)
        self._check_referrer_policy(headers, target_url)
        self._check_permissions_policy(headers, target_url)
        self._check_cache_control(headers, target_url)
        self._check_x_powered_by(headers, target_url)
        self._check_server_header(headers, target_url)

        return self.vulnerabilities

    # ------------------------------------------------------------------
    # Individual header checks
    # ------------------------------------------------------------------

    def _check_hsts(self, headers: dict, url: str) -> None:
        """Check Strict-Transport-Security header."""
        try:
            hsts = headers.get("strict-transport-security")
            if not hsts:
                self.add_vulnerability(Vulnerability(
                    title="Missing Strict-Transport-Security Header",
                    severity=Severity.HIGH,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        "The Strict-Transport-Security (HSTS) header is not set. "
                        "Without HSTS, browsers may connect over plain HTTP, "
                        "exposing users to man-in-the-middle attacks."
                    ),
                    evidence="Header 'Strict-Transport-Security' is absent from the response.",
                    url=url,
                    remediation=(
                        "Add the header: Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload"
                    ),
                    cvss_score=7.4,
                    cwe_id="CWE-319",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
                    ],
                    false_positive_likelihood="low",
                ))
                return

            hsts_lower = hsts.lower()
            issues: list[str] = []

            # Check max-age value
            max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
            if not max_age_match:
                issues.append("max-age directive is missing or malformed")
            elif int(max_age_match.group(1)) < 31536000:
                issues.append(
                    f"max-age is {max_age_match.group(1)} (recommended >= 31536000)"
                )

            if "includesubdomains" not in hsts_lower:
                issues.append("includeSubDomains directive is missing")

            if "preload" not in hsts_lower:
                issues.append("preload directive is missing")

            if issues:
                self.add_vulnerability(Vulnerability(
                    title="Weak Strict-Transport-Security Configuration",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        "The HSTS header is present but not optimally configured. "
                        "Issues: " + "; ".join(issues)
                    ),
                    evidence=f"Strict-Transport-Security: {hsts}",
                    url=url,
                    remediation=(
                        "Set the header to: Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload"
                    ),
                    cvss_score=4.8,
                    cwe_id="CWE-319",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
                    ],
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _check_csp(self, headers: dict, url: str) -> None:
        """Check Content-Security-Policy header."""
        try:
            csp = headers.get("content-security-policy")
            if not csp:
                self.add_vulnerability(Vulnerability(
                    title="Missing Content-Security-Policy Header",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.XSS,
                    description=(
                        "No Content-Security-Policy header is set. CSP provides "
                        "defence-in-depth against XSS and data injection attacks."
                    ),
                    evidence="Header 'Content-Security-Policy' is absent from the response.",
                    url=url,
                    remediation=(
                        "Implement a Content-Security-Policy header. Start with a "
                        "report-only policy and tighten it over time."
                    ),
                    cvss_score=5.8,
                    cwe_id="CWE-693",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
                    ],
                    false_positive_likelihood="low",
                ))
                return

            csp_lower = csp.lower()
            issues: list[str] = []

            if "'unsafe-inline'" in csp_lower:
                issues.append("'unsafe-inline' allows inline scripts/styles, weakening XSS protection")

            if "'unsafe-eval'" in csp_lower:
                issues.append("'unsafe-eval' allows eval(), significantly weakening XSS protection")

            if issues:
                self.add_vulnerability(Vulnerability(
                    title="Weak Content-Security-Policy Configuration",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.XSS,
                    description=(
                        "The CSP header contains directives that weaken its "
                        "effectiveness. Issues: " + "; ".join(issues)
                    ),
                    evidence=f"Content-Security-Policy: {csp}",
                    url=url,
                    remediation=(
                        "Remove 'unsafe-inline' and 'unsafe-eval' from the CSP. "
                        "Use nonces or hashes for inline scripts instead."
                    ),
                    cvss_score=4.7,
                    cwe_id="CWE-693",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
                    ],
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _check_content_type_options(self, headers: dict, url: str) -> None:
        """Check X-Content-Type-Options header."""
        try:
            value = headers.get("x-content-type-options")
            if not value:
                self.add_vulnerability(Vulnerability(
                    title="Missing X-Content-Type-Options Header",
                    severity=Severity.LOW,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        "The X-Content-Type-Options header is not set. Without it, "
                        "browsers may MIME-sniff responses, potentially executing "
                        "malicious content."
                    ),
                    evidence="Header 'X-Content-Type-Options' is absent from the response.",
                    url=url,
                    remediation="Add the header: X-Content-Type-Options: nosniff",
                    cvss_score=3.1,
                    cwe_id="CWE-16",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
                    ],
                    false_positive_likelihood="low",
                ))
            elif value.strip().lower() != "nosniff":
                self.add_vulnerability(Vulnerability(
                    title="Invalid X-Content-Type-Options Value",
                    severity=Severity.LOW,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        "X-Content-Type-Options is set but not to 'nosniff'. "
                        "The only valid value is 'nosniff'."
                    ),
                    evidence=f"X-Content-Type-Options: {value}",
                    url=url,
                    remediation="Set the header to: X-Content-Type-Options: nosniff",
                    cvss_score=3.1,
                    cwe_id="CWE-16",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
                    ],
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _check_frame_options(self, headers: dict, url: str) -> None:
        """Check X-Frame-Options header."""
        try:
            value = headers.get("x-frame-options")
            if not value:
                # Will be flagged by the clickjacking scanner in more detail;
                # still note the missing header here at INFO level.
                self.add_vulnerability(Vulnerability(
                    title="Missing X-Frame-Options Header",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        "The X-Frame-Options header is not set. This may allow "
                        "the page to be embedded in an iframe, enabling "
                        "clickjacking attacks."
                    ),
                    evidence="Header 'X-Frame-Options' is absent from the response.",
                    url=url,
                    remediation="Add the header: X-Frame-Options: DENY or SAMEORIGIN",
                    cvss_score=4.3,
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                    ],
                    false_positive_likelihood="medium",
                ))
            else:
                normalised = value.strip().upper()
                if normalised not in ("DENY", "SAMEORIGIN"):
                    self.add_vulnerability(Vulnerability(
                        title="Weak X-Frame-Options Value",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.SECURITY_MISCONFIG,
                        description=(
                            f"X-Frame-Options is set to '{value}'. Only 'DENY' and "
                            "'SAMEORIGIN' are recommended. 'ALLOW-FROM' is deprecated."
                        ),
                        evidence=f"X-Frame-Options: {value}",
                        url=url,
                        remediation="Set the header to: X-Frame-Options: DENY or SAMEORIGIN",
                        cvss_score=4.3,
                        cwe_id="CWE-1021",
                        owasp_category="A05:2021 Security Misconfiguration",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                        ],
                        false_positive_likelihood="low",
                    ))
        except Exception:
            pass

    def _check_xss_protection(self, headers: dict, url: str) -> None:
        """Check X-XSS-Protection header (deprecated)."""
        try:
            value = headers.get("x-xss-protection")
            if value:
                self.add_vulnerability(Vulnerability(
                    title="Deprecated X-XSS-Protection Header Present",
                    severity=Severity.INFO,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        "The X-XSS-Protection header is present. This header is "
                        "deprecated and can introduce XSS vulnerabilities in older "
                        "browsers. Modern browsers have removed support for it. "
                        "Use Content-Security-Policy instead."
                    ),
                    evidence=f"X-XSS-Protection: {value}",
                    url=url,
                    remediation=(
                        "Remove the X-XSS-Protection header and rely on a "
                        "well-configured Content-Security-Policy instead."
                    ),
                    cvss_score=0.0,
                    cwe_id="CWE-16",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
                    ],
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _check_referrer_policy(self, headers: dict, url: str) -> None:
        """Check Referrer-Policy header."""
        try:
            value = headers.get("referrer-policy")
            if not value:
                self.add_vulnerability(Vulnerability(
                    title="Missing Referrer-Policy Header",
                    severity=Severity.LOW,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        "The Referrer-Policy header is not set. Without it, "
                        "the browser may leak the full URL in the Referer header "
                        "when navigating to external sites."
                    ),
                    evidence="Header 'Referrer-Policy' is absent from the response.",
                    url=url,
                    remediation=(
                        "Add the header: Referrer-Policy: strict-origin-when-cross-origin "
                        "or 'no-referrer' for maximum privacy."
                    ),
                    cvss_score=3.1,
                    cwe_id="CWE-200",
                    owasp_category="A01:2021 Broken Access Control",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
                    ],
                    false_positive_likelihood="low",
                ))
            else:
                weak_policies = {"unsafe-url", "no-referrer-when-downgrade"}
                normalised = value.strip().lower()
                if normalised in weak_policies:
                    self.add_vulnerability(Vulnerability(
                        title="Weak Referrer-Policy Value",
                        severity=Severity.LOW,
                        category=VulnerabilityCategory.SENSITIVE_DATA,
                        description=(
                            f"Referrer-Policy is set to '{value}', which may leak "
                            "sensitive URL information to third-party sites."
                        ),
                        evidence=f"Referrer-Policy: {value}",
                        url=url,
                        remediation=(
                            "Use a stricter policy such as 'strict-origin-when-cross-origin' "
                            "or 'no-referrer'."
                        ),
                        cvss_score=3.1,
                        cwe_id="CWE-200",
                        owasp_category="A01:2021 Broken Access Control",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
                        ],
                        false_positive_likelihood="low",
                    ))
        except Exception:
            pass

    def _check_permissions_policy(self, headers: dict, url: str) -> None:
        """Check Permissions-Policy header."""
        try:
            value = headers.get("permissions-policy")
            if not value:
                self.add_vulnerability(Vulnerability(
                    title="Missing Permissions-Policy Header",
                    severity=Severity.LOW,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        "The Permissions-Policy header is not set. This header "
                        "allows control over which browser features (camera, "
                        "microphone, geolocation, etc.) the page can use."
                    ),
                    evidence="Header 'Permissions-Policy' is absent from the response.",
                    url=url,
                    remediation=(
                        "Add a Permissions-Policy header restricting unnecessary "
                        "browser features, e.g. Permissions-Policy: camera=(), "
                        "microphone=(), geolocation=()"
                    ),
                    cvss_score=2.6,
                    cwe_id="CWE-16",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
                    ],
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass

    def _check_cache_control(self, headers: dict, url: str) -> None:
        """Check Cache-Control header on the main page."""
        try:
            value = headers.get("cache-control")
            if not value:
                self.add_vulnerability(Vulnerability(
                    title="Missing Cache-Control Header",
                    severity=Severity.LOW,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        "The Cache-Control header is missing from the main page "
                        "response. Without explicit caching directives, sensitive "
                        "page content may be stored in browser or proxy caches."
                    ),
                    evidence="Header 'Cache-Control' is absent from the response.",
                    url=url,
                    remediation=(
                        "Add appropriate Cache-Control directives. For pages with "
                        "sensitive data: Cache-Control: no-store, no-cache, "
                        "must-revalidate, private"
                    ),
                    cvss_score=2.6,
                    cwe_id="CWE-525",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
                    ],
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass

    def _check_x_powered_by(self, headers: dict, url: str) -> None:
        """Check for X-Powered-By information disclosure."""
        try:
            value = headers.get("x-powered-by")
            if value:
                self.add_vulnerability(Vulnerability(
                    title="X-Powered-By Header Information Disclosure",
                    severity=Severity.LOW,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        "The X-Powered-By header reveals technology information "
                        f"('{value}'). Attackers can use this to tailor exploits "
                        "for the specific technology stack."
                    ),
                    evidence=f"X-Powered-By: {value}",
                    url=url,
                    remediation=(
                        "Remove the X-Powered-By header from server responses. "
                        "In Express.js: app.disable('x-powered-by'). In PHP: "
                        "expose_php = Off in php.ini."
                    ),
                    cvss_score=2.6,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ],
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _check_server_header(self, headers: dict, url: str) -> None:
        """Check Server header for version information disclosure."""
        try:
            value = headers.get("server")
            if not value:
                return

            # Flag if version numbers are present (e.g. Apache/2.4.51)
            if re.search(r"[\d]+\.[\d]+", value):
                self.add_vulnerability(Vulnerability(
                    title="Server Header Version Information Disclosure",
                    severity=Severity.LOW,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        f"The Server header discloses version information ('{value}'). "
                        "Attackers can use this to identify vulnerable software versions."
                    ),
                    evidence=f"Server: {value}",
                    url=url,
                    remediation=(
                        "Configure the web server to suppress version information "
                        "from the Server header. In Apache: ServerTokens Prod. "
                        "In Nginx: server_tokens off."
                    ),
                    cvss_score=2.6,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ],
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass
