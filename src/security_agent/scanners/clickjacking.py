"""Clickjacking Protection Scanner.

Verifies that the target is protected against clickjacking via
X-Frame-Options and/or the CSP frame-ancestors directive.
"""

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


class ClickjackingScanner(BaseScanner):
    """Checks for clickjacking protection headers and directives."""

    @property
    def name(self) -> str:
        return "Clickjacking Protection"

    @property
    def description(self) -> str:
        return "Checks for X-Frame-Options and CSP frame-ancestors clickjacking protections"

    @property
    def phase(self) -> int:
        return 2

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Fetch the target and analyse framing protections."""
        self.vulnerabilities = []

        response = await self.http_client.get(target_url)
        if response is None:
            return self.vulnerabilities

        headers = response.headers

        xfo = headers.get("x-frame-options")
        csp = headers.get("content-security-policy")

        has_xfo = xfo is not None
        has_frame_ancestors = self._has_frame_ancestors(csp)

        self._check_xfo(xfo, target_url)
        self._check_frame_ancestors(csp, target_url)
        self._check_no_protection(has_xfo, has_frame_ancestors, target_url)

        return self.vulnerabilities

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _check_xfo(self, xfo: str | None, url: str) -> None:
        """Validate X-Frame-Options value if present."""
        try:
            if xfo is None:
                return

            normalised = xfo.strip().upper()

            if normalised.startswith("ALLOW-FROM"):
                self.add_vulnerability(Vulnerability(
                    title="Deprecated X-Frame-Options ALLOW-FROM Directive",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        "The X-Frame-Options header uses the ALLOW-FROM directive, "
                        "which is deprecated and not supported by modern browsers. "
                        "This may leave the page unprotected against clickjacking."
                    ),
                    evidence=f"X-Frame-Options: {xfo}",
                    url=url,
                    remediation=(
                        "Replace ALLOW-FROM with the CSP frame-ancestors directive, "
                        "e.g. Content-Security-Policy: frame-ancestors 'self' https://trusted.example.com"
                    ),
                    cvss_score=4.3,
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                    ],
                    false_positive_likelihood="low",
                ))

            elif normalised not in ("DENY", "SAMEORIGIN"):
                self.add_vulnerability(Vulnerability(
                    title="Invalid X-Frame-Options Value",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        f"The X-Frame-Options header has an invalid value '{xfo}'. "
                        "Browsers may ignore it, leaving the page unprotected."
                    ),
                    evidence=f"X-Frame-Options: {xfo}",
                    url=url,
                    remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
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

    def _check_frame_ancestors(self, csp: str | None, url: str) -> None:
        """Inspect CSP frame-ancestors if present."""
        try:
            if csp is None:
                return

            fa_value = self._extract_frame_ancestors(csp)
            if fa_value is None:
                return

            # frame-ancestors * is essentially no protection
            fa_lower = fa_value.strip().lower()
            if fa_lower == "*":
                self.add_vulnerability(Vulnerability(
                    title="CSP frame-ancestors Set to Wildcard",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        "The Content-Security-Policy frame-ancestors directive is "
                        "set to '*', which allows any site to embed this page in "
                        "an iframe. This provides no clickjacking protection."
                    ),
                    evidence=f"frame-ancestors {fa_value}",
                    url=url,
                    remediation=(
                        "Set frame-ancestors to 'self' or a specific list of "
                        "trusted origins."
                    ),
                    cvss_score=4.3,
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"
                    ],
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _check_no_protection(
        self, has_xfo: bool, has_frame_ancestors: bool, url: str
    ) -> None:
        """Flag when neither protection mechanism is in place."""
        try:
            if has_xfo or has_frame_ancestors:
                return

            self.add_vulnerability(Vulnerability(
                title="No Clickjacking Protection",
                severity=Severity.MEDIUM,
                category=VulnerabilityCategory.SECURITY_MISCONFIG,
                description=(
                    "Neither X-Frame-Options nor CSP frame-ancestors is set. "
                    "The page can be embedded in an iframe on any site, making "
                    "it vulnerable to clickjacking attacks."
                ),
                evidence=(
                    "X-Frame-Options: absent\n"
                    "Content-Security-Policy frame-ancestors: absent"
                ),
                url=url,
                remediation=(
                    "Add X-Frame-Options: DENY (or SAMEORIGIN) and/or "
                    "Content-Security-Policy: frame-ancestors 'self'."
                ),
                cvss_score=4.3,
                cwe_id="CWE-1021",
                owasp_category="A05:2021 Security Misconfiguration",
                references=[
                    "https://owasp.org/www-community/attacks/Clickjacking"
                ],
                false_positive_likelihood="medium",
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _has_frame_ancestors(csp: str | None) -> bool:
        """Return True if the CSP header contains a frame-ancestors directive."""
        if csp is None:
            return False
        return "frame-ancestors" in csp.lower()

    @staticmethod
    def _extract_frame_ancestors(csp: str) -> str | None:
        """Extract the value of frame-ancestors from a CSP header string."""
        for directive in csp.split(";"):
            directive = directive.strip()
            if directive.lower().startswith("frame-ancestors"):
                # Everything after the directive name is the value
                return directive[len("frame-ancestors"):].strip()
        return None
