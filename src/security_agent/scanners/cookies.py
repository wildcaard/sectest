"""Cookie Security Scanner.

Analyses cookies set by the target application for missing security
attributes such as Secure, HttpOnly, and SameSite.
"""

import re
import math
from collections import Counter
from typing import Optional
from urllib.parse import urlparse

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


# Common session cookie name patterns (case-insensitive).
_SESSION_COOKIE_PATTERNS = re.compile(
    r"(sess|session|sid|token|auth|jwt|login|csrf|xsrf|connect\.sid|"
    r"phpsessid|jsessionid|asp\.net_sessionid|laravel_session)",
    re.IGNORECASE,
)


class CookiesScanner(BaseScanner):
    """Scans response cookies for insecure configurations."""

    @property
    def name(self) -> str:
        return "Cookie Security"

    @property
    def description(self) -> str:
        return "Checks cookies for missing Secure, HttpOnly, SameSite attributes and other issues"

    @property
    def phase(self) -> int:
        return 2

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Fetch the target and inspect every Set-Cookie header."""
        self.vulnerabilities = []

        response = await self.http_client.get(target_url)
        if response is None:
            return self.vulnerabilities

        is_https = urlparse(target_url).scheme == "https"

        # httpx exposes cookies via response.cookies (a Cookies jar) and raw
        # Set-Cookie headers via response.headers.get_list("set-cookie").
        raw_cookies: list[str] = []
        try:
            raw_cookies = response.headers.get_list("set-cookie")
        except AttributeError:
            # Fallback: iterate over multi-map
            raw_cookies = [
                v for k, v in response.headers.multi_items()
                if k.lower() == "set-cookie"
            ]

        if not raw_cookies:
            return self.vulnerabilities

        for raw in raw_cookies:
            self._analyse_cookie(raw, target_url, is_https)

        return self.vulnerabilities

    # ------------------------------------------------------------------
    # Per-cookie analysis
    # ------------------------------------------------------------------

    def _analyse_cookie(self, raw: str, url: str, is_https: bool) -> None:
        """Run all checks on a single Set-Cookie header value."""
        try:
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                return

            # First part is name=value
            name_value = parts[0]
            eq_idx = name_value.find("=")
            if eq_idx == -1:
                return
            cookie_name = name_value[:eq_idx].strip()
            cookie_value = name_value[eq_idx + 1:].strip()

            # Build a dict of attributes (lower-cased keys)
            attrs: dict[str, str] = {}
            for part in parts[1:]:
                if "=" in part:
                    k, v = part.split("=", 1)
                    attrs[k.strip().lower()] = v.strip()
                else:
                    attrs[part.strip().lower()] = ""

            is_session = bool(_SESSION_COOKIE_PATTERNS.search(cookie_name))

            self._check_secure_flag(cookie_name, attrs, url, is_https, is_session)
            self._check_httponly_flag(cookie_name, attrs, url, is_session)
            self._check_samesite(cookie_name, attrs, url)
            self._check_scope(cookie_name, attrs, url)
            self._check_prefixes(cookie_name, attrs, url, is_https)
            self._check_entropy(cookie_name, cookie_value, url, is_session)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Individual attribute checks
    # ------------------------------------------------------------------

    def _check_secure_flag(
        self,
        name: str,
        attrs: dict[str, str],
        url: str,
        is_https: bool,
        is_session: bool,
    ) -> None:
        """Flag cookies without the Secure attribute."""
        try:
            if "secure" in attrs:
                return

            severity = Severity.HIGH if is_session else Severity.MEDIUM
            self.add_vulnerability(Vulnerability(
                title=f"Cookie '{name}' Missing Secure Flag",
                severity=severity,
                category=VulnerabilityCategory.SENSITIVE_DATA,
                description=(
                    f"The cookie '{name}' does not have the Secure attribute. "
                    "It will be sent over unencrypted HTTP connections, "
                    "exposing it to interception."
                ),
                evidence=f"Set-Cookie: {name}=...; (Secure flag absent)",
                url=url,
                remediation="Add the Secure flag to the Set-Cookie header.",
                cvss_score=6.5 if is_session else 4.3,
                cwe_id="CWE-614",
                owasp_category="A02:2021 Cryptographic Failures",
                references=[
                    "https://owasp.org/www-community/controls/SecureCookieAttribute"
                ],
                false_positive_likelihood="low",
            ))
        except Exception:
            pass

    def _check_httponly_flag(
        self, name: str, attrs: dict[str, str], url: str, is_session: bool
    ) -> None:
        """Flag cookies without the HttpOnly attribute."""
        try:
            if "httponly" in attrs:
                return

            severity = Severity.MEDIUM if is_session else Severity.LOW
            self.add_vulnerability(Vulnerability(
                title=f"Cookie '{name}' Missing HttpOnly Flag",
                severity=severity,
                category=VulnerabilityCategory.SENSITIVE_DATA,
                description=(
                    f"The cookie '{name}' does not have the HttpOnly attribute. "
                    "Client-side scripts can read this cookie, increasing the "
                    "impact of XSS attacks."
                ),
                evidence=f"Set-Cookie: {name}=...; (HttpOnly flag absent)",
                url=url,
                remediation="Add the HttpOnly flag to the Set-Cookie header.",
                cvss_score=5.3 if is_session else 3.1,
                cwe_id="CWE-1004",
                owasp_category="A05:2021 Security Misconfiguration",
                references=[
                    "https://owasp.org/www-community/HttpOnly"
                ],
                false_positive_likelihood="low",
            ))
        except Exception:
            pass

    def _check_samesite(
        self, name: str, attrs: dict[str, str], url: str
    ) -> None:
        """Flag cookies with missing or permissive SameSite attribute."""
        try:
            samesite = attrs.get("samesite")
            if samesite is None:
                self.add_vulnerability(Vulnerability(
                    title=f"Cookie '{name}' Missing SameSite Attribute",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.CSRF,
                    description=(
                        f"The cookie '{name}' does not set the SameSite attribute. "
                        "Modern browsers default to Lax, but explicitly setting it "
                        "provides consistent CSRF protection across all browsers."
                    ),
                    evidence=f"Set-Cookie: {name}=...; (SameSite attribute absent)",
                    url=url,
                    remediation="Add SameSite=Lax or SameSite=Strict to the Set-Cookie header.",
                    cvss_score=4.3,
                    cwe_id="CWE-1275",
                    owasp_category="A01:2021 Broken Access Control",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                    ],
                    false_positive_likelihood="medium",
                ))
            elif samesite.lower() == "none":
                self.add_vulnerability(Vulnerability(
                    title=f"Cookie '{name}' Has SameSite=None",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.CSRF,
                    description=(
                        f"The cookie '{name}' uses SameSite=None, which sends the "
                        "cookie on all cross-site requests. This disables SameSite "
                        "CSRF protection for this cookie."
                    ),
                    evidence=f"Set-Cookie: {name}=...; SameSite=None",
                    url=url,
                    remediation=(
                        "Use SameSite=Lax or SameSite=Strict unless cross-site "
                        "delivery is genuinely required."
                    ),
                    cvss_score=4.3,
                    cwe_id="CWE-1275",
                    owasp_category="A01:2021 Broken Access Control",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                    ],
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass

    def _check_scope(
        self, name: str, attrs: dict[str, str], url: str
    ) -> None:
        """Flag overly broad cookie scope."""
        try:
            domain = attrs.get("domain")
            path = attrs.get("path")

            issues: list[str] = []
            if domain and domain.startswith("."):
                issues.append(
                    f"Domain is set to '{domain}', making the cookie accessible "
                    "to all subdomains"
                )
            if path and path == "/":
                # path=/ is common and often acceptable; only note it.
                pass  # Informational at best, skip to avoid noise.

            if issues:
                self.add_vulnerability(Vulnerability(
                    title=f"Cookie '{name}' Has Broad Domain Scope",
                    severity=Severity.LOW,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        f"The cookie '{name}' has a broad scope. " + " ".join(issues)
                    ),
                    evidence=f"Domain={domain}, Path={path or '/'}",
                    url=url,
                    remediation=(
                        "Restrict the cookie domain to the most specific host "
                        "needed, and limit the path where possible."
                    ),
                    cvss_score=2.6,
                    cwe_id="CWE-1004",
                    owasp_category="A05:2021 Security Misconfiguration",
                    references=[],
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass

    def _check_prefixes(
        self, name: str, attrs: dict[str, str], url: str, is_https: bool
    ) -> None:
        """Validate __Secure- and __Host- cookie prefix requirements."""
        try:
            if name.startswith("__Secure-"):
                if "secure" not in attrs:
                    self.add_vulnerability(Vulnerability(
                        title=f"Cookie '{name}' Violates __Secure- Prefix Rules",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.SECURITY_MISCONFIG,
                        description=(
                            f"The cookie '{name}' uses the __Secure- prefix but "
                            "does not have the Secure attribute, violating the "
                            "prefix specification."
                        ),
                        evidence=f"Set-Cookie: {name}=...; (Secure flag absent)",
                        url=url,
                        remediation="Add the Secure flag when using the __Secure- prefix.",
                        cvss_score=4.3,
                        cwe_id="CWE-614",
                        owasp_category="A05:2021 Security Misconfiguration",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes"
                        ],
                        false_positive_likelihood="low",
                    ))

            if name.startswith("__Host-"):
                issues: list[str] = []
                if "secure" not in attrs:
                    issues.append("Secure flag is missing")
                if "domain" in attrs:
                    issues.append("Domain attribute must not be set")
                if attrs.get("path") != "/":
                    issues.append("Path must be '/'")

                if issues:
                    self.add_vulnerability(Vulnerability(
                        title=f"Cookie '{name}' Violates __Host- Prefix Rules",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.SECURITY_MISCONFIG,
                        description=(
                            f"The cookie '{name}' uses the __Host- prefix but "
                            f"violates prefix requirements: {'; '.join(issues)}."
                        ),
                        evidence=f"Set-Cookie: {name}=...; Issues: {'; '.join(issues)}",
                        url=url,
                        remediation=(
                            "__Host- cookies must have Secure, Path=/, and no "
                            "Domain attribute."
                        ),
                        cvss_score=4.3,
                        cwe_id="CWE-614",
                        owasp_category="A05:2021 Security Misconfiguration",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes"
                        ],
                        false_positive_likelihood="low",
                    ))
        except Exception:
            pass

    def _check_entropy(
        self, name: str, value: str, url: str, is_session: bool
    ) -> None:
        """Flag session cookies with short or low-entropy values."""
        try:
            if not is_session or not value:
                return

            # Minimum reasonable session token length (16 bytes hex = 32 chars)
            if len(value) < 16:
                self.add_vulnerability(Vulnerability(
                    title=f"Session Cookie '{name}' Has Short Value",
                    severity=Severity.HIGH,
                    category=VulnerabilityCategory.BROKEN_AUTH,
                    description=(
                        f"The session cookie '{name}' has a value of only "
                        f"{len(value)} characters. Short session tokens are "
                        "easier to brute-force."
                    ),
                    evidence=f"Cookie value length: {len(value)} characters",
                    url=url,
                    remediation=(
                        "Use a cryptographically secure random generator to "
                        "produce session tokens of at least 128 bits (32 hex chars)."
                    ),
                    cvss_score=7.4,
                    cwe_id="CWE-330",
                    owasp_category="A07:2021 Identification and Authentication Failures",
                    references=[],
                    false_positive_likelihood="medium",
                ))
                return

            # Shannon entropy check
            entropy = self._shannon_entropy(value)
            # Threshold: well-randomised hex/base64 typically > 3.0 bits/char
            if entropy < 2.5:
                self.add_vulnerability(Vulnerability(
                    title=f"Session Cookie '{name}' Has Low Entropy",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.BROKEN_AUTH,
                    description=(
                        f"The session cookie '{name}' has a Shannon entropy of "
                        f"{entropy:.2f} bits/char, suggesting a predictable value."
                    ),
                    evidence=(
                        f"Cookie value length: {len(value)}, "
                        f"entropy: {entropy:.2f} bits/char"
                    ),
                    url=url,
                    remediation=(
                        "Use a cryptographically secure random generator for "
                        "session tokens (e.g. secrets.token_hex in Python)."
                    ),
                    cvss_score=5.3,
                    cwe_id="CWE-330",
                    owasp_category="A07:2021 Identification and Authentication Failures",
                    references=[],
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy in bits per character."""
        if not data:
            return 0.0
        length = len(data)
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
