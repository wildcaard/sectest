"""Open redirect detection scanner - passive analysis."""

import re
from urllib.parse import urlparse, parse_qs, urljoin

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


class OpenRedirectScanner(BaseScanner):
    """Scanner that identifies potential open redirect vulnerabilities."""

    REDIRECT_PARAM_NAMES: list[str] = [
        "redirect", "url", "next", "return", "goto", "destination",
        "redir", "returnurl", "return_url", "continue", "redirect_uri",
        "redirect_url", "target", "to", "out", "view", "login_url",
        "forward", "forward_url", "ref", "referrer", "callback",
        "checkout_url", "success_url", "failure_url", "back",
    ]

    @property
    def name(self) -> str:
        return "Open Redirect Scanner"

    @property
    def description(self) -> str:
        return "Detects potential open redirect vulnerabilities in URL parameters"

    @property
    def phase(self) -> int:
        return 3

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Execute open redirect detection scan."""
        self.vulnerabilities = []

        try:
            response = await self.http_client.get(target_url)
            if response is None:
                return self.vulnerabilities

            body: str = response.text

            self._check_url_parameters(target_url)
            self._check_redirect_in_response(target_url, response)
            self._check_link_parameters(target_url, body)
            await self._probe_common_redirect_params(target_url)

        except Exception:
            pass

        return self.vulnerabilities

    def _check_url_parameters(self, target_url: str) -> None:
        """Check if current URL parameters contain redirect-like values."""
        try:
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query)

            for param_name, values in params.items():
                param_lower = param_name.lower()

                is_redirect_param = any(
                    rp == param_lower or rp in param_lower
                    for rp in self.REDIRECT_PARAM_NAMES
                )

                if not is_redirect_param:
                    continue

                for value in values:
                    if self._looks_like_url_or_path(value):
                        is_external = self._is_external_url(value, target_url)
                        severity = Severity.MEDIUM

                        if is_external:
                            self.add_vulnerability(Vulnerability(
                                title=f"Open Redirect: Parameter '{param_name}' Points to External Domain",
                                severity=severity,
                                category=VulnerabilityCategory.BROKEN_ACCESS,
                                description=(
                                    f"The URL parameter '{param_name}' contains a value that redirects to "
                                    f"an external domain. This may be exploitable as an open redirect."
                                ),
                                evidence=f"Parameter: {param_name}={value[:200]}",
                                url=target_url,
                                remediation=(
                                    "Validate redirect URLs against a whitelist of allowed domains. "
                                    "Use relative paths instead of full URLs where possible."
                                ),
                                cwe_id="CWE-601",
                                owasp_category="A01:2021 Broken Access Control",
                                false_positive_likelihood="low",
                            ))
                        else:
                            self.add_vulnerability(Vulnerability(
                                title=f"Potential Open Redirect: Parameter '{param_name}'",
                                severity=severity,
                                category=VulnerabilityCategory.BROKEN_ACCESS,
                                description=(
                                    f"The URL parameter '{param_name}' accepts a URL or path value. "
                                    "If not properly validated, this could be exploited for open redirects."
                                ),
                                evidence=f"Parameter: {param_name}={value[:200]}",
                                url=target_url,
                                remediation=(
                                    "Validate redirect URLs against a whitelist of allowed domains. "
                                    "Reject absolute URLs to external domains."
                                ),
                                cwe_id="CWE-601",
                                owasp_category="A01:2021 Broken Access Control",
                                false_positive_likelihood="medium",
                            ))
        except Exception:
            pass

    def _check_redirect_in_response(self, target_url: str, response: object) -> None:
        """Check if the response is a redirect and where it points."""
        try:
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location", "")
                if location and self._is_external_url(location, target_url):
                    self.add_vulnerability(Vulnerability(
                        title="Response Redirects to External Domain",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.BROKEN_ACCESS,
                        description=(
                            "The server response is a redirect to an external domain. "
                            "If the redirect destination is influenced by user input, this is an open redirect."
                        ),
                        evidence=f"Status: {response.status_code}, Location: {location[:200]}",
                        url=target_url,
                        remediation="Validate redirect destinations against a whitelist of allowed domains.",
                        cwe_id="CWE-601",
                        false_positive_likelihood="medium",
                    ))
        except Exception:
            pass

    def _check_link_parameters(self, target_url: str, body: str) -> None:
        """Check links in the page for redirect parameters."""
        try:
            link_pattern = re.compile(
                r'(?:href|action)\s*=\s*["\']([^"\']+)["\']',
                re.IGNORECASE,
            )

            redirect_links: list[str] = []
            for match in link_pattern.finditer(body):
                url_value = match.group(1)
                try:
                    link_parsed = urlparse(url_value)
                    link_params = parse_qs(link_parsed.query)
                    for param_name in link_params:
                        if param_name.lower() in self.REDIRECT_PARAM_NAMES:
                            redirect_links.append(f"{param_name} in {url_value[:100]}")
                except Exception:
                    continue

            if redirect_links:
                self.add_vulnerability(Vulnerability(
                    title="Links Contain Redirect Parameters",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.BROKEN_ACCESS,
                    description=(
                        f"Found {len(redirect_links)} link(s) on the page containing redirect parameters. "
                        "These endpoints may be vulnerable to open redirect attacks."
                    ),
                    evidence=f"Redirect links found: {'; '.join(redirect_links[:10])}",
                    url=target_url,
                    remediation="Validate all redirect parameters against a whitelist of allowed destinations.",
                    cwe_id="CWE-601",
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass

    async def _probe_common_redirect_params(self, target_url: str) -> None:
        """Test common redirect parameter names on the target URL to find redirect endpoints."""
        try:
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Only test a few high-value parameter names to avoid excessive requests
            high_value_params = ["redirect", "url", "next", "return", "goto", "returnUrl", "continue"]

            for param in high_value_params:
                test_url = f"{base_url}?{param}=https://example.com"
                try:
                    response = await self.http_client.get(
                        test_url,
                        follow_redirects=False,
                    )
                    if response is None:
                        continue

                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location", "")
                        if "example.com" in location:
                            self.add_vulnerability(Vulnerability(
                                title=f"Confirmed Open Redirect via '{param}' Parameter",
                                severity=Severity.MEDIUM,
                                category=VulnerabilityCategory.BROKEN_ACCESS,
                                description=(
                                    f"The application redirects to an attacker-controlled domain when "
                                    f"the '{param}' parameter is set. This is a confirmed open redirect."
                                ),
                                evidence=(
                                    f"Request: GET {test_url}\n"
                                    f"Response: {response.status_code} -> Location: {location[:200]}"
                                ),
                                url=test_url,
                                remediation=(
                                    "Validate redirect URLs server-side against a whitelist. "
                                    "Do not allow redirects to arbitrary external domains."
                                ),
                                cwe_id="CWE-601",
                                owasp_category="A01:2021 Broken Access Control",
                                false_positive_likelihood="low",
                            ))
                except Exception:
                    continue
        except Exception:
            pass

    @staticmethod
    def _looks_like_url_or_path(value: str) -> bool:
        """Check if a parameter value looks like a URL or path."""
        value = value.strip()
        if value.startswith(("http://", "https://", "//", "/")):
            return True
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
            return True
        return False

    @staticmethod
    def _is_external_url(url: str, target_url: str) -> bool:
        """Check if a URL points to an external domain."""
        try:
            target_domain = urlparse(target_url).netloc.lower()
            if url.startswith("//"):
                url = "https:" + url
            parsed = urlparse(url)
            if not parsed.netloc:
                return False
            return parsed.netloc.lower() != target_domain
        except Exception:
            return False
