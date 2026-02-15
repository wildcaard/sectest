"""SSRF (Server-Side Request Forgery) detection scanner - passive analysis only."""

import re
from urllib.parse import urlparse, parse_qs

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


class SSRFScanner(BaseScanner):
    """Passive SSRF detection scanner that identifies potential injection points."""

    SSRF_PARAM_NAMES: list[str] = [
        "url", "link", "src", "href", "path", "file", "page",
        "feed", "host", "site", "uri", "source", "dest",
        "redirect", "img", "image", "load", "fetch", "proxy",
        "request", "endpoint", "target", "domain", "callback",
        "resource", "content", "data", "location",
    ]

    SSRF_FORM_PATTERNS: list[tuple[str, str]] = [
        (r'<input[^>]*name\s*=\s*["\']?url["\']?', "URL input field"),
        (r'<input[^>]*name\s*=\s*["\']?link["\']?', "Link input field"),
        (r'<input[^>]*name\s*=\s*["\']?src["\']?', "Source input field"),
        (r'<input[^>]*name\s*=\s*["\']?href["\']?', "Href input field"),
        (r'<input[^>]*name\s*=\s*["\']?file["\']?', "File input field"),
        (r'<input[^>]*name\s*=\s*["\']?path["\']?', "Path input field"),
        (r'<input[^>]*name\s*=\s*["\']?feed["\']?', "Feed input field"),
        (r'<input[^>]*name\s*=\s*["\']?host["\']?', "Host input field"),
        (r'<input[^>]*name\s*=\s*["\']?site["\']?', "Site input field"),
        (r'<input[^>]*type\s*=\s*["\']?url["\']?', "URL-type input field"),
        (r'<textarea[^>]*name\s*=\s*["\']?url["\']?', "URL textarea"),
    ]

    @property
    def name(self) -> str:
        return "SSRF Scanner"

    @property
    def description(self) -> str:
        return "Detects potential Server-Side Request Forgery (SSRF) injection points through passive analysis"

    @property
    def phase(self) -> int:
        return 3

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Execute passive SSRF detection scan."""
        self.vulnerabilities = []

        try:
            response = await self.http_client.get(target_url)
            if response is None:
                return self.vulnerabilities

            body: str = response.text

            self._check_url_parameters(target_url)
            self._check_form_patterns(target_url, body)
            self._check_resource_loading_params(target_url, body)
            self._check_link_params_in_page(target_url, body)

        except Exception:
            pass

        return self.vulnerabilities

    def _check_url_parameters(self, target_url: str) -> None:
        """Check if current URL parameters could be SSRF vectors."""
        try:
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query)

            ssrf_params: list[tuple[str, str]] = []
            for param_name, values in params.items():
                param_lower = param_name.lower()
                if param_lower in self.SSRF_PARAM_NAMES:
                    for value in values:
                        if self._looks_like_url_or_path(value):
                            ssrf_params.append((param_name, value))

            if ssrf_params:
                param_details = "; ".join(
                    f"{name}={val[:80]}" for name, val in ssrf_params
                )
                self.add_vulnerability(Vulnerability(
                    title="Potential SSRF Parameters in URL",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SSRF,
                    description=(
                        f"The URL contains {len(ssrf_params)} parameter(s) with names commonly "
                        "associated with server-side resource fetching. If the server processes these "
                        "URLs without validation, it may be vulnerable to SSRF."
                    ),
                    evidence=f"SSRF-candidate parameters: {param_details}",
                    url=target_url,
                    remediation=(
                        "Validate and sanitize all URL parameters that trigger server-side requests. "
                        "Use an allowlist of permitted domains and protocols. "
                        "Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 169.254.0.0/16)."
                    ),
                    cwe_id="CWE-918",
                    owasp_category="A10:2021 Server-Side Request Forgery",
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass

    def _check_form_patterns(self, target_url: str, body: str) -> None:
        """Check for SSRF-vulnerable patterns in forms."""
        try:
            found_patterns: list[str] = []

            for pattern, description in self.SSRF_FORM_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    found_patterns.append(description)

            if found_patterns:
                self.add_vulnerability(Vulnerability(
                    title="Forms with Potential SSRF Input Fields",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SSRF,
                    description=(
                        f"Found {len(found_patterns)} form field(s) that accept URL-like input. "
                        "If the server fetches resources based on these inputs, SSRF may be possible."
                    ),
                    evidence=f"SSRF-candidate form fields: {', '.join(found_patterns)}",
                    url=target_url,
                    remediation=(
                        "Validate all user-supplied URLs on the server side. "
                        "Implement URL allowlists and block internal network access."
                    ),
                    cwe_id="CWE-918",
                    owasp_category="A10:2021 Server-Side Request Forgery",
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass

    def _check_resource_loading_params(self, target_url: str, body: str) -> None:
        """Look for patterns where the server may fetch remote resources."""
        try:
            # Look for image proxy patterns, PDF generators, webhook URLs, etc.
            resource_patterns: list[tuple[str, str]] = [
                (r"/proxy\?.*url=", "Proxy endpoint with URL parameter"),
                (r"/fetch\?.*url=", "Fetch endpoint with URL parameter"),
                (r"/load\?.*url=", "Load endpoint with URL parameter"),
                (r"/render\?.*url=", "Render endpoint with URL parameter"),
                (r"/screenshot\?.*url=", "Screenshot endpoint with URL parameter"),
                (r"/pdf\?.*url=", "PDF generation endpoint with URL parameter"),
                (r"/webhook", "Webhook endpoint"),
                (r"/import\?.*url=", "Import endpoint with URL parameter"),
                (r"/preview\?.*url=", "Preview endpoint with URL parameter"),
            ]

            found: list[str] = []
            for pattern, description in resource_patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    found.append(description)

            if found:
                self.add_vulnerability(Vulnerability(
                    title="Server-Side Resource Fetching Endpoints Detected",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SSRF,
                    description=(
                        f"Found {len(found)} endpoint pattern(s) that appear to fetch remote resources "
                        "on the server side. These are common SSRF attack vectors."
                    ),
                    evidence=f"Patterns found: {', '.join(found)}",
                    url=target_url,
                    remediation=(
                        "Validate and restrict URLs accepted by resource-fetching endpoints. "
                        "Use network-level controls to prevent access to internal services."
                    ),
                    cwe_id="CWE-918",
                    owasp_category="A10:2021 Server-Side Request Forgery",
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass

    def _check_link_params_in_page(self, target_url: str, body: str) -> None:
        """Check links in the page for parameters that accept URLs."""
        try:
            link_pattern = re.compile(
                r'(?:href|action|src)\s*=\s*["\']([^"\']+)["\']',
                re.IGNORECASE,
            )

            ssrf_links: list[str] = []
            for match in link_pattern.finditer(body):
                url_value = match.group(1)
                try:
                    link_parsed = urlparse(url_value)
                    link_params = parse_qs(link_parsed.query)
                    for param_name, values in link_params.items():
                        if param_name.lower() in self.SSRF_PARAM_NAMES:
                            for value in values:
                                if self._looks_like_url_or_path(value):
                                    ssrf_links.append(
                                        f"{param_name}={value[:60]} in {url_value[:80]}"
                                    )
                except Exception:
                    continue

            if ssrf_links:
                self.add_vulnerability(Vulnerability(
                    title="Page Links Contain SSRF-Candidate Parameters",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SSRF,
                    description=(
                        f"Found {len(ssrf_links)} link(s) on the page with parameters that accept URLs. "
                        "These endpoints may be vulnerable to SSRF if they fetch the URLs server-side."
                    ),
                    evidence=f"SSRF-candidate links: {'; '.join(ssrf_links[:10])}",
                    url=target_url,
                    remediation=(
                        "Audit all server-side URL fetching functionality. "
                        "Implement strict URL validation and network segmentation."
                    ),
                    cwe_id="CWE-918",
                    false_positive_likelihood="medium",
                ))
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
        if "." in value and "/" in value:
            return True
        return False
