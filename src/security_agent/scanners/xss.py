"""XSS (Cross-Site Scripting) detection scanner - passive analysis only."""

import re
from typing import Optional
from urllib.parse import urlparse, parse_qs

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


class XSSScanner(BaseScanner):
    """Passive XSS detection scanner that identifies potential injection points."""

    DOM_XSS_PATTERNS: list[tuple[str, str]] = [
        (r"document\.write\s*\(", "document.write usage"),
        (r"\.innerHTML\s*=", "innerHTML assignment"),
        (r"\.outerHTML\s*=", "outerHTML assignment"),
        (r"eval\s*\(", "eval() usage"),
        (r"setTimeout\s*\(\s*[\"']", "setTimeout with string argument"),
        (r"setInterval\s*\(\s*[\"']", "setInterval with string argument"),
        (r"location\.hash", "location.hash access"),
        (r"location\.search", "location.search access"),
        (r"location\.href\s*=", "location.href assignment"),
        (r"document\.URL", "document.URL access"),
        (r"document\.referrer", "document.referrer access"),
        (r"window\.name", "window.name access"),
        (r"document\.cookie", "document.cookie access"),
    ]

    FORM_INPUT_PATTERN: str = (
        r"<form[^>]*>(.*?)</form>"
    )
    INPUT_FIELD_PATTERN: str = (
        r"<input[^>]*>"
    )

    @property
    def name(self) -> str:
        return "XSS Scanner"

    @property
    def description(self) -> str:
        return "Detects potential Cross-Site Scripting (XSS) vulnerabilities through passive analysis"

    @property
    def phase(self) -> int:
        return 3

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Execute passive XSS detection scan."""
        self.vulnerabilities = []

        try:
            response = await self.http_client.get(target_url)
            if response is None:
                return self.vulnerabilities

            body: str = response.text
            has_csp = self._check_csp_protection(response, target_url)

            self._check_reflected_parameters(target_url, body, has_csp)
            self._check_form_injection_points(target_url, body, has_csp)
            self._check_dom_xss_patterns(target_url, body, has_csp)

        except Exception:
            pass

        return self.vulnerabilities

    def _check_csp_protection(self, response: object, target_url: str) -> bool:
        """Check if Content-Security-Policy mitigates XSS. Returns True if CSP with script-src exists."""
        try:
            csp_header: Optional[str] = None
            for header_name in ("content-security-policy", "content-security-policy-report-only"):
                value = response.headers.get(header_name)
                if value:
                    csp_header = value
                    break

            if csp_header is None:
                self.add_vulnerability(Vulnerability(
                    title="No Content-Security-Policy Header",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.XSS,
                    description=(
                        "The response does not include a Content-Security-Policy header. "
                        "CSP is a critical defense-in-depth mechanism against XSS attacks."
                    ),
                    evidence="No CSP header found in response",
                    url=target_url,
                    remediation="Implement a strict Content-Security-Policy header with a script-src directive.",
                    cwe_id="CWE-79",
                    false_positive_likelihood="low",
                ))
                return False

            if "script-src" in csp_header:
                if "'unsafe-inline'" in csp_header or "'unsafe-eval'" in csp_header:
                    self.add_vulnerability(Vulnerability(
                        title="Weak CSP script-src Directive",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.XSS,
                        description=(
                            "The CSP header includes 'unsafe-inline' or 'unsafe-eval' in script-src, "
                            "which significantly weakens XSS protection."
                        ),
                        evidence=f"CSP header: {csp_header}",
                        url=target_url,
                        remediation="Remove 'unsafe-inline' and 'unsafe-eval' from script-src. Use nonces or hashes instead.",
                        cwe_id="CWE-79",
                        false_positive_likelihood="low",
                    ))
                    return False
                return True

            return False

        except Exception:
            return False

    def _check_reflected_parameters(self, target_url: str, body: str, has_csp: bool) -> None:
        """Check for URL parameters reflected unencoded in the response body."""
        try:
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query)

            for param_name, values in params.items():
                for value in values:
                    if len(value) < 3:
                        continue
                    if value in body:
                        severity = Severity.MEDIUM if has_csp else Severity.HIGH
                        self.add_vulnerability(Vulnerability(
                            title=f"Reflected Parameter: {param_name}",
                            severity=severity,
                            category=VulnerabilityCategory.XSS,
                            description=(
                                f"The URL parameter '{param_name}' is reflected unencoded in the response body. "
                                "This could allow reflected XSS if user input is not properly sanitized."
                            ),
                            evidence=(
                                f"Parameter '{param_name}' with value '{value[:100]}' "
                                f"found reflected in response body"
                            ),
                            url=target_url,
                            remediation="Encode all user-supplied input before rendering it in HTML output.",
                            cwe_id="CWE-79",
                            false_positive_likelihood="medium",
                        ))
        except Exception:
            pass

    def _check_form_injection_points(self, target_url: str, body: str, has_csp: bool) -> None:
        """Parse HTML forms and identify input fields that could be XSS injection points."""
        try:
            forms = re.findall(self.FORM_INPUT_PATTERN, body, re.DOTALL | re.IGNORECASE)

            for form_index, form_content in enumerate(forms):
                inputs = re.findall(self.INPUT_FIELD_PATTERN, form_content, re.IGNORECASE)
                text_inputs: list[str] = []

                for input_tag in inputs:
                    input_type_match = re.search(r'type\s*=\s*["\']?(\w+)', input_tag, re.IGNORECASE)
                    input_type = input_type_match.group(1).lower() if input_type_match else "text"

                    if input_type in ("text", "search", "url", "tel", "email", "hidden"):
                        name_match = re.search(r'name\s*=\s*["\']?([^"\'>\s]+)', input_tag, re.IGNORECASE)
                        field_name = name_match.group(1) if name_match else f"unnamed_field_{form_index}"
                        text_inputs.append(field_name)

                # Also check for textarea elements
                textareas = re.findall(
                    r'<textarea[^>]*name\s*=\s*["\']?([^"\'>\s]+)',
                    form_content,
                    re.IGNORECASE,
                )
                text_inputs.extend(textareas)

                if text_inputs:
                    severity = Severity.MEDIUM if has_csp else Severity.HIGH
                    self.add_vulnerability(Vulnerability(
                        title=f"Potential XSS Injection Points in Form #{form_index + 1}",
                        severity=severity,
                        category=VulnerabilityCategory.XSS,
                        description=(
                            f"Form #{form_index + 1} contains {len(text_inputs)} text-accepting input field(s) "
                            "that could be potential XSS injection points if output is not properly encoded."
                        ),
                        evidence=f"Input fields: {', '.join(text_inputs[:20])}",
                        url=target_url,
                        remediation="Ensure all form input values are properly HTML-encoded when rendered in responses.",
                        cwe_id="CWE-79",
                        false_positive_likelihood="medium",
                    ))
        except Exception:
            pass

    def _check_dom_xss_patterns(self, target_url: str, body: str, has_csp: bool) -> None:
        """Check for DOM-based XSS patterns in inline JavaScript."""
        try:
            script_blocks = re.findall(
                r"<script[^>]*>(.*?)</script>", body, re.DOTALL | re.IGNORECASE
            )

            found_patterns: list[str] = []

            for script in script_blocks:
                for pattern, description in self.DOM_XSS_PATTERNS:
                    if re.search(pattern, script, re.IGNORECASE):
                        found_patterns.append(description)

            # Deduplicate
            found_patterns = list(dict.fromkeys(found_patterns))

            if found_patterns:
                severity = Severity.MEDIUM if has_csp else Severity.HIGH
                self.add_vulnerability(Vulnerability(
                    title="Potential DOM-based XSS Patterns Detected",
                    severity=severity,
                    category=VulnerabilityCategory.XSS,
                    description=(
                        "Inline JavaScript contains patterns commonly associated with DOM-based XSS. "
                        "These sinks can execute attacker-controlled data if sources are not sanitized."
                    ),
                    evidence=f"Patterns found: {', '.join(found_patterns)}",
                    url=target_url,
                    remediation=(
                        "Avoid using dangerous DOM sinks like innerHTML and document.write. "
                        "Use textContent or safe DOM APIs instead. Sanitize all URL-derived data."
                    ),
                    cwe_id="CWE-79",
                    false_positive_likelihood="medium",
                ))
        except Exception:
            pass
