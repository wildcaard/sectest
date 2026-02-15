"""CSRF (Cross-Site Request Forgery) protection scanner."""

import re
from typing import Optional

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


class CSRFScanner(BaseScanner):
    """Scanner that checks for CSRF protection on forms."""

    CSRF_TOKEN_NAMES: list[str] = [
        "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
        "_csrf", "_token", "token", "authenticity_token",
        "__requestverificationtoken", "antiforgery",
        "xsrf", "xsrf_token", "_xsrf",
        "nonce", "form_token", "form_key",
    ]

    SENSITIVE_FORM_ACTIONS: list[str] = [
        "login", "signin", "signup", "register",
        "password", "account", "profile", "settings",
        "admin", "delete", "remove", "update", "edit",
        "transfer", "payment", "checkout", "purchase",
        "order", "submit", "create", "upload",
    ]

    @property
    def name(self) -> str:
        return "CSRF Scanner"

    @property
    def description(self) -> str:
        return "Checks for Cross-Site Request Forgery protection on forms"

    @property
    def phase(self) -> int:
        return 3

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Execute CSRF protection scan."""
        self.vulnerabilities = []

        try:
            response = await self.http_client.get(target_url)
            if response is None:
                return self.vulnerabilities

            body: str = response.text

            samesite_protected = self._check_samesite_cookies(response, target_url)
            self._check_forms(target_url, body, samesite_protected)
            self._check_custom_header_requirement(response, target_url)

        except Exception:
            pass

        return self.vulnerabilities

    def _check_samesite_cookies(self, response: object, target_url: str) -> bool:
        """Check if cookies have SameSite attribute set."""
        try:
            set_cookie_headers: list[str] = response.headers.get_list("set-cookie") if hasattr(
                response.headers, "get_list"
            ) else []

            # Fallback: try to get from raw headers
            if not set_cookie_headers:
                raw_cookies: Optional[str] = response.headers.get("set-cookie")
                if raw_cookies:
                    set_cookie_headers = [raw_cookies]

            if not set_cookie_headers:
                return False

            all_have_samesite = True
            for cookie in set_cookie_headers:
                cookie_lower = cookie.lower()
                if "samesite=strict" in cookie_lower or "samesite=lax" in cookie_lower:
                    continue
                else:
                    all_have_samesite = False
                    cookie_name_match = re.match(r"([^=]+)=", cookie)
                    cookie_name = cookie_name_match.group(1).strip() if cookie_name_match else "unknown"
                    self.add_vulnerability(Vulnerability(
                        title=f"Cookie Missing SameSite Attribute: {cookie_name}",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.CSRF,
                        description=(
                            f"The cookie '{cookie_name}' does not have a SameSite attribute set to "
                            "'Strict' or 'Lax'. This means the cookie will be sent with cross-site "
                            "requests, potentially enabling CSRF attacks."
                        ),
                        evidence=f"Set-Cookie: {cookie[:200]}",
                        url=target_url,
                        remediation="Set SameSite=Strict or SameSite=Lax on all session and authentication cookies.",
                        cwe_id="CWE-352",
                        owasp_category="A01:2021 Broken Access Control",
                        false_positive_likelihood="low",
                    ))

            return all_have_samesite

        except Exception:
            return False

    def _check_forms(self, target_url: str, body: str, samesite_protected: bool) -> None:
        """Parse all HTML forms and check for CSRF protection."""
        try:
            form_pattern = re.compile(
                r"<form\b([^>]*)>(.*?)</form>",
                re.DOTALL | re.IGNORECASE,
            )

            for match in form_pattern.finditer(body):
                form_attrs = match.group(1)
                form_content = match.group(2)

                # Extract method
                method_match = re.search(r'method\s*=\s*["\']?(\w+)', form_attrs, re.IGNORECASE)
                method = method_match.group(1).upper() if method_match else "GET"

                # Extract action
                action_match = re.search(r'action\s*=\s*["\']?([^"\'>\s]+)', form_attrs, re.IGNORECASE)
                action = action_match.group(1) if action_match else ""

                # Only check POST forms (GET forms are less CSRF-critical)
                if method != "POST":
                    continue

                has_csrf_token = self._form_has_csrf_token(form_content)

                if not has_csrf_token:
                    severity = self._determine_form_severity(action, form_content)
                    action_display = action if action else "(same page)"

                    description = (
                        f"A form with method='POST' and action='{action_display}' does not appear "
                        "to have a CSRF token. This form may be vulnerable to Cross-Site Request Forgery."
                    )
                    if samesite_protected:
                        description += (
                            " Note: SameSite cookies provide partial mitigation, "
                            "but a CSRF token is still recommended."
                        )

                    self.add_vulnerability(Vulnerability(
                        title=f"POST Form Without CSRF Token (action: {action_display})",
                        severity=severity,
                        category=VulnerabilityCategory.CSRF,
                        description=description,
                        evidence=self._extract_form_summary(form_attrs, form_content),
                        url=target_url,
                        remediation=(
                            "Add a CSRF token to all state-changing forms. "
                            "Use framework-provided CSRF protection mechanisms."
                        ),
                        cwe_id="CWE-352",
                        owasp_category="A01:2021 Broken Access Control",
                        false_positive_likelihood="medium" if samesite_protected else "low",
                    ))

        except Exception:
            pass

    def _form_has_csrf_token(self, form_content: str) -> bool:
        """Check if a form contains a CSRF token hidden field."""
        try:
            hidden_inputs = re.findall(
                r'<input[^>]*type\s*=\s*["\']?hidden["\']?[^>]*>',
                form_content,
                re.IGNORECASE,
            )

            for hidden_input in hidden_inputs:
                name_match = re.search(
                    r'name\s*=\s*["\']?([^"\'>\s]+)', hidden_input, re.IGNORECASE
                )
                if name_match:
                    field_name = name_match.group(1).lower()
                    for token_name in self.CSRF_TOKEN_NAMES:
                        if token_name in field_name:
                            return True

            # Also check for meta tags with csrf tokens that JS might use
            if re.search(
                r'<meta[^>]*name\s*=\s*["\']?csrf',
                form_content,
                re.IGNORECASE,
            ):
                return True

            return False

        except Exception:
            return False

    def _determine_form_severity(self, action: str, form_content: str) -> Severity:
        """Determine severity based on form action and content."""
        try:
            action_lower = action.lower()
            content_lower = form_content.lower()

            for keyword in self.SENSITIVE_FORM_ACTIONS:
                if keyword in action_lower or keyword in content_lower:
                    return Severity.HIGH

            # Check for password fields
            if re.search(r'type\s*=\s*["\']?password', form_content, re.IGNORECASE):
                return Severity.HIGH

            return Severity.MEDIUM

        except Exception:
            return Severity.MEDIUM

    def _extract_form_summary(self, form_attrs: str, form_content: str) -> str:
        """Extract a summary of the form for evidence."""
        try:
            field_names = re.findall(
                r'name\s*=\s*["\']?([^"\'>\s]+)',
                form_content,
                re.IGNORECASE,
            )
            summary = f"Form attributes: <form {form_attrs.strip()[:200]}>"
            if field_names:
                summary += f"\nFields: {', '.join(field_names[:15])}"
            return summary
        except Exception:
            return f"Form attributes: <form {form_attrs.strip()[:200]}>"

    def _check_custom_header_requirement(self, response: object, target_url: str) -> None:
        """Check if the application requires custom headers (e.g., X-Requested-With) for CSRF protection."""
        try:
            # Check CORS headers that might indicate custom header requirements
            vary_header = response.headers.get("vary", "")
            if "x-requested-with" in vary_header.lower():
                return  # Custom header check is in place

            # This is informational - custom header requirement can't be passively verified
        except Exception:
            pass
