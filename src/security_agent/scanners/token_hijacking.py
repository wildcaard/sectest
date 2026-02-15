"""Token Hijacking / Exposure Scanner.

Detects conditions that could allow token or session hijacking: tokens in URLs,
tokens exposed in response bodies, weak Referrer-Policy, and client-side
token storage patterns. Defensive only; does not steal or capture tokens.
"""

import re
import json
from urllib.parse import urlparse, parse_qs

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)

# Query/fragment parameter names that suggest auth tokens (case-insensitive).
TOKEN_PARAM_NAMES = frozenset({
    "token", "session", "sid", "auth", "jwt", "key", "api_key",
    "access_token", "refresh_token", "apikey", "sessionid", "session_id",
})

# JWT pattern: three base64url segments separated by dots (reasonable length).
JWT_PATTERN = re.compile(
    r"\b([A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})\b"
)

# JSON keys that may hold tokens (lowercase for case-insensitive match).
TOKEN_JSON_KEYS = frozenset({
    "access_token", "token", "apikey", "api_key", "jwt", "refresh_token",
    "bearer", "auth_token", "session_token",
})

# Client-side storage patterns: token/auth/jwt in localStorage or sessionStorage.
LOCAL_STORAGE_TOKEN_PATTERN = re.compile(
    r"localStorage\.(?:setItem|getItem)\s*\(\s*['\"][^'\"]*?(?:token|auth|jwt)[^'\"]*?['\"]",
    re.IGNORECASE,
)
SESSION_STORAGE_TOKEN_PATTERN = re.compile(
    r"sessionStorage\.(?:setItem|getItem)\s*\(\s*['\"][^'\"]*?(?:token|auth|jwt)[^'\"]*?['\"]",
    re.IGNORECASE,
)


class TokenHijackingScanner(BaseScanner):
    """Scanner that detects token/session exposure and hijacking risks."""

    @property
    def name(self) -> str:
        return "Token Hijacking / Exposure"

    @property
    def description(self) -> str:
        return "Detects token/session exposure in URLs, responses, and client-side storage patterns"

    @property
    def phase(self) -> int:
        return 2

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Run token exposure and hijacking-risk checks."""
        self.vulnerabilities = []

        try:
            has_token_in_url = self._check_token_in_url(target_url)
            response = await self.http_client.get(target_url)
            if response is not None:
                self._check_token_in_response(target_url, response)
                self._check_client_side_storage(target_url, response.text)
                referrer_policy = response.headers.get("referrer-policy", "").strip().lower()
                if has_token_in_url or self._has_client_storage_finding():
                    self._check_referrer_policy(target_url, referrer_policy)
        except Exception:
            pass

        return self.vulnerabilities

    def _check_token_in_url(self, url: str) -> bool:
        """Check if URL query or fragment contains token-like parameter names."""
        parsed = urlparse(url)
        found: list[str] = []

        for part in (parsed.query, parsed.fragment):
            if not part:
                continue
            try:
                params = parse_qs(part, keep_blank_values=True)
                for key in params:
                    if key.lower() in TOKEN_PARAM_NAMES:
                        found.append(key)
            except Exception:
                continue

        if not found:
            return False

        param_list = ", ".join(sorted(set(found)))
        self.add_vulnerability(Vulnerability(
            title="Token or Session ID in URL",
            severity=Severity.HIGH,
            category=VulnerabilityCategory.BROKEN_AUTH,
            description=(
                "The URL contains query or fragment parameters that typically carry "
                "authentication or session tokens. Tokens in URLs are logged in server "
                "logs, browser history, and Referer headers, enabling token hijacking."
            ),
            evidence=f"Parameter name(s) found (values redacted): {param_list}",
            url=url,
            remediation=(
                "Do not pass tokens or session IDs in URLs. Use HttpOnly cookies for "
                "sessions, or send tokens in Authorization headers or POST bodies."
            ),
            cvss_score=7.4,
            cwe_id="CWE-598",
            owasp_category="A07:2021 – Identification and Authentication Failures",
            false_positive_likelihood="low",
        ))
        return True

    def _check_token_in_response(self, url: str, response: object) -> None:
        """Check response body for JWT-like strings and JSON token keys."""
        body = getattr(response, "text", "") or ""
        headers = getattr(response, "headers", None)
        content_type = (headers.get("content-type", "") if headers else "").lower()

        # JWT in body (any text)
        jwt_matches = JWT_PATTERN.findall(body)
        if jwt_matches:
            self.add_vulnerability(Vulnerability(
                title="JWT or Token-Like Value in Response Body",
                severity=Severity.HIGH,
                category=VulnerabilityCategory.SENSITIVE_DATA,
                description=(
                    "The response body contains a string that resembles a JWT (three "
                    "base64 segments). Exposing tokens in responses increases the risk "
                    "of token theft via XSS or logging."
                ),
                evidence="JWT-like value present in response (redacted).",
                url=url,
                remediation=(
                    "Avoid returning JWTs or session tokens in response bodies. Prefer "
                    "HttpOnly cookies or short-lived tokens passed only in headers."
                ),
                cvss_score=6.5,
                cwe_id="CWE-200",
                owasp_category="A02:2021 – Cryptographic Failures",
                false_positive_likelihood="medium",
            ))
            return

        # JSON token keys
        if "json" in content_type or body.strip().startswith("{"):
            try:
                data = json.loads(body)
                found_keys = self._find_token_keys_in_json(data, set())
                if found_keys:
                    key_list = ", ".join(sorted(found_keys))
                    self.add_vulnerability(Vulnerability(
                        title="Token or API Key in JSON Response",
                        severity=Severity.HIGH,
                        category=VulnerabilityCategory.SENSITIVE_DATA,
                        description=(
                            "The JSON response contains keys that typically hold "
                            "tokens or API keys. Exposing these in responses can lead "
                            "to token hijacking."
                        ),
                        evidence=f"Keys with values present (redacted): {key_list}",
                        url=url,
                        remediation=(
                            "Do not return access tokens or API keys in API responses. "
                            "Use secure, HttpOnly cookies or opaque session identifiers."
                        ),
                        cvss_score=6.5,
                        cwe_id="CWE-200",
                        owasp_category="A02:2021 – Cryptographic Failures",
                        false_positive_likelihood="medium",
                    ))
            except (json.JSONDecodeError, TypeError):
                pass

    def _find_token_keys_in_json(self, obj: object, found: set[str]) -> set[str]:
        """Recursively find JSON keys that look like token holders (with non-empty string values)."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in TOKEN_JSON_KEYS and isinstance(v, str) and len(v.strip()) > 0:
                    found.add(k)
                self._find_token_keys_in_json(v, found)
        elif isinstance(obj, list):
            for item in obj:
                self._find_token_keys_in_json(item, found)
        return found

    def _check_client_side_storage(self, url: str, text: str) -> None:
        """Check for token/auth patterns in localStorage/sessionStorage usage."""
        if not text:
            return
        local_match = LOCAL_STORAGE_TOKEN_PATTERN.search(text)
        session_match = SESSION_STORAGE_TOKEN_PATTERN.search(text)
        if not (local_match or session_match):
            return

        storage = []
        if local_match:
            storage.append("localStorage")
        if session_match:
            storage.append("sessionStorage")

        self.add_vulnerability(Vulnerability(
            title="Token or Auth Data in Client-Side Storage",
            severity=Severity.MEDIUM,
            category=VulnerabilityCategory.SENSITIVE_DATA,
            description=(
                "The page uses localStorage or sessionStorage with keys suggesting "
                "tokens or auth data. Tokens in client storage are accessible to "
                "JavaScript and can be stolen via XSS."
            ),
            evidence=f"Token/auth pattern detected in client storage: {', '.join(storage)}.",
            url=url,
            remediation=(
                "Avoid storing session or auth tokens in localStorage/sessionStorage. "
                "Use HttpOnly cookies for session identifiers."
            ),
            cvss_score=5.4,
            cwe_id="CWE-522",
            owasp_category="A02:2021 – Cryptographic Failures",
            false_positive_likelihood="medium",
        ))

    def _has_client_storage_finding(self) -> bool:
        """Return True if we already added a client-side storage finding this run."""
        return any(
            "Client-Side Storage" in v.title for v in self.vulnerabilities
        )

    def _check_referrer_policy(self, url: str, referrer_policy: str) -> None:
        """Add finding if Referrer-Policy is missing or permissive when tokens are at risk."""
        if not referrer_policy:
            policy_desc = "missing"
        else:
            policy_desc = referrer_policy

        weak = not referrer_policy or referrer_policy in (
            "unsafe-url",
            "no-referrer-when-downgrade",
        )

        if not weak:
            return

        self.add_vulnerability(Vulnerability(
            title="Weak or Missing Referrer-Policy (Token Leakage Risk)",
            severity=Severity.MEDIUM,
            category=VulnerabilityCategory.SENSITIVE_DATA,
            description=(
                "Referrer-Policy is missing or permissive while tokens or auth data "
                "may be in use. The full URL (including token query params) can be "
                "sent to third parties via the Referer header."
            ),
            evidence=f"Referrer-Policy: {policy_desc}",
            url=url,
            remediation=(
                "Set a strict Referrer-Policy (e.g. strict-origin-when-cross-origin or "
                "no-referrer) to prevent token leakage via Referer."
            ),
            cvss_score=4.3,
            cwe_id="CWE-200",
            owasp_category="A05:2021 – Security Misconfiguration",
            false_positive_likelihood="medium",
        ))
