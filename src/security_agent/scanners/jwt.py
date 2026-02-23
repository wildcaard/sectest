"""JWT Security Scanner.

Analyzes JWT tokens for security vulnerabilities including:
- Weak algorithms (none, no algorithm)
- Missing expiration (exp), not before (nbf), issued at (iat) claims
- Weak secrets for HS256
- Algorithm confusion attacks (RS256 to HS256)
- Key confusion vulnerabilities
"""

import re
import json
import base64
from typing import Optional
from urllib.parse import urlparse

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


# JWT pattern: three base64url segments separated by dots
JWT_PATTERN = re.compile(
    r"\b([A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
)

# Common weak secrets for HS256 brute-force detection
WEAK_SECRETS = frozenset({
    "secret", "key", "password", "123456", "12345678", "123456789",
    "admin", "administrator", "root", "test", "testing", "guest",
    "default", "changeme", "letmein", "qwerty", "abc123", "monkey",
    "master", "dragon", "111111", "baseball", "iloveyou", "trustno1",
    "sunshine", "princess", "welcome", "shadow", "superman", "michael",
    "football", "password1", "password123", "jesus", "ninja", "mustang",
    "password12", "admin123", "welcome1", "secret123", "access",
    "hello", "charlie", "donald", "admin1234", "root123", "pass123",
    "passw0rd", "p@ssword", "p@ssw0rd", "qwerty123", "1q2w3e4r",
    "1qaz2wsx", "zaq12wsx", "xsw21qaz", "qwe123", "ewq321",
})

# Minimum secret length for HS256
MIN_SECRET_LENGTH = 16


def base64url_decode(data: str) -> Optional[bytes]:
    """Decode base64url encoded string."""
    try:
        # Add padding if needed
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)
    except Exception:
        return None


def parse_jwt(token: str) -> tuple[Optional[dict], Optional[dict]]:
    """Parse JWT token without verification.
    
    Returns (header, payload) tuple or (None, None) if parsing fails.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None, None
        
        header_data = base64url_decode(parts[0])
        payload_data = base64url_decode(parts[1])
        
        if header_data is None or payload_data is None:
            return None, None
        
        header = json.loads(header_data)
        payload = json.loads(payload_data)
        
        return header, payload
    except Exception:
        return None, None


class JWTAnalyzer(BaseScanner):
    """Scanner that analyzes JWT tokens for security vulnerabilities."""

    @property
    def name(self) -> str:
        return "JWT Security Scanner"

    @property
    def description(self) -> str:
        return "Analyze JWT tokens for security vulnerabilities"

    @property
    def phase(self) -> int:
        return 2  # Passive scanning

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Run JWT security checks on the target URL."""
        self.vulnerabilities = []

        try:
            # Make request to target
            response = await self.http_client.get(target_url)
            if response is not None:
                # Extract and analyze JWT tokens from response
                self._analyze_response(target_url, response)
                
                # Also check headers for JWT tokens
                self._check_headers(target_url, response.headers)
                
                # Check URL for JWT tokens
                self._check_url(target_url)
        except Exception:
            pass

        return self.vulnerabilities

    def _analyze_response(self, target_url: str, response) -> None:
        """Extract and analyze JWT tokens from response."""
        # Check response body for JWT tokens
        text = response.text if hasattr(response, 'text') else str(response)
        jwt_matches = JWT_PATTERN.findall(text)
        
        for jwt_token in jwt_matches:
            self._analyze_jwt(target_url, jwt_token)

    def _check_headers(self, target_url: str, headers: dict) -> None:
        """Check response headers for JWT tokens."""
        for header_name, header_value in headers.items():
            if isinstance(header_value, str):
                jwt_matches = JWT_PATTERN.findall(header_value)
                for jwt_token in jwt_matches:
                    self._analyze_jwt(target_url, jwt_token)

    def _check_url(self, target_url: str) -> None:
        """Check URL for JWT tokens."""
        parsed = urlparse(target_url)
        jwt_matches = JWT_PATTERN.findall(parsed.query)
        for jwt_token in jwt_matches:
            self._analyze_jwt(target_url, jwt_token)

    def _analyze_jwt(self, url: str, token: str) -> None:
        """Analyze a single JWT token for vulnerabilities."""
        header, payload = parse_jwt(token)
        
        if header is None:
            # Could not parse JWT, skip
            return
        
        # Check 1: Weak Algorithm - "none" algorithm
        algorithm = header.get("alg", "").lower()
        if algorithm == "none" or algorithm == "":
            self._add_vulnerability(
                title="JWT 'none' Algorithm Detected",
                severity=Severity.CRITICAL,
                description="JWT token uses 'none' algorithm or has no algorithm specified. "
                           "This allows attackers to forge tokens by removing the signature.",
                evidence=f"Algorithm: '{algorithm}' in token: {token[:50]}...",
                url=url,
                cwe_id="CWE-347",
                remediation="Use a strong algorithm like RS256 or ES256. "
                           "Always verify the algorithm server-side and reject 'none'.",
            )
            return  # Critical finding, no need to check further for this token
        
        # Check 2: Missing Expiration (exp) claim
        if "exp" not in payload:
            self._add_vulnerability(
                title="JWT Missing Expiration Claim",
                severity=Severity.HIGH,
                description="JWT token does not have an 'exp' (expiration) claim. "
                           "This allows tokens to be valid indefinitely.",
                evidence=f"Token payload missing 'exp' claim: {json.dumps(payload)[:100]}...",
                url=url,
                cwe_id="CWE-613",
                remediation="Add an 'exp' claim to set a reasonable expiration time for tokens.",
            )
        
        # Check 3: Missing Not Before (nbf) claim
        if "nbf" not in payload:
            self._add_vulnerability(
                title="JWT Missing Not Before Claim",
                severity=Severity.MEDIUM,
                description="JWT token does not have an 'nbf' (not before) claim. "
                           "This could allow premature token usage.",
                evidence=f"Token payload missing 'nbf' claim: {json.dumps(payload)[:100]}...",
                url=url,
                remediation="Add an 'nbf' claim to specify when the token becomes valid.",
            )
        
        # Check 4: Missing Issued At (iat) claim
        if "iat" not in payload:
            self._add_vulnerability(
                title="JWT Missing Issued At Claim",
                severity=Severity.MEDIUM,
                description="JWT token does not have an 'iat' (issued at) claim. "
                           "This makes it difficult to determine token age.",
                evidence=f"Token payload missing 'iat' claim: {json.dumps(payload)[:100]}...",
                url=url,
                remediation="Add an 'iat' claim to track when the token was issued.",
            )
        
        # Check 5: Algorithm Confusion - RS256 to HS256
        if algorithm == "rs256":
            self._add_vulnerability(
                title="JWT Algorithm Confusion Risk (RS256)",
                severity=Severity.HIGH,
                description="JWT uses RS256 algorithm. Verify server is not vulnerable to "
                           "algorithm confusion where RS256 tokens are verified with HS256 "
                           "using the public key as the secret.",
                evidence=f"Token uses RS256 algorithm. Header: {json.dumps(header)}",
                url=url,
                cwe_id="CWE-347",
                remediation="Ensure server correctly verifies algorithm and does not accept "
                           "HS256 with public key as secret. Use 'alg: none' protection.",
            )
        
        # Check 6: Key Confusion - Public key as secret
        if "jwk" in header or "x5c" in header or "x5t" in header:
            self._add_vulnerability(
                title="JWT Key Confusion - Embedded Public Key",
                severity=Severity.HIGH,
                description="JWT contains embedded key information (JWK, x5c, or x5t). "
                           "Ensure the server properly validates keys and is not vulnerable "
                           "to key confusion attacks.",
                evidence=f"Token header contains key data: {json.dumps(header)}",
                url=url,
                cwe_id="CWE-347",
                remediation="Validate that the embedded key matches expected keys and "
                           "properly handle key validation.",
            )
        
        # Check 7: Weak secret detection is done separately
        # This requires access to the secret, which we can't determine from the token alone
        # But we can detect if HS256 is used without knowing the secret
        if algorithm == "hs256":
            # HS256 is used - note that secret strength cannot be checked without the secret
            # But we can add an informational finding
            pass

    def _check_weak_secret(self, url: str, token: str, secret: str) -> None:
        """Check if a provided secret is weak for HS256."""
        header, payload = parse_jwt(token)
        
        if header is None:
            return
        
        algorithm = header.get("alg", "").lower()
        
        if algorithm == "hs256":
            # Check for common weak secrets
            if secret.lower() in WEAK_SECRETS:
                self._add_vulnerability(
                    title="JWT Weak Secret Detected",
                    severity=Severity.HIGH,
                    description=f"JWT token uses a weak or common secret: '{secret}'. "
                               "This secret is easily guessable and can be brute-forced.",
                    evidence=f"Weak secret '{secret}' used with HS256 algorithm",
                    url=url,
                    cwe_id="CWE-916",
                    remediation="Use a strong, unique secret with at least 32 characters. "
                               "Use a cryptographically secure random generator.",
                )
            # Check for short secrets
            elif len(secret) < MIN_SECRET_LENGTH:
                self._add_vulnerability(
                    title="JWT Short Secret Detected",
                    severity=Severity.MEDIUM,
                    description=f"JWT token uses a short secret (length: {len(secret)}). "
                               "Short secrets are vulnerable to brute-force attacks.",
                    evidence=f"Secret length: {len(secret)} characters",
                    url=url,
                    cwe_id="CWE-916",
                    remediation=f"Use a secret with at least {MIN_SECRET_LENGTH} characters.",
                )

    def _add_vulnerability(
        self,
        title: str,
        severity: Severity,
        description: str,
        evidence: str,
        url: str,
        cwe_id: str = "",
        remediation: str = "",
    ) -> None:
        """Add a vulnerability to the results."""
        vuln = Vulnerability(
            title=title,
            severity=severity,
            category=VulnerabilityCategory.BROKEN_AUTH,
            description=description,
            evidence=evidence,
            url=url,
            remediation=remediation,
            cwe_id=cwe_id,
            owasp_category="A2: Broken Authentication",
        )
        self.add_vulnerability(vuln)
