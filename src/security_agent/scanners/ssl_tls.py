"""SSL/TLS Scanner.

Evaluates the SSL/TLS configuration of the target, including certificate
validity, protocol support, HTTPS enforcement, and mixed-content issues.
"""

import ssl
import socket
import asyncio
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


class SslTlsScanner(BaseScanner):
    """Scans target SSL/TLS configuration for weaknesses."""

    @property
    def name(self) -> str:
        return "SSL/TLS Configuration"

    @property
    def description(self) -> str:
        return "Checks SSL/TLS certificates, protocol support, and HTTPS enforcement"

    @property
    def phase(self) -> int:
        return 2

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Run all SSL/TLS checks against *target_url*."""
        self.vulnerabilities = []

        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        await self._check_certificate(hostname, port, target_url)
        await self._check_https_enforcement(target_url)
        await self._check_mixed_content(target_url)

        return self.vulnerabilities

    # ------------------------------------------------------------------
    # Certificate checks
    # ------------------------------------------------------------------

    async def _check_certificate(
        self, hostname: str, port: int, target_url: str
    ) -> None:
        """Validate the server certificate using Python's ssl module."""
        try:
            cert_info = await asyncio.get_event_loop().run_in_executor(
                None, self._get_certificate_info, hostname, port
            )
            if cert_info is None:
                return

            cert, context_error = cert_info

            if context_error:
                self.add_vulnerability(Vulnerability(
                    title="SSL/TLS Certificate Validation Failure",
                    severity=Severity.HIGH,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        f"The server certificate could not be validated: {context_error}"
                    ),
                    evidence=str(context_error),
                    url=target_url,
                    remediation=(
                        "Ensure the certificate is issued by a trusted CA, is "
                        "not expired, and the hostname matches the certificate."
                    ),
                    cvss_score=7.4,
                    cwe_id="CWE-295",
                    owasp_category="A02:2021 Cryptographic Failures",
                    references=[
                        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    ],
                    false_positive_likelihood="low",
                ))
                return

            if cert is None:
                return

            # --- Expiry check ---
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                try:
                    not_after = datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days_remaining = (not_after - datetime.now(timezone.utc)).days

                    if days_remaining < 0:
                        self.add_vulnerability(Vulnerability(
                            title="Expired SSL/TLS Certificate",
                            severity=Severity.CRITICAL,
                            category=VulnerabilityCategory.SECURITY_MISCONFIG,
                            description=(
                                f"The SSL certificate expired on {not_after_str}. "
                                "Browsers will display security warnings to visitors."
                            ),
                            evidence=f"Certificate notAfter: {not_after_str}",
                            url=target_url,
                            remediation="Renew the SSL/TLS certificate immediately.",
                            cvss_score=9.1,
                            cwe_id="CWE-298",
                            owasp_category="A02:2021 Cryptographic Failures",
                            references=[],
                            false_positive_likelihood="low",
                        ))
                    elif days_remaining < 30:
                        self.add_vulnerability(Vulnerability(
                            title="SSL/TLS Certificate Expiring Soon",
                            severity=Severity.MEDIUM,
                            category=VulnerabilityCategory.SECURITY_MISCONFIG,
                            description=(
                                f"The SSL certificate expires in {days_remaining} "
                                f"day(s) (on {not_after_str}). Renew it promptly "
                                "to avoid service interruption."
                            ),
                            evidence=(
                                f"Certificate notAfter: {not_after_str} "
                                f"({days_remaining} days remaining)"
                            ),
                            url=target_url,
                            remediation=(
                                "Renew the SSL/TLS certificate before it expires. "
                                "Consider automating renewal with Let's Encrypt / ACME."
                            ),
                            cvss_score=4.8,
                            cwe_id="CWE-298",
                            owasp_category="A02:2021 Cryptographic Failures",
                            references=[],
                            false_positive_likelihood="low",
                        ))
                except ValueError:
                    pass

            # --- Subject / Issuer / SAN informational record ---
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            san_list = cert.get("subjectAltName", ())

            san_str = ", ".join(f"{t}:{v}" for t, v in san_list) if san_list else "N/A"

            self.add_vulnerability(Vulnerability(
                title="SSL/TLS Certificate Information",
                severity=Severity.INFO,
                category=VulnerabilityCategory.SECURITY_MISCONFIG,
                description="Certificate details collected during scan.",
                evidence=(
                    f"Subject CN: {subject.get('commonName', 'N/A')}\n"
                    f"Issuer O: {issuer.get('organizationName', 'N/A')}\n"
                    f"Issuer CN: {issuer.get('commonName', 'N/A')}\n"
                    f"SAN: {san_str}\n"
                    f"Not Before: {cert.get('notBefore', 'N/A')}\n"
                    f"Not After: {cert.get('notAfter', 'N/A')}"
                ),
                url=target_url,
                remediation="Informational -- no action required.",
                cvss_score=0.0,
                cwe_id="",
                owasp_category="",
                references=[],
                false_positive_likelihood="low",
            ))

        except Exception:
            pass

    @staticmethod
    def _get_certificate_info(
        hostname: str, port: int
    ) -> Optional[tuple[Optional[dict], Optional[str]]]:
        """Synchronous helper -- retrieve the peer certificate dict.

        Returns ``(cert_dict, None)`` on success or ``(None, error_str)`` on
        failure.  Returns ``None`` when connection cannot be established at
        all.
        """
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return (cert, None)
        except ssl.SSLCertVerificationError as exc:
            # Still try to grab the cert for informational purposes
            try:
                ctx_noverify = ssl.create_default_context()
                ctx_noverify.check_hostname = False
                ctx_noverify.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with ctx_noverify.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        # getpeercert() returns {} when verify_mode is CERT_NONE
                        return (None, str(exc))
            except Exception:
                return (None, str(exc))
        except (socket.timeout, OSError):
            return None

    # ------------------------------------------------------------------
    # HTTPS enforcement
    # ------------------------------------------------------------------

    async def _check_https_enforcement(self, target_url: str) -> None:
        """Check whether an HTTP request is redirected to HTTPS."""
        try:
            parsed = urlparse(target_url)
            if parsed.scheme != "https":
                return  # Target is already HTTP; not applicable.

            http_url = target_url.replace("https://", "http://", 1)

            # Use a non-following client call to see the raw redirect
            response = await self.http_client.get(
                http_url, follow_redirects=False
            )
            if response is None:
                return

            if response.status_code in (301, 302, 307, 308):
                location = response.headers.get("location", "")
                if location.startswith("https://"):
                    # Good -- redirect to HTTPS detected.
                    return

            self.add_vulnerability(Vulnerability(
                title="HTTPS Not Enforced",
                severity=Severity.HIGH,
                category=VulnerabilityCategory.SENSITIVE_DATA,
                description=(
                    "The HTTP version of the site does not redirect to HTTPS. "
                    "Users who visit the site over plain HTTP will have their "
                    "traffic transmitted unencrypted."
                ),
                evidence=(
                    f"HTTP request to {http_url} returned status "
                    f"{response.status_code} without redirecting to HTTPS."
                ),
                url=http_url,
                remediation=(
                    "Configure a server-level redirect from HTTP to HTTPS "
                    "(301 redirect). Also deploy HSTS to prevent future HTTP access."
                ),
                cvss_score=7.4,
                cwe_id="CWE-319",
                owasp_category="A02:2021 Cryptographic Failures",
                references=[],
                false_positive_likelihood="low",
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Mixed content
    # ------------------------------------------------------------------

    async def _check_mixed_content(self, target_url: str) -> None:
        """Check for HTTP resources loaded from an HTTPS page."""
        try:
            parsed = urlparse(target_url)
            if parsed.scheme != "https":
                return

            response = await self.http_client.get(target_url)
            if response is None:
                return

            body = response.text
            # Look for common patterns loading http:// resources
            http_refs = re.findall(
                r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']',
                body,
                re.IGNORECASE,
            )

            if http_refs:
                examples = http_refs[:5]  # Limit evidence to 5 examples
                self.add_vulnerability(Vulnerability(
                    title="Mixed Content Detected",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        f"The HTTPS page loads {len(http_refs)} resource(s) over "
                        "plain HTTP. Browsers may block these or show warnings, "
                        "and attackers could intercept or modify these resources."
                    ),
                    evidence="Examples:\n" + "\n".join(examples),
                    url=target_url,
                    remediation=(
                        "Update all resource URLs to use HTTPS or protocol-relative "
                        "URLs (//). Use Content-Security-Policy: upgrade-insecure-requests "
                        "as an additional safeguard."
                    ),
                    cvss_score=4.8,
                    cwe_id="CWE-319",
                    owasp_category="A02:2021 Cryptographic Failures",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"
                    ],
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass
