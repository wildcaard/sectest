"""Subdomain enumeration scanner using DNS resolution."""

import asyncio
from typing import Optional
from urllib.parse import urlparse

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


class SubdomainScanner(BaseScanner):
    """Subdomain enumeration scanner that discovers subdomains via DNS resolution."""

    COMMON_SUBDOMAINS: list[str] = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging",
        "test", "beta", "portal", "cdn", "static", "app", "login",
        "dashboard", "docs", "blog", "shop", "store", "support",
        "status", "m", "mobile",
    ]

    @property
    def name(self) -> str:
        return "Subdomain Scanner"

    @property
    def description(self) -> str:
        return "Enumerates subdomains using DNS resolution"

    @property
    def phase(self) -> int:
        return 1

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Execute subdomain enumeration scan."""
        self.vulnerabilities = []

        if not HAS_DNSPYTHON:
            self.add_vulnerability(Vulnerability(
                title="Subdomain Scanner Unavailable",
                severity=Severity.INFO,
                category=VulnerabilityCategory.SECURITY_MISCONFIG,
                description="The dnspython library is not installed. Subdomain enumeration is unavailable.",
                evidence="ImportError: dns.resolver module not found",
                url=target_url,
                remediation="Install dnspython: pip install dnspython",
                false_positive_likelihood="low",
            ))
            return self.vulnerabilities

        try:
            parsed = urlparse(target_url)
            base_domain = self._extract_base_domain(parsed.netloc)

            if not base_domain:
                return self.vulnerabilities

            found_subdomains = await self._enumerate_subdomains(base_domain)

            if found_subdomains:
                evidence_lines: list[str] = []
                for subdomain, ips in found_subdomains:
                    evidence_lines.append(f"{subdomain} -> {', '.join(ips)}")

                self.add_vulnerability(Vulnerability(
                    title=f"Discovered {len(found_subdomains)} Subdomain(s)",
                    severity=Severity.INFO,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        f"DNS enumeration discovered {len(found_subdomains)} subdomain(s) for "
                        f"{base_domain}. Each subdomain represents a potential attack surface."
                    ),
                    evidence="\n".join(evidence_lines),
                    url=target_url,
                    remediation=(
                        "Review all discovered subdomains for security posture. "
                        "Remove DNS entries for decommissioned services to prevent subdomain takeover."
                    ),
                    cwe_id="CWE-200",
                    false_positive_likelihood="low",
                ))

                # Report individual subdomains that might be interesting
                interesting_prefixes = {"admin", "staging", "dev", "test", "beta", "dashboard", "login"}
                for subdomain, ips in found_subdomains:
                    prefix = subdomain.split(".")[0]
                    if prefix in interesting_prefixes:
                        self.add_vulnerability(Vulnerability(
                            title=f"Interesting Subdomain Found: {subdomain}",
                            severity=Severity.INFO,
                            category=VulnerabilityCategory.SECURITY_MISCONFIG,
                            description=(
                                f"The subdomain '{subdomain}' suggests a {prefix} environment that "
                                "may have weaker security controls or expose sensitive functionality."
                            ),
                            evidence=f"{subdomain} resolves to: {', '.join(ips)}",
                            url=f"https://{subdomain}",
                            remediation=(
                                f"Ensure the {prefix} subdomain has appropriate access controls "
                                "and is not exposed to the public internet unnecessarily."
                            ),
                            false_positive_likelihood="low",
                        ))

        except Exception:
            pass

        return self.vulnerabilities

    async def _enumerate_subdomains(self, base_domain: str) -> list[tuple[str, list[str]]]:
        """Resolve common subdomains and return those that exist."""
        found: list[tuple[str, list[str]]] = []
        loop = asyncio.get_event_loop()

        # Run DNS resolutions concurrently using executor for blocking dns.resolver calls
        tasks = []
        for prefix in self.COMMON_SUBDOMAINS:
            subdomain = f"{prefix}.{base_domain}"
            tasks.append((subdomain, loop.run_in_executor(None, self._resolve_subdomain, subdomain)))

        for subdomain, task in tasks:
            try:
                ips = await task
                if ips:
                    found.append((subdomain, ips))
            except Exception:
                continue

        return found

    @staticmethod
    def _resolve_subdomain(subdomain: str) -> Optional[list[str]]:
        """Resolve a subdomain to its IP addresses. Returns None if resolution fails."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(subdomain, "A")
            ips = [str(rdata) for rdata in answers]
            return ips if ips else None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return None
        except dns.exception.Timeout:
            return None
        except Exception:
            return None

    @staticmethod
    def _extract_base_domain(netloc: str) -> str:
        """Extract the base domain from a netloc string, removing port if present."""
        try:
            # Remove port
            host = netloc.split(":")[0].strip().lower()
            if not host:
                return ""
            # Remove leading www. to get base domain
            if host.startswith("www."):
                host = host[4:]
            return host
        except Exception:
            return ""
