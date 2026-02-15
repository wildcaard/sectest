"""Information Disclosure Scanner.

Probes for commonly exposed files, directories, and error pages that may
leak sensitive information about the application or its environment.
"""

import re
from typing import Optional
from urllib.parse import urlparse, urljoin

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


# Default sensitive paths to check.  Each tuple is
# (path, title, severity, description, cwe_id).
_DEFAULT_SENSITIVE_PATHS: list[tuple[str, str, Severity, str, str]] = [
    (
        "/.git/config",
        "Exposed Git Configuration",
        Severity.HIGH,
        "The .git/config file is publicly accessible, which may allow "
        "an attacker to reconstruct the full source code repository.",
        "CWE-538",
    ),
    (
        "/.env",
        "Exposed Environment File",
        Severity.CRITICAL,
        "The .env file is publicly accessible and likely contains "
        "secrets such as API keys, database credentials, and tokens.",
        "CWE-200",
    ),
    (
        "/.htaccess",
        "Exposed .htaccess File",
        Severity.MEDIUM,
        "The .htaccess file is publicly accessible, revealing server "
        "configuration details.",
        "CWE-538",
    ),
    (
        "/web.config",
        "Exposed web.config File",
        Severity.HIGH,
        "The web.config file is publicly accessible and may contain "
        "connection strings, secrets, and server configuration.",
        "CWE-200",
    ),
    (
        "/package.json",
        "Exposed package.json",
        Severity.MEDIUM,
        "The package.json file is publicly accessible, revealing "
        "application dependencies and their versions which may have "
        "known vulnerabilities.",
        "CWE-200",
    ),
    (
        "/.well-known/security.txt",
        "Security.txt Found",
        Severity.INFO,
        "A security.txt file was found. This is good practice for "
        "vulnerability disclosure but should be reviewed for accuracy.",
        "CWE-200",
    ),
]

# Common backup extensions to check on the main URL path.
_BACKUP_EXTENSIONS = [".bak", ".old", ".swp", ".save", ".orig", ".tmp"]

# Patterns that suggest a directory listing page.
_DIRECTORY_LISTING_PATTERNS = [
    re.compile(r"<title>\s*Index of\s", re.IGNORECASE),
    re.compile(r"<h1>\s*Index of\s", re.IGNORECASE),
    re.compile(r"Directory listing for", re.IGNORECASE),
]

# Patterns that suggest stack-trace / debug info in error pages.
_STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"at\s+[\w.$]+\([\w.]+:\d+\)"),  # Java-style stack trace
    re.compile(r"Exception in thread", re.IGNORECASE),
    re.compile(r"Fatal error:.*on line \d+", re.IGNORECASE),  # PHP
    re.compile(r"Microsoft \.NET Framework.*Version:", re.IGNORECASE),
    re.compile(r"<b>Warning</b>:.*on line <b>\d+</b>", re.IGNORECASE),  # PHP
    re.compile(r"Unhandled Exception", re.IGNORECASE),
    re.compile(r"Stack Trace:", re.IGNORECASE),
]


class InfoDisclosureScanner(BaseScanner):
    """Scans for information disclosure via exposed files and error pages."""

    @property
    def name(self) -> str:
        return "Information Disclosure"

    @property
    def description(self) -> str:
        return "Checks for exposed sensitive files, directory listings, and verbose error pages"

    @property
    def phase(self) -> int:
        return 2

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Run all information-disclosure checks."""
        self.vulnerabilities = []

        base_url = self._base_url(target_url)

        # Gather extra paths from config if available
        extra_paths: list[tuple[str, str, Severity, str, str]] = []
        configured_paths = (
            self.config.get("scanners", {})
            .get("info_disclosure", {})
            .get("extra_paths", [])
        )
        for entry in configured_paths:
            if isinstance(entry, dict) and "path" in entry:
                extra_paths.append((
                    entry["path"],
                    entry.get("title", f"Exposed {entry['path']}"),
                    Severity[entry.get("severity", "MEDIUM").upper()],
                    entry.get("description", f"The file {entry['path']} is publicly accessible."),
                    entry.get("cwe_id", "CWE-200"),
                ))

        all_paths = list(_DEFAULT_SENSITIVE_PATHS) + extra_paths

        for path, title, severity, desc, cwe in all_paths:
            await self._check_sensitive_path(base_url, path, title, severity, desc, cwe)

        await self._check_robots_txt(base_url)
        await self._check_sitemap_xml(base_url)
        await self._check_backup_files(target_url)
        await self._check_error_page(base_url)
        await self._check_directory_listing(base_url)

        return self.vulnerabilities

    # ------------------------------------------------------------------
    # Sensitive-path probing
    # ------------------------------------------------------------------

    async def _check_sensitive_path(
        self,
        base_url: str,
        path: str,
        title: str,
        severity: Severity,
        description: str,
        cwe_id: str,
    ) -> None:
        """Use HEAD first; GET only if HEAD returns 200."""
        try:
            full_url = urljoin(base_url, path)

            head_resp = await self.http_client.head(full_url)
            if head_resp is None or head_resp.status_code != 200:
                return

            # Confirm with GET to reduce false positives from generic 200 pages
            get_resp = await self.http_client.get(full_url)
            if get_resp is None or get_resp.status_code != 200:
                return

            body = get_resp.text
            # Skip soft-404 pages (very short custom error pages)
            if len(body.strip()) < 10:
                return

            self.add_vulnerability(Vulnerability(
                title=title,
                severity=severity,
                category=VulnerabilityCategory.SENSITIVE_DATA,
                description=description,
                evidence=(
                    f"URL: {full_url}\n"
                    f"Status: {get_resp.status_code}\n"
                    f"Content-Length: {len(body)}"
                ),
                url=full_url,
                remediation=(
                    f"Restrict access to {path}. Configure your web server "
                    "to deny requests for sensitive files."
                ),
                cvss_score=self._severity_to_cvss(severity),
                cwe_id=cwe_id,
                owasp_category="A01:2021 Broken Access Control",
                references=[],
                false_positive_likelihood="low" if severity.value != "informational" else "medium",
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # robots.txt
    # ------------------------------------------------------------------

    async def _check_robots_txt(self, base_url: str) -> None:
        """Parse robots.txt and flag potentially sensitive disallowed paths."""
        try:
            url = urljoin(base_url, "/robots.txt")
            response = await self.http_client.get(url)
            if response is None or response.status_code != 200:
                return

            body = response.text
            sensitive_keywords = [
                "admin", "login", "dashboard", "config", "backup",
                "secret", "private", "internal", "api", "token",
                "database", "db", "phpmyadmin", "cpanel", "wp-admin",
            ]

            sensitive_paths: list[str] = []
            for line in body.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if any(kw in path.lower() for kw in sensitive_keywords):
                        sensitive_paths.append(path)

            if sensitive_paths:
                self.add_vulnerability(Vulnerability(
                    title="Robots.txt Reveals Sensitive Paths",
                    severity=Severity.LOW,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        "The robots.txt file disallows paths that suggest "
                        "sensitive or administrative functionality."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"Sensitive disallowed paths:\n"
                        + "\n".join(f"  {p}" for p in sensitive_paths[:15])
                    ),
                    url=url,
                    remediation=(
                        "Sensitive areas should be protected by authentication "
                        "and authorisation, not merely excluded via robots.txt."
                    ),
                    cvss_score=2.6,
                    cwe_id="CWE-200",
                    owasp_category="A01:2021 Broken Access Control",
                    references=[],
                    false_positive_likelihood="medium",
                ))
            else:
                self.add_vulnerability(Vulnerability(
                    title="Robots.txt Found",
                    severity=Severity.INFO,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description="A robots.txt file is present.",
                    evidence=f"URL: {url}\nStatus: 200",
                    url=url,
                    remediation="Informational -- review the file for unintended disclosures.",
                    cvss_score=0.0,
                    cwe_id="",
                    owasp_category="",
                    references=[],
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # sitemap.xml
    # ------------------------------------------------------------------

    async def _check_sitemap_xml(self, base_url: str) -> None:
        """Check for an accessible sitemap.xml."""
        try:
            url = urljoin(base_url, "/sitemap.xml")
            response = await self.http_client.head(url)
            if response is None or response.status_code != 200:
                return

            self.add_vulnerability(Vulnerability(
                title="Sitemap.xml Found",
                severity=Severity.INFO,
                category=VulnerabilityCategory.SENSITIVE_DATA,
                description=(
                    "A sitemap.xml file is publicly accessible. While often "
                    "intentional, it reveals the full URL structure of the site."
                ),
                evidence=f"URL: {url}\nStatus: {response.status_code}",
                url=url,
                remediation=(
                    "Ensure the sitemap does not expose URLs that should remain "
                    "private or require authentication."
                ),
                cvss_score=0.0,
                cwe_id="CWE-200",
                owasp_category="A01:2021 Broken Access Control",
                references=[],
                false_positive_likelihood="low",
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Backup files
    # ------------------------------------------------------------------

    async def _check_backup_files(self, target_url: str) -> None:
        """Check for common backup extensions of the target page."""
        try:
            parsed = urlparse(target_url)
            # Only check if the URL has a file-like path (contains a dot)
            path = parsed.path.rstrip("/")
            if not path or path == "":
                path = "/index.html"

            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for ext in _BACKUP_EXTENSIONS:
                backup_url = urljoin(base_url, path + ext)
                try:
                    head_resp = await self.http_client.head(backup_url)
                    if head_resp is not None and head_resp.status_code == 200:
                        self.add_vulnerability(Vulnerability(
                            title=f"Backup File Found ({ext})",
                            severity=Severity.MEDIUM,
                            category=VulnerabilityCategory.SENSITIVE_DATA,
                            description=(
                                f"A backup file was found at {backup_url}. "
                                "Backup files may contain source code or "
                                "sensitive configuration data."
                            ),
                            evidence=f"URL: {backup_url}\nStatus: 200",
                            url=backup_url,
                            remediation=(
                                "Remove backup files from the web root or "
                                "configure the server to deny access to them."
                            ),
                            cvss_score=5.3,
                            cwe_id="CWE-530",
                            owasp_category="A05:2021 Security Misconfiguration",
                            references=[],
                            false_positive_likelihood="medium",
                        ))
                except Exception:
                    continue
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Error-page leak
    # ------------------------------------------------------------------

    async def _check_error_page(self, base_url: str) -> None:
        """Request a non-existent path to trigger a 404 and look for stack traces."""
        try:
            not_found_url = urljoin(base_url, "/thispagedoesnotexist_sectest_404")
            response = await self.http_client.get(not_found_url)
            if response is None:
                return

            body = response.text
            for pattern in _STACK_TRACE_PATTERNS:
                match = pattern.search(body)
                if match:
                    self.add_vulnerability(Vulnerability(
                        title="Verbose Error Page Leaks Technical Details",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.SENSITIVE_DATA,
                        description=(
                            "The server error page contains stack traces or debug "
                            "information that reveals implementation details."
                        ),
                        evidence=(
                            f"URL: {not_found_url}\n"
                            f"Status: {response.status_code}\n"
                            f"Pattern matched: {match.group(0)[:200]}"
                        ),
                        url=not_found_url,
                        remediation=(
                            "Configure custom error pages that do not expose "
                            "stack traces, framework versions, or internal paths. "
                            "Disable debug mode in production."
                        ),
                        cvss_score=5.3,
                        cwe_id="CWE-209",
                        owasp_category="A05:2021 Security Misconfiguration",
                        references=[],
                        false_positive_likelihood="low",
                    ))
                    break  # One finding is enough
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Directory listing
    # ------------------------------------------------------------------

    async def _check_directory_listing(self, base_url: str) -> None:
        """Check if the root URL exposes a directory listing."""
        try:
            response = await self.http_client.get(base_url)
            if response is None:
                return

            body = response.text
            for pattern in _DIRECTORY_LISTING_PATTERNS:
                if pattern.search(body):
                    self.add_vulnerability(Vulnerability(
                        title="Directory Listing Enabled",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.SENSITIVE_DATA,
                        description=(
                            "The web server has directory listing enabled, allowing "
                            "anyone to browse the file structure and discover files "
                            "that may not be intended to be public."
                        ),
                        evidence=(
                            f"URL: {base_url}\n"
                            f"Pattern matched: {pattern.pattern}"
                        ),
                        url=base_url,
                        remediation=(
                            "Disable directory listing in the web server configuration. "
                            "In Apache: Options -Indexes. In Nginx: autoindex off."
                        ),
                        cvss_score=5.3,
                        cwe_id="CWE-548",
                        owasp_category="A01:2021 Broken Access Control",
                        references=[],
                        false_positive_likelihood="low",
                    ))
                    break
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _base_url(url: str) -> str:
        """Return the scheme + netloc portion of a URL (no trailing slash)."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def _severity_to_cvss(severity: Severity) -> float:
        """Rough CVSS mapping for dynamic severity paths."""
        return {
            Severity.CRITICAL: 9.1,
            Severity.HIGH: 7.4,
            Severity.MEDIUM: 5.3,
            Severity.LOW: 2.6,
            Severity.INFO: 0.0,
        }.get(severity, 0.0)
