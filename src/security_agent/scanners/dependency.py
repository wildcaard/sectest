"""Frontend dependency vulnerability scanner.

Detects JavaScript/CSS libraries loaded by the page and checks for
known vulnerable versions or missing integrity attributes.
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

# (pattern_regex, library_display_name, version_group "1" or None)
LIBRARY_PATTERNS: list[tuple[str, str, Optional[str]]] = [
    (r"jquery[.-]?(\d+\.\d+\.\d+)", "jQuery", "1"),
    (r"jquery[.-]min[.-]?(\d+\.\d+\.\d+)", "jQuery", "1"),
    (r"vue[.-]?(\d+\.\d+\.\d+)", "Vue.js", "1"),
    (r"react[.-]?(\d+\.\d+\.\d+)", "React", "1"),
    (r"angular[.-]?(\d+\.\d+\.\d+)", "Angular", "1"),
    (r"bootstrap[.-]?(\d+\.\d+\.\d+)", "Bootstrap", "1"),
    (r"lodash[.-]?(\d+\.\d+\.\d+)", "Lodash", "1"),
    (r"moment[.-]?(\d+\.\d+\.\d+)", "Moment.js", "1"),
    (r"axios[.-]?(\d+\.\d+\.\d+)", "Axios", "1"),
    (r"popper[.-]?(\d+\.\d+\.\d+)", "Popper", "1"),
    (r"chart[.-]?(\d+\.\d+\.\d+)", "Chart.js", "1"),
    (r"d3[.-]?(\d+\.\d+\.\d+)", "D3", "1"),
    (r"underscore[.-]?(\d+\.\d+\.\d+)", "Underscore", "1"),
    (r"backbone[.-]?(\d+\.\d+\.\d+)", "Backbone", "1"),
]

# Known vulnerable versions (library_name_lower -> set of bad versions)
# Expand via CVE DB or npm audit in production.
KNOWN_VULNERABLE: dict[str, set[str]] = {
    "jquery": {"3.4.0", "3.4.1"},  # XSS CVEs
    "lodash": {"4.17.20", "4.17.21"},
}


def _extract_libraries_from_html(html: str, base_url: str) -> list[tuple[str, str, Optional[str], str]]:
    """Parse HTML for script/link hrefs and extract library name and version.

    Returns list of (library_key, library_display_name, version_or_none, source_url).
    """
    results: list[tuple[str, str, Optional[str], str]] = []
    seen: set[tuple[str, Optional[str]]] = set()

    def scan_path(path: str, src: str) -> None:
        for pattern, display_name, grp in LIBRARY_PATTERNS:
            mo = re.search(pattern, path, re.IGNORECASE)
            if mo:
                version = mo.group(int(grp)) if grp and mo.lastindex else None
                key_lower = display_name.lower()
                key = (key_lower, version)
                if key not in seen:
                    seen.add(key)
                    results.append((key_lower, display_name, version, src))
                break

    # Script src
    for m in re.finditer(
        r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']',
        html,
        re.IGNORECASE | re.DOTALL,
    ):
        src = m.group(1).strip()
        if not src or src.startswith("data:"):
            continue
        path = urlparse(src).path or src
        scan_path(path, src)

    # Link href for CSS (e.g. bootstrap)
    for m in re.finditer(
        r'<link[^>]+href\s*=\s*["\']([^"\']+)["\'][^>]*rel\s*=\s*["\']stylesheet',
        html,
        re.IGNORECASE | re.DOTALL,
    ):
        href = m.group(1).strip()
        path = urlparse(href).path or href
        scan_path(path, href)

    return results


def _check_integrity(html: str) -> bool:
    """Check if script/link tags use SRI (integrity attribute)."""
    # If at least one script has integrity, we consider SRI partially in use
    if re.search(r'<script[^>]+integrity\s*=', html, re.IGNORECASE):
        return True
    return False


class DependencyScanner(BaseScanner):
    """Scanner for frontend dependency vulnerabilities and missing SRI."""

    @property
    def name(self) -> str:
        return "Frontend Dependency Check"

    @property
    def description(self) -> str:
        return "Detects frontend libraries and known vulnerable versions"

    @property
    def phase(self) -> int:
        return 2

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Execute dependency scan: detect libraries and check for known issues."""
        self.vulnerabilities = []

        try:
            response = await self.http_client.get(target_url)
            if response is None:
                return self.vulnerabilities

            html = response.text
            base_url = target_url

            libraries = _extract_libraries_from_html(html, base_url)

            for lib_key, lib_name, version, source in libraries:
                if version and lib_key in KNOWN_VULNERABLE:
                    bad_versions = KNOWN_VULNERABLE[lib_key]
                    if version in bad_versions:
                        self.add_vulnerability(Vulnerability(
                            title=f"Potentially Vulnerable Dependency: {lib_name} {version}",
                            severity=Severity.HIGH,
                            category=VulnerabilityCategory.VULNERABLE_COMPONENTS,
                            description=(
                                f"The frontend uses {lib_name} version {version}, which may have "
                                "known security vulnerabilities. Upgrade to a patched version."
                            ),
                            evidence=f"Script/source: {source}",
                            url=target_url,
                            remediation=(
                                f"Upgrade {lib_name} to the latest secure version. "
                                "Check npm advisories or CVE databases for the specific version."
                            ),
                            cvss_score=7.0,
                            cwe_id="CWE-1035",
                            owasp_category="A06:2021 – Vulnerable and Outdated Components",
                            false_positive_likelihood="low",
                        ))
                        continue

                # Informational: dependency detected (no known vuln)
                title_suffix = f" {version}" if version else ""
                self.add_vulnerability(Vulnerability(
                    title=f"Frontend Dependency Detected: {lib_name}{title_suffix}",
                    severity=Severity.INFO,
                    category=VulnerabilityCategory.VULNERABLE_COMPONENTS,
                    description=(
                        f"The page loads {lib_name}{title_suffix}. "
                        "Ensure this dependency is kept up to date and monitor for CVEs."
                    ),
                    evidence=f"Source: {source}",
                    url=target_url,
                    remediation="Keep dependencies updated and run periodic vulnerability checks (e.g. npm audit).",
                    false_positive_likelihood="low",
                ))

            # SRI check: scripts without integrity
            if libraries and not _check_integrity(html):
                self.add_vulnerability(Vulnerability(
                    title="Scripts Loaded Without Subresource Integrity (SRI)",
                    severity=Severity.LOW,
                    category=VulnerabilityCategory.SECURITY_MISCONFIG,
                    description=(
                        "One or more script or link resources are loaded without an integrity "
                        "attribute. This allows a compromised CDN or MITM to inject malicious content."
                    ),
                    evidence=f"Page at {target_url} loads {len(libraries)} dependency/ies without SRI.",
                    url=target_url,
                    remediation=(
                        "Add integrity and crossorigin attributes to script/link tags, e.g. "
                        "<script src='...' integrity='sha384-...' crossorigin='anonymous'>"
                    ),
                    cvss_score=4.0,
                    cwe_id="CWE-353",
                    false_positive_likelihood="medium",
                ))

        except Exception:
            pass

        return self.vulnerabilities
