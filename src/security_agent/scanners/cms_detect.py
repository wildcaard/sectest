"""CMS and technology detection scanner."""

import re
from typing import Optional
from urllib.parse import urlparse, urljoin

from security_agent.scanners.base import BaseScanner
from security_agent.models.vulnerability import (
    Vulnerability,
    Severity,
    VulnerabilityCategory,
)


class CMSDetectScanner(BaseScanner):
    """Scanner that detects CMS platforms and technologies used by the target."""

    JS_FRAMEWORK_PATTERNS: list[tuple[str, str, Optional[str]]] = [
        # (pattern_in_html, framework_name, version_regex_or_none)
        (r"react", "React", r"react(?:\.min)?\.js[?/].*?v?(\d+\.\d+\.\d+)"),
        (r"angular", "Angular", r"angular(?:\.min)?\.js[?/].*?v?(\d+\.\d+\.\d+)"),
        (r"vue", "Vue.js", r"vue(?:\.min)?\.js[?/].*?v?(\d+\.\d+\.\d+)"),
        (r"jquery", "jQuery", r"jquery[.-](\d+\.\d+\.\d+)"),
        (r"bootstrap", "Bootstrap", r"bootstrap[.-](\d+\.\d+\.\d+)"),
        (r"backbone", "Backbone.js", None),
        (r"ember", "Ember.js", None),
        (r"next", "Next.js", r"_next"),
        (r"nuxt", "Nuxt.js", r"_nuxt"),
    ]

    @property
    def name(self) -> str:
        return "CMS & Technology Detection Scanner"

    @property
    def description(self) -> str:
        return "Detects CMS platforms, frameworks, and technologies used by the target"

    @property
    def phase(self) -> int:
        return 1

    async def scan(self, target_url: str) -> list[Vulnerability]:
        """Execute CMS and technology detection scan."""
        self.vulnerabilities = []

        try:
            response = await self.http_client.get(target_url)
            if response is None:
                return self.vulnerabilities

            body: str = response.text
            detected_technologies: list[str] = []

            self._detect_wordpress(target_url, body, response, detected_technologies)
            self._detect_drupal(target_url, body, response, detected_technologies)
            self._detect_joomla(target_url, body, response, detected_technologies)
            self._detect_meta_generator(target_url, body, detected_technologies)
            self._detect_response_headers(target_url, response, detected_technologies)
            self._detect_js_frameworks(target_url, body, detected_technologies)
            await self._check_package_json(target_url, detected_technologies)

            if detected_technologies:
                self.add_vulnerability(Vulnerability(
                    title="Technology Stack Detected",
                    severity=Severity.INFO,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        f"Detected {len(detected_technologies)} technology/technologies in use. "
                        "Knowing the technology stack can help attackers target known vulnerabilities."
                    ),
                    evidence="Detected technologies:\n" + "\n".join(f"- {t}" for t in detected_technologies),
                    url=target_url,
                    remediation=(
                        "Remove version information from HTTP headers and HTML where possible. "
                        "Keep all software components up to date."
                    ),
                    false_positive_likelihood="low",
                ))

        except Exception:
            pass

        return self.vulnerabilities

    def _detect_wordpress(
        self,
        target_url: str,
        body: str,
        response: object,
        detected: list[str],
    ) -> None:
        """Detect WordPress CMS."""
        try:
            wp_indicators = [
                "/wp-content/" in body,
                "/wp-includes/" in body,
                "wp-json" in body,
            ]

            if any(wp_indicators):
                version = ""
                version_match = re.search(
                    r'<meta[^>]*name\s*=\s*["\']generator["\'][^>]*content\s*=\s*["\']WordPress\s*([\d.]+)',
                    body,
                    re.IGNORECASE,
                )
                if version_match:
                    version = version_match.group(1)

                wp_label = f"WordPress {version}".strip()
                detected.append(wp_label)

                self.add_vulnerability(Vulnerability(
                    title=f"CMS Detected: {wp_label}",
                    severity=Severity.INFO,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        f"The target is running {wp_label}. "
                        "WordPress sites should be kept updated and hardened."
                    ),
                    evidence=(
                        "Indicators: " +
                        ", ".join(
                            ind for ind, found in zip(
                                ["/wp-content/", "/wp-includes/", "wp-json"],
                                wp_indicators,
                            ) if found
                        )
                    ),
                    url=target_url,
                    remediation="Keep WordPress core, themes, and plugins up to date. Disable XML-RPC if not needed.",
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _detect_drupal(
        self,
        target_url: str,
        body: str,
        response: object,
        detected: list[str],
    ) -> None:
        """Detect Drupal CMS."""
        try:
            drupal_indicators = [
                "/sites/default/" in body,
                "Drupal.settings" in body,
                response.headers.get("x-drupal-cache") is not None,
                response.headers.get("x-generator", "").lower().startswith("drupal"),
            ]

            if any(drupal_indicators):
                version = ""
                gen_header = response.headers.get("x-generator", "")
                version_match = re.search(r"Drupal\s+([\d.]+)", gen_header, re.IGNORECASE)
                if version_match:
                    version = version_match.group(1)

                drupal_label = f"Drupal {version}".strip()
                detected.append(drupal_label)

                self.add_vulnerability(Vulnerability(
                    title=f"CMS Detected: {drupal_label}",
                    severity=Severity.INFO,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=f"The target is running {drupal_label}.",
                    evidence=(
                        "Indicators: " +
                        ", ".join(
                            ind for ind, found in zip(
                                ["/sites/default/", "Drupal.settings", "X-Drupal-Cache header", "X-Generator header"],
                                drupal_indicators,
                            ) if found
                        )
                    ),
                    url=target_url,
                    remediation="Keep Drupal core and modules up to date. Follow Drupal security advisories.",
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _detect_joomla(
        self,
        target_url: str,
        body: str,
        response: object,
        detected: list[str],
    ) -> None:
        """Detect Joomla CMS."""
        try:
            joomla_indicators = [
                "/administrator/" in body and "/media/jui/" in body,
                "/media/jui/" in body,
            ]

            # Also check meta generator
            gen_match = re.search(
                r'<meta[^>]*name\s*=\s*["\']generator["\'][^>]*content\s*=\s*["\']Joomla[!]?\s*([\d.]*)',
                body,
                re.IGNORECASE,
            )

            if gen_match or any(joomla_indicators):
                version = gen_match.group(1) if gen_match else ""
                joomla_label = f"Joomla {version}".strip()
                detected.append(joomla_label)

                self.add_vulnerability(Vulnerability(
                    title=f"CMS Detected: {joomla_label}",
                    severity=Severity.INFO,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=f"The target is running {joomla_label}.",
                    evidence=(
                        "Joomla indicators found in HTML content"
                        + (f" (version from meta generator: {version})" if version else "")
                    ),
                    url=target_url,
                    remediation="Keep Joomla core and extensions up to date.",
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _detect_meta_generator(
        self,
        target_url: str,
        body: str,
        detected: list[str],
    ) -> None:
        """Check for CMS info in meta generator tag (generic, non-WP/Drupal/Joomla)."""
        try:
            gen_match = re.search(
                r'<meta[^>]*name\s*=\s*["\']generator["\'][^>]*content\s*=\s*["\']([^"\']+)',
                body,
                re.IGNORECASE,
            )
            if gen_match:
                generator = gen_match.group(1).strip()
                gen_lower = generator.lower()
                # Skip if already detected as WP/Drupal/Joomla
                if any(cms in gen_lower for cms in ("wordpress", "drupal", "joomla")):
                    return

                detected.append(f"Generator: {generator}")

                self.add_vulnerability(Vulnerability(
                    title=f"Meta Generator Tag: {generator}",
                    severity=Severity.INFO,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        f"The HTML meta generator tag reveals: '{generator}'. "
                        "This information helps attackers identify the software and target known vulnerabilities."
                    ),
                    evidence=f'<meta name="generator" content="{generator}">',
                    url=target_url,
                    remediation="Remove the meta generator tag from HTML output.",
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _detect_response_headers(
        self,
        target_url: str,
        response: object,
        detected: list[str],
    ) -> None:
        """Check response headers for technology information."""
        try:
            interesting_headers: dict[str, str] = {
                "x-powered-by": "X-Powered-By",
                "server": "Server",
                "x-aspnet-version": "X-AspNet-Version",
                "x-aspnetmvc-version": "X-AspNetMvc-Version",
                "x-generator": "X-Generator",
            }

            found_headers: list[str] = []
            for header_key, header_display in interesting_headers.items():
                value = response.headers.get(header_key)
                if value:
                    found_headers.append(f"{header_display}: {value}")
                    detected.append(f"{header_display}: {value}")

            if found_headers:
                self.add_vulnerability(Vulnerability(
                    title="Technology Information in Response Headers",
                    severity=Severity.INFO,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        "Response headers disclose technology information. "
                        "This can help attackers fingerprint the server and target known vulnerabilities."
                    ),
                    evidence="\n".join(found_headers),
                    url=target_url,
                    remediation=(
                        "Remove or obscure technology-revealing headers. "
                        "Configure the web server to suppress X-Powered-By, Server version, etc."
                    ),
                    cwe_id="CWE-200",
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    def _detect_js_frameworks(
        self,
        target_url: str,
        body: str,
        detected: list[str],
    ) -> None:
        """Detect JavaScript frameworks from script tags and HTML content."""
        try:
            script_srcs = re.findall(
                r'<script[^>]*src\s*=\s*["\']([^"\']+)["\']',
                body,
                re.IGNORECASE,
            )
            all_text = body + " ".join(script_srcs)

            found_frameworks: list[str] = []

            for pattern, fw_name, version_regex in self.JS_FRAMEWORK_PATTERNS:
                if re.search(pattern, all_text, re.IGNORECASE):
                    version = ""
                    if version_regex:
                        ver_match = re.search(version_regex, all_text, re.IGNORECASE)
                        if ver_match and ver_match.lastindex:
                            version = ver_match.group(1)

                    label = f"{fw_name} {version}".strip() if version else fw_name
                    found_frameworks.append(label)
                    detected.append(label)

            if found_frameworks:
                self.add_vulnerability(Vulnerability(
                    title="JavaScript Frameworks Detected",
                    severity=Severity.INFO,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        f"Detected {len(found_frameworks)} JavaScript framework(s) in the page. "
                        "Outdated frameworks may have known security vulnerabilities."
                    ),
                    evidence="Frameworks: " + ", ".join(found_frameworks),
                    url=target_url,
                    remediation="Keep all JavaScript frameworks up to date to the latest stable version.",
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass

    async def _check_package_json(self, target_url: str, detected: list[str]) -> None:
        """Check if /package.json is accessible for dependency information."""
        try:
            parsed = urlparse(target_url)
            package_url = f"{parsed.scheme}://{parsed.netloc}/package.json"

            response = await self.http_client.get(package_url)
            if response is None or response.status_code != 200:
                return

            # Verify it looks like JSON
            text = response.text.strip()
            if not text.startswith("{"):
                return

            try:
                import json
                data = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                return

            deps: list[str] = []
            for dep_key in ("dependencies", "devDependencies"):
                dep_dict = data.get(dep_key, {})
                if isinstance(dep_dict, dict):
                    for pkg, ver in list(dep_dict.items())[:20]:
                        deps.append(f"{pkg}: {ver}")
                        detected.append(f"npm: {pkg} {ver}")

            if deps:
                self.add_vulnerability(Vulnerability(
                    title="Exposed package.json",
                    severity=Severity.MEDIUM,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    description=(
                        "The file /package.json is publicly accessible, revealing dependency information. "
                        "This helps attackers identify vulnerable components."
                    ),
                    evidence=f"Dependencies found ({len(deps)}):\n" + "\n".join(deps[:30]),
                    url=package_url,
                    remediation="Block public access to package.json via web server configuration.",
                    cwe_id="CWE-200",
                    false_positive_likelihood="low",
                ))
        except Exception:
            pass
