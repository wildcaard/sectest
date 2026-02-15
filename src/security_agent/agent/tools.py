"""Scanner tool registry: expose scanners as LLM-callable tools with stable IDs and metadata."""

from typing import Any

from security_agent.scanners.base import BaseScanner
from security_agent.scanners.headers import HeadersScanner
from security_agent.scanners.ssl_tls import SslTlsScanner
from security_agent.scanners.cors import CorsScanner
from security_agent.scanners.cookies import CookiesScanner
from security_agent.scanners.xss import XSSScanner
from security_agent.scanners.sqli import SQLiScanner
from security_agent.scanners.csrf import CSRFScanner
from security_agent.scanners.open_redirect import OpenRedirectScanner
from security_agent.scanners.info_disclosure import InfoDisclosureScanner
from security_agent.scanners.subdomain import SubdomainScanner
from security_agent.scanners.directory import DirectoryScanner
from security_agent.scanners.cms_detect import CMSDetectScanner
from security_agent.scanners.api_security import APISecurityScanner
from security_agent.scanners.clickjacking import ClickjackingScanner
from security_agent.scanners.ssrf import SSRFScanner
from security_agent.scanners.dependency import DependencyScanner
from security_agent.scanners.token_hijacking import TokenHijackingScanner

# Same scanner classes as ScanEngine; order matches engine for consistency.
# Tool IDs are derived from module name (e.g. headers, ssl_tls) to match config keys.
SCANNER_CLASSES: list[type[BaseScanner]] = [
    HeadersScanner,
    SslTlsScanner,
    CorsScanner,
    CookiesScanner,
    TokenHijackingScanner,
    XSSScanner,
    SQLiScanner,
    CSRFScanner,
    OpenRedirectScanner,
    InfoDisclosureScanner,
    SubdomainScanner,
    DirectoryScanner,
    CMSDetectScanner,
    APISecurityScanner,
    ClickjackingScanner,
    SSRFScanner,
    DependencyScanner,
]


def _tool_id_for_class(cls: type[BaseScanner]) -> str:
    """Stable tool_id from scanner module name (matches config key)."""
    return cls.__module__.split(".")[-1]


def get_scanner_tool_definitions(config: dict) -> list[dict[str, Any]]:
    """Return tool definitions for all enabled scanners (tool_id, name, description).

    Only includes scanners that are enabled in config. Used by the agent
    to present available tools to the LLM.
    """
    definitions: list[dict[str, Any]] = []
    # Scanners need config; http_client is only used for scan(), not for name/description/is_enabled
    dummy_http_client: Any = None
    for cls in SCANNER_CLASSES:
        scanner = cls(dummy_http_client, config)
        if not scanner.is_enabled():
            continue
        definitions.append({
            "tool_id": _tool_id_for_class(cls),
            "name": scanner.name,
            "description": scanner.description,
        })
    return definitions


def get_scanner_class_by_id(tool_id: str) -> type[BaseScanner] | None:
    """Return the scanner class for a given tool_id, or None if not found."""
    for cls in SCANNER_CLASSES:
        if _tool_id_for_class(cls) == tool_id:
            return cls
    return None
