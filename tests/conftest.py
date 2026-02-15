"""Shared pytest fixtures for web-security-agent tests."""

import pytest


@pytest.fixture
def config_all_scanners_enabled():
    """Config with all scanners enabled (no scanner disabled)."""
    return {
        "scan": {"timeout": 30, "max_concurrent": 5, "rate_limit": 10},
        "scanners": {
            "headers": {"enabled": True},
            "ssl_tls": {"enabled": True},
            "cors": {"enabled": True},
            "cookies": {"enabled": True},
            "xss": {"enabled": True},
            "sqli": {"enabled": True},
            "csrf": {"enabled": True},
            "open_redirect": {"enabled": True},
            "info_disclosure": {"enabled": True},
            "subdomain": {"enabled": True},
            "directory": {"enabled": True},
            "cms_detect": {"enabled": True},
            "api_security": {"enabled": True},
            "clickjacking": {"enabled": True},
            "ssrf": {"enabled": True},
            "dependency": {"enabled": True},
            "token_hijacking": {"enabled": True},
        },
        "ai": {"enabled": True, "max_tokens": 4096},
        "agent": {"max_turns": 10},
    }


@pytest.fixture
def config_one_scanner_disabled(config_all_scanners_enabled):
    """Config with one scanner (headers) disabled."""
    cfg = dict(config_all_scanners_enabled)
    cfg["scanners"] = dict(cfg["scanners"])
    cfg["scanners"]["headers"] = {"enabled": False}
    return cfg


@pytest.fixture
def sample_vulnerability():
    """Single vulnerability for prompt/findings tests."""
    from security_agent.models.vulnerability import (
        Vulnerability,
        Severity,
        VulnerabilityCategory,
    )
    return Vulnerability(
        title="Missing HSTS",
        severity=Severity.HIGH,
        category=VulnerabilityCategory.SECURITY_MISCONFIG,
        description="HSTS header not set",
        evidence="Response lacked Strict-Transport-Security",
        url="https://example.com/",
    )
