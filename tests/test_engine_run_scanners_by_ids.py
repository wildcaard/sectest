"""Tests for ScanEngine.run_scanners_by_ids (agentic mode)."""

from unittest.mock import AsyncMock, patch

import pytest

from security_agent.core.engine import ScanEngine
from security_agent.models.vulnerability import Vulnerability, Severity, VulnerabilityCategory
from security_agent.utils.http_client import HttpClient


@pytest.fixture
def mock_scheduler_run_phase():
    """Mock scheduler.run_phase to avoid real HTTP; return empty vulns per scanner."""
    return AsyncMock(return_value={"HTTP Security Headers": []})


@pytest.mark.asyncio
async def test_run_scanners_by_ids_empty_list_returns_empty(config_all_scanners_enabled):
    engine = ScanEngine(config_all_scanners_enabled, interactive=False, selected_scanners=None)
    async with HttpClient(config_all_scanners_enabled.get("scan", {})) as http_client:
        vulns = await engine.run_scanners_by_ids("https://example.com", [], http_client)
    assert vulns == []
    assert engine.scan_result is None


@pytest.mark.asyncio
async def test_run_scanners_by_ids_creates_scan_result_and_runs_scanners(
    config_all_scanners_enabled, mock_scheduler_run_phase
):
    engine = ScanEngine(config_all_scanners_enabled, interactive=False, selected_scanners=None)
    async with HttpClient(config_all_scanners_enabled.get("scan", {})) as http_client:
        with patch.object(engine.scheduler, "run_phase", mock_scheduler_run_phase):
            vulns = await engine.run_scanners_by_ids("https://example.com", ["headers"], http_client)
    assert vulns == []
    assert engine.scan_result is not None
    assert engine.scan_result.target_url == "https://example.com"
    assert engine.scan_result.profile == "agent"
    assert any("Header" in n for n in engine.scan_result.scanners_run)


@pytest.mark.asyncio
async def test_run_scanners_by_ids_accumulates_vulnerabilities(
    config_all_scanners_enabled,
):
    fake_vuln = Vulnerability(
        title="Test",
        severity=Severity.LOW,
        category=VulnerabilityCategory.SECURITY_MISCONFIG,
        description="D",
        evidence="E",
        url="https://example.com",
    )
    mock_run_phase = AsyncMock(return_value={"HTTP Security Headers": [fake_vuln]})
    engine = ScanEngine(config_all_scanners_enabled, interactive=False, selected_scanners=None)
    async with HttpClient(config_all_scanners_enabled.get("scan", {})) as http_client:
        with patch.object(engine.scheduler, "run_phase", mock_run_phase):
            vulns = await engine.run_scanners_by_ids("https://example.com", ["headers"], http_client)
    assert len(vulns) == 1
    assert vulns[0].title == "Test"
    assert len(engine.scan_result.vulnerabilities) == 1


@pytest.mark.asyncio
async def test_run_scanners_by_ids_second_call_merges(config_all_scanners_enabled, mock_scheduler_run_phase):
    engine = ScanEngine(config_all_scanners_enabled, interactive=False, selected_scanners=None)
    async with HttpClient(config_all_scanners_enabled.get("scan", {})) as http_client:
        with patch.object(engine.scheduler, "run_phase", mock_scheduler_run_phase):
            await engine.run_scanners_by_ids("https://example.com", ["headers"], http_client)
            await engine.run_scanners_by_ids("https://example.com", ["cors"], http_client)
    assert engine.scan_result is not None
    assert len(engine.scan_result.scanners_run) == 2


@pytest.mark.asyncio
async def test_run_scanners_by_ids_invalid_url_raises(config_all_scanners_enabled):
    engine = ScanEngine(config_all_scanners_enabled, interactive=False, selected_scanners=None)
    async with HttpClient(config_all_scanners_enabled.get("scan", {})) as http_client:
        with pytest.raises(ValueError):
            await engine.run_scanners_by_ids("not-a-valid-url", ["headers"], http_client)


@pytest.mark.asyncio
async def test_run_scanners_by_ids_unknown_tool_id_skipped(config_all_scanners_enabled, mock_scheduler_run_phase):
    engine = ScanEngine(config_all_scanners_enabled, interactive=False, selected_scanners=None)
    async with HttpClient(config_all_scanners_enabled.get("scan", {})) as http_client:
        with patch.object(engine.scheduler, "run_phase", mock_scheduler_run_phase):
            vulns = await engine.run_scanners_by_ids(
                "https://example.com", ["headers", "nonexistent_tool", "cors"], http_client
            )
    # Only headers and cors should run (nonexistent_tool skipped)
    assert engine.scan_result is not None
    assert mock_scheduler_run_phase.await_count == 1
    # Should have 2 scanners in the phase (headers and cors)
    call_args = mock_scheduler_run_phase.call_args
    scanners_passed = call_args[0][0]
    assert len(scanners_passed) == 2
