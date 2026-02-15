"""Tests for agent prompt templates (prompts.py)."""

import pytest

from security_agent.agent.prompts import (
    SYSTEM_PROMPT,
    format_tools_list,
    format_findings_summary,
    build_user_prompt,
)


def test_system_prompt_contains_required_elements():
    assert "web security analyst" in SYSTEM_PROMPT.lower()
    assert "JSON" in SYSTEM_PROMPT
    assert "run_scanners" in SYSTEM_PROMPT
    assert "done" in SYSTEM_PROMPT
    assert "tool_id" in SYSTEM_PROMPT.lower()


def test_format_tools_list_empty():
    assert format_tools_list([]) == "(none)"


def test_format_tools_list_single():
    tools = [{"tool_id": "headers", "name": "HTTP Headers", "description": "Checks headers"}]
    out = format_tools_list(tools)
    assert "headers" in out
    assert "HTTP Headers" in out
    assert "Checks headers" in out
    assert "—" in out or "-" in out


def test_format_tools_list_multiple():
    tools = [
        {"tool_id": "a", "name": "A", "description": "Desc A"},
        {"tool_id": "b", "name": "B", "description": "Desc B"},
    ]
    out = format_tools_list(tools)
    assert "a" in out and "b" in out
    assert out.count("\n") >= 1


def test_format_findings_summary_empty():
    assert format_findings_summary([]) == "No findings yet."


def test_format_findings_summary_single(sample_vulnerability):
    out = format_findings_summary([sample_vulnerability])
    assert "Total: 1" in out
    assert "high" in out.lower()
    assert "Missing HSTS" in out
    assert "Recent findings:" in out


def test_format_findings_summary_truncates_evidence(sample_vulnerability):
    sample_vulnerability.evidence = "x" * 200
    out = format_findings_summary([sample_vulnerability], evidence_max_len=50)
    assert "..." in out or "x" in out


def test_build_user_prompt_includes_all_sections():
    tools = [{"tool_id": "headers", "name": "H", "description": "D"}]
    out = build_user_prompt(
        target_url="https://example.com",
        tool_definitions=tools,
        scanners_run=[],
        findings_summary="No findings yet.",
        turn=1,
    )
    assert "https://example.com" in out
    assert "headers" in out
    assert "None yet" in out
    assert "No findings yet" in out
    assert "Turn: 1" in out
    assert "run_scanners" in out
    assert "done" in out


def test_build_user_prompt_scanners_run_listed():
    out = build_user_prompt(
        target_url="https://x.com",
        tool_definitions=[],
        scanners_run=["headers", "cors"],
        findings_summary="None",
        turn=2,
    )
    assert "headers" in out and "cors" in out
    assert "Turn: 2" in out
