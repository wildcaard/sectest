"""Tests for agent runner (runner.py)."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from security_agent.agent.runner import _parse_agent_response, run_agent


class TestParseAgentResponse:
    def test_parse_raw_json(self):
        data = {"done": True, "summary": "Done"}
        text = json.dumps(data)
        assert _parse_agent_response(text) == data

    def test_parse_json_in_markdown_code_block(self):
        data = {"run_scanners": ["headers"], "done": False}
        text = "Here is the response:\n```json\n" + json.dumps(data) + "\n```"
        assert _parse_agent_response(text) == data

    def test_parse_json_code_block_without_json_label(self):
        data = {"done": True}
        text = "```\n" + json.dumps(data) + "\n```"
        assert _parse_agent_response(text) == data

    def test_parse_extracts_first_json_object(self):
        text = "Some preamble {\"done\": true, \"summary\": \"x\"} more text"
        result = _parse_agent_response(text)
        assert result == {"done": True, "summary": "x"}

    def test_parse_invalid_json_returns_none(self):
        assert _parse_agent_response("not json at all") is None
        assert _parse_agent_response("{ invalid }") is None

    def test_parse_empty_or_none(self):
        assert _parse_agent_response("") is None
        assert _parse_agent_response(None) is None


@pytest.mark.asyncio
async def test_run_agent_requires_llm(config_all_scanners_enabled):
    """Without LLM client, run_agent raises RuntimeError."""
    with patch("security_agent.agent.runner.get_llm_client", return_value=None):
        with pytest.raises(RuntimeError, match="Agent mode requires AI"):
            await run_agent("https://example.com", config_all_scanners_enabled, max_turns=2)


@pytest.mark.asyncio
async def test_run_agent_requires_enabled_scanners(config_all_scanners_enabled):
    """With no scanners enabled, run_agent raises RuntimeError."""
    config_no_scanners = dict(config_all_scanners_enabled)
    config_no_scanners["scanners"] = {k: {"enabled": False} for k in config_no_scanners["scanners"]}
    mock_llm = AsyncMock()
    mock_llm.complete = AsyncMock(return_value='{"done": true, "summary": "ok"}')
    with patch("security_agent.agent.runner.get_llm_client", return_value=mock_llm):
        with pytest.raises(RuntimeError, match="No scanners enabled"):
            await run_agent("https://example.com", config_no_scanners, max_turns=2)


@pytest.mark.asyncio
async def test_run_agent_done_on_first_turn(config_all_scanners_enabled):
    """When LLM returns done=true on first turn, run_agent returns a ScanResult with no scanners run."""
    mock_llm = AsyncMock()
    mock_llm.complete = AsyncMock(return_value='{"done": true, "summary": "Initial assessment complete"}')
    with patch("security_agent.agent.runner.get_llm_client", return_value=mock_llm):
        result = await run_agent("https://example.com", config_all_scanners_enabled, max_turns=5)
    assert result is not None
    assert result.target_url == "https://example.com"
    assert result.profile == "agent"
    assert result.scanners_run == []
    assert len(result.vulnerabilities) == 0
    assert result.end_time is not None


@pytest.mark.asyncio
async def test_run_agent_invalid_url(config_all_scanners_enabled):
    """Invalid URL leads to ValueError when creating scan_result on done-first-turn path."""
    mock_llm = AsyncMock()
    mock_llm.complete = AsyncMock(return_value='{"done": true, "summary": "ok"}')
    with patch("security_agent.agent.runner.get_llm_client", return_value=mock_llm):
        with pytest.raises(ValueError):
            await run_agent("not-a-url", config_all_scanners_enabled, max_turns=1)
