"""Tests for CLI agent command."""

import pytest
from click.testing import CliRunner

from security_agent.cli import cli


@pytest.fixture
def cli_runner():
    return CliRunner()


def test_agent_command_help(cli_runner):
    result = cli_runner.invoke(cli, ["agent", "--help"])
    assert result.exit_code == 0
    assert "agent" in result.output
    assert "max-turns" in result.output or "max_turns" in result.output
    assert "url" in result.output.lower()


def test_agent_command_with_no_ai_exits_with_message(cli_runner):
    """--no-ai should exit with code 1 and require AI message."""
    result = cli_runner.invoke(cli, ["agent", "https://example.com", "--no-ai"])
    assert result.exit_code == 1
    assert "requires AI" in result.output or "secagent scan" in result.output


def test_agent_command_accepts_url_and_options(cli_runner):
    """Invoke with URL and options; without API key it will fail later in run_agent, so we only check invocation."""
    result = cli_runner.invoke(
        cli,
        [
            "agent",
            "https://example.com",
            "--max-turns",
            "2",
            "--profile",
            "standard",
        ],
    )
    # May exit 0 (if load_config finds a profile and run_agent fails on missing LLM)
    # or 1 (if run_agent raises and asyncio.run catches). We mainly want no Click error.
    assert result.exit_code in (0, 1)
    # Should not be "Usage" error from missing URL
    assert "Error: Missing argument" not in result.output or "URL" not in result.output
