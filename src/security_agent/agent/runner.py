"""Agentic runner: LLM chooses which scanners to run each turn until done or max_turns."""

import json
import logging
import re
from datetime import datetime
from typing import Any, Optional

from security_agent.agent.prompts import (
    SYSTEM_PROMPT,
    build_user_prompt,
    format_findings_summary,
)
from security_agent.agent.tools import get_scanner_tool_definitions
from security_agent.models.scan_result import ScanResult
from security_agent.utils.http_client import HttpClient
from security_agent.ai.llm_client import get_llm_client

logger = logging.getLogger("security_agent")


def _parse_agent_response(text: str) -> Optional[dict[str, Any]]:
    """Extract JSON from LLM response; handle markdown code blocks."""
    text = (text or "").strip()
    # Try to find JSON in code block first
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        text = match.group(1)
    else:
        # Try raw {...}
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            text = match.group(0)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.warning("Agent response was not valid JSON: %s", text[:200])
        return None


async def run_agent(
    target_url: str,
    config: dict,
    max_turns: int = 10,
    interactive: bool = False,
) -> ScanResult:
    """Run the agentic loop: LLM selects scanners each turn; engine runs them; repeat until done or max_turns.

    Requires config["ai"] and a working LLM client. Returns the accumulated ScanResult.
    """
    llm = get_llm_client(config)
    if llm is None:
        raise RuntimeError(
            "Agent mode requires AI. Set ANTHROPIC_API_KEY or OPENAI_API_KEY, or use Ollama. "
            "Use 'secagent scan' for a non-AI scan."
        )

    tool_definitions = get_scanner_tool_definitions(config)
    if not tool_definitions:
        raise RuntimeError("No scanners enabled in config. Enable at least one scanner.")

    # Import here to avoid circular dependency
    from security_agent.core.engine import ScanEngine
    engine = ScanEngine(config, interactive=False, selected_scanners=None)
    ai_config = config.get("ai", {})
    max_tokens = ai_config.get("max_tokens", 4096)

    async with HttpClient(config.get("scan", {})) as http_client:
        turn = 0
        current_url = target_url
        while turn < max_turns:
            turn += 1
            scanners_run = list(engine.scan_result.scanners_run) if engine.scan_result else []
            vulnerabilities = engine.scan_result.vulnerabilities if engine.scan_result else []
            findings_summary = format_findings_summary(vulnerabilities)

            user_prompt = build_user_prompt(
                target_url=current_url,
                tool_definitions=tool_definitions,
                scanners_run=scanners_run,
                findings_summary=findings_summary,
                turn=turn,
            )

            # Single message: system + user combined for providers that prefer one blob
            full_prompt = f"{SYSTEM_PROMPT}\n\n---\n\n{user_prompt}"

            response_text = await llm.complete(full_prompt, max_tokens=max_tokens)
            data = _parse_agent_response(response_text)

            if data is None:
                logger.warning("Treating invalid JSON as done after turn %s.", turn)
                break

            if data.get("done") is True:
                break

            run_scanners = data.get("run_scanners")
            if not isinstance(run_scanners, list):
                run_scanners = []
            # Filter to valid tool_ids
            valid_ids = [t["tool_id"] for t in tool_definitions]
            to_run = [x for x in run_scanners if x in valid_ids]

            if to_run:
                new_vulns = await engine.run_scanners_by_ids(
                    current_url, to_run, http_client
                )
                if engine.scan_result:
                    current_url = engine.scan_result.target_url
                logger.info("Turn %s: ran %s, got %s new findings.", turn, to_run, len(new_vulns))

        # Ensure we have a scan_result (e.g. LLM said done before running any)
        if engine.scan_result is None:
            from security_agent.utils.validators import validate_url, normalize_url
            valid, result = validate_url(target_url)
            if not valid:
                raise ValueError(result)
            target_url = normalize_url(result)
            engine.scan_result = ScanResult(target_url=target_url, profile="agent")

        engine.scan_result.end_time = datetime.now().isoformat()
        engine.scan_result.total_requests = http_client.request_count
        return engine.scan_result
