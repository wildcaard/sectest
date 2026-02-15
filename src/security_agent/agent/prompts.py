"""Prompt templates for the agentic scanner (LLM chooses which scanners to run)."""

SYSTEM_PROMPT = """You are a web security analyst. Your job is to choose which security scanners to run next on a target URL.

You will be given:
1. The target URL
2. A list of available scanners (each has a tool_id, name, and description)
3. Which scanners have already been run in this session
4. A summary of current findings (if any)

Respond only with a single JSON object. No other text before or after.

To run scanners: use key "run_scanners" with a list of tool_ids (e.g. ["headers", "cors"]). Set "done" to false. Optionally include "reasoning" (string).

To finish: set "done" to true and include "summary" (short string). Do not include "run_scanners" when done.

Rules:
- Only use tool_ids from the available tools list.
- You may run zero scanners in a turn (use empty list or omit run_scanners) and then set done true to finish.
- Prefer running scanners that have not been run yet. After recon (e.g. subdomain, cms_detect), run passive then active checks.
- If many findings were found, you may decide to finish and summarize.
"""


def format_tools_list(tool_definitions: list[dict]) -> str:
    """Format tool definitions for the user prompt."""
    lines = []
    for t in tool_definitions:
        lines.append(f"- {t['tool_id']}: {t['name']} — {t['description']}")
    return "\n".join(lines) if lines else "(none)"


def format_findings_summary(
    vulnerabilities: list,
    max_findings: int = 15,
    evidence_max_len: int = 120,
) -> str:
    """Format a short summary of findings for the LLM context."""
    if not vulnerabilities:
        return "No findings yet."
    counts: dict[str, int] = {}
    for v in vulnerabilities:
        sev = getattr(v.severity, "value", str(v.severity))
        counts[sev] = counts.get(sev, 0) + 1
    parts = [f"Total: {len(vulnerabilities)}. "]
    for sev in ["critical", "high", "medium", "low", "informational"]:
        if counts.get(sev, 0) > 0:
            parts.append(f"{sev}: {counts[sev]}. ")
    summary = "".join(parts).strip()
    # Add last N findings (title, severity, evidence truncated)
    lines = [summary, "", "Recent findings:"]
    for v in vulnerabilities[-max_findings:]:
        ev = (v.evidence or "")[:evidence_max_len]
        if len((v.evidence or "")) > evidence_max_len:
            ev += "..."
        sev = getattr(v.severity, "value", str(v.severity))
        lines.append(f"- [{sev}] {v.title}: {ev}")
    return "\n".join(lines)


def build_user_prompt(
    target_url: str,
    tool_definitions: list[dict],
    scanners_run: list[str],
    findings_summary: str,
    turn: int,
) -> str:
    """Build the per-turn user prompt for the agent."""
    tools_blob = format_tools_list(tool_definitions)
    run_blob = ", ".join(scanners_run) if scanners_run else "None yet."
    return f"""Target URL: {target_url}

Available scanners (use tool_id in your response):
{tools_blob}

Scanners already run this session: {run_blob}

Current findings summary:
{findings_summary}

Turn: {turn}

Respond with a JSON object only. Either set "run_scanners" to a list of tool_ids to run next (and "done": false), or set "done": true with "summary" to finish."""
