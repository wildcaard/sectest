# Web Security Analysis Agent

CLI-based website security analysis and vulnerability scanner with a **human-in-the-loop** workflow. Run automated security scans, review findings interactively, and generate reports in HTML, Markdown, or JSON. **Agent mode** lets the AI choose which scanners to run each turn based on findings.

## Prerequisites

- **Python 3.11+**
- (Optional) **AI provider**: Anthropic or OpenAI API key for cloud AI; or **Ollama** running locally for AI analysis and fix suggestions

## Installation

From the project root:

```bash
pip install -e .
```

Or install in a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate   # Linux / macOS
pip install -e .
```

## AI Providers and Environment Variables

The agent supports three AI backends (set in `config/default_config.yaml` under `ai.provider`):

| Provider | Config `ai.provider` | Environment variable | Notes |
|----------|------------------------|----------------------|--------|
| **Anthropic** | `anthropic` | `ANTHROPIC_API_KEY` | Default. Use `--api-key` or env for API key. |
| **OpenAI** | `openai` | `OPENAI_API_KEY` | Use `--api-key` or env for API key. Model e.g. `gpt-4o`, `gpt-4o-mini`. |
| **Ollama** | `ollama` | (none) | Local models; no key. Ensure Ollama is running. Set `ai.base_url` if not `http://localhost:11434`. Model e.g. `llama2`, `mistral`, `codellama`. |

If no key is set (for Anthropic/OpenAI) or Ollama is unreachable, the tool runs without AI features (or falls back to non-AI risk assessment).

## How to Run

### Run a scan

```bash
# Quick scan with default (standard) profile
secagent scan https://example.com

# Non-interactive (no phase approval prompts)
secagent scan https://example.com --no-interactive

# Comprehensive profile, all report formats
secagent scan https://example.com --profile comprehensive --format all

# Custom output directory and report format
secagent scan https://example.com --output ./my-reports --format html

# Disable AI analysis
secagent scan https://example.com --no-ai

# Run only specific scanners (comma-separated)
secagent scan https://example.com --scanners headers,ssl_tls,cookies,token_hijacking
```

### Agent mode (AI-driven scanner selection)

```bash
secagent agent https://example.com
```

Runs an **agentic** scan: the AI chooses which scanners to run each turn based on current findings, then continues until it decides to finish or hits the turn limit. Requires an AI provider (Anthropic, OpenAI, or Ollama). Use `--max-turns` to cap turns (default: 10 from config).

```bash
secagent agent https://example.com --max-turns 5 --profile comprehensive
secagent agent https://example.com --interactive   # prompt for authorization first
```

### Interactive mode (step-by-step approval)

```bash
secagent interactive https://example.com
```

Prompts for approval before each scan phase and (if configured) for reviewing individual findings.

### Generate a report from a previous scan

```bash
# By scan ID (looks in output directory for saved scan JSON)
secagent report --scan-id <scan_id> --format html --output ./reports

# By input file
secagent report --input-file ./reports/example_com_abc123_scan.json --format html --output ./reports
```

### Other commands

```bash
# Show current configuration
secagent config

# List recent scan results (JSON files in reports directory)
secagent history
```

## Options Reference

| Option | Description |
|--------|-------------|
| `--profile`, `-p` | Scan profile: `quick`, `standard`, `comprehensive` |
| `--output`, `-o` | Output directory for reports (default: `./reports`) |
| `--format`, `-f` | Report format: `html`, `md`, `json`, or `all` |
| `--no-ai` | Disable AI analysis and fix suggestions (not supported for `agent`; use `scan` for non-AI) |
| `--api-key` | API key for the configured AI provider (Anthropic or OpenAI); ignored for Ollama |
| `--interactive` / `--no-interactive` | Enable or disable phase approval and finding review (`scan`); or authorization prompt (`agent`) |
| `--scanners`, `-s` | Comma-separated list of scanner IDs to run (e.g. `headers,ssl_tls,cookies,xss`) — `scan` only |
| `--max-turns` | Max agent turns (default: 10 from config) — `agent` only |
| `--verbose`, `-v` | Enable verbose logging (global) |

## Scan Profiles

Defined under `config/scan_profiles/`:

- **quick** — Fewer checks, faster run
- **standard** — Balanced set of scanners (default for `scan`)
- **comprehensive** — Full scan (default for `interactive`)

## Report Formats

- **html** — Interactive report with severity breakdown and remediation
- **md** — Markdown for docs or wikis
- **json** — Machine-readable for CI/CD or tooling

After each scan, a scan result JSON is saved as `{domain}_{scan_id}_scan.json` in the output directory so you can regenerate reports with `secagent report --scan-id <id>`.

## Disclaimer

**Only scan websites you own or have explicit written authorization to test.** Unauthorized scanning may violate laws and regulations. The tool will prompt for confirmation before starting a scan when run in interactive mode.

## Configuration

Default settings are in `config/default_config.yaml`. Scan profiles live in `config/scan_profiles/`. You can adjust timeouts, rate limits, which scanners are enabled, human-in-the-loop behavior, **AI provider** (`ai.provider`: `anthropic`, `openai`, or `ollama`), `ai.model`, and for Ollama optionally `ai.base_url`. For agent mode, `agent.max_turns` (default 10) sets the maximum number of LLM turns.

## Running tests

Install dev dependencies and run pytest (from project root):

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

Or with `PYTHONPATH` if not using editable install: `PYTHONPATH=src pytest tests/ -v`

## Running as a module

```bash
python -m security_agent scan https://example.com
python -m security_agent agent https://example.com
python -m security_agent interactive https://example.com
```
