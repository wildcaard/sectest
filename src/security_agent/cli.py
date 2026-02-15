import asyncio
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from security_agent.core.config import load_config
from security_agent.core.engine import ScanEngine
from security_agent.models.report import Report, ReportMetadata
from security_agent.reporting.generator import ReportGenerator
from security_agent.ai.analyzer import VulnerabilityAnalyzer
from security_agent.ai.fix_suggester import FixSuggester
from security_agent.ai.risk_assessor import RiskAssessor
from security_agent.utils.logger import setup_logger

console = Console()


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx, verbose):
    """Web Security Analysis Agent - Intelligent vulnerability scanner with human-in-the-loop."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logger(verbose=verbose)


@cli.command()
@click.argument("url")
@click.option("--profile", "-p", type=click.Choice(["quick", "standard", "comprehensive"]), default="standard", help="Scan profile")
@click.option("--output", "-o", default="./reports", help="Output directory for reports")
@click.option("--format", "-f", "report_format", default="all", help="Report format (html/md/json/all)")
@click.option("--no-ai", is_flag=True, help="Disable AI-powered analysis")
@click.option("--api-key", envvar="ANTHROPIC_API_KEY", help="API key for AI provider (Anthropic or OpenAI); not used for Ollama")
@click.option("--interactive/--no-interactive", default=True, help="Enable interactive mode")
@click.option("--scanners", "-s", default=None, help="Comma-separated list of scanners to run")
@click.pass_context
def scan(ctx, url, profile, output, report_format, no_ai, api_key, interactive, scanners):
    """Run a security scan on a target URL."""
    config = load_config(profile)
    if api_key:
        provider = config.get("ai", {}).get("provider", "anthropic")
        if provider == "anthropic":
            os.environ["ANTHROPIC_API_KEY"] = api_key
        elif provider == "openai":
            os.environ["OPENAI_API_KEY"] = api_key
        # ollama needs no key

    if no_ai:
        config["ai"]["enabled"] = False

    config["reporting"]["output_dir"] = output
    if report_format == "all":
        config["reporting"]["formats"] = ["html", "json", "md"]
    else:
        config["reporting"]["formats"] = [report_format]

    selected = scanners.split(",") if scanners else None

    async def _run():
        engine = ScanEngine(config, interactive=interactive, selected_scanners=selected)
        scan_result = await engine.run(url, profile=profile)

        # AI Analysis phase
        if config.get("ai", {}).get("enabled", False) and scan_result.vulnerabilities:
            console.print("\n[bold cyan]Phase 4: AI Analysis[/]")

            analyzer = VulnerabilityAnalyzer(config)
            scan_result.vulnerabilities = await analyzer.analyze_findings(
                scan_result.vulnerabilities, url, scan_result.technologies_detected
            )

            fix_suggester = FixSuggester(config)
            scan_result.vulnerabilities = await fix_suggester.suggest_fixes(
                scan_result.vulnerabilities, url, scan_result.technologies_detected
            )

            risk_assessor = RiskAssessor(config)
            risk_assessment = await risk_assessor.assess_risk(
                scan_result.vulnerabilities, url, scan_result.technologies_detected
            )
            ai_risk_text = risk_assessment.get("executive_summary", "")
            attack_chains = risk_assessment.get("attack_chains", [])
            remediation_roadmap = risk_assessment.get("remediation_priorities", [])
        else:
            ai_risk_text = ""
            attack_chains = []
            remediation_roadmap = []

        # Generate report
        report = Report(
            scan_result=scan_result,
            metadata=ReportMetadata(report_format=report_format),
            executive_summary=_generate_executive_summary(scan_result),
            ai_risk_assessment=ai_risk_text,
            attack_chains=attack_chains,
            remediation_roadmap=remediation_roadmap,
        )

        generator = ReportGenerator(config)
        report_files = await generator.generate(report)

        # Save scan result JSON for later report generation (report --input-file / --scan-id)
        output_dir = Path(config["reporting"]["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        domain = (urlparse(scan_result.target_url).hostname or "unknown").replace(".", "_").replace(":", "_")
        scan_json_path = output_dir / f"{domain}_{scan_result.scan_id}_scan.json"
        with open(scan_json_path, "w", encoding="utf-8") as f:
            json.dump(scan_result.to_dict(), f, indent=2, default=_json_serial)
        console.print(f"\n[dim]Scan result saved: {scan_json_path}[/]")

        console.print("\n[bold green]Reports generated:[/]")
        for f in report_files:
            console.print(f"  [cyan]{f}[/]")
        console.print()

    asyncio.run(_run())


@cli.command()
@click.argument("url")
@click.option("--profile", "-p", type=click.Choice(["quick", "standard", "comprehensive"]), default="comprehensive")
@click.option("--output", "-o", default="./reports")
@click.option("--format", "-f", "report_format", default="all")
@click.option("--api-key", envvar="ANTHROPIC_API_KEY")
@click.pass_context
def interactive(ctx, url, profile, output, report_format, api_key):
    """Run in interactive mode with step-by-step approval for each phase."""
    ctx.invoke(scan, url=url, profile=profile, output=output, report_format=report_format,
               no_ai=False, api_key=api_key, interactive=True, scanners=None)


@cli.command()
@click.argument("url")
@click.option("--profile", "-p", type=click.Choice(["quick", "standard", "comprehensive"]), default="standard", help="Scan profile")
@click.option("--output", "-o", default="./reports", help="Output directory for reports")
@click.option("--format", "-f", "report_format", default="all", help="Report format (html/md/json/all)")
@click.option("--max-turns", default=None, type=int, help="Max agent turns (default from config or 10)")
@click.option("--no-ai", is_flag=True, help="Disable AI (agent mode requires AI; use 'secagent scan' for non-AI)")
@click.option("--api-key", envvar="ANTHROPIC_API_KEY", help="API key for AI provider")
@click.option("--interactive/--no-interactive", default=False, help="Prompt for authorization before scan")
@click.pass_context
def agent(ctx, url, profile, output, report_format, max_turns, no_ai, api_key, interactive):
    """Run agentic scan: AI chooses which scanners to run each turn until done."""
    if no_ai:
        console.print("[red]Agent mode requires AI. Use 'secagent scan' for a non-AI scan.[/]")
        raise SystemExit(1)
    config = load_config(profile)
    if api_key:
        provider = config.get("ai", {}).get("provider", "anthropic")
        if provider == "anthropic":
            os.environ["ANTHROPIC_API_KEY"] = api_key
        elif provider == "openai":
            os.environ["OPENAI_API_KEY"] = api_key
    config["reporting"]["output_dir"] = output
    if report_format == "all":
        config["reporting"]["formats"] = ["html", "json", "md"]
    else:
        config["reporting"]["formats"] = [report_format]
    max_turns = max_turns or config.get("agent", {}).get("max_turns", 10)

    from security_agent.agent.runner import run_agent

    async def _run():
        if interactive:
            console.print("\n[bold yellow]Do you have authorization to scan this target? (yes/no): [/]", end="")
            consent = input().strip().lower()
            if consent not in ("yes", "y"):
                console.print("[red]Scan aborted. Authorization required.[/]")
                return
        console.print(f"\n[bold cyan]Agent mode[/] Target: {url} (max turns: {max_turns})\n")
        scan_result = await run_agent(url, config, max_turns=max_turns, interactive=interactive)

        if config.get("ai", {}).get("enabled", False) and scan_result.vulnerabilities:
            console.print("\n[bold cyan]AI Analysis[/]")
            analyzer = VulnerabilityAnalyzer(config)
            scan_result.vulnerabilities = await analyzer.analyze_findings(
                scan_result.vulnerabilities, url, scan_result.technologies_detected
            )
            fix_suggester = FixSuggester(config)
            scan_result.vulnerabilities = await fix_suggester.suggest_fixes(
                scan_result.vulnerabilities, url, scan_result.technologies_detected
            )
            risk_assessor = RiskAssessor(config)
            risk_assessment = await risk_assessor.assess_risk(
                scan_result.vulnerabilities, url, scan_result.technologies_detected
            )
            ai_risk_text = risk_assessment.get("executive_summary", "")
            attack_chains = risk_assessment.get("attack_chains", [])
            remediation_roadmap = risk_assessment.get("remediation_priorities", [])
        else:
            ai_risk_text = ""
            attack_chains = []
            remediation_roadmap = []

        report = Report(
            scan_result=scan_result,
            metadata=ReportMetadata(report_format=report_format),
            executive_summary=_generate_executive_summary(scan_result),
            ai_risk_assessment=ai_risk_text,
            attack_chains=attack_chains,
            remediation_roadmap=remediation_roadmap,
        )
        generator = ReportGenerator(config)
        report_files = await generator.generate(report)
        output_dir = Path(config["reporting"]["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        domain = (urlparse(scan_result.target_url).hostname or "unknown").replace(".", "_").replace(":", "_")
        scan_json_path = output_dir / f"{domain}_{scan_result.scan_id}_scan.json"
        with open(scan_json_path, "w", encoding="utf-8") as f:
            json.dump(scan_result.to_dict(), f, indent=2, default=_json_serial)
        console.print(f"\n[dim]Scan result saved: {scan_json_path}[/]")
        console.print("\n[bold green]Reports generated:[/]")
        for f in report_files:
            console.print(f"  [cyan]{f}[/]")
        console.print()

    asyncio.run(_run())


def _json_serial(obj):
    """JSON serializer for datetime and enums."""
    from datetime import datetime
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "value"):
        return obj.value
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


@cli.command()
@click.option("--scan-id", help="Scan ID to generate report from (finds saved scan in output dir)")
@click.option("--format", "-f", "report_format", default="html")
@click.option("--input-file", "-i", help="Path to scan result JSON file")
@click.option("--output", "-o", default="./reports")
def report(scan_id, report_format, input_file, output):
    """Generate report from previous scan results."""
    import json
    from security_agent.models.scan_result import ScanResult
    from security_agent.models.vulnerability import Vulnerability, Severity, VulnerabilityCategory

    if not input_file and scan_id:
        # Resolve --scan-id: look for saved scan JSON in output dir
        output_path = Path(output)
        if output_path.exists():
            for f in output_path.glob("*_scan.json"):
                if scan_id in f.stem:
                    input_file = str(f)
                    console.print(f"[dim]Using scan result: {input_file}[/]")
                    break
        if not input_file:
            console.print(f"[red]No scan result found with scan-id '{scan_id}' in {output}[/]")
            return

    if not input_file:
        console.print("[red]Please provide --input-file or --scan-id[/]")
        return

    path = Path(input_file)
    if not path.exists():
        console.print(f"[red]File not found: {input_file}[/]")
        return

    with open(path) as f:
        data = json.load(f)

    # Reconstruct scan result from JSON
    sr = ScanResult(target_url=data["target_url"], scan_id=data.get("scan_id", ""))
    sr.start_time = data.get("start_time", "")
    sr.end_time = data.get("end_time", "")
    sr.profile = data.get("profile", "standard")
    sr.scanners_run = data.get("scanners_run", [])
    sr.technologies_detected = data.get("technologies_detected", {})
    sr.total_requests = data.get("total_requests", 0)

    for vd in data.get("vulnerabilities", []):
        v = Vulnerability(
            title=vd["title"],
            severity=Severity(vd["severity"]),
            category=VulnerabilityCategory(vd["category"]),
            description=vd["description"],
            evidence=vd.get("evidence", ""),
            url=vd.get("url", ""),
        )
        v.id = vd.get("id", v.id)
        v.remediation = vd.get("remediation", "")
        v.cvss_score = vd.get("cvss_score", 0)
        v.cwe_id = vd.get("cwe_id", "")
        v.ai_analysis = vd.get("ai_analysis", "")
        v.ai_fix_suggestion = vd.get("ai_fix_suggestion", "")
        sr.vulnerabilities.append(v)

    config = {"reporting": {"formats": [report_format], "output_dir": output}}
    rpt = Report(scan_result=sr, executive_summary=_generate_executive_summary(sr))

    async def _gen():
        gen = ReportGenerator(config)
        files = await gen.generate(rpt)
        for f in files:
            console.print(f"[green]Report:[/] {f}")

    asyncio.run(_gen())


@cli.command()
def config():
    """Show current scan configuration."""
    import yaml
    cfg = load_config()
    console.print(Panel(yaml.dump(cfg, default_flow_style=False), title="Current Configuration"))


@cli.command()
def history():
    """View scan history (from reports directory)."""
    reports_dir = Path("./reports")
    if not reports_dir.exists():
        console.print("[yellow]No reports directory found.[/]")
        return

    json_files = sorted(reports_dir.glob("*.json"), reverse=True)
    if not json_files:
        console.print("[yellow]No scan results found.[/]")
        return

    from rich.table import Table
    table = Table(title="Scan History")
    table.add_column("File", style="cyan")
    table.add_column("Size")

    for f in json_files[:20]:
        size = f.stat().st_size
        size_str = f"{size/1024:.1f} KB" if size > 1024 else f"{size} B"
        table.add_row(f.name, size_str)

    console.print(table)


def _generate_executive_summary(scan_result) -> str:
    """Generate a text executive summary from scan results."""
    sr = scan_result
    counts = sr.severity_counts
    total = len(sr.vulnerabilities)

    if total == 0:
        return f"Security scan of {sr.target_url} completed with no vulnerabilities found. The target appears to have good security posture."

    summary_parts = [
        f"Security scan of {sr.target_url} completed with a score of {sr.grade} ({sr.security_score}/100).",
        f"A total of {total} findings were identified:",
    ]

    for sev in ["critical", "high", "medium", "low", "informational"]:
        count = counts.get(sev, 0)
        if count > 0:
            summary_parts.append(f"  - {sev.upper()}: {count}")

    if counts.get("critical", 0) > 0:
        summary_parts.append("\nImmediate attention required for critical findings.")
    elif counts.get("high", 0) > 0:
        summary_parts.append("\nHigh-severity issues should be addressed promptly.")

    return "\n".join(summary_parts)


def main():
    """Entry point for the CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
