import asyncio
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.text import Text

from security_agent.core.config import load_config
from security_agent.core.scheduler import ScanScheduler
from security_agent.models.scan_result import ScanResult
from security_agent.models.vulnerability import Vulnerability
from security_agent.utils.http_client import HttpClient
from security_agent.utils.validators import validate_url, normalize_url
from security_agent.agent.tools import SCANNER_CLASSES, get_scanner_class_by_id

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "informational": "dim",
}

PHASE_NAMES = {
    1: "Reconnaissance",
    2: "Passive Scanning",
    3: "Active Scanning",
}


class ScanEngine:
    """Orchestrates the full security scan workflow."""

    def __init__(
        self,
        config: dict,
        interactive: bool = True,
        selected_scanners: Optional[list[str]] = None,
    ):
        self.config = config
        self.interactive = interactive
        self.selected_scanners = selected_scanners
        self.scheduler = ScanScheduler(config)
        self.scan_result: Optional[ScanResult] = None
        self._http_client: Optional[HttpClient] = None

    def _create_all_scanners(self, http_client: HttpClient) -> list:
        """Instantiate all available scanners."""
        scanners = []
        for cls in SCANNER_CLASSES:
            scanner = cls(http_client, self.config)
            if scanner.is_enabled():
                if self.selected_scanners is None or any(
                    name in scanner.name.lower()
                    for name in (self.selected_scanners or [])
                ):
                    scanners.append(scanner)
        return scanners

    def _group_by_phase(self, scanners: list) -> dict[int, list]:
        """Group scanners by their execution phase."""
        phases: dict[int, list] = {}
        for scanner in scanners:
            phases.setdefault(scanner.phase, []).append(scanner)
        return dict(sorted(phases.items()))

    async def run_scanners_by_ids(
        self,
        target_url: str,
        scanner_ids: list[str],
        http_client: HttpClient,
    ) -> list[Vulnerability]:
        """Run only the selected scanners by tool_id (for agentic mode). Creates or
        updates scan_result; returns the new vulnerabilities from this run.
        """
        if not scanner_ids:
            return []

        # First call: validate URL and create scan_result
        if self.scan_result is None:
            valid, result = validate_url(target_url)
            if not valid:
                console.print(f"[bold red]Error:[/] {result}")
                raise ValueError(result)
            target_url = normalize_url(result)
            self.scan_result = ScanResult(target_url=target_url, profile="agent")

        scanners = []
        for tool_id in scanner_ids:
            cls = get_scanner_class_by_id(tool_id)
            if cls is None:
                continue
            scanner = cls(http_client, self.config)
            if scanner.is_enabled():
                scanners.append(scanner)

        if not scanners:
            return []

        results = await self.scheduler.run_phase(scanners, target_url, progress=None, phase_task_id=None)
        new_vulns: list[Vulnerability] = []
        for scanner_name, vulns in results.items():
            new_vulns.extend(vulns)
            self.scan_result.scanners_run.append(scanner_name)
        self.scan_result.vulnerabilities.extend(new_vulns)
        return new_vulns

    async def run(self, target_url: str, profile: Optional[str] = None) -> ScanResult:
        """Execute the full scan workflow."""
        # Validate target
        valid, result = validate_url(target_url)
        if not valid:
            console.print(f"[bold red]Error:[/] {result}")
            raise ValueError(result)

        target_url = normalize_url(result)
        self.scan_result = ScanResult(target_url=target_url, profile=profile or "standard")

        self._display_banner()
        self._display_disclaimer()

        if self.interactive:
            consent = console.input(
                "\n[bold yellow]Do you have authorization to scan this target? (yes/no): [/]"
            )
            if consent.lower() not in ("yes", "y"):
                console.print("[red]Scan aborted. Authorization required.[/]")
                raise SystemExit(1)

        console.print(f"\n[bold green]Target:[/] {target_url}")
        console.print(f"[bold green]Profile:[/] {self.scan_result.profile}\n")

        # Check reachability
        async with HttpClient(self.config.get("scan", {})) as http_client:
            self._http_client = http_client
            resp = await http_client.get(target_url)
            if resp is None:
                console.print("[bold red]Error:[/] Target is not reachable.")
                self.scan_result.errors.append("Target unreachable")
                return self.scan_result

            console.print(f"[green]Target reachable[/] - HTTP {resp.status_code}\n")

            # Create and group scanners
            all_scanners = self._create_all_scanners(http_client)
            phases = self._group_by_phase(all_scanners)

            # Execute each phase
            for phase_num, phase_scanners in phases.items():
                phase_name = PHASE_NAMES.get(phase_num, f"Phase {phase_num}")
                await self._run_phase(phase_num, phase_name, phase_scanners, target_url)

            self.scan_result.end_time = datetime.now().isoformat()
            self.scan_result.total_requests = http_client.request_count
            self._display_summary()

        return self.scan_result

    async def _run_phase(
        self,
        phase_num: int,
        phase_name: str,
        scanners: list,
        target_url: str,
    ):
        """Run a single scan phase with optional human approval."""
        # Display phase header
        scanner_list = "\n".join(f"  - {s.name}: {s.description}" for s in scanners)
        console.print(Panel(
            f"[bold]Scanners:[/]\n{scanner_list}\n\n"
            f"[bold]Target:[/] {target_url}",
            title=f"[bold cyan]Phase {phase_num}: {phase_name}[/]",
            border_style="cyan",
        ))

        if self.interactive and self.config.get("human_loop", {}).get("require_phase_approval", True):
            from security_agent.human_loop.approval import get_phase_approval
            approved, selected = get_phase_approval(scanners, phase_name)
            if not approved:
                console.print(f"[yellow]Phase {phase_num} skipped by user.[/]\n")
                self.scan_result.phase_approvals[phase_name] = "skipped"
                return
            scanners = selected
            self.scan_result.phase_approvals[phase_name] = "approved"

        # Run scanners with progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task(
                f"Phase {phase_num}: {phase_name}", total=len(scanners)
            )
            results = await self.scheduler.run_phase(
                scanners, target_url, progress, task_id
            )

        # Collect vulnerabilities
        all_vulns = []
        table = Table(title=f"Phase {phase_num} Results", show_lines=True)
        table.add_column("Scanner", style="cyan")
        table.add_column("Findings", justify="center")
        table.add_column("Breakdown", style="dim")

        for scanner_name, vulns in results.items():
            all_vulns.extend(vulns)
            self.scan_result.scanners_run.append(scanner_name)
            if vulns:
                breakdown = ", ".join(
                    f"{sum(1 for v in vulns if v.severity.value == s)}{s[0].upper()}"
                    for s in ["critical", "high", "medium", "low", "informational"]
                    if sum(1 for v in vulns if v.severity.value == s) > 0
                )
                table.add_row(scanner_name, str(len(vulns)), breakdown)
            else:
                table.add_row(scanner_name, "[green]0[/]", "No issues found")

        console.print(table)
        console.print()

        self.scan_result.vulnerabilities.extend(all_vulns)

        # Human review of findings
        if self.interactive and all_vulns:
            review_needed = self.config.get("human_loop", {}).get("require_finding_review", False)
            if review_needed:
                from security_agent.human_loop.reviewer import review_findings
                reviewed = review_findings(all_vulns)
                # Update vulnerabilities with human review data
                for vuln in reviewed:
                    vuln.human_verified = True

    def _display_banner(self):
        """Display the startup banner."""
        banner = Text()
        banner.append("\n  Web Security Analysis Agent v1.0\n", style="bold cyan")
        banner.append("  ─────────────────────────────────────\n", style="cyan")
        banner.append("  Intelligent Vulnerability Scanner with Human-in-Loop\n", style="dim")
        console.print(Panel(banner, border_style="bold cyan"))

    def _display_disclaimer(self):
        """Display the legal disclaimer."""
        console.print(Panel(
            "[bold yellow]IMPORTANT:[/] Only scan websites you own or have "
            "explicit written authorization to test.\n"
            "Unauthorized scanning may violate laws and regulations.",
            title="[bold red]Disclaimer[/]",
            border_style="red",
        ))

    def _display_summary(self):
        """Display the final scan summary."""
        sr = self.scan_result
        counts = sr.severity_counts

        summary = Table(show_header=False, box=None, padding=(0, 2))
        summary.add_column("Label", style="bold")
        summary.add_column("Value")
        summary.add_row("Target:", sr.target_url)
        summary.add_row("Duration:", sr.duration)
        summary.add_row("Score:", f"{sr.grade} ({sr.security_score}/100)")
        summary.add_row("Total Findings:", str(len(sr.vulnerabilities)))
        summary.add_row("Requests Made:", str(sr.total_requests))

        console.print(Panel(summary, title="[bold green]SCAN COMPLETE[/]", border_style="green"))

        # Severity breakdown
        sev_table = Table(title="Severity Breakdown", show_lines=False)
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="center")
        sev_table.add_column("Bar")

        total = max(len(sr.vulnerabilities), 1)
        colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "informational": "dim"}
        icons = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "informational": "INFO"}

        for sev in ["critical", "high", "medium", "low", "informational"]:
            count = counts.get(sev, 0)
            bar_len = int(count / total * 30) if count else 0
            bar = "█" * bar_len + "░" * (30 - bar_len)
            pct = f"{count/total*100:.0f}%" if count else "0%"
            sev_table.add_row(
                f"[{colors[sev]}]{icons[sev]}[/]",
                str(count),
                f"[{colors[sev]}]{bar}[/] {pct}",
            )

        console.print(sev_table)
        console.print()
