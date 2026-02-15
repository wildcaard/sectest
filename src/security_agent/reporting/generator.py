"""Report generation orchestrator."""

import os
from datetime import datetime
from urllib.parse import urlparse

from rich.console import Console

from security_agent.models.report import Report
from security_agent.reporting.json_report import JsonReportGenerator
from security_agent.reporting.markdown_report import MarkdownReportGenerator
from security_agent.reporting.html_report import HtmlReportGenerator


class ReportGenerator:
    """Orchestrates report generation across multiple output formats."""

    def __init__(self, config: dict) -> None:
        self.config = config
        reporting_config = config.get("reporting", {})
        self.output_dir = reporting_config.get("output_dir", "./reports")
        self.formats = reporting_config.get("formats", ["json", "markdown", "html"])
        self.console = Console()

        self._generators = {
            "json": JsonReportGenerator(),
            "markdown": MarkdownReportGenerator(),
            "html": HtmlReportGenerator(),
        }

    async def generate(self, report: Report) -> list[str]:
        """Generate reports in all configured formats.

        Args:
            report: The completed Report object to render.

        Returns:
            List of file paths that were created.
        """
        os.makedirs(self.output_dir, exist_ok=True)

        domain = self._extract_domain(report.scan_result.target_url)
        date_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        created_files: list[str] = []

        for fmt in self.formats:
            generator = self._generators.get(fmt)
            if generator is None:
                self.console.print(
                    f"[yellow]Warning:[/yellow] Unknown report format '{fmt}', skipping."
                )
                continue

            ext = self._format_extension(fmt)
            filename = f"{domain}_{date_str}_report.{ext}"
            output_path = os.path.join(self.output_dir, filename)

            self.console.print(f"  [cyan]Generating {fmt} report...[/cyan]", end=" ")
            try:
                path = generator.generate(report, output_path)
                created_files.append(path)
                self.console.print(f"[green]done[/green] -> {path}")
            except Exception as exc:
                self.console.print(f"[red]failed[/red]: {exc}")

        self.console.print(
            f"\n[bold green]Generated {len(created_files)} report(s)[/bold green]"
        )
        return created_files

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract a filesystem-safe domain string from a URL."""
        parsed = urlparse(url)
        domain = parsed.hostname or parsed.path
        return domain.replace(".", "_").replace(":", "_")

    @staticmethod
    def _format_extension(fmt: str) -> str:
        extensions = {
            "json": "json",
            "markdown": "md",
            "html": "html",
        }
        return extensions.get(fmt, fmt)
