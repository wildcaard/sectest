"""HTML report generator using Jinja2 templates."""

import os
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from security_agent.models.report import Report


class HtmlReportGenerator:
    """Generates an HTML-formatted security report from a Jinja2 template."""

    TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
    TEMPLATE_NAME = "report.html.j2"

    def generate(self, report: Report, output_path: str) -> str:
        """Render the report as an HTML document.

        Args:
            report: The Report object.
            output_path: Destination file path.

        Returns:
            The absolute path of the written file.
        """
        env = Environment(
            loader=FileSystemLoader(self.TEMPLATE_DIR),
            autoescape=True,
        )

        env.filters["severity_color"] = self._severity_color
        env.filters["severity_order"] = self._severity_order
        env.filters["format_datetime"] = self._format_datetime

        template = env.get_template(self.TEMPLATE_NAME)

        sorted_vulns = self._sort_by_severity(report.scan_result.vulnerabilities)

        html = template.render(
            report=report,
            sorted_vulnerabilities=sorted_vulns,
        )

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        return str(Path(output_path).resolve())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    SEVERITY_PRIORITY = ["critical", "high", "medium", "low", "info"]

    @staticmethod
    def _severity_color(severity: str) -> str:
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#0dcaf0",
            "info": "#6c757d",
        }
        sev = severity.lower() if isinstance(severity, str) else str(severity).lower()
        return colors.get(sev, "#6c757d")

    def _sort_by_severity(self, vulnerabilities) -> list:
        def _key(v):
            sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
            try:
                return self.SEVERITY_PRIORITY.index(sev.lower())
            except ValueError:
                return 999
        return sorted(vulnerabilities, key=_key)

    @staticmethod
    def _severity_order(severity: str) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(severity.lower(), 5)

    @staticmethod
    def _format_datetime(datetime_str: str, format_str: str = '%Y-%m-%d %H:%M') -> str:
        """Format an ISO datetime string using strftime format."""
        if not datetime_str:
            return 'N/A'
        try:
            # Parse ISO format datetime string
            dt = datetime.fromisoformat(datetime_str)
            return dt.strftime(format_str)
        except (ValueError, TypeError):
            # If parsing fails, return the original string
            return str(datetime_str)
