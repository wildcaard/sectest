"""JSON report generator."""

import json
from datetime import datetime
from pathlib import Path

from security_agent.models.report import Report


class JsonReportGenerator:
    """Generates a JSON-formatted security report."""

    def generate(self, report: Report, output_path: str) -> str:
        """Write the report as formatted JSON.

        Args:
            report: The Report object to serialise.
            output_path: Destination file path.

        Returns:
            The absolute path of the written file.
        """
        data = report.to_dict()

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=self._json_serializer)

        return str(Path(output_path).resolve())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _json_serializer(obj):
        """Handle types that are not natively JSON-serializable."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "value"):
            # Enum members
            return obj.value
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
