"""Feedback collector for post-scan human input."""

import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, IntPrompt

console = Console()


class FeedbackCollector:
    """Collects, displays, and exports user feedback after a scan."""

    def __init__(self):
        self._feedback_history: list[dict] = []

    def collect_scan_feedback(self) -> dict:
        """Interactively collect post-scan feedback from the user.

        Asks the user to rate the overall scan quality on a 1-5 scale,
        provide general comments, and flag any concerns.

        Returns:
            A dict containing the feedback fields: scan_quality_rating,
            comments, concerns, and timestamp.
        """
        console.print()
        console.print(
            Panel(
                "[bold]We value your feedback to improve scan quality.[/bold]\n"
                "[dim]Please take a moment to rate this scan.[/dim]",
                title="[bold cyan]Scan Feedback[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        # Quality rating
        console.print()
        console.print("[bold]Rate overall scan quality:[/bold]")
        console.print("  [dim]1[/dim] = Poor")
        console.print("  [dim]2[/dim] = Below Average")
        console.print("  [dim]3[/dim] = Average")
        console.print("  [dim]4[/dim] = Good")
        console.print("  [dim]5[/dim] = Excellent")

        while True:
            try:
                rating = IntPrompt.ask(
                    "[bold]Rating (1-5)[/bold]", default=3
                )
                if 1 <= rating <= 5:
                    break
                console.print("[red]Please enter a number between 1 and 5.[/red]")
            except Exception:
                console.print("[red]Please enter a valid number.[/red]")

        # Stars display
        stars = Text()
        for i in range(1, 6):
            if i <= rating:
                stars.append("\u2605 ", style="bold yellow")
            else:
                stars.append("\u2606 ", style="dim")
        console.print(stars)

        # General comments
        console.print()
        comments = Prompt.ask(
            "[bold]General comments (press Enter to skip)[/bold]",
            default="",
            show_default=False,
        )

        # Concerns
        console.print()
        concerns_input = Prompt.ask(
            "[bold]Any concerns or issues? (press Enter to skip)[/bold]",
            default="",
            show_default=False,
        )

        # Parse concerns: if user provides comma-separated items, split them
        concerns: list[str] = []
        if concerns_input.strip():
            concerns = [c.strip() for c in concerns_input.split(",") if c.strip()]

        feedback = {
            "scan_quality_rating": rating,
            "comments": comments,
            "concerns": concerns,
            "timestamp": datetime.now().isoformat(),
        }

        self._feedback_history.append(feedback)

        console.print()
        console.print("[bold green]Thank you for your feedback![/bold green]")

        return feedback

    def request_deeper_scan(self, scanner_names: list[str]) -> list[str]:
        """Show available scanners and let the user select areas for deeper investigation.

        Args:
            scanner_names: List of scanner name strings available for deeper scanning.

        Returns:
            List of selected scanner names.
        """
        if not scanner_names:
            console.print("[dim]No scanners available for deeper investigation.[/dim]")
            return []

        console.print()
        console.print(
            Panel(
                "[bold]Select scanners for deeper investigation.[/bold]\n"
                "[dim]These scanners will perform more thorough checks.[/dim]",
                title="[bold cyan]Deeper Scan Request[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        # Display scanner list
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Scanner", style="bold white")

        for idx, name in enumerate(scanner_names, start=1):
            table.add_row(str(idx), name)

        console.print(table)
        console.print()
        console.print("[dim]Enter numbers comma-separated, 'all' for all, or 'none' to cancel.[/dim]")

        raw = Prompt.ask("[bold]Selection[/bold]", default="none")
        raw = raw.strip().lower()

        if raw == "none" or not raw:
            console.print("[dim]No scanners selected.[/dim]")
            return []

        if raw == "all":
            console.print(
                f"[bold green]Selected all {len(scanner_names)} scanner(s) for deeper scan.[/bold green]"
            )
            return list(scanner_names)

        selected: list[str] = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                num = int(part)
                if 1 <= num <= len(scanner_names):
                    name = scanner_names[num - 1]
                    if name not in selected:
                        selected.append(name)
                else:
                    console.print(f"[red]Invalid number: {num}. Skipping.[/red]")
            except ValueError:
                console.print(f"[red]Invalid input: '{part}'. Skipping.[/red]")

        if selected:
            console.print(
                f"[bold green]Selected {len(selected)} scanner(s): {', '.join(selected)}[/bold green]"
            )
        else:
            console.print("[dim]No valid scanners selected.[/dim]")

        return selected

    def export_feedback(self, feedback: dict, filepath: str) -> None:
        """Save feedback data to a JSON file.

        Args:
            feedback: The feedback dictionary to export.
            filepath: Destination file path for the JSON output.
        """
        path = Path(filepath)

        # Ensure parent directory exists
        path.parent.mkdir(parents=True, exist_ok=True)

        # If the file already exists, try to merge with existing data
        existing_data: list[dict] = []
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, list):
                    existing_data = loaded
                elif isinstance(loaded, dict):
                    existing_data = [loaded]
            except (json.JSONDecodeError, OSError):
                existing_data = []

        existing_data.append(feedback)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=2, default=str)

        console.print(
            f"[bold green]Feedback exported to:[/bold green] [underline]{filepath}[/underline]"
        )
