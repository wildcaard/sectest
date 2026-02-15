"""Phase approval workflow for human-in-the-loop scan control."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "informational": "dim",
}


def get_phase_approval(scanners: list, phase_name: str) -> tuple[bool, list]:
    """Display phase scanners and prompt user for approval.

    Args:
        scanners: List of scanner objects (with .name and .description attributes).
        phase_name: Human-readable name for the scan phase.

    Returns:
        A tuple of (approved, selected_scanners) where approved is True if the
        phase should proceed, and selected_scanners is the list of scanner
        objects to run.
    """
    if not scanners:
        console.print(
            f"[dim]No scanners available for phase: {phase_name}. Skipping.[/dim]"
        )
        return False, []

    # Build the scanner table
    table = Table(
        show_header=True,
        header_style="bold cyan",
        expand=True,
        border_style="dim",
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Scanner", style="bold white")
    table.add_column("Description", style="white")

    for idx, scanner in enumerate(scanners, start=1):
        table.add_row(str(idx), scanner.name, scanner.description)

    # Compose panel content
    header = Text()
    header.append(f"Phase: {phase_name}\n", style="bold magenta")
    header.append(f"Scanners: {len(scanners)} available\n", style="white")

    panel = Panel(
        table,
        title=f"[bold cyan]Phase Approval - {phase_name}[/bold cyan]",
        subtitle="[dim]Review scanners before proceeding[/dim]",
        border_style="cyan",
        padding=(1, 2),
    )

    console.print()
    console.print(header)
    console.print(panel)
    console.print()

    # Prompt for action
    options_text = Text()
    options_text.append("[A]", style="bold green")
    options_text.append("pprove All  ", style="white")
    options_text.append("[S]", style="bold yellow")
    options_text.append("elect Individual  ", style="white")
    options_text.append("[K]", style="bold blue")
    options_text.append(" Skip Phase  ", style="white")
    options_text.append("[Q]", style="bold red")
    options_text.append("uit", style="white")
    console.print(options_text)

    while True:
        choice = Prompt.ask(
            "[bold]Choose an action[/bold]",
            choices=["a", "s", "k", "q"],
            default="a",
            show_choices=False,
        ).lower()

        if choice == "a":
            console.print(
                f"[bold green]Approved all {len(scanners)} scanners for {phase_name}.[/bold green]"
            )
            return True, list(scanners)

        elif choice == "s":
            return _select_individual_scanners(scanners, phase_name)

        elif choice == "k":
            console.print(
                f"[bold blue]Phase '{phase_name}' skipped.[/bold blue]"
            )
            return False, []

        elif choice == "q":
            console.print("[bold red]Scan aborted by user.[/bold red]")
            raise SystemExit(0)


def _select_individual_scanners(
    scanners: list, phase_name: str
) -> tuple[bool, list]:
    """Let the user pick specific scanners by number.

    Args:
        scanners: Full list of available scanners.
        phase_name: Phase name for display.

    Returns:
        (approved, selected_scanners) tuple.
    """
    console.print()
    console.print("[bold yellow]Select scanners to run:[/bold yellow]")

    for idx, scanner in enumerate(scanners, start=1):
        console.print(f"  [bold]{idx}[/bold]. {scanner.name} - [dim]{scanner.description}[/dim]")

    console.print()
    raw = Prompt.ask(
        "[bold]Enter scanner numbers (comma-separated, e.g. 1,3,4)[/bold]"
    )

    selected = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            num = int(part)
            if 1 <= num <= len(scanners):
                selected.append(scanners[num - 1])
            else:
                console.print(
                    f"[red]Invalid number: {num}. Skipping.[/red]"
                )
        except ValueError:
            console.print(f"[red]Invalid input: '{part}'. Skipping.[/red]")

    if not selected:
        console.print(
            "[bold red]No valid scanners selected. Phase skipped.[/bold red]"
        )
        return False, []

    # Show confirmation
    names = ", ".join(s.name for s in selected)
    console.print(
        f"[bold green]Selected {len(selected)} scanner(s) for {phase_name}: {names}[/bold green]"
    )
    return True, selected
