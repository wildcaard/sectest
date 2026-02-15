"""Interactive finding review interface for human-in-the-loop verification."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

from security_agent.models.vulnerability import Severity

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "informational": "dim",
}


def _severity_badge(severity: Severity) -> Text:
    """Create a colored severity badge."""
    label = severity.value.upper()
    style = SEVERITY_COLORS.get(severity.value, "white")
    badge = Text(f" {label} ", style=f"{style} reverse")
    return badge


def _build_finding_panel(vuln, index: int, total: int) -> Panel:
    """Build a rich Panel displaying a single vulnerability finding.

    Args:
        vuln: Vulnerability object.
        index: 1-based index of the current finding.
        total: Total number of findings.

    Returns:
        A rich Panel with all finding details.
    """
    content = Text()

    # Severity badge
    badge = _severity_badge(vuln.severity)
    header_line = Text()
    header_line.append(f"FINDING {index}/{total}  ", style="bold white")
    header_line.append_text(badge)
    content.append_text(header_line)
    content.append("\n\n")

    # Title
    content.append("Title: ", style="bold cyan")
    content.append(f"{vuln.title}\n", style="white")

    # Category
    content.append("Category: ", style="bold cyan")
    content.append(f"{vuln.category.value}\n", style="white")

    # CVSS / CWE / OWASP row
    content.append("CVSS Score: ", style="bold cyan")
    cvss_style = "bold red" if vuln.cvss_score >= 7.0 else (
        "yellow" if vuln.cvss_score >= 4.0 else "green"
    )
    content.append(f"{vuln.cvss_score:.1f}", style=cvss_style)
    content.append("  |  ", style="dim")
    content.append("CWE: ", style="bold cyan")
    content.append(f"{vuln.cwe_id or 'N/A'}", style="white")
    content.append("  |  ", style="dim")
    content.append("OWASP: ", style="bold cyan")
    content.append(f"{vuln.owasp_category or 'N/A'}\n", style="white")

    # URL
    content.append("URL: ", style="bold cyan")
    content.append(f"{vuln.url}\n", style="underline blue")

    # False positive likelihood
    content.append("False Positive Likelihood: ", style="bold cyan")
    fp_style = {"low": "green", "medium": "yellow", "high": "red"}.get(
        vuln.false_positive_likelihood, "white"
    )
    content.append(f"{vuln.false_positive_likelihood}\n", style=fp_style)

    content.append("\n")

    # Description
    content.append("Description:\n", style="bold cyan")
    content.append(f"{vuln.description}\n\n", style="white")

    # Evidence
    if vuln.evidence:
        content.append("Evidence:\n", style="bold cyan")
        content.append(f"{vuln.evidence}\n\n", style="dim white")

    # AI analysis
    if vuln.ai_analysis:
        content.append("AI Analysis:\n", style="bold magenta")
        content.append(f"{vuln.ai_analysis}\n\n", style="white")

    # AI fix suggestion
    if vuln.ai_fix_suggestion:
        content.append("AI Suggested Fix:\n", style="bold green")
        content.append(f"{vuln.ai_fix_suggestion}\n\n", style="white")

    # Remediation
    if vuln.remediation:
        content.append("Remediation:\n", style="bold cyan")
        content.append(f"{vuln.remediation}\n", style="white")

    # Scanner
    content.append("\n")
    content.append(f"Scanner: {vuln.scanner_name}", style="dim")

    severity_color = SEVERITY_COLORS.get(vuln.severity.value, "white")
    return Panel(
        content,
        title=f"[bold]{vuln.id}[/bold]",
        border_style=severity_color.replace("bold ", ""),
        padding=(1, 2),
        expand=True,
    )


def _show_actions() -> None:
    """Display the available review actions."""
    actions = Text()
    actions.append("[C]", style="bold green")
    actions.append("onfirm  ", style="white")
    actions.append("[F]", style="bold red")
    actions.append("alse Positive  ", style="white")
    actions.append("[E]", style="bold yellow")
    actions.append("dit Severity  ", style="white")
    actions.append("[N]", style="bold blue")
    actions.append("ote  ", style="white")
    actions.append("[Enter/\u2192]", style="bold white")
    actions.append(" Next  ", style="white")
    actions.append("[S]", style="bold magenta")
    actions.append("kip Remaining", style="white")
    console.print(actions)


def _edit_severity(vuln) -> None:
    """Let the user pick a new severity for a vulnerability.

    Args:
        vuln: The Vulnerability object to modify.
    """
    console.print("\n[bold yellow]Select new severity:[/bold yellow]")
    for idx, sev in enumerate(Severity, start=1):
        style = SEVERITY_COLORS.get(sev.value, "white")
        console.print(f"  [bold]{idx}[/bold]. [{style}]{sev.value}[/{style}]")

    choice = Prompt.ask(
        "[bold]Enter number[/bold]",
        choices=[str(i) for i in range(1, len(Severity) + 1)],
        show_choices=False,
    )
    new_severity = list(Severity)[int(choice) - 1]
    old_value = vuln.severity.value
    vuln.severity = new_severity
    console.print(
        f"[bold yellow]Severity changed: {old_value} -> {new_severity.value}[/bold yellow]"
    )


def review_findings(vulnerabilities: list) -> list:
    """Interactively review a list of vulnerability findings.

    Presents each finding one at a time with a rich UI and allows the user
    to confirm, mark as false positive, edit severity, add notes, skip to
    the next finding, or skip all remaining findings.

    Args:
        vulnerabilities: List of Vulnerability objects to review.

    Returns:
        The filtered and possibly modified list of vulnerabilities (false
        positives removed, severities/notes updated, verified flags set).
    """
    if not vulnerabilities:
        console.print("[dim]No findings to review.[/dim]")
        return []

    total = len(vulnerabilities)
    console.print()
    console.print(
        Panel(
            f"[bold]Reviewing {total} finding(s)[/bold]\n"
            "[dim]You will see each finding and can take action on it.[/dim]",
            title="[bold cyan]Finding Review[/bold cyan]",
            border_style="cyan",
        )
    )

    reviewed: list = list(vulnerabilities)  # work on a copy-safe reference
    false_positives: set = set()  # track IDs to remove
    index = 0

    while index < len(reviewed):
        vuln = reviewed[index]

        # Skip items already marked as false positive (shouldn't happen, but guard)
        if vuln.id in false_positives:
            index += 1
            continue

        console.print()
        panel = _build_finding_panel(vuln, index + 1, len(reviewed))
        console.print(panel)
        _show_actions()

        action = Prompt.ask(
            "[bold]Action[/bold]",
            default="",
            show_default=False,
        ).strip().lower()

        if action == "c":
            vuln.human_verified = True
            console.print("[bold green]Finding confirmed and verified.[/bold green]")
            index += 1

        elif action == "f":
            console.print(
                f"[bold red]Marked as false positive: {vuln.title}[/bold red]"
            )
            false_positives.add(vuln.id)
            index += 1

        elif action == "e":
            _edit_severity(vuln)
            # Stay on the same finding so user can take further action

        elif action == "n":
            note = Prompt.ask("[bold blue]Enter note[/bold blue]")
            if note:
                if vuln.human_notes:
                    vuln.human_notes += f"\n{note}"
                else:
                    vuln.human_notes = note
                console.print("[bold blue]Note added.[/bold blue]")
            # Stay on the same finding

        elif action == "s":
            remaining = len(reviewed) - index
            console.print(
                f"[bold magenta]Skipping {remaining} remaining finding(s).[/bold magenta]"
            )
            break

        else:
            # Enter / empty / anything else -> next
            index += 1

    # Filter out false positives
    result = [v for v in reviewed if v.id not in false_positives]

    # Summary
    removed = len(reviewed) - len(result)
    verified = sum(1 for v in result if v.human_verified)
    console.print()
    summary_table = Table(
        title="Review Summary",
        show_header=False,
        border_style="cyan",
        padding=(0, 2),
    )
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", justify="right")
    summary_table.add_row("Total reviewed", str(len(reviewed)))
    summary_table.add_row("False positives removed", str(removed))
    summary_table.add_row("Verified findings", str(verified))
    summary_table.add_row("Findings remaining", str(len(result)))
    console.print(summary_table)

    return result
