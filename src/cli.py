"""CLI entry point for the password strength checker."""

import getpass
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table

from src.core.entropy import StrengthLevel
from src.core.scorer import analyze_password
from src.report_generator import export_report

console = Console(width=100)

STRENGTH_COLORS = {
    StrengthLevel.COMPROMISED: "bright_magenta",
    StrengthLevel.VERY_WEAK: "bright_red",
    StrengthLevel.WEAK: "red",
    StrengthLevel.FAIR: "yellow",
    StrengthLevel.STRONG: "green",
    StrengthLevel.VERY_STRONG: "bright_green",
}

STRENGTH_PERCENT = {
    StrengthLevel.COMPROMISED: 0,
    StrengthLevel.VERY_WEAK: 15,
    StrengthLevel.WEAK: 35,
    StrengthLevel.FAIR: 55,
    StrengthLevel.STRONG: 80,
    StrengthLevel.VERY_STRONG: 100,
}


def render_report(report) -> None:
    color = STRENGTH_COLORS[report.strength]

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("Length", str(report.password_length))
    table.add_row("Raw entropy", f"{report.raw_entropy_bits} bits")
    table.add_row("Effective entropy", f"[{color}]{report.effective_entropy_bits} bits[/{color}]")
    table.add_row("Strength", f"[bold {color}]{report.strength.value}[/bold {color}]")

    console.print(Panel(table, title="Password Analysis", border_style=color))

    percent = STRENGTH_PERCENT[report.strength]
    with Progress(
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=40, complete_style=color),
        TextColumn("{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Strength", total=100)
        progress.update(task, completed=percent)

    if report.warnings:
        console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for w in report.warnings:
            console.print(f"  • {w}")
    else:
        console.print("\n[bold green]No weak patterns detected.[/bold green]")


def main() -> None:
    console.print(Panel("[bold]Password Strength Checker + Analyzer[/bold]", border_style="cyan"))

    username = Prompt.ask("Username (optional, for context-aware checks)", default="") or None
    email = Prompt.ask("Email (optional, for context-aware checks)", default="") or None

    while True:
        password = Prompt.ask("\nEnter a password to analyze")

        if not password:
            console.print("[bold red]Error:[/bold red] password cannot be empty.")
            continue

        report = analyze_password(password, username=username, email=email)
        render_report(report)

        save = Prompt.ask("Save report (JSON + HTML)?", choices=["y", "n"], default="n")
        if save == "y":
            filename = Prompt.ask("Base filename (no extension)", default="report")
            json_path, html_path = export_report(report, Path("reports") / filename)
            console.print(f"[green]Saved:[/green] {json_path}, {html_path}")

        again = Prompt.ask("\nCheck another password?", choices=["y", "n"], default="n")
        if again == "n":
            break

    console.print("\n[dim]Goodbye.[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted. Goodbye.[/dim]")
        sys.exit(0)