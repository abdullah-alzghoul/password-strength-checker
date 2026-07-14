"""CLI entry point for the password strength checker."""

import argparse
import csv
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.prompt import Prompt
from rich.table import Table

from src.core.entropy import StrengthLevel
from src.core.passphrase_generator import generate_passphrase
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

WEAK_TIERS = (StrengthLevel.COMPROMISED, StrengthLevel.VERY_WEAK, StrengthLevel.WEAK)


def render_report(report) -> None:
    color = STRENGTH_COLORS[report.strength]

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("Length", str(report.password_length))
    table.add_row("Raw entropy", f"{report.raw_entropy_bits} bits")
    table.add_row("Effective entropy", f"[{color}]{report.effective_entropy_bits} bits[/{color}]")
    table.add_row("Strength", f"[bold {color}]{report.strength.value}[/bold {color}]")

    console.print(Panel(table, title="Password Analysis", border_style=color))

    breakdown_table = Table(title="Score Breakdown", show_header=False, box=None, padding=(0, 1))
    for item in report.score_breakdown:
        sign_color = "green" if item.points >= 0 else "red"
        sign = "+" if item.points >= 0 else ""
        breakdown_table.add_row(item.label, f"[{sign_color}]{sign}{item.points:g}[/{sign_color}]")
    console.print(breakdown_table)

    percent = STRENGTH_PERCENT[report.strength]
    with Progress(
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=40, complete_style=color),
        TextColumn("{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Strength", total=100)
        progress.update(task, completed=percent)

    crack_table = Table(
        title="Estimated Time to Crack", show_header=False, box=None, padding=(0, 1)
    )
    for estimate in report.crack_time_estimates:
        crack_table.add_row(estimate.scenario, estimate.human_readable)
    console.print(crack_table)

    compliance_table = Table(title="Compliance", show_header=False, box=None, padding=(0, 1))
    for check in report.compliance_checks:
        status = "[green]✓ Pass[/green]" if check.passed else "[red]✗ Fail[/red]"
        compliance_table.add_row(check.name, status)
    console.print(compliance_table)

    if report.warnings:
        console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for w in report.warnings:
            console.print(f"  • {w}")
    else:
        console.print("\n[bold green]No weak patterns detected.[/bold green]")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Password Strength Checker + Analyzer")
    parser.add_argument(
        "-p",
        "--password",
        help="Password to analyze non-interactively. WARNING: may be visible in shell history "
        "and process listings — prefer the interactive prompt for real passwords.",
    )
    parser.add_argument(
        "-f",
        "--file",
        help="Path to a text file with one password per line, for batch analysis. "
        "Plaintext passwords are never written back out — only aggregate metrics are.",
    )
    parser.add_argument("-u", "--username", help="Username for context-aware checks")
    parser.add_argument("-e", "--email", help="Email for context-aware checks")
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Skip the Have I Been Pwned breach check (no internet required)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Base filename to save the report (JSON+HTML for single/generate, CSV for batch)",
    )
    parser.add_argument(
        "-g",
        "--generate",
        action="store_true",
        help="Generate a secure passphrase instead of checking one",
    )
    parser.add_argument(
        "-w",
        "--words",
        type=int,
        default=6,
        help="Number of words in the generated passphrase (default: 6, used with --generate)",
    )
    return parser


def run_one_check(
    password: str, username: str | None, email: str | None, check_breaches: bool, output: str | None
) -> None:
    report = analyze_password(
        password, username=username, email=email, check_breaches=check_breaches
    )
    render_report(report)
    if output:
        json_path, html_path = export_report(report, Path("reports") / output)
        console.print(f"[green]Saved:[/green] {json_path}, {html_path}")


def run_generate(word_count: int, output: str | None) -> None:
    result = generate_passphrase(word_count=word_count)
    console.print(
        Panel(f"[bold cyan]{result.passphrase}[/bold cyan]", title="Generated Passphrase")
    )
    console.print(f"Entropy: {result.entropy_bits} bits (from a {result.wordlist_size}-word list)")

    if result.wordlist_size < 1000:
        console.print(
            "[yellow]Note:[/yellow] using the built-in demo wordlist. For real-world use, "
            "download the EFF long wordlist (eff.org/dice) as data/passphrase_words.txt."
        )

    report = analyze_password(result.passphrase, check_breaches=False)
    console.print(
        f"\nSelf-check: [bold]{report.strength.value}[/bold] "
        f"({report.effective_entropy_bits} bits effective)"
    )

    if output:
        json_path, html_path = export_report(report, Path("reports") / output)
        console.print(f"[green]Saved:[/green] {json_path}, {html_path}")


def export_batch_csv(results: list, path: Path) -> Path:
    """Export aggregate metrics only — the plaintext passwords are never written out."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "index",
                "length",
                "raw_entropy_bits",
                "effective_entropy_bits",
                "strength",
                "warning_count",
            ]
        )
        for i, report in enumerate(results, start=1):
            writer.writerow(
                [
                    i,
                    report.password_length,
                    report.raw_entropy_bits,
                    report.effective_entropy_bits,
                    report.strength.value,
                    len(report.warnings),
                ]
            )
    return path


def run_batch_check(
    filepath: str, username: str | None, email: str | None, check_breaches: bool, output: str | None
) -> None:
    path = Path(filepath)
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] file not found: {filepath}")
        return

    passwords = [
        line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    if not passwords:
        console.print("[bold red]Error:[/bold red] file contains no passwords.")
        return

    with console.status(f"Analyzing {len(passwords)} passwords..."):
        reports = [
            analyze_password(pwd, username=username, email=email, check_breaches=check_breaches)
            for pwd in passwords
        ]

    summary = Table(title=f"Batch Results ({len(passwords)} passwords)")
    summary.add_column("#")
    summary.add_column("Length")
    summary.add_column("Strength")
    summary.add_column("Warnings")

    for i, report in enumerate(reports, start=1):
        color = STRENGTH_COLORS[report.strength]
        summary.add_row(
            str(i),
            str(report.password_length),
            f"[{color}]{report.strength.value}[/{color}]",
            str(len(report.warnings)),
        )
    console.print(summary)

    weak_count = sum(1 for r in reports if r.strength in WEAK_TIERS)
    console.print(
        f"\n[bold]{weak_count}/{len(passwords)}[/bold] passwords are weak or compromised."
    )

    if output:
        csv_path = export_batch_csv(reports, Path("reports") / f"{output}.csv")
        console.print(f"[green]Saved:[/green] {csv_path}")


def main() -> None:
    args = build_arg_parser().parse_args()
    console.print(Panel("[bold]Password Strength Checker + Analyzer[/bold]", border_style="cyan"))

    if args.generate:
        run_generate(args.words, args.output)
        return

    if args.file:
        run_batch_check(args.file, args.username, args.email, not args.no_network, args.output)
        return

    if args.password:
        run_one_check(args.password, args.username, args.email, not args.no_network, args.output)
        return

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
