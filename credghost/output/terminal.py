"""Rich terminal rendering for scan results, the quick check and inventory."""

from __future__ import annotations

from rich.box import HEAVY, ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from credghost.models.nhi import NHIIdentity, RiskLevel, ScanResult

RISK_STYLE = {
    RiskLevel.CRITICAL: ("🔴", "bold red"),
    RiskLevel.HIGH: ("🟠", "dark_orange3"),
    RiskLevel.MEDIUM: ("🟡", "yellow"),
    RiskLevel.LOW: ("🟢", "green"),
    RiskLevel.INFO: ("⚪", "dim"),
}


def _pct(part: int, total: int) -> str:
    if total == 0:
        return " 0%"
    return f"{round(part / total * 100):>2}%"


def render_header(console: Console, result: ScanResult) -> None:
    when = result.scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    body = Text.assemble(
        ("CredGhost — NHI Security Scan\n", "bold white"),
        (f"AWS Account: {result.account}\n", "white"),
        (f"Scanned: {when}", "dim white"),
    )
    console.print(Panel(body, box=HEAVY, border_style="cyan", expand=False))


def render_summary(console: Console, result: ScanResult) -> None:
    total = result.total_nhis
    console.rule("[bold]SUMMARY")
    console.print(f"Total NHIs:          {total}")
    console.print(
        f"Orphaned:            {result.orphaned} ({_pct(result.orphaned, total)})"
    )
    console.print(f"Stale (>90d):        {result.stale} ({_pct(result.stale, total)})")
    console.print(
        f"Never used:          {result.never_used} ({_pct(result.never_used, total)})"
    )
    console.print(
        f"Over-privileged:     {result.over_privileged} "
        f"({_pct(result.over_privileged, total)})"
    )
    console.print()

    by_risk = result.by_risk()
    parts = []
    levels = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]
    if by_risk[RiskLevel.INFO.value]:
        levels.append(RiskLevel.INFO)
    for level in levels:
        icon, style = RISK_STYLE[level]
        parts.append(
            f"[{style}]{icon} {level.value.upper()}: {by_risk[level.value]}[/]"
        )
    console.print("    ".join(parts))
    console.print()


def _findings_table(title: str, identities: list[NHIIdentity], style: str) -> Table:
    table = Table(
        title=title, box=ROUNDED, border_style=style, title_style=f"bold {style}"
    )
    table.add_column("Identity", style="bold", no_wrap=True, max_width=28)
    table.add_column("Type")
    table.add_column("Last Used")
    table.add_column("Owner", max_width=16)
    table.add_column("Risk Reason", max_width=44)
    for nhi in identities:
        table.add_row(
            nhi.name,
            nhi.nhi_type.value.replace("_", " ").title(),
            nhi.last_used_display(),
            nhi.owner or "[red]None[/]",
            "; ".join(nhi.risk_reasons) or "—",
        )
    return table


def render_findings(console: Console, result: ScanResult, levels=None) -> None:
    show = levels or (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM)
    for level in (
        RiskLevel.CRITICAL,
        RiskLevel.HIGH,
        RiskLevel.MEDIUM,
        RiskLevel.LOW,
        RiskLevel.INFO,
    ):
        if level not in show:
            continue
        identities = result.identities_by_level(level)
        if not identities:
            continue
        icon, style = RISK_STYLE[level]
        console.rule(f"[bold]{level.value.upper()} FINDINGS ({len(identities)})")
        console.print(
            _findings_table(
                f"{icon} {level.value.upper()}", identities, style.split()[-1]
            )
        )
        console.print()


def render_recommendations(console: Console, result: ScanResult) -> None:
    by_risk = result.by_risk()
    console.rule("[bold]RECOMMENDED ACTIONS")
    n = 1
    if by_risk["critical"]:
        console.print(
            f"{n}. Immediately investigate {by_risk['critical']} CRITICAL identities"
        )
        n += 1
    if by_risk["high"]:
        console.print(
            f"{n}. Schedule review of {by_risk['high']} HIGH findings within 7 days"
        )
        n += 1
    if any("CloudTrail" in w for w in result.warnings):
        console.print(f"{n}. Enable CloudTrail data events for deeper coverage")
        n += 1
    if result.orphaned:
        console.print(
            f"{n}. {result.orphaned} orphaned identities have no owner — "
            "assign before next audit"
        )
        n += 1
    console.print()


def render_warnings_errors(console: Console, result: ScanResult) -> None:
    for warning in result.warnings:
        console.print(f"[yellow]⚠  {warning}[/]")
    for error in result.errors:
        console.print(f"[red]✖  {error}[/]")
    if result.warnings or result.errors:
        console.print()


def render_scan(console: Console, result: ScanResult, levels=None) -> None:
    render_header(console, result)
    render_warnings_errors(console, result)
    render_summary(console, result)
    render_findings(console, result, levels=levels)
    render_recommendations(console, result)
    console.print(f"[green]Scan complete in {result.scan_duration_seconds} seconds.[/]")
    console.print(
        "[dim]Run `credghost report --input scan.json --format html` "
        "to generate an audit report.[/]"
    )


def render_check(console: Console, result: ScanResult) -> None:
    """Compact 'how bad is my problem' view."""
    by_risk = result.by_risk()
    total = result.total_nhis
    console.print("[bold]CredGhost — Quick Check[/]")
    console.rule(style="cyan")
    console.print(f"\nAWS Account: {result.account}\n")
    console.print(f"  Total NHIs found:        {total:>5}")
    console.print(
        f"  Orphaned (no owner):     {result.orphaned:>5}  ← {_pct(result.orphaned, total)}"
    )
    console.print(
        f"  Stale (>90 days unused): {result.stale:>5}  ← {_pct(result.stale, total)}"
    )
    console.print(
        f"  Over-privileged:         {result.over_privileged:>5}  "
        f"← {_pct(result.over_privileged, total)}"
    )
    console.print(f"  Never used:              {result.never_used:>5}")
    console.print("\n  Risk breakdown:")
    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
        icon, style = RISK_STYLE[level]
        console.print(
            f"  [{style}]{icon} {level.value.capitalize():<9} {by_risk[level.value]:>4}[/]"
        )
    console.print(
        f"\nRun `credghost scan --provider {result.provider}` for full details."
    )


def render_inventory(console: Console, result: ScanResult) -> None:
    """Plain inventory, no risk scoring emphasis."""
    render_header(console, result)
    render_warnings_errors(console, result)
    table = Table(box=ROUNDED, border_style="cyan")
    table.add_column("Identity", style="bold", no_wrap=True, max_width=30)
    table.add_column("Type")
    table.add_column("Created")
    table.add_column("Last Used")
    table.add_column("Owner")
    table.add_column("Granted Perms", justify="right")
    for nhi in sorted(result.identities, key=lambda x: x.nhi_type.value):
        created = nhi.created_at.strftime("%Y-%m-%d") if nhi.created_at else "—"
        table.add_row(
            nhi.name,
            nhi.nhi_type.value.replace("_", " ").title(),
            created,
            nhi.last_used_display(),
            nhi.owner or "None",
            str(len(nhi.granted_permissions)),
        )
    console.print(table)
    console.print(f"\n[dim]{result.total_nhis} identities found.[/]")
