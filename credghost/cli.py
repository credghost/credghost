"""CredGhost CLI — Click entrypoint.

Commands: scan, check, inventory, report, configure. Phase 1 supports the AWS
provider only. All operations are read-only.
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

from credghost import __version__
from credghost.config import get_profile, load_config, policy_json_path, set_profile
from credghost.engine.inventory import build_inventory
from credghost.models.nhi import NHIType, RiskLevel
from credghost.output import html_reporter, json_reporter, terminal
from credghost.providers.aws.client import CredentialsMissing

console = Console()
err_console = Console(stderr=True)

SUPPORTED_PROVIDERS = ("aws",)

_STAGE_LABELS = {
    "users": "Scanning IAM users",
    "roles": "Scanning IAM roles",
    "analyzer": "Pulling Access Analyzer",
    "cloudtrail": "Enriching from CloudTrail",
}


def _build_provider(provider: str, profile, region, account_id):
    if provider != "aws":
        raise click.ClickException(
            f"Provider '{provider}' is not supported in Phase 1. Only 'aws' is available."
        )
    from credghost.providers.aws import AWSProvider

    return AWSProvider(profile=profile, region=region, account_id=account_id)


def _run_scan(provider, profile, region, account_id, stale_after, score, show_progress):
    prov = _build_provider(provider, profile, region, account_id)

    if not show_progress:
        return build_inventory(prov, stale_threshold_days=stale_after, score=score)

    # Render live progress per stage as the provider reports it.
    seen: list[str] = []

    def progress_cb(stage, total):
        label = _STAGE_LABELS.get(stage, stage)
        count = f"{total}" if total is not None else "done"
        if stage not in seen:
            seen.append(stage)
        err_console.print(f"[cyan]{label:<28}[/] [green]{count}[/]")

    with err_console.status("[cyan]Scanning...[/]", spinner="dots"):
        return build_inventory(
            prov,
            stale_threshold_days=stale_after,
            score=score,
            progress_callback=progress_cb,
        )


def _handle_credentials_error(exc: CredentialsMissing):
    err_console.print(f"[bold red]No AWS credentials found.[/]\n{exc}")
    sys.exit(2)


def _parse_severity(value: str | None):
    if not value:
        return None
    levels = []
    for token in value.split(","):
        token = token.strip().lower()
        try:
            levels.append(RiskLevel(token))
        except ValueError:
            raise click.BadParameter(f"Unknown severity '{token}'")
    return levels


# --------------------------------------------------------------------------- CLI


@click.group()
@click.version_option(__version__, prog_name="credghost")
def main():
    """CredGhost — find every ghost key in your cloud (read-only NHI audit)."""


@main.command()
@click.option("--provider", default="aws", show_default=True, help="Cloud provider to scan.")
@click.option("--profile", default=None, help="Named AWS credentials profile.")
@click.option("--region", default=None, help="AWS region (optional).")
@click.option("--account-id", default=None, help="Expected AWS account id.")
@click.option("--stale-after", default=None, type=int, help="Staleness threshold in days (default 90).")
@click.option("--output", "output_fmt", type=click.Choice(["terminal", "json", "html"]), default="terminal", show_default=True)
@click.option("--report-path", default=None, help="Output file path for html/json reports.")
@click.option("--severity", default=None, help="Comma list to filter findings, e.g. high,critical.")
@click.option("--config-profile", default=None, help="Use a saved configure profile.")
def scan(provider, profile, region, account_id, stale_after, output_fmt, report_path, severity, config_profile):
    """Full scan: inventory + risk scoring + report."""
    cfg = load_config()
    if config_profile:
        saved = get_profile(config_profile) or {}
        provider = saved.get("provider", provider)
        profile = profile or saved.get("profile")
        region = region or saved.get("region")
        account_id = account_id or saved.get("account_id")
        stale_after = stale_after or saved.get("stale_after")
    if stale_after is None:
        stale_after = cfg.get("stale_after", 90)

    levels = _parse_severity(severity)
    show_progress = output_fmt == "terminal"

    try:
        result = _run_scan(provider, profile, region, account_id, stale_after, True, show_progress)
    except CredentialsMissing as exc:
        _handle_credentials_error(exc)

    if output_fmt == "json":
        if report_path:
            json_reporter.write_json(result, report_path)
            err_console.print(f"[green]JSON written to {report_path}[/]")
        else:
            click.echo(json_reporter.to_json(result))
    elif output_fmt == "html":
        path = report_path or "credghost-report.html"
        html_reporter.write_html(result, path)
        err_console.print(f"[green]HTML report written to {path}[/]")
    else:
        console.print()
        terminal.render_scan(console, result, levels=levels)


@main.command()
@click.option("--stale-after", default=90, type=int, show_default=True)
@click.option("--output", "output_fmt", type=click.Choice(["terminal", "json", "html"]), default="terminal", show_default=True)
@click.option("--report-path", default=None, help="Output file path for html/json reports.")
@click.option("--severity", default=None, help="Comma list to filter findings, e.g. high,critical.")
def demo(stale_after, output_fmt, report_path, severity):
    """Run a full scan against built-in synthetic data — no AWS account needed.

    Great for screenshots, demos, and trying the risk engine offline.
    """
    from credghost.providers.demo import DemoProvider

    levels = _parse_severity(severity)
    result = build_inventory(DemoProvider(), stale_threshold_days=stale_after)

    if output_fmt == "json":
        if report_path:
            json_reporter.write_json(result, report_path)
            err_console.print(f"[green]JSON written to {report_path}[/]")
        else:
            click.echo(json_reporter.to_json(result))
    elif output_fmt == "html":
        path = report_path or "credghost-demo.html"
        html_reporter.write_html(result, path)
        err_console.print(f"[green]HTML report written to {path}[/]")
    else:
        console.print()
        terminal.render_scan(console, result, levels=levels)


@main.command()
@click.option("--provider", default="aws", show_default=True)
@click.option("--profile", default=None)
@click.option("--region", default=None)
@click.option("--account-id", default=None)
def check(provider, profile, region, account_id):
    """Quick health check — 'how bad is my problem' in ~30 seconds."""
    try:
        result = _run_scan(provider, profile, region, account_id, 90, True, False)
    except CredentialsMissing as exc:
        _handle_credentials_error(exc)
    console.print()
    terminal.render_check(console, result)


@main.command()
@click.option("--provider", default="aws", show_default=True)
@click.option("--profile", default=None)
@click.option("--region", default=None)
@click.option("--account-id", default=None)
@click.option("--type", "nhi_type", default=None, help="Filter by NHI type (e.g. iam_role, access_key).")
@click.option("--output", "output_fmt", type=click.Choice(["terminal", "json"]), default="terminal", show_default=True)
def inventory(provider, profile, region, account_id, nhi_type, output_fmt):
    """List what exists — no risk scoring."""
    try:
        result = _run_scan(provider, profile, region, account_id, 90, False, output_fmt == "terminal")
    except CredentialsMissing as exc:
        _handle_credentials_error(exc)

    if nhi_type:
        try:
            wanted = NHIType(nhi_type)
        except ValueError:
            raise click.BadParameter(f"Unknown type '{nhi_type}'")
        result.identities = [i for i in result.identities if i.nhi_type == wanted]
        result.total_nhis = len(result.identities)

    if output_fmt == "json":
        click.echo(json_reporter.to_json(result))
    else:
        console.print()
        terminal.render_inventory(console, result)


@main.command()
@click.option("--input", "input_path", required=True, help="Saved JSON scan to render.")
@click.option("--format", "fmt", type=click.Choice(["html", "json", "pdf"]), default="html", show_default=True)
@click.option("--output", "output_path", default=None, help="Output file path.")
def report(input_path, fmt, output_path):
    """Generate an audit-ready report from a saved JSON scan."""
    try:
        result = json_reporter.load_scan(input_path)
    except (OSError, ValueError) as exc:
        raise click.ClickException(f"Could not read scan file: {exc}")

    if fmt == "html":
        path = output_path or "credghost-report.html"
        html_reporter.write_html(result, path)
        err_console.print(f"[green]HTML report written to {path}[/]")
    elif fmt == "json":
        path = output_path or "credghost-report.json"
        json_reporter.write_json(result, path)
        err_console.print(f"[green]JSON written to {path}[/]")
    else:  # pdf
        path = output_path or "credghost-report.html"
        html_reporter.write_html(result, path)
        err_console.print(
            f"[yellow]PDF export is not bundled in Phase 1.[/] "
            f"Wrote print-ready HTML to {path} — open it and 'Print → Save as PDF'."
        )


@main.command()
@click.option("--provider", default="aws", show_default=True)
@click.option("--profile", default="default", help="AWS credentials profile to save.")
@click.option("--region", default=None)
@click.option("--account-id", default=None)
@click.option("--stale-after", default=90, type=int, show_default=True)
@click.option("--name", default="default", help="Name for this saved configure profile.")
@click.option("--show-policy", is_flag=True, help="Print the required read-only IAM policy and exit.")
def configure(provider, profile, region, account_id, stale_after, name, show_policy):
    """Save provider config, or print the required IAM policy."""
    if show_policy:
        click.echo(policy_json_path().read_text())
        return
    path = set_profile(
        name=name,
        provider=provider,
        profile=profile,
        region=region,
        stale_after=stale_after,
        account_id=account_id,
    )
    err_console.print(
        f"[green]Saved profile '{name}' for provider '{provider}' to {path}[/]"
    )


if __name__ == "__main__":
    main()
