from __future__ import annotations

import sys
from datetime import date

import click

from tool_scan.baseline import Baseline
from tool_scan.config import ConfigError, load_config
from tool_scan.engine import collect_all, run_scan
from tool_scan.findings import SEVERITY_ORDER, Severity
from tool_scan.reporters.json_reporter import JsonReporter
from tool_scan.reporters.sarif import SarifReporter
from tool_scan.reporters.terminal import TerminalReporter

_REPORTERS = {
    "terminal": TerminalReporter(),
    "json": JsonReporter(),
    "sarif": SarifReporter(),
}


@click.group()
def main() -> None:
    """MCP tool-poisoning scanner."""


@main.command()
@click.option("--config", "config_path", default="./tool-scan.config.yaml", show_default=True)
@click.option("--update-baseline", is_flag=True, default=False)
def scan(config_path: str, update_baseline: bool) -> None:
    """Run a scan against the declared sources and detectors."""
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        click.echo(f"Config error: {exc}", err=True)
        sys.exit(2)

    baseline = Baseline.load(config.baseline.file)

    if update_baseline:
        tools = collect_all(config)
        for tool in tools:
            baseline.approve(
                tool.id,
                tool.content_hash,
                reviewer_note="approved via --update-baseline",
                approved_date=date.today().isoformat(),
            )
        baseline.save(config.baseline.file)
        click.echo(f"Baseline updated with {len(tools)} tool(s).")
        sys.exit(0)

    findings = run_scan(config, baseline=baseline)

    min_shown = Severity(config.report.min_severity_shown)
    shown = [f for f in findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[min_shown]]

    for fmt in config.report.formats:
        reporter = _REPORTERS.get(fmt)
        if reporter is None:
            continue
        output = reporter.render(shown)
        if fmt == "terminal":
            click.echo(output)
        elif fmt == "json":
            with open(config.report.json.output_path, "w") as fh:
                fh.write(output)
        elif fmt == "sarif":
            with open(config.report.sarif.output_path, "w") as fh:
                fh.write(output)

    fail_threshold = Severity(config.report.fail_on_severity)
    if any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[fail_threshold] for f in findings):
        sys.exit(1)
    sys.exit(0)
