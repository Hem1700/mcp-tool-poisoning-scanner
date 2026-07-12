from __future__ import annotations

import sys

import click

from tool_scan.config import ConfigError, load_config
from tool_scan.engine import run_scan
from tool_scan.findings import SEVERITY_ORDER, Severity
from tool_scan.reporters.json_reporter import JsonReporter
from tool_scan.reporters.terminal import TerminalReporter

_REPORTERS = {
    "terminal": TerminalReporter(),
    "json": JsonReporter(),
}


@click.group()
def main() -> None:
    """MCP tool-poisoning scanner."""


@main.command()
@click.option("--config", "config_path", default="./tool-scan.config.yaml", show_default=True)
def scan(config_path: str) -> None:
    """Run a scan against the declared sources and detectors."""
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        click.echo(f"Config error: {exc}", err=True)
        sys.exit(2)

    findings = run_scan(config)

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

    fail_threshold = Severity(config.report.fail_on_severity)
    if any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[fail_threshold] for f in findings):
        sys.exit(1)
    sys.exit(0)
