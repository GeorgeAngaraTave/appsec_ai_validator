from __future__ import annotations

from pathlib import Path
import typer

from app.services.report_service import ReportService
from app.services.validation_service import ValidationService

app = typer.Typer(help="AI-assisted static validator for Python security findings")


@app.callback()
def main() -> None:
    """CLI entrypoint."""
    return None


@app.command()
def validate(
    project: str = typer.Option(..., help="Path to the Python project to analyze"),
    findings: str = typer.Option(..., help="Path to findings.json"),
    output: str = typer.Option("reports", help="Output directory for JSON and HTML report"),
) -> None:
    service = ValidationService()
    report = service.run(project_root=project, findings_path=findings)
    report_service = ReportService()
    json_path, html_path = report_service.write(report, output)

    typer.echo(f"Validation finished for project: {report.project}")
    typer.echo(f"Total findings: {report.summary.total}")
    typer.echo(f"True Positive: {report.summary.true_positive}")
    typer.echo(f"False Positive: {report.summary.false_positive}")
    typer.echo(f"JSON report: {Path(json_path).resolve()}")
    typer.echo(f"HTML report: {Path(html_path).resolve()}")
