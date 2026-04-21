from __future__ import annotations

from pathlib import Path

from app.agents.validator_agent import ValidatorAgent
from app.analyzers.source_sink_analyzer import SourceSinkAnalyzer
from app.models.report import AnalysisResult, CodeLocation, Summary, ValidationReport
from app.parsers.findings_parser import load_findings
from app.parsers.python_ast_parser import parse_python_module
from app.utils.file_loader import ProjectFileLoader


class ValidationService:
    def __init__(self) -> None:
        self.validator = ValidatorAgent()

    def run(self, project_root: str, findings_path: str) -> ValidationReport:
        loader = ProjectFileLoader(project_root)
        files = loader.load_python_files()
        modules = {path: parse_python_module(path, code) for path, code in files.items()}
        analyzer = SourceSinkAnalyzer(modules)
        findings = load_findings(findings_path)

        results = []
        for finding in findings.vulnerabilities:
            evidence = analyzer.build_evidence(source_line=finding.source_line, sink_line=finding.sink_line)
            validation = self.validator.validate(finding.type, evidence)
            results.append(
                AnalysisResult(
                    id=finding.id,
                    type=finding.type,
                    message=finding.message,
                    verdict=validation["verdict"],
                    severity=validation["severity"],
                    confidence=validation["confidence"],
                    priority=validation["priority"],
                    source=CodeLocation(
                        file=evidence.source_file,
                        line=evidence.source_line,
                        code=evidence.source_code.strip(),
                    ),
                    sink=CodeLocation(
                        file=evidence.sink_file,
                        line=evidence.sink_line,
                        code=evidence.sink_code.strip(),
                    ),
                    trace=evidence.trace_steps,
                    sanitizers=validation["sanitizers"],
                    assumptions=validation["assumptions"],
                    explanation=validation["explanation"],
                    minimal_counterexample=validation["minimal_counterexample"],
                )
            )

        summary = Summary(
            total=len(results),
            true_positive=sum(1 for x in results if x.verdict == "True Positive"),
            false_positive=sum(1 for x in results if x.verdict == "False Positive"),
        )
        return ValidationReport(project=Path(project_root).name, summary=summary, results=results)
