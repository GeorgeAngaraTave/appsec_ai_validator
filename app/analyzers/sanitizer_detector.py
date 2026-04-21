from __future__ import annotations

from typing import List

from app.analyzers.source_sink_analyzer import TraceEvidence


KNOWN_SANITIZERS = [
    "parameterized query",
    "allowlist",
    "shlex.quote",
    "urllib.parse.quote",
    "validators",
]


def detect_sanitizers(evidence: TraceEvidence, vulnerability_type: str) -> List[str]:
    findings: List[str] = []
    assignment = (evidence.assignment_expr or "").lower()
    sink_code = evidence.sink_code.lower()

    if vulnerability_type.lower() == "sql injection":
        query_text = evidence.sink_args[0] if evidence.sink_args else ""
        if ("?" in sink_code or "?" in query_text) and len(evidence.sink_args) > 1:
            findings.append("Parameterized SQL query with placeholders")
    if vulnerability_type.lower() == "command injection":
        if "shlex.quote" in assignment or "shlex.quote" in sink_code:
            findings.append("Shell escaping via shlex.quote")
    if vulnerability_type.lower() == "ssrf":
        if "allowlist" in assignment or "allowlist" in sink_code:
            findings.append("Destination allowlist")
    return findings
