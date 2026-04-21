from __future__ import annotations

from app.analyzers.command_injection_analyzer import evaluate_command_injection
from app.analyzers.sanitizer_detector import detect_sanitizers
from app.analyzers.source_sink_analyzer import TraceEvidence
from app.analyzers.sqli_analyzer import evaluate_sqli
from app.analyzers.ssrf_analyzer import evaluate_ssrf


class ValidatorAgent:
    """Local deterministic validator.

    This class is intentionally designed as the extension point where a real
    LLM-backed agent could be added later.
    """

    def validate(self, vulnerability_type: str, evidence: TraceEvidence) -> dict:
        vuln = vulnerability_type.lower()
        sanitizers = detect_sanitizers(evidence, vulnerability_type)

        if vuln == "sql injection":
            is_tp, explanation = evaluate_sqli(evidence)
            severity = "High" if is_tp else "Info"
            counterexample = (
                "A payload like '\' OR 1=1 --' is treated as data when placeholders are used, so it cannot change the SQL structure."
                if not is_tp else None
            )
        elif vuln == "ssrf":
            is_tp, explanation = evaluate_ssrf(evidence)
            severity = "Medium" if is_tp else "Low"
            counterexample = (
                "The host is fixed to a trusted domain, so the attacker cannot redirect the request to internal hosts or metadata services."
                if not is_tp else None
            )
        elif vuln == "command injection":
            is_tp, explanation = evaluate_command_injection(evidence)
            severity = "Critical" if is_tp else "Low"
            counterexample = None if is_tp else "The command is not passed to a shell-capable sink in an exploitable way."
        else:
            is_tp = False
            explanation = "Unsupported vulnerability type for this validator"
            severity = "Info"
            counterexample = "No rule implemented for this vulnerability type."

        assumptions = [
            "input() and equivalent external input are treated as user-controlled",
            "Parameterized SQL queries are considered safe against classic SQL injection when the query text is not dynamically concatenated",
            "SSRF requires meaningful control over the outbound target, especially the host or full URL",
            "os.system and shell-capable subprocess execution are considered dangerous sinks",
        ]

        return {
            "verdict": "True Positive" if is_tp else "False Positive",
            "severity": severity,
            "confidence": "High",
            "priority": 1 if severity == "Critical" else 2 if severity == "High" else 3 if severity == "Medium" else 4,
            "sanitizers": sanitizers,
            "assumptions": assumptions,
            "explanation": explanation,
            "minimal_counterexample": counterexample,
        }
