from __future__ import annotations

from app.analyzers.source_sink_analyzer import TraceEvidence


def evaluate_command_injection(evidence: TraceEvidence):
    sink_code = evidence.sink_code.lower()
    assignment = (evidence.assignment_expr or "").lower()

    dangerous = ["os.system", "subprocess.run", "subprocess.call", "subprocess.popen"]
    if not any(item in sink_code for item in dangerous):
        return False, "Command execution sink not detected in sink line"

    if "shell=false" in sink_code:
        return False, "subprocess is invoked without shell, reducing shell injection risk in this pattern"

    if any(var in sink_code or var in assignment for var in evidence.variable_names):
        return True, "User-controlled input reaches a shell command sink, allowing shell metacharacters to alter the command."

    return True, "Potential command injection because a dynamic command reaches a shell-capable sink."
