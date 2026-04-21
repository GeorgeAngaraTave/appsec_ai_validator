from __future__ import annotations

from app.analyzers.source_sink_analyzer import TraceEvidence


def evaluate_sqli(evidence: TraceEvidence):
    sink_code = evidence.sink_code.lower()
    assignment = (evidence.assignment_expr or "").lower()

    if "execute" not in sink_code:
        return False, "SQL sink not detected in sink line"

    query_text = evidence.sink_args[0] if evidence.sink_args else ""
    if ("?" in sink_code or "?" in query_text) and len(evidence.sink_args) > 1:
        return False, "The SQL call uses placeholders and passes user input as parameters, which prevents changing the SQL structure."

    if any(token in assignment for token in ["f\"", "f'", ".format(", "%s", "%("]):
        return True, "The query is dynamically constructed from user-controlled input before execution."

    if evidence.sink_args:
        first_arg = evidence.sink_args[0]
        if first_arg in evidence.variable_names and len(evidence.sink_args) == 1:
            return True, "A user-controlled variable reaches execute() without evidence of parameterization."

    if assignment:
        return True, "The SQL query assigned to the sink argument appears dynamically composed and unparameterized."

    return True, "Potential SQL injection because execute() receives data influenced by user input without strong sanitization evidence."
