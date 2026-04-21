from __future__ import annotations

from urllib.parse import urlparse

from app.analyzers.source_sink_analyzer import TraceEvidence


def evaluate_ssrf(evidence: TraceEvidence):
    sink_code = evidence.sink_code
    text = evidence.assignment_expr or sink_code

    if "requests.get" not in sink_code and "requests.post" not in sink_code:
        return False, "HTTP client sink not detected in sink line"

    lowered = text.lower()
    if "http://" in lowered or "https://" in lowered:
        start = lowered.find("http")
        end = lowered.find("/", start + 8)
        candidate = lowered[start:] if end == -1 else lowered[start:end]
        parsed = urlparse(candidate)
        host = parsed.netloc
        if host and host not in {"", "{username}", "{}"}:
            return False, "The destination host is fixed; the user only influences the path segment, which does not match classic SSRF exploitable control over the target host."

    if any(var in text for var in evidence.variable_names):
        return True, "User-controlled data appears to influence the outbound request target without a fixed trusted destination."

    return False, "No exploitable user control over the remote target could be confirmed."
