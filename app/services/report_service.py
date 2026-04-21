from __future__ import annotations

import json
from pathlib import Path
from jinja2 import Template

from app.models.report import ValidationReport


HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AI AppSec Validator Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 32px; color: #222; }
    h1, h2 { color: #0f172a; }
    .card { border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    .tp { border-left: 6px solid #b91c1c; }
    .fp { border-left: 6px solid #15803d; }
    code { background: #f5f5f5; padding: 2px 4px; border-radius: 4px; }
    ul { margin-top: 8px; }
  </style>
</head>
<body>
  <h1>AI AppSec Validator Report</h1>
  <p><strong>Project:</strong> {{ report.project }}</p>
  <p><strong>Summary:</strong> Total {{ report.summary.total }} | TP {{ report.summary.true_positive }} | FP {{ report.summary.false_positive }}</p>
  {% for item in report.results %}
    <div class="card {{ 'tp' if item.verdict == 'True Positive' else 'fp' }}">
      <h2>{{ item.id }} — {{ item.type }}</h2>
      <p><strong>Verdict:</strong> {{ item.verdict }} | <strong>Severity:</strong> {{ item.severity }} | <strong>Priority:</strong> {{ item.priority }}</p>
      <p><strong>Message:</strong> {{ item.message }}</p>
      <p><strong>Source:</strong> {{ item.source.file }}:{{ item.source.line }} — <code>{{ item.source.code }}</code></p>
      <p><strong>Sink:</strong> {{ item.sink.file }}:{{ item.sink.line }} — <code>{{ item.sink.code }}</code></p>
      <p><strong>Explanation:</strong> {{ item.explanation }}</p>
      <p><strong>Sanitizers:</strong> {{ item.sanitizers | join(', ') if item.sanitizers else 'None' }}</p>
      {% if item.minimal_counterexample %}
      <p><strong>Minimal counterexample:</strong> {{ item.minimal_counterexample }}</p>
      {% endif %}
      <strong>Trace:</strong>
      <ul>{% for step in item.trace %}<li>{{ step }}</li>{% endfor %}</ul>
      <strong>Assumptions:</strong>
      <ul>{% for a in item.assumptions %}<li>{{ a }}</li>{% endfor %}</ul>
    </div>
  {% endfor %}
</body>
</html>
"""


class ReportService:
    def write(self, report: ValidationReport, output_dir: str | Path) -> tuple[Path, Path]:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        json_path = out / "report.json"
        html_path = out / "report.html"

        json_path.write_text(json.dumps(report.model_dump(), indent=2), encoding="utf-8")
        html = Template(HTML_TEMPLATE).render(report=report.model_dump())
        html_path.write_text(html, encoding="utf-8")
        return json_path, html_path
