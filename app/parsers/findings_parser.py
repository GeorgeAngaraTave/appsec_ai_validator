from __future__ import annotations

import json
from pathlib import Path

from app.models.finding import FindingsFile


def load_findings(path: str | Path) -> FindingsFile:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return FindingsFile.model_validate(payload)
