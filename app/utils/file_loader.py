from __future__ import annotations

from pathlib import Path
from typing import Dict


class ProjectFileLoader:
    def __init__(self, project_root: str | Path):
        self.project_root = Path(project_root)

    def load_python_files(self) -> Dict[str, str]:
        files: Dict[str, str] = {}
        for path in sorted(self.project_root.rglob("*.py")):
            if path.name.startswith("test_"):
                continue
            files[str(path.relative_to(self.project_root))] = path.read_text(encoding="utf-8")
        return files
