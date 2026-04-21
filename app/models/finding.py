from __future__ import annotations

from typing import List
from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str
    type: str
    sink_line: int
    source_line: int
    message: str


class FindingsFile(BaseModel):
    vulnerabilities: List[Finding] = Field(default_factory=list)
