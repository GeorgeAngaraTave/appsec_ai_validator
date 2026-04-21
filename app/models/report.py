from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class CodeLocation(BaseModel):
    file: str
    line: int
    code: str = ""


class AnalysisResult(BaseModel):
    id: str
    type: str
    message: str
    verdict: str
    severity: str
    confidence: str
    priority: int
    source: CodeLocation
    sink: CodeLocation
    trace: List[str] = Field(default_factory=list)
    sanitizers: List[str] = Field(default_factory=list)
    assumptions: List[str] = Field(default_factory=list)
    explanation: str
    minimal_counterexample: Optional[str] = None


class Summary(BaseModel):
    total: int
    true_positive: int
    false_positive: int


class ValidationReport(BaseModel):
    project: str
    summary: Summary
    results: List[AnalysisResult]
