from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from .common import AnalysisStage, JobState, ResultStatus


class PeValidationResult(BaseModel):
    is_valid: bool
    error_code: str | None = None
    error_reason: str | None = None
    pe_offset: int | None = None
    machine: str | None = None
    bitness: Literal["x86", "x64", "unknown"] = "unknown"


class InferenceResult(BaseModel):
    """Stable adapter contract for the future XGBoost and MalConv2 models."""

    stage1_result: Literal["Normal", "Malware"]
    stage1_confidence: float = Field(ge=0, le=1)
    family_class: str | None = None
    family_confidence: float | None = Field(default=None, ge=0, le=1)
    is_unknown: bool = False
    stage2_executed: bool = False


class AnalysisResultRow(BaseModel):
    index: int
    filename: str
    relative_path: str | None = None
    pe_validation: PeValidationResult
    stage1_result: Literal["Normal", "Malware"] | None = None
    stage1_confidence: float | None = Field(default=None, ge=0, le=1)
    family_class: str | None = None
    family_confidence: float | None = Field(default=None, ge=0, le=1)
    is_unknown: bool = False
    status: ResultStatus
    error_reason: str | None = None


class AnalysisProgress(BaseModel):
    stage: AnalysisStage = AnalysisStage.DISCOVERING
    current_filename: str | None = None
    total_files: int = 0
    valid_pe_files: int = 0
    completed_files: int = 0
    error_files: int = 0


class AnalysisJob(BaseModel):
    job_id: str
    input_kind: Literal["file", "folder"]
    state: JobState
    created_at: datetime
    updated_at: datetime
    progress: AnalysisProgress
    results: list[AnalysisResultRow] = Field(default_factory=list)
    class_counts: dict[str, int] = Field(default_factory=dict)
    cancellation_requested: bool = False
    failure_reason: str | None = None
