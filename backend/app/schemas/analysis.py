from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from .common import AnalysisStage, EvidenceStatus, JobState, ResultStatus


class PeValidationResult(BaseModel):
    """Structural PE-header result; validity does not imply that a file is safe."""
    is_valid: bool
    error_code: str | None = None
    error_reason: str | None = None
    pe_offset: int | None = None
    machine: str | None = None
    bitness: Literal["x86", "x64", "unknown"] = "unknown"


class InferenceResult(BaseModel):
    """Stable interface shared by mock and future real model adapters.

    Scores are constrained to the 0--1 model-output range, but their meaning
    depends on calibration.  They must never be presented as a safety guarantee.
    """

    stage1_result: Literal["Normal", "Suspicious", "Malware"]
    stage1_confidence: float = Field(ge=0, le=1)
    family_class: str | None = None
    family_confidence: float | None = Field(default=None, ge=0, le=1)
    is_unknown: bool = False
    stage2_executed: bool = False


class EvidenceRegion(BaseModel):
    """가림 재추론으로 확인한 모델 판단 근거 후보 구간이다.

    위치는 메모리 주소(RVA)가 아닌, 업로드 원본 안의 파일 오프셋이다.
    점수는 특정 악성 클래스의 모델 출력 변화이며 악성 행위의 확정 증거는 아니다.
    """
    offset_start: int = Field(ge=0)
    offset_end: int = Field(ge=0)
    section_name: str | None = None
    target_class: str
    baseline_confidence: float = Field(ge=0, le=1)
    occluded_confidence: float = Field(ge=0, le=1)
    score_drop: float
    nearby_strings: list[str] = Field(default_factory=list)
    observation: str
    interpretation: str


class AnalysisResultRow(BaseModel):
    """One input file's final row, retained in original upload/discovery order."""
    index: int
    filename: str
    relative_path: str | None = None
    pe_validation: PeValidationResult
    stage1_result: Literal["Normal", "Suspicious", "Malware"] | None = None
    stage1_confidence: float | None = Field(default=None, ge=0, le=1)
    family_class: str | None = None
    family_confidence: float | None = Field(default=None, ge=0, le=1)
    is_unknown: bool = False
    status: ResultStatus
    evidence_status: EvidenceStatus = EvidenceStatus.NOT_APPLICABLE
    evidence_regions: list[EvidenceRegion] = Field(default_factory=list)
    evidence_error_reason: str | None = None
    error_reason: str | None = None


class AnalysisProgress(BaseModel):
    """Counters and the currently visible pipeline step for one job."""
    stage: AnalysisStage = AnalysisStage.DISCOVERING
    current_filename: str | None = None
    total_files: int = 0
    valid_pe_files: int = 0
    completed_files: int = 0
    error_files: int = 0
    evidence_current: int = 0
    evidence_total: int = 0


class AnalysisJob(BaseModel):
    """Transient job sent to the React client through polling/SSE snapshots."""
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
