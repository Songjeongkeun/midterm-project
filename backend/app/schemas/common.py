from __future__ import annotations

from enum import StrEnum


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class AnalysisStage(StrEnum):
    DISCOVERING = "discovering"
    VALIDATING_PE = "validating_pe"
    PREPARING_SEQUENCE = "preparing_sequence"
    CLASSIFYING_STAGE1 = "classifying_stage1"
    CLASSIFYING_STAGE2 = "classifying_stage2"
    COMPLETED = "completed"


class ResultStatus(StrEnum):
    REVIEW_REQUIRED = "review_required"
    UNSUPPORTED_ERROR = "unsupported_error"
