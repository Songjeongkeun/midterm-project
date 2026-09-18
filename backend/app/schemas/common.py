from __future__ import annotations

from enum import StrEnum


class JobState(StrEnum):
    """개별 파일 진행 단계와 별개인 분석 요청 전체의 생명주기 상태다."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class AnalysisStage(StrEnum):
    """작업이 실행 중일 때 화면에 표시할 가장 최근 파이프라인 단계다."""
    DISCOVERING = "discovering"
    VALIDATING_PE = "validating_pe"
    PREPARING_SEQUENCE = "preparing_sequence"
    CLASSIFYING_STAGE1 = "classifying_stage1"
    CLASSIFYING_STAGE2 = "classifying_stage2"
    EXPLAINING_EVIDENCE = "explaining_evidence"
    COMPLETED = "completed"


class ResultStatus(StrEnum):
    """서버의 1·2차 모델 정책으로 계산한 최종 분석 상태다.

    ``UNSUPPORTED``는 입력이 PE 전용 서비스 범위 밖이라는 뜻이다.
    ``ERROR``는 PE로 보였지만 검증·읽기·추론을 안정적으로 끝내지 못한 경우다.
    """
    NORMAL = "normal"
    MALWARE_SUSPECTED = "malware_suspected"
    CONFLICT = "conflict"
    UNCERTAIN = "uncertain"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class EvidenceStatus(StrEnum):
    """악성 유형 의심 파일의 모델 판단 근거 생성 상태다."""
    NOT_APPLICABLE = "not_applicable"
    ANALYZING = "analyzing"
    READY = "ready"
    NO_CLEAR_EVIDENCE = "no_clear_evidence"
    FAILED = "failed"
