"""악성 유형 안내와 Gemini 전문가 조언 API의 입출력 형식이다."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class ExpertAdviceStatus(StrEnum):
    """AI 조언 요청의 처리 상태다."""

    READY = "ready"
    CACHED = "cached"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class FamilyGuidance(BaseModel):
    """서버가 관리하는 악성 유형별 기본 대응 안내다."""

    family_class: str | None = None
    title: str
    description: str
    recommended_actions: list[str] = Field(min_length=1, max_length=4)
    disclaimer: str


class FamilyGuidanceResponse(BaseModel):
    """정적 분류 결과에 맞는 유형 안내 조회 응답이다."""

    status: Literal["ready", "not_available"]
    guidance: FamilyGuidance | None = None
    reason: str | None = None


class ExpertAdviceRequest(BaseModel):
    """같은 파일의 캐시된 조언을 새로 만들지 여부를 받는다."""

    refresh: bool = False


class ExpertAdviceContent(BaseModel):
    """Gemini가 JSON으로 반환해야 하는 짧고 안전한 조언 구조다."""

    summary: str = Field(min_length=1, max_length=280)
    immediate_checks: list[str] = Field(min_length=1, max_length=3)
    prevention_tips: list[str] = Field(min_length=1, max_length=3)
    response_if_executed: list[str] = Field(min_length=1, max_length=3)
    disclaimer: str = Field(min_length=1, max_length=280)


class ExpertAdviceResponse(BaseModel):
    """Gemini 생성 결과와 서버의 유형 안내를 함께 반환한다."""

    status: ExpertAdviceStatus
    source: Literal["generated", "cached"] | None = None
    provider: str | None = None
    model: str | None = None
    guidance: FamilyGuidance
    advice: ExpertAdviceContent | None = None
    reason: str | None = None
