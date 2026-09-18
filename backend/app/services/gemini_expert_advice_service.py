"""Gemini Flash를 이용해 정적 분석 결과의 일반 보안 조언을 생성한다."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from app.schemas.expert_advice import ExpertAdviceContent, FamilyGuidance

try:
    # 의존성을 아직 설치하지 않은 개발 환경도 기존 정적 분석 API는 계속 동작해야 한다.
    from google import genai
except ImportError:  # pragma: no cover - 설치 여부는 실행 환경에 따라 다르다.
    genai = None

try:
    # requirements 설치 후에는 backend/.env를 자동으로 읽는다. 패키지가 없으면
    # 환경 변수로만 설정해도 동작하도록 아래에서 조용히 건너뛴다.
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - 설치 여부는 실행 환경에 따라 다르다.
    load_dotenv = None


class GeminiAdviceUnavailableError(RuntimeError):
    """API 키 또는 SDK가 없어 조언 기능을 사용할 수 없을 때 발생한다."""


class GeminiAdviceGenerationError(RuntimeError):
    """외부 API 응답을 안전한 조언 구조로 바꾸지 못했을 때 발생한다."""


class GeminiExpertAdviceService:
    """파일 바이트 없이 분류 메타데이터만 Gemini에 전달하는 어댑터다."""

    def __init__(self) -> None:
        if load_dotenv is not None:
            # 이 파일은 backend/app/services 아래에 있으므로 부모 두 단계가 backend다.
            load_dotenv(Path(__file__).resolve().parents[2] / ".env")
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip()
        # 이 기능은 긴 보고서가 아닌 짧은 방어 조언을 생성한다. 그래서 응답 지연과
        # 과부하 가능성이 낮은 Flash Lite 최신 별칭을 기본으로 둔다. 필요하면
        # .env의 GEMINI_MODEL 값으로 상위 Flash 모델을 직접 지정할 수 있다.
        self.model = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest").strip() or "gemini-flash-lite-latest"

    @property
    def configured(self) -> bool:
        """실제 호출 전에 필요한 최소 설정이 모두 있는지 확인한다."""
        return bool(self.api_key) and genai is not None

    def generate(
        self,
        *,
        stage1_result: str | None,
        stage1_confidence: float | None,
        final_status: str,
        guidance: FamilyGuidance,
    ) -> ExpertAdviceContent:
        """Gemini의 구조화 JSON 응답을 검증해 화면에 사용할 조언으로 반환한다."""
        if not self.api_key:
            raise GeminiAdviceUnavailableError("GEMINI_API_KEY가 설정되지 않았습니다.")
        if genai is None:
            raise GeminiAdviceUnavailableError("google-genai 패키지가 설치되지 않았습니다.")

        # 파일명·상대 경로·원본 바이트·추출 문자열은 프롬프트에 포함하지 않는다.
        # 외부 서비스에는 모델의 제한된 결과와 서버 제공 일반 안내만 전달한다.
        context = {
            "stage1_result": stage1_result,
            "stage1_score": round(stage1_confidence, 4) if stage1_confidence is not None else None,
            "final_status": final_status,
            "family_class": guidance.family_class,
            "family_guidance": guidance.model_dump(),
        }
        prompt = (
            "당신은 보안 전문가입니다. 아래는 읽기 전용 정적 분석의 제한된 "
            "분류 메타데이터입니다. 악성코드를 제작·회피·실행하는 방법은 절대 제공하지 마세요. "
            "추측을 사실처럼 말하지 말고, 분석 결과가 확정 판정이 아니라는 점을 유지하세요. "
            "각 목록은 사용자가 바로 확인할 수 있는 방어적 항목 1~3개로 작성하세요.\n\n"
            f"분석 메타데이터: {json.dumps(context, ensure_ascii=False)}"
        )
        try:
            client = genai.Client(api_key=self.api_key)
            # google-genai SDK의 표준 콘텐츠 생성 인터페이스를 사용한다. JSON 스키마를
            # 지정해 자유 형식 문장이 아닌 검증 가능한 응답만 받는다.
            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
                config={
                    "response_mime_type": "application/json",
                    "response_json_schema": ExpertAdviceContent.model_json_schema(),
                },
            )
            output_text = getattr(response, "text", None)
            if not output_text:
                raise GeminiAdviceGenerationError("Gemini가 비어 있는 응답을 반환했습니다.")
            return ExpertAdviceContent.model_validate_json(output_text)
        except GeminiAdviceGenerationError:
            raise
        except Exception as error:
            # 외부 서비스의 자세한 오류(키, 계정 등)는 브라우저로 보내지 않는다.
            raise GeminiAdviceGenerationError("Gemini API 요청 또는 응답 검증에 실패했습니다.") from error
