"""모델 결과와 분리해 관리하는 악성 유형별 기본 안내다."""

from __future__ import annotations

from app.schemas.expert_advice import FamilyGuidance


DEFAULT_DISCLAIMER = "이 안내는 정적 모델의 분류 결과를 바탕으로 한 일반적인 대응 정보이며, 감염 또는 악성을 확정하지 않습니다."


def _guidance(title: str, description: str, actions: list[str], family_class: str | None) -> FamilyGuidance:
    """반복되는 공통 문구를 한 곳에서 붙여 일관된 응답을 만든다."""
    return FamilyGuidance(
        family_class=family_class,
        title=title,
        description=description,
        recommended_actions=actions,
        disclaimer=DEFAULT_DISCLAIMER,
    )


def get_family_guidance(family_class: str | None, final_status: str) -> FamilyGuidance:
    """2차 최고 클래스와 최종 상태에 알맞은 읽기 전용 안내를 반환한다.

    이 함수는 외부 API를 호출하지 않는다. 따라서 Gemini 키가 없거나 네트워크가
    불안정해도 '악성 유형 안내' 탭은 항상 일관된 내용을 보여줄 수 있다.
    """
    normalized = (family_class or "").strip().lower()

    if final_status == "conflict" or normalized == "benign":
        return _guidance(
            "판정 충돌 안내",
            "1차 모델은 위험 신호를 보았지만 2차 모델의 최고 클래스는 benign입니다. 두 모델의 기준이 일치하지 않아 추가 확인이 필요합니다.",
            ["신뢰할 수 있는 백신 또는 EDR로 파일을 추가 검사합니다.", "파일의 출처·서명·해시를 확인하고 알 수 없는 경우 실행하지 않습니다.", "업무 환경이라면 보안 담당자에게 검토를 요청합니다."],
            family_class,
        )
    if final_status == "uncertain" or not normalized or normalized == "unknown":
        return _guidance(
            "분류 불확실 안내",
            "2차 모델이 특정 악성 유형을 충분한 점수로 특정하지 못했습니다. 안전하다는 뜻은 아니므로 출처와 실행 이력을 함께 확인해야 합니다.",
            ["알 수 없는 파일은 격리된 환경 외에서는 실행하지 않습니다.", "신뢰할 수 있는 보안 도구로 추가 검사합니다.", "파일의 다운로드 출처와 디지털 서명을 확인합니다."],
            family_class,
        )

    guidance_by_family = {
        "trojan": (
            "Trojan 유형 안내",
            "정상 프로그램처럼 위장해 사용자의 실행을 유도할 수 있는 유형입니다.",
            ["파일의 출처와 전자서명을 확인하고 신뢰되지 않으면 실행하지 않습니다.", "동일 파일이 배포된 경로와 계정을 보안 담당자에게 알립니다.", "신뢰할 수 있는 백신으로 전체 검사를 수행합니다."],
        ),
        "ransomware": (
            "Ransomware 유형 안내",
            "파일 암호화와 금전 요구로 이어질 수 있는 유형으로 분류되었습니다.",
            ["파일을 실행하지 말고 관련 장치의 네트워크 연결을 분리합니다.", "백업본의 무결성을 별도 환경에서 확인합니다.", "조직 환경에서는 즉시 보안 담당자와 사고 대응 절차에 알립니다."],
        ),
        "worm": (
            "Worm 유형 안내",
            "네트워크나 이동식 저장장치를 통해 확산을 시도할 수 있는 유형입니다.",
            ["파일을 실행하지 말고 공유 폴더와 이동식 저장장치 연결을 점검합니다.", "운영체제와 보안 제품의 최신 업데이트 상태를 확인합니다.", "같은 네트워크 장치에서 유사 파일이 있는지 보안 담당자에게 확인합니다."],
        ),
        "spyware": (
            "Spyware 유형 안내",
            "사용자 정보나 활동을 수집할 가능성이 있는 유형으로 분류되었습니다.",
            ["저장된 비밀번호와 민감 정보가 노출되지 않았는지 점검합니다.", "브라우저 확장 프로그램과 시작 프로그램을 확인합니다.", "의심 파일을 실행했다면 안전한 다른 장치에서 중요 계정 비밀번호를 변경합니다."],
        ),
        "adware": (
            "Adware 유형 안내",
            "원치 않는 광고 표시 또는 브라우저 설정 변경과 연관될 수 있는 유형입니다.",
            ["출처가 불분명한 설치 파일은 실행하지 않습니다.", "브라우저 확장 프로그램과 설치 프로그램 목록을 점검합니다.", "신뢰할 수 있는 보안 도구로 추가 검사합니다."],
        ),
    }
    title, description, actions = guidance_by_family.get(
        normalized,
        (
            "악성 유형 의심 안내",
            f"2차 모델이 '{family_class}' 유형으로 분류했습니다. 모델 분류는 참고 정보이므로 추가 보안 검증이 필요합니다.",
            ["파일을 실행하지 말고 출처와 디지털 서명을 확인합니다.", "신뢰할 수 있는 백신 또는 EDR로 추가 검사합니다.", "조직 환경이라면 보안 담당자에게 파일 정보와 검사 결과를 전달합니다."],
        ),
    )
    return _guidance(title, description, actions, family_class)
