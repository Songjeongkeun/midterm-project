"""2차 모델의 예측 클래스에 영향을 준 파일 구간 후보를 계산한다."""

from __future__ import annotations

from collections.abc import Callable

from app.schemas.analysis import EvidenceRegion, PeValidationResult
from app.schemas.common import EvidenceStatus

from .byte_preprocessor import prepare_malconv2_byte_sequence
from .pe_section_service import extract_nearby_strings, select_evidence_candidates


MIN_SCORE_DROP = 0.02
MAX_EVIDENCE_REGIONS = 3


class EvidenceService:
    """12개 후보를 가림 재추론하고 영향도가 큰 상위 3개만 남긴다."""

    def __init__(self, stage2_service) -> None:
        self.stage2 = stage2_service

    def analyze(
        self,
        *,
        file_bytes: bytes,
        validation: PeValidationResult,
        target_class: str,
        baseline_confidence: float,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> tuple[EvidenceStatus, list[EvidenceRegion]]:
        """원본은 보존한 채 후보 구간만 0x00으로 가려 점수 변화를 비교한다."""
        candidates = select_evidence_candidates(file_bytes, validation)
        total = len(candidates)
        if on_progress:
            on_progress(0, total)
        if not candidates:
            return EvidenceStatus.NO_CLEAR_EVIDENCE, []

        regions: list[EvidenceRegion] = []
        for current, candidate in enumerate(candidates, start=1):
            # bytearray는 원본 bytes와 분리된 복사본이다. 실제 업로드 파일과 디스크의
            # 임시 파일 모두 수정하지 않으며, 재추론을 마치면 즉시 버려진다.
            masked = bytearray(file_bytes)
            masked[candidate.offset_start : candidate.offset_end] = b"\x00" * (
                candidate.offset_end - candidate.offset_start
            )
            masked_score = self.stage2.predict_class_confidence(
                prepare_malconv2_byte_sequence(bytes(masked)), target_class
            )
            score_drop = round(baseline_confidence - masked_score, 4)
            if score_drop >= MIN_SCORE_DROP:
                drop_percent = score_drop * 100
                regions.append(
                    EvidenceRegion(
                        offset_start=candidate.offset_start,
                        offset_end=candidate.offset_end - 1,
                        section_name=candidate.section_name,
                        target_class=target_class,
                        baseline_confidence=baseline_confidence,
                        occluded_confidence=masked_score,
                        score_drop=score_drop,
                        nearby_strings=extract_nearby_strings(file_bytes, candidate),
                        observation=(
                            f"해당 구간을 0x00으로 가린 뒤 재추론했을 때 "
                            f"{target_class} 클래스 점수가 {drop_percent:.2f}%p 감소했습니다."
                        ),
                        interpretation=(
                            f"검사한 후보 구간 중 {target_class} 분류에 영향을 준 "
                            "주요 후보 구간입니다."
                        ),
                    )
                )
            if on_progress:
                on_progress(current, total)

        regions.sort(key=lambda region: region.score_drop, reverse=True)
        selected = regions[:MAX_EVIDENCE_REGIONS]
        return (EvidenceStatus.READY if selected else EvidenceStatus.NO_CLEAR_EVIDENCE), selected
