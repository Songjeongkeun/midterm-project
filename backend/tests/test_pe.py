import asyncio
from io import BytesIO

from fastapi import UploadFile

from app.schemas.common import ResultStatus
from app.schemas.expert_advice import ExpertAdviceContent
from app.services.analysis_service import AnalysisManager
from app.services.byte_preprocessor import prepare_raw_byte_sequence
from app.services.evidence_service import EvidenceService
from app.services.pe_section_service import select_evidence_candidates
from app.services.pe_validator import validate_pe
from app.services.stage1_xgboost_service import Stage1Prediction


def valid_pe() -> bytes:
    data = bytearray(0x100)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x8664).to_bytes(2, "little")
    return bytes(data)


def pe_with_sections() -> bytes:
    """근거 후보 테스트용으로만 쓰는 실행 불가능한 PE 바이트를 만든다."""
    data = bytearray(0x2400)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    data[coff : coff + 2] = (0x8664).to_bytes(2, "little")
    data[coff + 2 : coff + 4] = (3).to_bytes(2, "little")
    data[coff + 16 : coff + 18] = (0xE0).to_bytes(2, "little")
    section_table = coff + 20 + 0xE0

    for index, (name, raw_start, raw_size) in enumerate(
        ((b".text", 0x400, 0x800), (b".rdata", 0xC00, 0x400), (b".weird", 0x1000, 0x400))
    ):
        offset = section_table + (index * 40)
        data[offset : offset + 8] = name.ljust(8, b"\x00")
        data[offset + 16 : offset + 20] = raw_size.to_bytes(4, "little")
        data[offset + 20 : offset + 24] = raw_start.to_bytes(4, "little")

    data[0x400:0xC00] = b"A" * 0x800
    string_block = b"config-value\x00"
    data[0xC00:0x1000] = (string_block * ((0x400 + len(string_block) - 1) // len(string_block)))[:0x400]
    data[0x1000:0x1400] = b"B" * 0x400
    return bytes(data)


def test_accepts_minimally_valid_pe() -> None:
    result = validate_pe(valid_pe())
    assert result.is_valid is True
    assert result.machine == "AMD64"


def test_rejects_extension_like_non_pe_bytes() -> None:
    result = validate_pe(b"not-a-pe-file" * 10)
    assert result.is_valid is False
    assert result.error_code == "NOT_MZ"
    assert result.error_reason == "PE 파일이 아닙니다."


def test_rejects_out_of_range_pe_offset() -> None:
    data = bytearray(0x80)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0xFFFF).to_bytes(4, "little")
    assert validate_pe(bytes(data)).is_valid is False


def test_byte_sequence_keeps_fixed_length_and_zero_padding() -> None:
    prepared = prepare_raw_byte_sequence(b"\x01\x02\x03", max_length=5)
    assert prepared.values == b"\x01\x02\x03\x00\x00"
    assert prepared.original_length == 3


def test_manager_analyzes_a_valid_pe_without_executing_it() -> None:
    """Exercise upload storage, validation and mock stages with synthetic bytes."""

    async def scenario() -> None:
        class FixedStage1:
            """Keep this orchestration test independent from external model weights."""

            def analyze_file(self, _file_path):
                return Stage1Prediction("Normal", 0.02, False)

        manager = AnalysisManager(stage1_service=FixedStage1())
        upload = UploadFile(file=BytesIO(valid_pe()), filename="sample.exe")
        job = await manager.create_job(
            input_kind="file",
            uploads=[upload],
            relative_paths=["sample.exe"],
        )
        # The mock worker uses a thread. Yield briefly until it stores the row.
        for _ in range(20):
            current = manager.snapshot(job.job_id)
            if current.state.value in {"completed", "failed"}:
                break
            await asyncio.sleep(0.01)

        current = manager.snapshot(job.job_id)
        assert current.state.value == "completed"
        assert current.progress.completed_files == 1
        assert current.results[0].pe_validation.is_valid is True
        assert current.results[0].status.value == "normal"

    asyncio.run(scenario())


def test_manager_separates_unsupported_file_from_broken_pe_error() -> None:
    """Non-PE inputs are unsupported; an MZ file with invalid PE data is an error."""

    async def analyze(content: bytes, filename: str) -> str:
        # The stage-1 service is never called because both inputs fail validation.
        manager = AnalysisManager(stage1_service=object())
        upload = UploadFile(file=BytesIO(content), filename=filename)
        job = await manager.create_job(
            input_kind="file",
            uploads=[upload],
            relative_paths=[filename],
        )
        for _ in range(20):
            current = manager.snapshot(job.job_id)
            if current.state.value in {"completed", "failed"}:
                break
            await asyncio.sleep(0.01)
        return manager.snapshot(job.job_id).results[0].status.value

    malformed_pe = bytearray(0x80)
    malformed_pe[:2] = b"MZ"
    malformed_pe[0x3C:0x40] = (0xFFFF).to_bytes(4, "little")

    assert asyncio.run(analyze(b"ordinary text", "note.txt")) == "unsupported"
    assert asyncio.run(analyze(bytes(malformed_pe), "broken.exe")) == "error"


def test_final_status_combines_stage1_and_stage2_results() -> None:
    """The API, not only the React UI, owns the two-stage status policy."""
    assert AnalysisManager._final_status("Normal", None, False) == ResultStatus.NORMAL
    assert AnalysisManager._final_status("Malware", "trojan", False) == ResultStatus.MALWARE_SUSPECTED
    assert AnalysisManager._final_status("Suspicious", "benign", False) == ResultStatus.CONFLICT
    assert AnalysisManager._final_status("Suspicious", "Unknown", True) == ResultStatus.UNCERTAIN


def test_evidence_candidates_are_bounded_unique_and_inside_the_file() -> None:
    content = pe_with_sections()
    candidates = select_evidence_candidates(content, validate_pe(content))

    assert len(candidates) == 12
    assert len({candidate.offset_start for candidate in candidates}) == len(candidates)
    assert any(candidate.section_name == ".text" for candidate in candidates)
    assert all(0 <= candidate.offset_start < candidate.offset_end <= len(content) for candidate in candidates)


def test_evidence_service_keeps_original_bytes_and_returns_at_most_three_regions() -> None:
    class FixedStage2:
        """가림 위치에 따라 결정적인 점수 변화를 반환하는 가짜 2차 모델이다."""

        def predict_class_confidence(self, sequence, _target_class):
            # .text 첫 후보가 가려지면 가장 큰 점수 하락을 만들도록 한다.
            if sequence.values[0x400] == 0:
                return 0.50
            if sequence.values[0xC00] == 0:
                return 0.70
            return 0.88

    content = pe_with_sections()
    original = bytes(content)
    status, regions = EvidenceService(FixedStage2()).analyze(
        file_bytes=content,
        validation=validate_pe(content),
        target_class="trojan",
        baseline_confidence=0.90,
    )

    assert status.value == "ready"
    assert 1 <= len(regions) <= 3
    assert regions == sorted(regions, key=lambda region: region.score_drop, reverse=True)
    assert content == original


def test_manager_keeps_evidence_disabled_for_malware_suspected_result() -> None:
    """후보 구간 검색을 비활성화해도 1·2차 분류 결과는 정상 완료되는지 확인한다."""

    async def scenario() -> None:
        class MalwareStage1:
            def analyze_file(self, _file_path):
                return Stage1Prediction("Malware", 0.95, True)

        class MalwareStage2:
            def predict_stage2(self, _sequence):
                return "trojan", 0.90, False

            def predict_class_confidence(self, sequence, _target_class):
                return 0.50 if sequence.values[0x400] == 0 else 0.88

        content = pe_with_sections()
        manager = AnalysisManager(stage1_service=MalwareStage1(), stage2_service=MalwareStage2())
        upload = UploadFile(file=BytesIO(content), filename="suspected.exe")
        job = await manager.create_job(
            input_kind="file",
            uploads=[upload],
            relative_paths=["suspected.exe"],
        )
        for _ in range(50):
            current = manager.snapshot(job.job_id)
            if current.state.value in {"completed", "failed"}:
                break
            await asyncio.sleep(0.01)

        row = manager.snapshot(job.job_id).results[0]
        assert row.status.value == "malware_suspected"
        assert row.evidence_status.value == "not_applicable"
        assert row.evidence_regions == []

    asyncio.run(scenario())


def test_expert_advice_uses_cached_result_without_sending_file_bytes() -> None:
    """Gemini 어댑터에는 분석 결과만 전달하고, 두 번째 요청은 캐시를 쓴다."""

    class FixedAdviceService:
        model = "test-gemini"

        def __init__(self):
            self.calls = 0

        def generate(self, **_kwargs):
            self.calls += 1
            return ExpertAdviceContent(
                summary="테스트 조언입니다.",
                immediate_checks=["출처를 확인합니다."],
                prevention_tips=["신뢰할 수 있는 보안 도구를 사용합니다."],
                response_if_executed=["네트워크 연결을 분리합니다."],
                disclaimer="정적 분석 결과는 확정 판정이 아닙니다.",
            )

    async def scenario() -> None:
        class MalwareStage1:
            def analyze_file(self, _file_path):
                return Stage1Prediction("Malware", 0.95, True)

        class MalwareStage2:
            def predict_stage2(self, _sequence):
                return "trojan", 0.90, False

        advice_service = FixedAdviceService()
        manager = AnalysisManager(
            stage1_service=MalwareStage1(),
            stage2_service=MalwareStage2(),
            expert_advice_service=advice_service,
        )
        upload = UploadFile(file=BytesIO(valid_pe()), filename="suspected.exe")
        job = await manager.create_job(
            input_kind="file",
            uploads=[upload],
            relative_paths=["suspected.exe"],
        )
        for _ in range(20):
            current = manager.snapshot(job.job_id)
            if current.state.value in {"completed", "failed"}:
                break
            await asyncio.sleep(0.01)

        guidance = manager.family_guidance(job.job_id, 0)
        first = manager.expert_advice(job.job_id, 0)
        second = manager.expert_advice(job.job_id, 0)
        assert guidance.status == "ready"
        assert guidance.guidance is not None
        assert first.status == "ready"
        assert second.status == "cached"
        assert advice_service.calls == 1

    asyncio.run(scenario())


def test_nan_stage2_score_returns_safe_user_message() -> None:
    """모델의 NaN 출력은 내부 검증 오류를 노출하지 않고 안전하게 처리한다."""

    async def scenario() -> None:
        class MalwareStage1:
            def analyze_file(self, _file_path):
                return Stage1Prediction("Malware", 0.95, True)

        class InvalidScoreStage2:
            def predict_stage2(self, _sequence):
                return "trojan", float("nan"), False

        manager = AnalysisManager(
            stage1_service=MalwareStage1(),
            stage2_service=InvalidScoreStage2(),
        )
        upload = UploadFile(file=BytesIO(valid_pe()), filename="invalid-score.exe")
        job = await manager.create_job(
            input_kind="file",
            uploads=[upload],
            relative_paths=["invalid-score.exe"],
        )
        for _ in range(20):
            current = manager.snapshot(job.job_id)
            if current.state.value in {"completed", "failed"}:
                break
            await asyncio.sleep(0.01)

        row = manager.snapshot(job.job_id).results[0]
        assert row.status.value == "error"
        assert row.error_reason == "2차 모델 분석을 완료하지 못했습니다. 잠시 후 다시 시도하세요."
        assert "nan" not in row.error_reason.lower()

    asyncio.run(scenario())
