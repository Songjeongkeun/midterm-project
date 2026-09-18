from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from uuid import uuid4

from fastapi import UploadFile

from app.schemas.analysis import AnalysisJob, AnalysisProgress, AnalysisResultRow, PeValidationResult
from app.schemas.expert_advice import (
    ExpertAdviceResponse,
    ExpertAdviceStatus,
    FamilyGuidanceResponse,
)
from app.schemas.common import AnalysisStage, EvidenceStatus, JobState, ResultStatus
from app.storage.job_store import JobNotFoundError, JobStore

from .byte_preprocessor import prepare_malconv2_byte_sequence
# 후보 구간 가림 재추론 기능은 현재 성능·검증 기준을 정리하는 동안 잠시
# 비활성화한다. 다시 사용하려면 아래 import와 _process_one의 주석 블록을
# 함께 복원한다.
# from .evidence_service import EvidenceService
from .family_guidance_service import get_family_guidance
from .gemini_expert_advice_service import (
    GeminiAdviceGenerationError,
    GeminiAdviceUnavailableError,
    GeminiExpertAdviceService,
)
from .pe_validator import validate_pe
from .stage1_xgboost_service import Stage1ModelLoadError, Stage1XGBoostService
from .stage2_malconv2_service import Stage2MalConvService, Stage2ModelLoadError


logger = logging.getLogger(__name__)


# 업로드 스트리밍 중에 크기를 제한해, 사용자가 고른 파일이 디스크나 메모리를
# 과도하게 차지하기 전에 막는다. 이는 PE 형식 제한이 아니라 서비스 제한이다.
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_FOLDER_FILES = 2_000
# 이 위치에는 임시 사본만 저장한다. 사용자의 원본 로컬 파일은 절대 수정하지 않는다.
UPLOAD_ROOT = Path(tempfile.gettempdir()) / "pe-static-analysis"
# 아래 코드는 PE 실행 파일 자체가 아닌 입력을 뜻하므로, 앱 고장이 아니라
# 미지원으로 표시한다. MZ로 시작하지만 PE 구조가 손상된 파일은 분석 오류다.
UNSUPPORTED_PE_CODES = {"FILE_TOO_SHORT", "NOT_MZ"}


class InvalidUploadError(ValueError):
    pass


class AnalysisResultNotFoundError(ValueError):
    """존재하지 않는 작업 행에 부가 정보를 요청했을 때 사용하는 오류다."""

    pass


@dataclass(frozen=True)
class StoredInput:
    """업로드 후 보관할 표시용 정보이며, 브라우저의 원본 경로는 사용하지 않는다.

    ``index``는 이 정보를 내부 ``00000.bin`` 임시 파일과 연결한다.
    화면의 파일명·경로는 서버 파일 시스템 경로와 분리해서 보관한다.
    """
    index: int
    filename: str
    relative_path: str | None


def utc_now() -> datetime:
    return datetime.now(UTC)


def safe_relative_path(raw_path: str) -> str:
    """브라우저의 상대 표시 경로를 메타데이터로 저장하기 전에 확인한다.

    이 값은 서버 경로 생성에 사용하지 않지만, 절대 경로와 ``..``을 막아
    혼동되거나 위험한 값이 로그·추후 코드로 전달되는 일을 예방한다.
    """
    path = PurePosixPath(raw_path.replace("\\", "/"))
    if not raw_path or path.is_absolute() or ".." in path.parts:
        raise InvalidUploadError("상대 경로에 빈 값, 절대 경로 또는 상위 경로를 사용할 수 없습니다.")
    return path.as_posix()


class AnalysisManager:
    """비동기 작업, 임시 업로드 파일, 두 모델 단계를 관리한다.

    FastAPI 프로세스 하나당 인스턴스 하나를 사용한다. 결과는 메모리에만
    있으므로 백엔드를 재시작하면 이전 분석 이력은 의도적으로 사라진다.
    """
    def __init__(
        self,
        stage1_service: Stage1XGBoostService | None = None,
        stage2_service: Stage2MalConvService | None = None,
        expert_advice_service: GeminiExpertAdviceService | None = None,
    ) -> None:
        self.store = JobStore()
        # 1차는 내보낸 XGBoost 번들이다. 한 번만 불러와 파일마다 비싼
        # 모델·특징 스키마 검증을 반복하지 않는다. 2차도 같은 방식으로 가중치를
        # 한 번만 불러오며, 모델 파일이 없어도 진단을 위해 서버는 시작한다.
        if stage1_service is not None:
            self.stage1 = stage1_service
            self.stage1_load_error: str | None = None
        else:
            try:
                self.stage1 = Stage1XGBoostService()
                self.stage1_load_error = None
            except Stage1ModelLoadError as error:
                # 진단을 위해 API는 시작하되, 모델 누락을 Normal 결과처럼
                # 보이지 않게 각 분석 행에 명확한 오류 사유를 반환한다.
                self.stage1 = None
                self.stage1_load_error = str(error)
        # MalConv2는 PyTorch 가중치와 구조를 준비하는 데 시간이 걸릴 수 있다.
        # 서버 시작 단계에서 이를 기다리면 /health조차 응답하지 않아 React에서
        # "Failed to fetch"가 발생한다. 따라서 2차 분류가 필요한 첫 파일을
        # 처리하는 작업 스레드에서 한 번만 불러온다.
        self.stage2: Stage2MalConvService | None = stage2_service
        self.stage2_load_error: str | None = None
        self._stage2_load_attempted = stage2_service is not None
        self._stage2_load_lock = threading.Lock()
        self._inputs: dict[str, list[StoredInput]] = {}
        self._job_dirs: dict[str, Path] = {}
        # AI 조언은 분석 파일마다 한 번 생성한 결과를 메모리에 보관한다. 새 분석을
        # 시작하거나 서버를 재시작하면 기존 작업과 함께 자연스럽게 사라진다.
        self.expert_advice_service = expert_advice_service or GeminiExpertAdviceService()
        self._expert_advice_cache: dict[tuple[str, int], ExpertAdviceResponse] = {}
        self._expert_advice_cache_lock = threading.RLock()
        self._expert_advice_request_locks: dict[tuple[str, int], threading.Lock] = {}

    async def create_job(
        self,
        *,
        input_kind: str,
        uploads: list[UploadFile],
        relative_paths: list[str | None],
    ) -> AnalysisJob:
        # 작업 폴더나 백그라운드 작업을 만들기 전에 요청 전체를 먼저 확인한다.
        if not uploads:
            raise InvalidUploadError("분석할 파일을 하나 이상 선택하세요.")
        if input_kind == "folder" and len(uploads) > MAX_FOLDER_FILES:
            raise InvalidUploadError(f"폴더 분석은 최대 {MAX_FOLDER_FILES}개 파일까지 지원합니다.")
        if len(uploads) != len(relative_paths):
            raise InvalidUploadError("파일과 상대 경로 개수가 일치하지 않습니다.")

        job_id = uuid4().hex
        now = utc_now()
        job = AnalysisJob(
            job_id=job_id,
            input_kind=input_kind,
            state=JobState.QUEUED,
            created_at=now,
            updated_at=now,
            progress=AnalysisProgress(total_files=len(uploads)),
        )
        # 무작위 작업 폴더를 사용해 서로 다른 요청의 파일이 섞이지 않게 한다.
        job_dir = UPLOAD_ROOT / job_id
        job_dir.mkdir(parents=True, exist_ok=False)
        stored_inputs: list[StoredInput] = []

        try:
            for index, (upload, raw_relative_path) in enumerate(zip(uploads, relative_paths)):
                relative_path = safe_relative_path(raw_relative_path) if raw_relative_path else None
                # 중립적인 순번 파일명만 저장한다. 클라이언트가 보낸 파일명이나
                # 상대 경로가 서버의 저장 위치를 결정해서는 안 된다.
                await self._save_upload(upload, job_dir / f"{index:05d}.bin")
                stored_inputs.append(
                    StoredInput(
                        index=index,
                        filename=Path(upload.filename or f"file-{index}").name,
                        relative_path=relative_path,
                    )
                )
        except Exception:
            shutil.rmtree(job_dir, ignore_errors=True)
            raise

        self.store.add(job)
        self._inputs[job_id] = stored_inputs
        self._job_dirs[job_id] = job_dir
        # HTTP 202로 바로 응답한다. 시간이 걸리는 PE·모델 작업은 별도 스레드에서
        # 처리해 FastAPI 이벤트 루프가 멈추지 않게 한다.
        asyncio.create_task(self._run_job(job_id), name=f"analysis-{job_id}")
        return self.store.snapshot(job_id)

    @staticmethod
    async def _save_upload(upload: UploadFile, destination: Path) -> None:
        total_bytes = 0
        try:
            with destination.open("wb") as output:
                # 업로드 전체를 메모리에 올리지 않고 1MiB씩 읽는다. 각 조각을
                # 쓰기 전에 크기를 확인한다.
                while chunk := await upload.read(1024 * 1024):
                    total_bytes += len(chunk)
                    if total_bytes > MAX_FILE_BYTES:
                        raise InvalidUploadError(f"파일은 최대 {MAX_FILE_BYTES:,} bytes까지 지원합니다.")
                    output.write(chunk)
        finally:
            await upload.close()

    def snapshot(self, job_id: str) -> AnalysisJob:
        return self.store.snapshot(job_id)

    def request_cancel(self, job_id: str) -> AnalysisJob:
        job = self.store.get_mutable(job_id)
        if job.state in {JobState.QUEUED, JobState.RUNNING}:
            # 작업 스레드는 파일 사이에서 이 값을 확인한다. 입출력 중 스레드를
            # 강제로 죽이지 않아 기존 임시 파일 정리가 안전하게 유지된다.
            job.cancellation_requested = True
            job.updated_at = utc_now()
        return self.store.snapshot(job_id)

    def family_guidance(self, job_id: str, result_index: int) -> FamilyGuidanceResponse:
        """선택한 결과 행의 서버 제공 악성 유형 안내를 조회한다."""
        row = self._result_row(job_id, result_index)
        if row.status in {ResultStatus.NORMAL, ResultStatus.UNSUPPORTED, ResultStatus.ERROR}:
            return FamilyGuidanceResponse(
                status="not_available",
                reason="정상 또는 분석 불가 결과에는 악성 유형 안내를 제공하지 않습니다.",
            )
        return FamilyGuidanceResponse(
            status="ready",
            guidance=get_family_guidance(row.family_class, row.status.value),
        )

    def expert_advice(
        self,
        job_id: str,
        result_index: int,
        *,
        refresh: bool = False,
    ) -> ExpertAdviceResponse:
        """캐시를 우선 사용해 Gemini 호출 횟수와 응답 대기 시간을 줄인다."""
        row = self._result_row(job_id, result_index)
        guidance_response = self.family_guidance(job_id, result_index)
        if guidance_response.guidance is None:
            # 응답 형태를 일정하게 유지하려면 guidance가 필요하다. 정상 결과는 UI에서
            # 이 API를 호출하지 않지만, 직접 호출한 경우에도 명확히 거절한다.
            return ExpertAdviceResponse(
                status=ExpertAdviceStatus.UNAVAILABLE,
                guidance=get_family_guidance(None, "uncertain"),
                reason=guidance_response.reason,
            )

        cache_key = (job_id, result_index)
        with self._expert_advice_cache_lock:
            cached = self._expert_advice_cache.get(cache_key)
            if cached is not None and not refresh:
                return cached.model_copy(update={"status": ExpertAdviceStatus.CACHED, "source": "cached"})
            request_lock = self._expert_advice_request_locks.setdefault(cache_key, threading.Lock())

        # 같은 파일에서 탭을 여러 번 열어도 API를 동시에 여러 번 호출하지 않는다.
        with request_lock:
            with self._expert_advice_cache_lock:
                cached = self._expert_advice_cache.get(cache_key)
                if cached is not None and not refresh:
                    return cached.model_copy(update={"status": ExpertAdviceStatus.CACHED, "source": "cached"})
            try:
                advice = self.expert_advice_service.generate(
                    stage1_result=row.stage1_result,
                    stage1_confidence=row.stage1_confidence,
                    final_status=row.status.value,
                    guidance=guidance_response.guidance,
                )
            except GeminiAdviceUnavailableError as error:
                return ExpertAdviceResponse(
                    status=ExpertAdviceStatus.UNAVAILABLE,
                    guidance=guidance_response.guidance,
                    reason=str(error),
                )
            except GeminiAdviceGenerationError:
                return ExpertAdviceResponse(
                    status=ExpertAdviceStatus.FAILED,
                    guidance=guidance_response.guidance,
                    reason="AI 전문가 조언을 만들지 못했습니다. 잠시 후 다시 시도하세요.",
                )

            response = ExpertAdviceResponse(
                status=ExpertAdviceStatus.READY,
                source="generated",
                provider="Gemini",
                model=self.expert_advice_service.model,
                guidance=guidance_response.guidance,
                advice=advice,
            )
            with self._expert_advice_cache_lock:
                self._expert_advice_cache[cache_key] = response
            return response

    def _result_row(self, job_id: str, result_index: int) -> AnalysisResultRow:
        """작업 스냅샷에서 브라우저가 선택한 원래 순번의 행을 안전하게 찾는다."""
        job = self.store.snapshot(job_id)
        for row in job.results:
            if row.index == result_index:
                return row
        raise AnalysisResultNotFoundError(f"분석 결과 {result_index}번을 찾을 수 없습니다.")

    async def _run_job(self, job_id: str) -> None:
        job = self.store.get_mutable(job_id)
        job.state = JobState.RUNNING
        job.updated_at = utc_now()
        try:
            # ``read_bytes``와 XGBoost는 동기·차단 작업이다. 스레드로 옮겨 SSE와
            # 다른 HTTP 요청이 계속 응답하도록 한다.
            await asyncio.to_thread(self._process_files, job_id)
            if job.cancellation_requested:
                job.state = JobState.CANCELLED
            else:
                job.state = JobState.COMPLETED
                job.progress.stage = AnalysisStage.COMPLETED
        except Exception as error:
            # 예상하지 못한 작업 전체 오류는 개별 파일 행이 없으므로 진행 화면에
            # 표시할 수 있게 작업 단위 오류로 보관한다.
            job.state = JobState.FAILED
            job.failure_reason = f"분석 작업 처리 실패: {error}"
        finally:
            job.updated_at = utc_now()
            self._remove_uploaded_bytes(job_id)

    def _process_files(self, job_id: str) -> None:
        job = self.store.get_mutable(job_id)
        job_dir = self._job_dirs[job_id]
        # 저장된 순서를 의도적으로 유지한다. 화면 요구사항이 정렬·필터를 금지하므로
        # 각 행은 폴더에서 발견된 순서대로 남아야 한다.
        for source in self._inputs[job_id]:
            if job.cancellation_requested:
                break
            job.progress.current_filename = source.filename
            self._touch(job)
            row = self._process_one(job, job_dir, source)
            job.results.append(row)
            job.progress.completed_files += 1
            # 미지원 입력과 처리 오류는 모델 집계에서 제외하지만, 둘의 서로 다른
            # 상태는 결과 행에 그대로 보존한다.
            if row.status in {ResultStatus.UNSUPPORTED, ResultStatus.ERROR}:
                job.progress.error_files += 1
            # 2차의 구체적인 패밀리 집계를 우선한다. 2차가 실행되지 않았다면
            # 1차의 넓은 분류를 요약에 사용한다.
            elif row.family_class:
                job.class_counts[row.family_class] = job.class_counts.get(row.family_class, 0) + 1
            elif row.stage1_result:
                job.class_counts[row.stage1_result] = job.class_counts.get(row.stage1_result, 0) + 1
            self._touch(job)

    def _process_one(self, job: AnalysisJob, job_dir: Path, source: StoredInput) -> AnalysisResultRow:
        # 이전 파일의 근거 진행 수가 다음 파일 화면에 남지 않게 초기화한다.
        job.progress.evidence_current = 0
        job.progress.evidence_total = 0
        try:
            file_bytes = (job_dir / f"{source.index:05d}.bin").read_bytes()
        except OSError as error:
            return self._error_row(source, "파일을 읽을 수 없습니다: " + str(error))

        job.progress.stage = AnalysisStage.VALIDATING_PE
        # 어떤 특징 추출·모델 호출보다 먼저 헤더를 검증한다. 그래서 문서 파일의
        # 확장자를 .exe로 바꿔도 PE가 아니면 거부된다.
        validation = validate_pe(file_bytes)
        if not validation.is_valid:
            return AnalysisResultRow(
                index=source.index,
                filename=source.filename,
                relative_path=source.relative_path,
                pe_validation=validation,
                status=(
                    ResultStatus.UNSUPPORTED
                    if validation.error_code in UNSUPPORTED_PE_CODES
                    else ResultStatus.ERROR
                ),
                error_reason=validation.error_reason,
            )

        job.progress.valid_pe_files += 1
        try:
            # 1차 번들은 저장된 PE 파일에서 341개 특징을 자체 추출한다. 원시 바이트를
            # 패딩한 시퀀스를 입력으로 받지 않는다.
            job.progress.stage = AnalysisStage.PREPARING_SEQUENCE
            job.progress.stage = AnalysisStage.CLASSIFYING_STAGE1
            if self.stage1 is None:
                raise RuntimeError(self.stage1_load_error or "1차 모델을 사용할 수 없습니다.")
            stage1 = self.stage1.analyze_file(job_dir / f"{source.index:05d}.bin")
            if stage1.result == "Error":
                return AnalysisResultRow(
                    index=source.index,
                    filename=source.filename,
                    relative_path=source.relative_path,
                    pe_validation=validation,
                    # 기본 PE 검증은 통과했으므로, 특징 추출 실패는 미지원 형식이 아닌
                    # 분석 오류로 처리한다.
                    status=ResultStatus.ERROR,
                    error_reason=stage1.error_reason,
                )

            family_class = None
            family_confidence = None
            is_unknown = False
            if stage1.needs_stage2:
                # LowMemConv는 내부 청크 단위로 원본 파일 전체를 순회한다. 기존 Mock의
                # 65,536바이트 자르기 경로를 사용하면 안 된다.
                job.progress.stage = AnalysisStage.PREPARING_SEQUENCE
                sequence = prepare_malconv2_byte_sequence(file_bytes)
                job.progress.stage = AnalysisStage.CLASSIFYING_STAGE2
                stage2 = self._get_stage2()
                family_class, family_confidence, is_unknown = stage2.predict_stage2(sequence)

            final_status = self._final_status(stage1.result, family_class, is_unknown)
            evidence_status = EvidenceStatus.NOT_APPLICABLE
            evidence_regions = []
            evidence_error_reason = None
            # 후보 구간 검색과 가림 재추론은 현재 주석 처리한 상태다.
            # 이 기능은 2차 모델이 악성 유형을 예측한 파일에 대해 후보 12개를
            # 가린 뒤 점수 하락을 비교한다. 모델 추론 시간이 늘고, 해석 기준을
            # 더 검증해야 하므로 현 버전의 일반 분석 흐름에서는 실행하지 않는다.
            #
            # if final_status == ResultStatus.MALWARE_SUSPECTED:
            #     job.progress.stage = AnalysisStage.EXPLAINING_EVIDENCE
            #     try:
            #         evidence_status = EvidenceStatus.ANALYZING
            #         evidence_status, evidence_regions = EvidenceService(stage2).analyze(
            #             file_bytes=file_bytes,
            #             validation=validation,
            #             target_class=family_class or "",
            #             baseline_confidence=family_confidence or 0.0,
            #             on_progress=lambda current, total: self._update_evidence_progress(job, current, total),
            #         )
            #     except Exception as error:
            #         evidence_status = EvidenceStatus.FAILED
            #         evidence_error_reason = f"모델 판단 근거를 만들지 못했습니다: {error}"

            return AnalysisResultRow(
                index=source.index,
                filename=source.filename,
                relative_path=source.relative_path,
                pe_validation=validation,
                stage1_result=stage1.result,
                # 이 값은 XGBoost의 보정되지 않은 악성 점수다. 안전 확률이 아니며
                # 자동 보안 결정을 내리기에는 충분하지 않다.
                stage1_confidence=stage1.malware_score,
                family_class=family_class,
                family_confidence=family_confidence,
                is_unknown=is_unknown,
                status=final_status,
                evidence_status=evidence_status,
                evidence_regions=evidence_regions,
                evidence_error_reason=evidence_error_reason,
            )
        except Exception:
            # 모델·라이브러리의 내부 예외와 원시 값(NaN 등)은 개발자 로그에만
            # 남긴다. 사용자에게는 구현 세부 정보 대신 재시도 가능한 안내만 보인다.
            logger.exception("파일 분석 중 2차 모델 또는 결과 검증 오류가 발생했습니다.")
            return AnalysisResultRow(
                index=source.index,
                filename=source.filename,
                relative_path=source.relative_path,
                pe_validation=validation,
                status=ResultStatus.ERROR,
                error_reason="2차 모델 분석을 완료하지 못했습니다. 잠시 후 다시 시도하세요.",
            )

    @staticmethod
    def _final_status(
        stage1_result: str,
        family_class: str | None,
        is_unknown: bool,
    ) -> ResultStatus:
        """두 모델의 처리 결과를 공통 최종 상태로 변환한다."""
        if stage1_result == "Normal":
            return ResultStatus.NORMAL
        normalized_family = (family_class or "").strip().lower()
        if is_unknown or not normalized_family or normalized_family == "unknown":
            return ResultStatus.UNCERTAIN
        if normalized_family == "benign":
            return ResultStatus.CONFLICT
        return ResultStatus.MALWARE_SUSPECTED

    def _get_stage2(self) -> Stage2MalConvService:
        """2차 모델을 필요해진 시점에 한 번만 준비해 반환한다.

        여러 폴더 파일이 같은 시점에 2차 분류로 들어와도 잠금으로 중복 로딩을
        막는다. 한 번 로딩에 실패한 경우에는 매 파일마다 무거운 재시도를 하지
        않고, 동일한 원인을 해당 파일의 분석 오류로 보여 준다.
        """
        with self._stage2_load_lock:
            if not self._stage2_load_attempted:
                self._stage2_load_attempted = True
                try:
                    self.stage2 = Stage2MalConvService()
                    self.stage2_load_error = None
                except Stage2ModelLoadError as error:
                    self.stage2 = None
                    self.stage2_load_error = str(error)

        if self.stage2 is None:
            raise RuntimeError(self.stage2_load_error or "2차 모델을 사용할 수 없습니다.")
        return self.stage2

    def _update_evidence_progress(self, job: AnalysisJob, current: int, total: int) -> None:
        """SSE 화면에 12개 후보 중 현재 근거 분석 위치를 전달한다."""
        job.progress.evidence_current = current
        job.progress.evidence_total = total
        self._touch(job)

    @staticmethod
    def _error_row(source: StoredInput, reason: str) -> AnalysisResultRow:
        return AnalysisResultRow(
            index=source.index,
            filename=source.filename,
            relative_path=source.relative_path,
            pe_validation=PeValidationResult(
                is_valid=False,
                error_code="READ_ERROR",
                error_reason=reason,
            ),
            # 디스크 읽기 실패는 비-PE 파일과 운영상 다른 오류다.
            status=ResultStatus.ERROR,
            error_reason=reason,
        )

    @staticmethod
    def _touch(job: AnalysisJob) -> None:
        job.updated_at = utc_now()

    def _remove_uploaded_bytes(self, job_id: str) -> None:
        # 현재 브라우저 세션에는 가벼운 결과 메타데이터만 남긴다. 업로드 바이트는
        # 성공·취소·예상하지 못한 오류 모두에서 삭제한다.
        self._inputs.pop(job_id, None)
        job_dir = self._job_dirs.pop(job_id, None)
        if job_dir:
            shutil.rmtree(job_dir, ignore_errors=True)
