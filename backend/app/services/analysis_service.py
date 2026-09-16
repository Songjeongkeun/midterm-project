from __future__ import annotations

import asyncio
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from uuid import uuid4

from fastapi import UploadFile

from app.schemas.analysis import AnalysisJob, AnalysisProgress, AnalysisResultRow, PeValidationResult
from app.schemas.common import AnalysisStage, JobState, ResultStatus
from app.storage.job_store import JobNotFoundError, JobStore

from .byte_preprocessor import prepare_raw_byte_sequence
from .model_inference_service import MockModelInferenceService
from .pe_validator import validate_pe


MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_FOLDER_FILES = 2_000
UPLOAD_ROOT = Path(tempfile.gettempdir()) / "pe-static-analysis"


class InvalidUploadError(ValueError):
    pass


@dataclass(frozen=True)
class StoredInput:
    index: int
    filename: str
    relative_path: str | None


def utc_now() -> datetime:
    return datetime.now(UTC)


def safe_relative_path(raw_path: str) -> str:
    """Retain a folder display path while rejecting paths that could traverse server folders."""
    path = PurePosixPath(raw_path.replace("\\", "/"))
    if not raw_path or path.is_absolute() or ".." in path.parts:
        raise InvalidUploadError("상대 경로에 빈 값, 절대 경로 또는 상위 경로를 사용할 수 없습니다.")
    return path.as_posix()


class AnalysisManager:
    def __init__(self) -> None:
        self.store = JobStore()
        self.inference = MockModelInferenceService()
        self._inputs: dict[str, list[StoredInput]] = {}
        self._job_dirs: dict[str, Path] = {}

    async def create_job(
        self,
        *,
        input_kind: str,
        uploads: list[UploadFile],
        relative_paths: list[str | None],
    ) -> AnalysisJob:
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
        job_dir = UPLOAD_ROOT / job_id
        job_dir.mkdir(parents=True, exist_ok=False)
        stored_inputs: list[StoredInput] = []

        try:
            for index, (upload, raw_relative_path) in enumerate(zip(uploads, relative_paths)):
                relative_path = safe_relative_path(raw_relative_path) if raw_relative_path else None
                # Store only index.bin. The browser path is never used as a server path.
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
        asyncio.create_task(self._run_job(job_id), name=f"analysis-{job_id}")
        return self.store.snapshot(job_id)

    @staticmethod
    async def _save_upload(upload: UploadFile, destination: Path) -> None:
        total_bytes = 0
        try:
            with destination.open("wb") as output:
                # Chunked reads avoid holding each complete browser upload in memory.
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
            # The worker observes this flag between files; it never kills a thread mid-I/O.
            job.cancellation_requested = True
            job.updated_at = utc_now()
        return self.store.snapshot(job_id)

    async def _run_job(self, job_id: str) -> None:
        job = self.store.get_mutable(job_id)
        job.state = JobState.RUNNING
        job.updated_at = utc_now()
        try:
            await asyncio.to_thread(self._process_files, job_id)
            if job.cancellation_requested:
                job.state = JobState.CANCELLED
            else:
                job.state = JobState.COMPLETED
                job.progress.stage = AnalysisStage.COMPLETED
        except Exception as error:
            job.state = JobState.FAILED
            job.failure_reason = f"분석 작업 처리 실패: {error}"
        finally:
            job.updated_at = utc_now()
            self._remove_uploaded_bytes(job_id)

    def _process_files(self, job_id: str) -> None:
        job = self.store.get_mutable(job_id)
        job_dir = self._job_dirs[job_id]
        for source in self._inputs[job_id]:
            if job.cancellation_requested:
                break
            job.progress.current_filename = source.filename
            self._touch(job)
            row = self._process_one(job, job_dir, source)
            job.results.append(row)
            job.progress.completed_files += 1
            if row.status == ResultStatus.UNSUPPORTED_ERROR:
                job.progress.error_files += 1
            elif row.family_class:
                job.class_counts[row.family_class] = job.class_counts.get(row.family_class, 0) + 1
            elif row.stage1_result:
                job.class_counts[row.stage1_result] = job.class_counts.get(row.stage1_result, 0) + 1
            self._touch(job)

    def _process_one(self, job: AnalysisJob, job_dir: Path, source: StoredInput) -> AnalysisResultRow:
        try:
            file_bytes = (job_dir / f"{source.index:05d}.bin").read_bytes()
        except OSError as error:
            return self._error_row(source, "파일을 읽을 수 없습니다: " + str(error))

        job.progress.stage = AnalysisStage.VALIDATING_PE
        validation = validate_pe(file_bytes)
        if not validation.is_valid:
            return AnalysisResultRow(
                index=source.index,
                filename=source.filename,
                relative_path=source.relative_path,
                pe_validation=validation,
                status=ResultStatus.UNSUPPORTED_ERROR,
                error_reason=validation.error_reason,
            )

        job.progress.valid_pe_files += 1
        try:
            job.progress.stage = AnalysisStage.PREPARING_SEQUENCE
            sequence = prepare_raw_byte_sequence(file_bytes)
            job.progress.stage = AnalysisStage.CLASSIFYING_STAGE1
            stage1_result, stage1_confidence = self.inference.predict_stage1(sequence)

            family_class = None
            family_confidence = None
            is_unknown = False
            if stage1_result == "Malware":
                job.progress.stage = AnalysisStage.CLASSIFYING_STAGE2
                family_class, family_confidence, is_unknown = self.inference.predict_stage2(sequence)

            return AnalysisResultRow(
                index=source.index,
                filename=source.filename,
                relative_path=source.relative_path,
                pe_validation=validation,
                stage1_result=stage1_result,
                stage1_confidence=stage1_confidence,
                family_class=family_class,
                family_confidence=family_confidence,
                is_unknown=is_unknown,
                # A model prediction never certifies safety, including Normal.
                status=ResultStatus.REVIEW_REQUIRED,
            )
        except Exception as error:
            return AnalysisResultRow(
                index=source.index,
                filename=source.filename,
                relative_path=source.relative_path,
                pe_validation=validation,
                status=ResultStatus.UNSUPPORTED_ERROR,
                error_reason=f"추론 준비 또는 Mock 추론에 실패했습니다: {error}",
            )

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
            status=ResultStatus.UNSUPPORTED_ERROR,
            error_reason=reason,
        )

    @staticmethod
    def _touch(job: AnalysisJob) -> None:
        job.updated_at = utc_now()

    def _remove_uploaded_bytes(self, job_id: str) -> None:
        # Keep only result metadata for the current session; remove the uploaded bytes.
        self._inputs.pop(job_id, None)
        job_dir = self._job_dirs.pop(job_id, None)
        if job_dir:
            shutil.rmtree(job_dir, ignore_errors=True)
