"""HTTP endpoints for the read-only PE analysis workflow."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import StreamingResponse

from app.schemas.analysis import AnalysisJob
from app.schemas.expert_advice import (
    ExpertAdviceRequest,
    ExpertAdviceResponse,
    FamilyGuidanceResponse,
)
from app.services.analysis_service import AnalysisResultNotFoundError, InvalidUploadError
from app.storage.job_store import JobNotFoundError

router = APIRouter(prefix="/analyses", tags=["analyses"])


def _manager(request: Request):
    """Return the single manager created during FastAPI startup.

    Keeping this lookup in one helper makes every route use the same job store
    and avoids a global variable that would be hard to replace in tests.
    """
    return request.app.state.analysis_manager


def _not_found(error: JobNotFoundError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))


def _result_not_found(error: AnalysisResultNotFoundError) -> HTTPException:
    """작업은 있지만 선택한 파일 행이 없을 때의 404 응답을 만든다."""
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))


@router.post("/file", response_model=AnalysisJob, status_code=status.HTTP_202_ACCEPTED)
async def create_single_file_analysis(request: Request, file: UploadFile = File(...)) -> AnalysisJob:
    """Accept one multipart file and immediately create an asynchronous job.

    The API returns HTTP 202 rather than waiting for classification to finish.
    The frontend then receives incremental progress through the SSE endpoint.
    """
    try:
        return await _manager(request).create_job(
            input_kind="file",
            uploads=[file],
            relative_paths=[file.filename or "uploaded-file"],
        )
    except InvalidUploadError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error


@router.post("/folder", response_model=AnalysisJob, status_code=status.HTTP_202_ACCEPTED)
async def create_folder_analysis(
    request: Request,
    files: list[UploadFile] = File(...),
    relative_paths: list[str] = Form(...),
) -> AnalysisJob:
    """Queue browser-selected folder files, preserving their discovery order.

    Browsers cannot send a real local directory path to a server.  Instead,
    they send each file and its display-only ``webkitRelativePath`` separately.
    Matching their indexes is important because the result table must retain
    exactly the selected folder order.
    """
    if len(files) != len(relative_paths):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="files와 relative_paths의 개수가 일치하지 않습니다.",
        )
    try:
        return await _manager(request).create_job(
            input_kind="folder", uploads=files, relative_paths=relative_paths
        )
    except InvalidUploadError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error


@router.get("/{job_id}", response_model=AnalysisJob)
async def get_analysis(request: Request, job_id: str) -> AnalysisJob:
    """Return a snapshot, not the mutable job object used by the worker."""
    try:
        return _manager(request).snapshot(job_id)
    except JobNotFoundError as error:
        raise _not_found(error) from error


@router.get("/{job_id}/results/{result_index}/family-guidance", response_model=FamilyGuidanceResponse)
async def get_family_guidance(
    request: Request,
    job_id: str,
    result_index: int,
) -> FamilyGuidanceResponse:
    """외부 AI 없이도 제공되는 악성 유형별 기본 대응 안내를 반환한다."""
    try:
        return _manager(request).family_guidance(job_id, result_index)
    except JobNotFoundError as error:
        raise _not_found(error) from error
    except AnalysisResultNotFoundError as error:
        raise _result_not_found(error) from error


@router.post("/{job_id}/results/{result_index}/expert-advice", response_model=ExpertAdviceResponse)
async def create_expert_advice(
    request: Request,
    job_id: str,
    result_index: int,
    payload: ExpertAdviceRequest | None = None,
) -> ExpertAdviceResponse:
    """Gemini Flash 조언을 생성하거나 메모리 캐시의 결과를 반환한다.

    Gemini SDK는 동기 호출이므로 이벤트 루프를 막지 않도록 별도 스레드에서 실행한다.
    원본 PE 바이트·문자열·사용자 로컬 경로는 이 경로에서 외부로 전달하지 않는다.
    """
    try:
        return await asyncio.to_thread(
            _manager(request).expert_advice,
            job_id,
            result_index,
            refresh=bool(payload and payload.refresh),
        )
    except JobNotFoundError as error:
        raise _not_found(error) from error
    except AnalysisResultNotFoundError as error:
        raise _result_not_found(error) from error


@router.delete("/{job_id}", response_model=AnalysisJob)
async def cancel_analysis(request: Request, job_id: str) -> AnalysisJob:
    """Request cancellation; completed rows are deliberately retained.

    Cancellation is cooperative: the worker checks the request between files,
    so a file is never interrupted halfway through a disk read.
    """
    try:
        return _manager(request).request_cancel(job_id)
    except JobNotFoundError as error:
        raise _not_found(error) from error


@router.get("/{job_id}/events")
async def stream_analysis_progress(request: Request, job_id: str) -> StreamingResponse:
    """Send changed job snapshots as Server-Sent Events (SSE).

    SSE is a one-way server-to-browser channel.  It fits progress updates
    because the client only needs to listen; upload and cancellation remain
    normal HTTP requests.
    """
    try:
        _manager(request).snapshot(job_id)
    except JobNotFoundError as error:
        raise _not_found(error) from error

    async def event_stream():
        last_payload = ""
        while True:
            try:
                job = _manager(request).snapshot(job_id)
            except JobNotFoundError:
                return

            # Pydantic serializes enums and datetimes into JSON safe for the
            # EventSource client.  Do not emit duplicate snapshots every tick.
            payload = job.model_dump_json()
            if payload != last_payload:
                yield f"event: progress\ndata: {payload}\n\n"
                last_payload = payload
            if job.state.value in {"completed", "cancelled", "failed"}:
                return

            # This small polling loop is adequate for the in-process worker.
            # A queue worker (Celery/RQ, etc.) can publish its own updates while
            # retaining this same HTTP contract for the React application.
            await asyncio.sleep(0.35)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
