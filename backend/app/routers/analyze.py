"""HTTP endpoints for the read-only PE analysis workflow."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import StreamingResponse

from app.schemas.analysis import AnalysisJob
from app.services.analysis_service import InvalidUploadError
from app.storage.job_store import JobNotFoundError

router = APIRouter(prefix="/analyses", tags=["analyses"])


def _manager(request: Request):
    """Return the app-scoped manager initialized in the application lifespan."""
    return request.app.state.analysis_manager


def _not_found(error: JobNotFoundError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))


@router.post("/file", response_model=AnalysisJob, status_code=status.HTTP_202_ACCEPTED)
async def create_single_file_analysis(request: Request, file: UploadFile = File(...)) -> AnalysisJob:
    """Queue one uploaded file for validation and read-only byte analysis."""
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
    """Queue files selected from one folder in the browser's discovery order."""
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
    """Return the latest in-memory state for one analysis."""
    try:
        return _manager(request).snapshot(job_id)
    except JobNotFoundError as error:
        raise _not_found(error) from error


@router.delete("/{job_id}", response_model=AnalysisJob)
async def cancel_analysis(request: Request, job_id: str) -> AnalysisJob:
    """Request cancellation; already processed rows remain visible to the user."""
    try:
        return _manager(request).request_cancel(job_id)
    except JobNotFoundError as error:
        raise _not_found(error) from error


@router.get("/{job_id}/events")
async def stream_analysis_progress(request: Request, job_id: str) -> StreamingResponse:
    """Send job snapshots as Server-Sent Events while analysis is in progress."""
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

            payload = job.model_dump_json()
            if payload != last_payload:
                yield f"event: progress\ndata: {payload}\n\n"
                last_payload = payload
            if job.state.value in {"completed", "cancelled", "failed"}:
                return

            # Polling is used only for the in-memory mock pipeline. A production
            # worker can publish real events through this unchanged endpoint.
            await asyncio.sleep(0.35)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
