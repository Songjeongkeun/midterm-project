from __future__ import annotations

from threading import RLock

from app.schemas.analysis import AnalysisJob


class JobNotFoundError(KeyError):
    pass


class JobStore:
    """Memory-only job storage; it intentionally provides no scan history."""

    def __init__(self) -> None:
        self._jobs: dict[str, AnalysisJob] = {}
        self._lock = RLock()

    def add(self, job: AnalysisJob) -> None:
        with self._lock:
            self._jobs[job.job_id] = job

    def get_mutable(self, job_id: str) -> AnalysisJob:
        with self._lock:
            try:
                return self._jobs[job_id]
            except KeyError as error:
                raise JobNotFoundError(job_id) from error

    def snapshot(self, job_id: str) -> AnalysisJob:
        with self._lock:
            try:
                return self._jobs[job_id].model_copy(deep=True)
            except KeyError as error:
                raise JobNotFoundError(job_id) from error
