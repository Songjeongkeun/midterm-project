from __future__ import annotations

from threading import RLock

from app.schemas.analysis import AnalysisJob


class JobNotFoundError(KeyError):
    pass


class JobStore:
    """Thread-safe, memory-only job storage with no persistent scan history.

    The analysis worker runs in a background thread while FastAPI/SSE handlers
    run elsewhere, hence the lock.  ``snapshot`` deep-copies a job so API code
    cannot mutate the state that the worker is currently updating.
    """

    def __init__(self) -> None:
        self._jobs: dict[str, AnalysisJob] = {}
        self._lock = RLock()

    def add(self, job: AnalysisJob) -> None:
        """Register a newly queued job before its background task starts."""
        with self._lock:
            self._jobs[job.job_id] = job

    def get_mutable(self, job_id: str) -> AnalysisJob:
        """Return the worker-owned object; callers must hold no reference long-term."""
        with self._lock:
            try:
                return self._jobs[job_id]
            except KeyError as error:
                raise JobNotFoundError(job_id) from error

    def snapshot(self, job_id: str) -> AnalysisJob:
        """Return an isolated copy suitable for JSON responses and SSE messages."""
        with self._lock:
            try:
                return self._jobs[job_id].model_copy(deep=True)
            except KeyError as error:
                raise JobNotFoundError(job_id) from error
