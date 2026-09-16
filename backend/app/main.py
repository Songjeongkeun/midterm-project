"""FastAPI application entry point for the PE static-analysis demo."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers.analyze import router as analyze_router
from app.services.analysis_service import AnalysisManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create the session-scoped analysis manager when the server starts."""
    app.state.analysis_manager = AnalysisManager()
    yield


app = FastAPI(
    title="PE Static Analysis API",
    version="0.2.0",
    description="Read-only PE validation and mock two-stage inference API.",
    lifespan=lifespan,
)

# Vite's local development server is allowed to call this API. Add a deployed
# frontend origin here only when the service is deployed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

app.include_router(analyze_router, prefix="/api/v1")


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Small endpoint used to verify that the API process is reachable."""
    return {"status": "ok"}
