"""PE 읽기 전용 정적 분석 FastAPI 애플리케이션의 시작점이다."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers.analyze import router as analyze_router
from app.services.analysis_service import AnalysisManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI 프로세스가 살아 있는 동안 분석 관리자 하나를 생성한다.

    엔드포인트마다 관리자를 만들지 않고 ``app.state``에 보관한다. 모든 요청이
    같은 메모리 작업 목록과 이미 불러온 XGBoost 모델을 공유하며, 업로드 바이트는
    작업별로 계속 삭제된다.
    """
    app.state.analysis_manager = AnalysisManager()
    yield


app = FastAPI(
    title="PE Static Analysis API",
    version="0.2.0",
    description="Read-only PE validation and two-stage XGBoost/MalConv2 inference API.",
    lifespan=lifespan,
)

# 브라우저는 기본적으로 다른 출처 요청을 막는다. 그래서 React 개발 서버(5173)가
# FastAPI(8000)를 호출하도록 명시적으로 허용한다. 배포 때는 와일드카드 대신
# 실제 프론트엔드 도메인으로 이 주소를 교체해야 한다.
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
    """서버 연결 가능 여부만 반환하며, 모델 사용 가능 여부는 확인하지 않는다."""
    return {"status": "ok"}
