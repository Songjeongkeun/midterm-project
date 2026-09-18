// 개발 중에는 FastAPI의 로컬 주소를 쓰고, 배포 시에는 .env의 주소를 사용한다.
// 이 개발 환경의 기본 FastAPI 포트는 8000이다. 다른 포트에서 실행하려면
// VITE_API_BASE_URL을 지정해 프런트엔드가 호출할 주소를 바꾼다.
// 일부 환경에서 localhost가 IPv6(::1)로 해석되어 연결이 거부되는 일을 막는다.
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1";

async function requestJob(path, body) {
  // FormData를 그대로 보내야 파일의 이진 데이터가 multipart/form-data로 전송된다.
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, { method: "POST", body });
  } catch {
    // 브라우저의 "Failed to fetch"는 서버 미실행·포트 불일치·CORS처럼 HTTP
    // 응답조차 받지 못한 경우다. 사용자가 바로 조치할 수 있는 안내로 바꾼다.
    throw new Error("백엔드에 연결할 수 없습니다. backend 폴더에서 uvicorn app.main:app --reload --port 8000 명령을 실행했는지 확인하세요.");
  }
  if (!response.ok) {
    // FastAPI의 HTTPException은 보통 { detail: "..." } 형식이다. 다만
    // 프록시/예상 밖 응답도 있으므로 JSON 파싱 실패 시 기본 메시지를 사용한다.
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail ?? "분석 요청에 실패했습니다.");
  }
  return response.json();
}

async function requestJson(path, options = {}) {
  // 파일 업로드 외의 JSON API도 동일한 연결 실패 안내를 사용한다.
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, options);
  } catch {
    throw new Error("백엔드에 연결할 수 없습니다. backend 폴더에서 uvicorn app.main:app --reload --port 8000 명령을 실행했는지 확인하세요.");
  }
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail ?? "요청을 처리하지 못했습니다.");
  }
  return response.json();
}

export function startSingleFileAnalysis(file) {
  // key 이름 "file"은 FastAPI의 create_single_file_analysis 인자명과 같아야 한다.
  const body = new FormData();
  body.append("file", file);
  return requestJob("/analyses/file", body);
}

export function startFolderAnalysis(files) {
  const body = new FormData();
  Array.from(files).forEach((file) => {
    // 서버는 files와 relative_paths의 같은 순서를 하나의 결과 행으로 연결한다.
    // webkitRelativePath는 폴더 선택 시 "선택폴더/하위폴더/파일" 형태를 제공한다.
    body.append("files", file);
    body.append("relative_paths", file.webkitRelativePath || file.name);
  });
  return requestJob("/analyses/folder", body);
}

export function subscribeToAnalysis(jobId, onChange) {
  // SSE는 서버 → 브라우저 단방향 연결이다. 진행률처럼 서버가 갱신하는 값에 적합하다.
  const events = new EventSource(`${API_BASE}/analyses/${jobId}/events`);
  events.addEventListener("progress", (event) => {
    // 서버가 보낸 전체 작업 snapshot으로 현재 상태를 교체한다. 일부 필드만
    // 병합하면 오래된 카운터/결과 행을 남길 위험이 있어 전체 교체를 사용한다.
    onChange(JSON.parse(event.data));
  });
  return () => events.close();
}

export async function cancelAnalysis(jobId) {
  // DELETE는 실행 중인 작업에 취소 요청만 남긴다. 현재 파일 처리 후 안전하게 멈춘다.
  const response = await fetch(`${API_BASE}/analyses/${jobId}`, { method: "DELETE" });
  if (!response.ok) throw new Error("분석 취소에 실패했습니다.");
  return response.json();
}

export function getFamilyGuidance(jobId, resultIndex) {
  // 이 안내는 Gemini 키와 무관하게 FastAPI 서버가 직접 제공한다.
  return requestJson(`/analyses/${jobId}/results/${resultIndex}/family-guidance`);
}

export function requestExpertAdvice(jobId, resultIndex, refresh = false) {
  // refresh=true일 때만 서버 캐시를 건너뛰고 Gemini에 새 조언을 요청한다.
  return requestJson(`/analyses/${jobId}/results/${resultIndex}/expert-advice`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh }),
  });
}
