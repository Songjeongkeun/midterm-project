// 개발 중에는 FastAPI의 로컬 주소를 쓰고, 배포 시에는 .env의 주소를 사용한다.
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1";

async function requestJob(path, body) {
  // FormData를 그대로 보내야 파일의 이진 데이터가 multipart/form-data로 전송된다.
  const response = await fetch(`${API_BASE}${path}`, { method: "POST", body });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail ?? "분석 요청에 실패했습니다.");
  }
  return response.json();
}

export function startSingleFileAnalysis(file) {
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
  events.addEventListener("progress", (event) => onChange(JSON.parse(event.data)));
  return () => events.close();
}

export async function cancelAnalysis(jobId) {
  // DELETE는 실행 중인 작업에 취소 요청만 남긴다. 현재 파일 처리 후 안전하게 멈춘다.
  const response = await fetch(`${API_BASE}/analyses/${jobId}`, { method: "DELETE" });
  if (!response.ok) throw new Error("분석 취소에 실패했습니다.");
  return response.json();
}
