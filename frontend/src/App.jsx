import { useEffect, useState } from "react";

import {
  cancelAnalysis,
  startFolderAnalysis,
  startSingleFileAnalysis,
  subscribeToAnalysis,
} from "./api/analysis";
import FolderResultScreen from "./screens/FolderResultScreen";
import ProgressScreen from "./screens/ProgressScreen";
import SingleResultScreen from "./screens/SingleResultScreen";
import StartScreen from "./screens/StartScreen";
import UnsupportedScreen from "./screens/UnsupportedScreen";

export default function App() {
  // ``job`` 하나가 현재 화면의 모든 상태를 결정한다. 별도의 라우터 없이도
  // 시작 → 진행 → 단일/폴더 결과 → 분석 불가의 다섯 화면을 일관되게 전환한다.
  const [job, setJob] = useState(null);
  // 폴더 결과에서 선택한 한 행만 별도로 보관해, 결과를 다시 요청하거나 정렬하지
  // 않고도 기존 단일 파일 화면에서 상세 정보를 보여 준다.
  const [selectedFolderResult, setSelectedFolderResult] = useState(null);
  // 서버 연결/업로드 오류는 작업 객체가 없을 수 있으므로 화면 메시지로 분리한다.
  const [message, setMessage] = useState("");

  useEffect(() => {
    // 완료된 작업은 더 이상 서버가 변경하지 않으므로 SSE 연결을 즉시 정리한다.
    if (!job || ["completed", "cancelled", "failed"].includes(job.state)) return undefined;
    // SSE가 서버의 실제 작업 상태를 전달하므로 페이지 전환은 이 값만 따른다.
    // cleanup 함수는 job이 바뀌거나 컴포넌트가 사라질 때 EventSource를 닫는다.
    return subscribeToAnalysis(job.job_id, setJob);
  }, [job?.job_id, job?.state]);

  async function start(request) {
    // 파일/폴더 업로드 함수의 공통 처리. 새 요청 전에 과거 오류를 지운다.
    setMessage("");
    try {
      setJob(await request());
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "분석을 시작하지 못했습니다.");
    }
  }

  async function cancel() {
    if (!job) return;
    try {
      setJob(await cancelAnalysis(job.job_id));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "분석 취소 요청에 실패했습니다.");
    }
  }

  function reset() {
    // 서버에 결과를 저장하지 않는 앱이므로, 화면을 초기 상태로 돌리면
    // 브라우저 측에서 이전 작업을 참조하는 상태도 함께 해제된다.
    setJob(null);
    setSelectedFolderResult(null);
    setMessage("");
  }

  // 아래 분기는 명시적인 화면 상태 머신이다. API의 job.state를 유일한
  // 근거로 사용하므로, 클라이언트가 분석 완료 여부를 추정하지 않는다.
  if (!job) {
    return <StartScreen message={message} onSingleFile={(file) => start(() => startSingleFileAnalysis(file))} onFolder={(files) => start(() => startFolderAnalysis(files))} />;
  }
  if (job.state === "completed" && job.input_kind === "file") {
    const result = job.results[0];
    // 미지원 파일과 분석 오류는 모두 분석 불가 화면으로 가지만, 화면 내부
    // 배지와 제목은 result.status에 따라 서로 다르게 표시한다.
    return ["unsupported", "error"].includes(result?.status)
      ? <UnsupportedScreen result={result} onReset={reset} />
      : <SingleResultScreen jobId={job.job_id} result={result} onReset={reset} />;
  }
  if (job.state === "completed" && job.input_kind === "folder") {
    if (selectedFolderResult) {
      return <SingleResultScreen jobId={job.job_id} result={selectedFolderResult} onReset={reset} onBack={() => setSelectedFolderResult(null)} />;
    }
    return <FolderResultScreen job={job} onReset={reset} onViewDetails={setSelectedFolderResult} />;
  }
  return <ProgressScreen job={job} onCancel={cancel} onReset={reset} />;
}
