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
  const [job, setJob] = useState(null);
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!job || ["completed", "cancelled", "failed"].includes(job.state)) return undefined;
    // SSE가 서버의 실제 작업 상태를 전달하므로 페이지 전환은 이 값만 따른다.
    return subscribeToAnalysis(job.job_id, setJob);
  }, [job?.job_id, job?.state]);

  async function start(request) {
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
    setJob(null);
    setMessage("");
  }

  if (!job) {
    return <StartScreen message={message} onSingleFile={(file) => start(() => startSingleFileAnalysis(file))} onFolder={(files) => start(() => startFolderAnalysis(files))} />;
  }
  if (job.state === "completed" && job.input_kind === "file") {
    const result = job.results[0];
    return result?.status === "unsupported_error"
      ? <UnsupportedScreen result={result} onReset={reset} />
      : <SingleResultScreen result={result} onReset={reset} />;
  }
  if (job.state === "completed" && job.input_kind === "folder") {
    return <FolderResultScreen job={job} onReset={reset} />;
  }
  return <ProgressScreen job={job} onCancel={cancel} onReset={reset} />;
}
