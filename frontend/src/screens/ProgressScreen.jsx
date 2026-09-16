import ProgressSummary from "../components/ProgressSummary";

const stageLabel = {
  discovering: "파일 탐색 중",
  validating_pe: "PE 형식 검증 중",
  preparing_sequence: "바이트 시퀀스 구성 중",
  classifying_stage1: "1차 Normal/Malware 분석 중",
  classifying_stage2: "2차 패밀리 분석 중",
  completed: "분석 완료",
};

export default function ProgressScreen({ job, onCancel, onReset }) {
  const { progress } = job;
  const ended = ["cancelled", "failed"].includes(job.state);
  const percent = progress.total_files ? Math.round((progress.completed_files / progress.total_files) * 100) : 0;

  return (
    <main className="grid min-h-screen place-items-center bg-slate-950 px-5 py-12 text-slate-100">
      <section className="w-full max-w-3xl rounded-3xl border border-slate-700 bg-slate-900/70 p-8 text-center shadow-2xl sm:p-12">
        <p className="text-xs font-extrabold tracking-[0.18em] text-sky-300">ANALYSIS IN PROGRESS</p>
        <h1 className="mt-3 text-3xl font-black sm:text-4xl">{ended ? "분석이 종료되었습니다" : stageLabel[progress.stage]}</h1>
        <p className="mt-4 min-h-6 break-all text-slate-400">{progress.current_filename || "분석을 준비하고 있습니다."}</p>
        <div className="mt-8 h-3 overflow-hidden rounded-full bg-slate-700">
          <div className="h-full rounded-full bg-linear-to-r from-sky-400 to-teal-300 transition-all" style={{ width: `${percent}%` }} />
        </div>
        <p className="mt-3 font-bold">{progress.completed_files} / {progress.total_files}개 처리 ({percent}%)</p>
        <div className="mt-8"><ProgressSummary progress={progress} /></div>
        {job.failure_reason && <p className="mt-6 rounded-lg bg-[#FEE2E2] p-3 text-sm text-[#B91C1C]">{job.failure_reason}</p>}
        <button className="mt-8 rounded-xl border border-slate-600 px-5 py-3 font-bold hover:border-slate-400" onClick={ended ? onReset : onCancel}>
          {ended ? "시작 화면으로" : "분석 취소"}
        </button>
      </section>
    </main>
  );
}
