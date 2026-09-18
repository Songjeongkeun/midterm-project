import AppHeader from "../components/AppHeader";
import ProgressSummary from "../components/ProgressSummary";

// API enum 값은 안정적인 영문 식별자로 유지하고, 이 화면에서만 한국어 문구로
// 변환한다. 백엔드 로직에 화면 문구가 섞이지 않도록 분리한 것이다.
const stageLabel = {
  discovering: "파일 탐색 중",
  validating_pe: "PE 형식 검증 중",
  preparing_sequence: "바이트 시퀀스 구성 중",
  classifying_stage1: "1차 XGBoost 분석 중",
  classifying_stage2: "2차 패밀리 분석 중",
  explaining_evidence: "모델 판단 근거 분석 중",
  completed: "분석 완료",
};

export default function ProgressScreen({ job, onCancel, onReset }) {
  const { progress } = job;
  const ended = ["cancelled", "failed"].includes(job.state);
  // 실제 완료 파일 수로만 진행률을 계산한다. 현재 파일의 내부 단계는 분석
  // 시간이 달라질 수 있으므로 퍼센트에 임의의 가중치를 주지 않는다.
  const percent = progress.total_files ? Math.round((progress.completed_files / progress.total_files) * 100) : 0;

  return (
    <main className="min-h-screen bg-[#F9FAFB] font-sans text-[#111827]">
      <AppHeader onNewAnalysis={onReset} />
      <section className="mx-auto flex min-h-[calc(100vh-53px)] w-full max-w-[512px] flex-col justify-center px-5 py-12">
        <article className="overflow-hidden rounded-xl border border-[#E5E7EB] bg-white shadow-[0_1px_3px_rgba(0,0,0,0.10)]">
          <div className="border-b border-[#F3F4F6] px-6 py-5"><p className="flex items-center gap-2 text-sm font-semibold text-[#374151]"><span className="size-2 rounded-full bg-[#2563EB]" />{ended ? "분석이 종료되었습니다" : "분석 진행 중..."}</p><p className="mt-3 truncate text-xs text-[#6B7280]">{progress.current_filename || "분석을 준비하고 있습니다."}</p></div>
          <div className="px-6 py-5"><div className="flex justify-between text-xs text-[#374151]"><span>{stageLabel[progress.stage]}</span><span>{percent}%</span></div>{progress.stage === "explaining_evidence" && progress.evidence_total > 0 && <p className="mt-2 text-xs text-[#6B7280]">후보 {progress.evidence_current}/{progress.evidence_total} 구간을 확인하고 있습니다.</p>}<div className="mt-2 h-2 overflow-hidden rounded-full bg-[#E5E7EB]"><div className="h-full rounded-full bg-[#1D4ED8] transition-all" style={{ width: `${percent}%` }} /></div><div className="mt-6"><ProgressSummary progress={progress} /></div></div>
          <div className="border-t border-[#F3F4F6] bg-[#FAFAFA] px-6 py-4"><p className="text-[11px] text-[#9CA3AF]">파일은 실행하지 않고 읽기 전용으로 처리한다.</p>{job.failure_reason && <p className="mt-2 text-xs text-[#B91C1C]">{job.failure_reason}</p>}<button className="mt-3 w-full rounded-md border border-[#E5E7EB] bg-white py-2 text-[13px] font-semibold text-[#374151] hover:bg-[#F3F4F6]" onClick={ended ? onReset : onCancel}>{ended ? "시작 화면으로" : "분석 취소"}</button></div>
        </article>
      </section>
    </main>
  );
}
