import AppHeader from "../components/AppHeader";
import ProgressSummary from "../components/ProgressSummary";
import ResultTable from "../components/ResultTable";

export default function FolderResultScreen({ job, onReset }) {
  return (
    <main className="min-h-screen bg-[#F9FAFB] font-sans text-[#111827]">
      <AppHeader onNewAnalysis={onReset} />
      <section className="mx-auto w-full max-w-7xl px-6 py-12 sm:px-10">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end"><div><p className="text-xs text-[#9CA3AF]">분석 결과 / 폴더</p><h1 className="mt-2 text-[30px] font-bold tracking-[-0.04em]">폴더 분석 결과</h1><p className="mt-2 text-sm text-[#6B7280]">선택한 폴더의 파일을 탐색 순서대로 표시한다.</p></div><button className="rounded-md bg-[#1D4ED8] px-4 py-2 text-[13px] font-semibold text-white hover:bg-[#1E40AF]" onClick={onReset}>+ 새 분석</button></div>
        <div className="mt-10"><ProgressSummary progress={job.progress} /></div>
        <div className="mt-4 flex flex-wrap gap-2">{Object.entries(job.class_counts).map(([label, count]) => <span key={label} className="rounded bg-white px-3 py-1.5 text-xs text-[#6B7280] shadow-sm ring-1 ring-[#E5E7EB]">{label} <b className="ml-1 text-[#111827]">{count}</b></span>)}</div>
        <div className="mt-8 flex flex-col justify-between gap-3 sm:flex-row sm:items-center"><h2 className="text-base font-bold">파일별 분석 결과</h2><p className="text-xs text-[#9CA3AF]">정렬·검색·필터·내보내기 미제공</p></div>
        <div className="mt-3"><ResultTable results={job.results} /></div>
        <div className="mt-5 rounded-lg border border-[#FDE68A] bg-[#FFFBEB] px-4 py-3 text-xs leading-5 text-[#92400E]"><b>검토 필요</b>는 모델 판정만으로 안전 또는 악성을 확정하지 않는다는 뜻이다. Normal은 1차 점수가 0.10 미만이라는 의미일 뿐이다.</div>
      </section>
    </main>
  );
}
