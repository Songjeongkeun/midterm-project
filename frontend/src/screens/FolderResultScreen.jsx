import ProgressSummary from "../components/ProgressSummary";
import ResultTable from "../components/ResultTable";

export default function FolderResultScreen({ job, onReset }) {
  return (
    <main className="min-h-screen bg-slate-950 px-5 py-10 text-slate-100">
      <section className="mx-auto max-w-7xl rounded-3xl border border-slate-700 bg-slate-900/70 p-6 shadow-2xl sm:p-10">
        <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-center">
          <div><p className="text-xs font-extrabold tracking-[0.18em] text-sky-300">FOLDER ANALYSIS RESULT</p><h1 className="mt-2 text-3xl font-black sm:text-4xl">폴더 분석 결과</h1></div>
          <button className="rounded-xl bg-sky-300 px-5 py-3 font-bold text-slate-950 hover:bg-sky-200" onClick={onReset}>새 분석</button>
        </div>
        <div className="mt-8"><ProgressSummary progress={job.progress} /></div>
        <div className="mt-5 flex flex-wrap gap-2">
          {Object.entries(job.class_counts).map(([label, count]) => (
            <span key={label} className="rounded-lg bg-slate-800 px-3 py-2 text-sm text-slate-200">{label} <b className="ml-1 text-white">{count}</b></span>
          ))}
        </div>
        <p className="mt-6 text-sm text-slate-400">결과는 선택 폴더의 탐색 순서입니다. 요구사항에 따라 정렬·검색·필터·내보내기 기능은 제공하지 않습니다.</p>
        <div className="mt-4"><ResultTable results={job.results} /></div>
      </section>
    </main>
  );
}
