import AppHeader from "../components/AppHeader";
import StatusBadge from "../components/StatusBadge";

export default function UnsupportedScreen({ result, onReset }) {
  return (
    <main className="min-h-screen bg-[#F9FAFB] font-sans text-[#111827]">
      <AppHeader onNewAnalysis={onReset} />
      <section className="mx-auto flex min-h-[calc(100vh-53px)] max-w-[512px] items-center px-5 py-12">
        <article className="w-full overflow-hidden rounded-xl border border-[#E5E7EB] bg-white shadow-[0_1px_3px_rgba(0,0,0,0.10)]">
          <div className="border-b border-[#F3F4F6] px-6 py-5"><p className="text-xs text-[#9CA3AF]">분석 불가</p><h1 className="mt-2 text-xl font-bold">분석할 수 없는 파일입니다</h1><p className="mt-3 truncate font-mono text-[11px] text-[#9CA3AF]">{result.filename}</p></div>
          <div className="px-6 py-5"><StatusBadge status="unsupported_error" /><p className="mt-4 rounded-md border border-[#FECACA] bg-[#FEF2F2] p-3 text-sm leading-6 text-[#B91C1C]">{result.error_reason || "PE 파일이 아닙니다."}</p></div>
          <div className="border-t border-[#F3F4F6] bg-[#FAFAFA] px-6 py-4"><button className="w-full rounded-md bg-[#1D4ED8] py-2 text-[13px] font-semibold text-white hover:bg-[#1E40AF]" onClick={onReset}>새 파일 또는 폴더 분석</button></div>
        </article>
      </section>
    </main>
  );
}
