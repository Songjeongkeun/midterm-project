import AppHeader from "../components/AppHeader";
import StatusBadge from "../components/StatusBadge";

export default function UnsupportedScreen({ result, onReset }) {
  // 이 화면은 모델이 "정상"이라고 판단한 결과가 아니다. PE 헤더 검증 또는
  // 읽기/특징 추출에서 실패하여 모델 분석 자체를 진행하지 못한 경우에만 표시한다.
  const isUnsupported = result.status === "unsupported";
  const title = isUnsupported ? "지원하지 않는 파일 형식입니다" : "파일 분석 중 오류가 발생했습니다";
  const description = result.error_reason || (isUnsupported ? "PE 파일이 아닙니다." : "분석을 완료하지 못했습니다.");

  return (
    <main className="min-h-screen bg-[#F9FAFB] font-sans text-[#111827]">
      <AppHeader onNewAnalysis={onReset} />
      <section className="mx-auto flex min-h-[calc(100vh-53px)] max-w-[512px] items-center px-5 py-12">
        <article className="w-full overflow-hidden rounded-xl border border-[#E5E7EB] bg-white shadow-[0_1px_3px_rgba(0,0,0,0.10)]">
          <div className="border-b border-[#F3F4F6] px-6 py-5"><p className="text-xs text-[#9CA3AF]">분석 불가</p><h1 className="mt-2 text-xl font-bold">{title}</h1><p className="mt-3 truncate font-mono text-[11px] text-[#9CA3AF]">{result.filename}</p></div>
          <div className="px-6 py-5"><StatusBadge result={result} /><p className={`mt-4 rounded-md border p-3 text-sm leading-6 ${isUnsupported ? "border-[#E5E7EB] bg-[#F9FAFB] text-[#4B5563]" : "border-[#FECACA] bg-[#FEF2F2] text-[#B91C1C]"}`}>{description}</p></div>
          <div className="border-t border-[#F3F4F6] bg-[#FAFAFA] px-6 py-4"><button className="w-full rounded-md bg-[#1D4ED8] py-2 text-[13px] font-semibold text-white hover:bg-[#1E40AF]" onClick={onReset}>새 파일 또는 폴더 분석</button></div>
        </article>
      </section>
    </main>
  );
}
