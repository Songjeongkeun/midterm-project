import AppHeader from "../components/AppHeader";
import StatusBadge from "../components/StatusBadge";

function score(value) {
  return value === null || value === undefined ? "-" : value.toFixed(4);
}

function StageBadge({ result, value }) {
  const tones = {
    Normal: "border-[#166534] bg-[#F0FDF4] text-[#166534]",
    Suspicious: "border-[#92400E] bg-[#FFFBEB] text-[#92400E]",
    Malware: "border-[#9F1239] bg-[#FFF1F2] text-[#9F1239]",
  };
  return <span className={`inline-flex rounded-full border px-2 py-0.5 text-[11px] font-semibold ${tones[result] || tones.Suspicious}`}>{result} <span className="ml-1 opacity-70">{score(value)}</span></span>;
}

export default function SingleResultScreen({ result, onReset }) {
  return (
    <main className="min-h-screen bg-[#F9FAFB] font-sans text-[#111827]">
      <AppHeader onNewAnalysis={onReset} />
      <section className="mx-auto flex min-h-[calc(100vh-53px)] w-full max-w-[512px] flex-col justify-center px-5 py-12">
        <div className="flex items-center gap-2 text-xs text-[#9CA3AF]"><button className="text-[#6B7280] hover:text-[#1D4ED8]" onClick={onReset}>← 새 분석</button><span>/</span><span>단일 파일 결과</span></div>
        <article className="mt-5 overflow-hidden rounded-xl border border-[#E5E7EB] bg-white shadow-[0_1px_3px_rgba(0,0,0,0.10)]">
          <div className="flex items-start justify-between border-b border-[#F3F4F6] px-6 py-5">
            <div className="min-w-0"><h1 className="truncate text-[15px] font-bold">{result.filename}</h1><p className="mt-1 truncate font-mono text-[11px] text-[#9CA3AF]">{result.relative_path || result.filename}</p></div>
            <StatusBadge status={result.status} />
          </div>
          <ResultRow label="PE 검증 결과"><span className="font-semibold text-[#166534]">✓ 유효한 PE 파일</span><span className="ml-2 text-[#9CA3AF]">{result.pe_validation.machine}</span></ResultRow>
          <div className="px-6 py-4">
            <div className="flex items-center border-b border-[#F9FAFB] pb-3"><div className="w-32"><p className="text-xs text-[#6B7280]">1차 분석 결과</p><p className="text-[10px] text-[#D1D5DB]">Normal / Suspicious / Malware</p></div><StageBadge result={result.stage1_result} value={result.stage1_confidence} /></div>
            <div className="flex items-center pt-3"><div className="w-32"><p className="text-xs text-[#6B7280]">악성코드 패밀리</p><p className="text-[10px] text-[#D1D5DB]">2차 분류 결과</p></div><span className="rounded border border-[#FCA5A5] bg-[#FEF2F2] px-2 py-0.5 text-[11px] font-semibold text-[#7F1D1D]">{result.family_class || "해당 없음"}{result.family_confidence !== null && result.family_confidence !== undefined ? ` · ${score(result.family_confidence)}` : ""}</span></div>
          </div>
          <div className="border-t border-[#F3F4F6] bg-[#FAFAFA] px-6 py-4"><p className="text-[11px] leading-5 text-[#9CA3AF]">※ 검토 필요는 모델 결과만으로 파일의 안전 또는 악성을 확정하지 않는다는 뜻이다. 2차 패밀리 분류는 현재 Mock 단계다.</p><button className="mt-3 w-full rounded-md bg-[#1D4ED8] py-2 text-[13px] font-semibold text-white hover:bg-[#1E40AF]" onClick={onReset}>새 파일 또는 폴더 분석</button></div>
        </article>
      </section>
    </main>
  );
}

function ResultRow({ label, children }) {
  return <div className="flex items-center border-b border-[#F3F4F6] px-6 py-4 text-xs"><span className="w-32 text-[#6B7280]">{label}</span><span>{children}</span></div>;
}
