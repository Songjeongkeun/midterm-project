// Figma의 공통 상단 바를 모든 분석 상태에서 재사용한다.
export default function AppHeader({ onNewAnalysis }) {
  return (
    <header className="flex h-[53px] items-center justify-between border-b border-[#E5E7EB] bg-white px-5">
      <div className="flex items-center gap-2.5">
        <span className="grid size-6 place-items-center rounded bg-linear-to-br from-[#1D4ED8] to-[#4F46E5]">
          <img className="size-3" src="/figma-assets/brand-shield.svg" alt="" />
        </span>
        <span className="text-[13px] font-bold tracking-[-0.02em] text-[#111827]">PE 악성코드 분석기</span>
        <span className="rounded bg-[#F3F4F6] px-1.5 py-0.5 text-[10px] text-[#6B7280]">v1.0</span>
      </div>
      <button className="rounded border border-[#E5E7EB] bg-[#F3F4F6] px-3 py-1.5 text-xs text-[#374151] hover:bg-[#E5E7EB]" onClick={onNewAnalysis}>
        + 새 분석
      </button>
    </header>
  );
}
