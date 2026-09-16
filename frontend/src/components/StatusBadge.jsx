// 모든 분석 결과는 모델 판정과 무관하게 사람이 검토해야 한다는 원칙을 표시한다.
export default function StatusBadge({ status }) {
  if (status === "unsupported_error") {
    return (
      <span className="inline-flex rounded-full border border-[#B91C1C] bg-[#FEE2E2] px-2.5 py-1 text-xs font-bold text-[#B91C1C]">
        미지원·오류
      </span>
    );
  }

  return (
    <span className="inline-flex rounded-full border border-[#92400E] bg-[#FEF3C7] px-2.5 py-1 text-xs font-bold text-[#92400E]">
      검토 필요
    </span>
  );
}
