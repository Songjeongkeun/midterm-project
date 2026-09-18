// API의 내부 상태와 1·2차 모델 값을 조합해 화면에 보여 줄 최종 상태를 만든다.
// `review_required`는 이전 API 호환용 내부 값이므로 사용자 화면에는 표시하지 않는다.
export function getDisplayStatus(result) {
  if (result.status === "unsupported") return "unsupported";
  if (result.status === "error") return "error";
  // 실제 2차 모델이 연결된 뒤에는 백엔드가 같은 정책으로 최종 상태를
  // 계산한다. 이 분기를 우선해 API와 화면의 상태 규칙이 어긋나지 않게 한다.
  if (result.status === "normal") return "normal";
  if (result.status === "malware_suspected") return "malware-suspected";
  if (result.status === "conflict") return "conflict";
  if (result.status === "uncertain") return "uncertain";

  // 이전 분석 결과(review_required)를 열었을 때도 화면이 깨지지 않도록
  // 아래 계산은 하위 호환용으로 남긴다.
  if (result.stage1_result === "Normal") return "normal";

  const family = String(result.family_class || "").trim().toLowerCase();
  // 1차는 위험으로 보았지만 2차 최고 클래스가 benign이면 두 결과가 충돌한다.
  if (family === "benign") return "conflict";
  // 2차가 유형을 특정하지 못했거나 임계값 미달로 Unknown이면 불확실 상태다.
  if (result.is_unknown || !family || family === "unknown") return "uncertain";
  return "malware-suspected";
}

const badgeStyles = {
  unsupported: "border-[#9CA3AF] bg-[#F3F4F6] text-[#4B5563]",
  error: "border-[#B91C1C] bg-[#FEE2E2] text-[#B91C1C]",
  normal: "border-[#86EFAC] bg-[#F0FDF4] text-[#166534]",
  conflict: "border-[#F59E0B] bg-[#FFFBEB] text-[#92400E]",
  uncertain: "border-[#A8A29E] bg-[#FAFAF9] text-[#57534E]",
  "malware-suspected": "border-[#FDA4AF] bg-[#FFF1F2] text-[#BE123C]",
};

const badgeLabels = {
  unsupported: "미지원",
  error: "오류",
  normal: "Normal",
  conflict: "판정 충돌",
  uncertain: "분류 불확실",
  "malware-suspected": "악성 유형 의심",
};

export default function StatusBadge({ result }) {
  const displayStatus = getDisplayStatus(result);
  return <span className={`inline-flex shrink-0 whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-bold ${badgeStyles[displayStatus]}`}>{badgeLabels[displayStatus]}</span>;
}
