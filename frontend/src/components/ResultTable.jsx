import StatusBadge from "./StatusBadge";

function score(value) {
  return value === null || value === undefined ? "-" : value.toFixed(4);
}

function decisionReason(result) {
  // 오류 사유가 있으면 그대로 표시하고, 분석 성공 행에는 점수 구간 근거를 만든다.
  if (result.error_reason) return result.error_reason;
  const stage1Score = score(result.stage1_confidence);
  if (result.stage1_result === "Normal") {
    return `1차 점수 ${stage1Score}가 Normal 기준(0.10 미만)입니다. 안전을 보장하지는 않습니다.`;
  }
  if (result.stage1_result === "Suspicious") {
    return `1차 점수 ${stage1Score}가 Suspicious 구간(0.10 이상 0.90 미만)입니다. 2차 분석 대상으로 전달했습니다.`;
  }
  if (result.stage1_result === "Malware") {
    return `1차 점수 ${stage1Score}가 Malware 기준(0.90 이상)입니다. 2차 분석 대상으로 전달했습니다.`;
  }
  return "판정 근거를 만들 수 없습니다.";
}

// 표는 API가 보낸 순서로만 렌더링한다. 정렬·검색·필터 UI를 의도적으로 제공하지 않는다.
export default function ResultTable({ results }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-[#E5E7EB] bg-white shadow-sm">
      <table className="w-full min-w-[1050px] border-collapse text-left text-sm">
        <thead className="bg-[#F9FAFB] text-xs tracking-wide text-[#6B7280]">
          <tr>
            <th className="px-4 py-3">파일명</th>
            <th className="px-4 py-3">상대 경로</th>
            <th className="px-4 py-3">PE 검증</th>
            <th className="px-4 py-3">1차 분석</th>
            <th className="px-4 py-3">2차 패밀리</th>
            <th className="px-4 py-3">1차 모델 점수</th>
            <th className="px-4 py-3">상태</th>
            <th className="px-4 py-3">판정 사유</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[#F3F4F6] text-[#374151]">
          {results.map((result) => (
            <tr key={result.index}>
              <td className="max-w-52 truncate px-4 py-3 font-medium" title={result.filename}>{result.filename}</td>
              <td className="max-w-64 truncate px-4 py-3 text-[#9CA3AF]" title={result.relative_path}>{result.relative_path || "-"}</td>
              <td className="px-4 py-3">{result.pe_validation.is_valid ? "유효" : "실패"}</td>
              <td className="px-4 py-3">{result.stage1_result || "-"}</td>
              <td className="px-4 py-3">{result.family_class || "-"}</td>
              <td className="px-4 py-3">{score(result.stage1_confidence)}</td>
              <td className="px-4 py-3"><StatusBadge status={result.status} /></td>
              <td className="max-w-96 truncate px-4 py-3 text-[#6B7280]" title={decisionReason(result)}>{decisionReason(result)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
