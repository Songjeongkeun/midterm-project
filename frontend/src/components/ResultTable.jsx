import StatusBadge from "./StatusBadge";

function percent(value) {
  return value === null || value === undefined ? "-" : `${(value * 100).toFixed(1)}%`;
}

// 표는 API가 보낸 순서로만 렌더링한다. 정렬·검색·필터 UI를 의도적으로 제공하지 않는다.
export default function ResultTable({ results }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-700">
      <table className="w-full min-w-[1050px] border-collapse text-left text-sm">
        <thead className="bg-slate-900 text-xs uppercase tracking-wide text-sky-200">
          <tr>
            <th className="px-4 py-3">파일명</th>
            <th className="px-4 py-3">상대 경로</th>
            <th className="px-4 py-3">PE 검증</th>
            <th className="px-4 py-3">1차 분석</th>
            <th className="px-4 py-3">2차 패밀리</th>
            <th className="px-4 py-3">점수</th>
            <th className="px-4 py-3">상태</th>
            <th className="px-4 py-3">사유</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800 bg-slate-950/40 text-slate-200">
          {results.map((result) => (
            <tr key={result.index}>
              <td className="max-w-52 truncate px-4 py-3 font-medium" title={result.filename}>{result.filename}</td>
              <td className="max-w-64 truncate px-4 py-3 text-slate-400" title={result.relative_path}>{result.relative_path || "-"}</td>
              <td className="px-4 py-3">{result.pe_validation.is_valid ? "유효" : "실패"}</td>
              <td className="px-4 py-3">{result.stage1_result || "-"}</td>
              <td className="px-4 py-3">{result.family_class || "-"}</td>
              <td className="px-4 py-3">{percent(result.family_confidence ?? result.stage1_confidence)}</td>
              <td className="px-4 py-3"><StatusBadge status={result.status} /></td>
              <td className="max-w-72 truncate px-4 py-3 text-slate-400" title={result.error_reason}>{result.error_reason || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
