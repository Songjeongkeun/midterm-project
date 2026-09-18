import StatusBadge from "./StatusBadge";

// 표는 API가 보낸 순서로만 렌더링한다. 정렬·검색·필터 UI를 의도적으로 제공하지 않는다.
export default function ResultTable({ results, onViewDetails }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-[#E5E7EB] bg-white shadow-sm">
      {/* 판정 사유 열을 제거하고 남은 여덟 열의 폭을 재배분한다. 일반적인
          데스크톱 화면에서는 표 전체가 한 화면에 들어오며, 작은 화면에서만
          접근성을 위해 가로 스크롤을 허용한다. */}
      <table className="w-full min-w-[1080px] table-fixed border-collapse text-left text-sm">
        <colgroup>
          <col className="w-[230px]" />
          <col className="w-[270px]" />
          <col className="w-[75px]" />
          <col className="w-[105px]" />
          <col className="w-[155px]" />
          <col className="w-[125px]" />
          <col className="w-[120px]" />
        </colgroup>
        <thead className="bg-[#F9FAFB] text-xs tracking-wide text-[#6B7280]">
          <tr>
            <th className="whitespace-nowrap px-4 py-4">파일명</th>
            <th className="whitespace-nowrap px-4 py-4">상대 경로</th>
            <th className="whitespace-nowrap px-4 py-4">PE 검증</th>
            <th className="whitespace-nowrap px-4 py-4">1차 분석</th>
            <th className="whitespace-nowrap px-4 py-4">2차 패밀리</th>
            <th className="whitespace-nowrap px-4 py-4">상태</th>
            <th className="whitespace-nowrap px-4 py-4">상세 정보</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[#F3F4F6] text-[#374151]">
          {results.map((result) => (
            // index는 백엔드가 업로드 시 부여한 고정 순번이다. 파일명이 같아도
            // 고유하므로 React key로 사용하며, 결과 정렬은 절대 수행하지 않는다.
            <tr key={result.index}>
              <td className="truncate px-4 py-4 font-medium" title={result.filename}>{result.filename}</td>
              <td className="truncate px-4 py-4 text-[#9CA3AF]" title={result.relative_path}>{result.relative_path || "-"}</td>
              <td className="whitespace-nowrap px-4 py-4">{result.pe_validation.is_valid ? "유효" : "실패"}</td>
              <td className="whitespace-nowrap px-4 py-4">{result.stage1_result || "-"}</td>
              <td className="truncate px-4 py-4" title={result.family_class}>{result.family_class || "-"}</td>
              <td className="whitespace-nowrap px-4 py-4"><StatusBadge result={result} /></td>
              <td className="whitespace-nowrap px-4 py-4">
                {result.status === "malware_suspected" ? (
                  <button className="rounded-md border border-[#D1D5DB] bg-white px-3 py-2 text-xs font-semibold text-[#374151] transition-colors hover:bg-[#F3F4F6]" onClick={() => onViewDetails?.(result)}>
                    상세 정보 보기
                  </button>
                ) : "-"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
