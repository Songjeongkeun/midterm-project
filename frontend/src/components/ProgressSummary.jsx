const labels = [
  ["전체 탐색", "total_files"],
  ["유효 PE", "valid_pe_files"],
  ["분석 완료", "completed_files"],
  ["오류", "error_files"],
];

// 서버가 계산한 수치를 그대로 사용해, 브라우저가 진행률을 임의로 추측하지 않는다.
export default function ProgressSummary({ progress }) {
  return (
    <div className="grid grid-cols-2 divide-x divide-y divide-[#F3F4F6] overflow-hidden rounded-xl border border-[#E5E7EB] bg-white sm:grid-cols-4">
      {labels.map(([label, key]) => (
        <div key={key} className="p-3 text-center">
          <p className="text-xs text-[#6B7280]">{label}</p>
          <p className="mt-1 text-xl font-bold text-[#111827]">{progress[key]}</p>
        </div>
      ))}
    </div>
  );
}
