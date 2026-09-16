const labels = [
  ["전체 탐색", "total_files"],
  ["유효 PE", "valid_pe_files"],
  ["분석 완료", "completed_files"],
  ["오류", "error_files"],
];

// 서버가 계산한 수치를 그대로 사용해, 브라우저가 진행률을 임의로 추측하지 않는다.
export default function ProgressSummary({ progress }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      {labels.map(([label, key]) => (
        <div key={key} className="rounded-xl border border-slate-700 bg-slate-900/60 p-3 text-center">
          <p className="text-xs text-slate-400">{label}</p>
          <p className="mt-1 text-xl font-bold text-white">{progress[key]}</p>
        </div>
      ))}
    </div>
  );
}
