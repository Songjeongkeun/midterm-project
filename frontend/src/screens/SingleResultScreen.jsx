import StatusBadge from "../components/StatusBadge";

function percent(value) {
  return value === null || value === undefined ? "-" : `${(value * 100).toFixed(1)}%`;
}

function Detail({ label, children }) {
  return <div className="rounded-xl border border-slate-700 bg-slate-900/55 p-4"><dt className="text-xs text-slate-400">{label}</dt><dd className="mt-1 break-all font-bold text-slate-100">{children}</dd></div>;
}

export default function SingleResultScreen({ result, onReset }) {
  return (
    <main className="grid min-h-screen place-items-center bg-slate-950 px-5 py-12 text-slate-100">
      <section className="w-full max-w-3xl rounded-3xl border border-slate-700 bg-slate-900/70 p-8 shadow-2xl sm:p-12">
        <p className="text-xs font-extrabold tracking-[0.18em] text-sky-300">ANALYSIS RESULT</p>
        <h1 className="mt-3 text-3xl font-black sm:text-4xl">단일 파일 분석 결과</h1>
        <dl className="mt-8 grid gap-3 sm:grid-cols-2">
          <Detail label="파일명">{result.filename}</Detail>
          <Detail label="파일 경로">{result.relative_path || result.filename}</Detail>
          <Detail label="PE 검증">유효 · {result.pe_validation.machine || "알 수 없는 머신"}</Detail>
          <Detail label="1차 분석">{result.stage1_result} · {percent(result.stage1_confidence)}</Detail>
          <Detail label="2차 패밀리">{result.family_class || "해당 없음"}</Detail>
          <Detail label="2차 점수">{result.is_unknown ? "Unknown (임계값 미달)" : percent(result.family_confidence)}</Detail>
        </dl>
        <div className="mt-6"><StatusBadge status={result.status} /></div>
        <p className="mt-5 leading-7 text-slate-400">이 결과는 더미 모델 인터페이스의 예측 흐름입니다. 실제 모델을 연결한 뒤에도 Normal 판정은 안전을 보장하지 않으므로 검토가 필요합니다.</p>
        <button className="mt-8 rounded-xl bg-sky-300 px-5 py-3 font-bold text-slate-950 hover:bg-sky-200" onClick={onReset}>새 분석</button>
      </section>
    </main>
  );
}
