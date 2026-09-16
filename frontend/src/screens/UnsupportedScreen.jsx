import StatusBadge from "../components/StatusBadge";

export default function UnsupportedScreen({ result, onReset }) {
  return (
    <main className="grid min-h-screen place-items-center bg-slate-950 px-5 py-12 text-slate-100">
      <section className="w-full max-w-xl rounded-3xl border border-slate-700 bg-slate-900/70 p-8 shadow-2xl sm:p-12">
        <p className="text-xs font-extrabold tracking-[0.18em] text-sky-300">UNSUPPORTED INPUT</p>
        <h1 className="mt-3 text-3xl font-black">분석할 수 없는 파일입니다</h1>
        <p className="mt-5 break-all font-bold">{result.filename}</p>
        <div className="mt-5"><StatusBadge status="unsupported_error" /></div>
        <p className="mt-5 rounded-lg bg-[#FEE2E2] p-4 leading-6 text-[#B91C1C]">{result.error_reason || "유효한 PE 파일이 아닙니다."}</p>
        <button className="mt-8 rounded-xl bg-sky-300 px-5 py-3 font-bold text-slate-950 hover:bg-sky-200" onClick={onReset}>시작 화면으로</button>
      </section>
    </main>
  );
}
