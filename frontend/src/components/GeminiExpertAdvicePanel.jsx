import { useEffect, useState } from "react";

import { requestExpertAdvice } from "../api/analysis";

function AdviceList({ title, items, tone }) {
  return (
    <section className={`rounded-xl border p-5 ${tone}`}>
      <h4 className="text-lg font-bold text-[#1F2937]">{title}</h4>
      <ul className="mt-3 space-y-2.5">
        {items.map((item) => <li className="flex gap-2.5 text-base leading-6 text-[#4B5563]" key={item}><span className="mt-2 size-1.5 shrink-0 rounded-full bg-current" />{item}</li>)}
      </ul>
    </section>
  );
}

export default function GeminiExpertAdvicePanel({ jobId, result }) {
  // 탭을 열면 자동으로 한 번 요청한다. 서버가 같은 작업·파일의 결과를 캐시한다.
  const [state, setState] = useState({ loading: true, data: null, error: "" });

  async function load(refresh = false) {
    setState((previous) => ({ ...previous, loading: true, error: "" }));
    try {
      const data = await requestExpertAdvice(jobId, result.index, refresh);
      setState({ loading: false, data, error: "" });
    } catch (error) {
      setState({ loading: false, data: null, error: error instanceof Error ? error.message : "AI 전문가 조언을 불러오지 못했습니다." });
    }
  }

  useEffect(() => { load(); }, [jobId, result.index]);

  if (state.loading) {
    return <div className="p-6 sm:p-8"><div className="rounded-xl border border-[#DBEAFE] bg-[#F8FBFF] p-6 text-base text-[#1D4ED8]">Gemini Flash가 분석 결과를 바탕으로 방어적 조언을 정리하고 있습니다.</div></div>;
  }
  if (state.error) {
    return <div className="p-6 sm:p-8"><div className="rounded-xl border border-[#FECACA] bg-[#FFF7F7] p-6"><p className="text-base text-[#9F1239]">{state.error}</p><button className="mt-4 rounded-md border border-[#CBD5E1] bg-white px-4 py-2 text-sm font-semibold text-[#334155] hover:bg-[#F8FAFC]" onClick={() => load(true)}>다시 시도</button></div></div>;
  }
  if (state.data?.status === "unavailable") {
    return <div className="p-6 sm:p-8"><div className="rounded-xl border border-[#FDE68A] bg-[#FFFBEB] p-6"><h3 className="text-lg font-bold text-[#92400E]">AI 전문가 조언을 사용할 수 없습니다.</h3><p className="mt-2 text-base leading-6 text-[#78350F]">{state.data.reason || "Gemini 설정을 확인하세요."}</p><p className="mt-4 rounded-lg bg-white/70 px-4 py-3 font-mono text-sm text-[#92400E]">backend/.env에 GEMINI_API_KEY를 설정한 뒤 백엔드를 다시 시작하세요.</p></div></div>;
  }
  if (state.data?.status === "failed" || !state.data?.advice) {
    return <div className="p-6 sm:p-8"><div className="rounded-xl border border-[#FECACA] bg-[#FFF7F7] p-6"><p className="text-base text-[#9F1239]">{state.data?.reason || "AI 전문가 조언을 만들지 못했습니다."}</p><button className="mt-4 rounded-md border border-[#CBD5E1] bg-white px-4 py-2 text-sm font-semibold text-[#334155] hover:bg-[#F8FAFC]" onClick={() => load(true)}>다시 생성</button></div></div>;
  }

  const { advice } = state.data;
  return (
    <section className="p-5 sm:p-6 lg:p-8">
      <div className="flex flex-col justify-between gap-4 rounded-xl border border-[#DBEAFE] bg-gradient-to-br from-[#F8FBFF] to-white p-6 sm:flex-row sm:items-start">
        <div>
          <p className="text-sm font-semibold text-[#1D4ED8]">AI 전문가 조언 · {state.data.provider || "Gemini"}</p>
          <h3 className="mt-2 text-2xl font-bold tracking-[-0.04em] text-[#1F2937]">분석 결과 기반 보안 조언</h3>
          <p className="mt-3 max-w-3xl text-base leading-7 text-[#4B5563]">{advice.summary}</p>
        </div>
        <button className="shrink-0 rounded-md border border-[#CBD5E1] bg-white px-4 py-2.5 text-sm font-semibold text-[#334155] hover:bg-[#F8FAFC]" onClick={() => load(true)}>다시 생성</button>
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-3">
        <AdviceList title="지금 확인할 항목" items={advice.immediate_checks} tone="border-[#FDE68A] bg-[#FFFBEB] text-[#92400E]" />
        <AdviceList title="예방 방법" items={advice.prevention_tips} tone="border-[#BFDBFE] bg-[#F8FBFF] text-[#1D4ED8]" />
        <AdviceList title="실행했다면" items={advice.response_if_executed} tone="border-[#FECACA] bg-[#FFF7F7] text-[#9F1239]" />
      </div>

      <p className="mt-5 rounded-lg bg-[#F8FAFC] px-4 py-3 text-sm leading-6 text-[#64748B]">{advice.disclaimer}</p>
    </section>
  );
}
