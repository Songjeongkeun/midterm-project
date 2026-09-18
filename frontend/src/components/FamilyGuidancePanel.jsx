import { useEffect, useState } from "react";

import { getFamilyGuidance } from "../api/analysis";

function LoadingPanel() {
  return <div className="p-6 sm:p-8"><div className="rounded-xl border border-[#E2E8F0] bg-[#F8FAFC] p-6 text-base text-[#64748B]">악성 유형 안내를 불러오는 중입니다.</div></div>;
}

export default function FamilyGuidancePanel({ jobId, result }) {
  // 이 탭을 처음 열 때만 서버 제공 안내를 요청한다. 원본 파일은 다시 전송하지 않는다.
  const [state, setState] = useState({ loading: true, data: null, error: "" });

  useEffect(() => {
    let cancelled = false;
    setState({ loading: true, data: null, error: "" });
    getFamilyGuidance(jobId, result.index)
      .then((data) => {
        if (!cancelled) setState({ loading: false, data, error: "" });
      })
      .catch((error) => {
        if (!cancelled) setState({ loading: false, data: null, error: error instanceof Error ? error.message : "안내를 불러오지 못했습니다." });
      });
    return () => { cancelled = true; };
  }, [jobId, result.index]);

  if (state.loading) return <LoadingPanel />;
  if (state.error) return <div className="p-6 sm:p-8"><p className="rounded-xl border border-[#FECACA] bg-[#FFF7F7] p-5 text-base text-[#9F1239]">{state.error}</p></div>;
  if (state.data?.status !== "ready" || !state.data?.guidance) {
    return <div className="p-6 sm:p-8"><p className="rounded-xl border border-[#E2E8F0] bg-[#F8FAFC] p-5 text-base text-[#64748B]">{state.data?.reason || "이 결과에는 유형 안내가 없습니다."}</p></div>;
  }

  const { guidance } = state.data;
  return (
    <section className="p-5 sm:p-6 lg:p-8">
      <div className="rounded-xl border border-[#FDE68A] bg-gradient-to-br from-[#FFFBEB] to-white p-6 sm:p-7">
        <p className="text-sm font-semibold text-[#B45309]">서버 제공 악성 유형 안내</p>
        <h3 className="mt-2 text-2xl font-bold tracking-[-0.04em] text-[#1F2937]">{guidance.title}</h3>
        <p className="mt-3 max-w-3xl text-base leading-7 text-[#4B5563]">{guidance.description}</p>
      </div>

      <div className="mt-5 rounded-xl border border-[#E5E7EB] p-6">
        <h4 className="text-lg font-bold text-[#1F2937]">권장 대응 방안</h4>
        <ol className="mt-4 space-y-3">
          {guidance.recommended_actions.map((action, index) => (
            <li className="flex gap-3 text-base leading-6 text-[#4B5563]" key={action}>
              <span className="grid size-6 shrink-0 place-items-center rounded-full bg-[#EFF6FF] text-sm font-bold text-[#1D4ED8]">{index + 1}</span>
              <span>{action}</span>
            </li>
          ))}
        </ol>
      </div>

      <p className="mt-5 rounded-lg bg-[#F8FAFC] px-4 py-3 text-sm leading-6 text-[#64748B]">{guidance.disclaimer}</p>
    </section>
  );
}
