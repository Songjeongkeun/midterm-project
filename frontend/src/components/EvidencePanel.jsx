function percent(value) {
  return `${(Number(value) * 100).toFixed(2)}%`;
}

function offset(value) {
  return `0x${Number(value).toString(16).toUpperCase()}`;
}

export default function EvidencePanel({ result }) {
  const regions = result.evidence_regions || [];
  const status = result.evidence_status;

  // 후보 구간 검색은 서버에서 잠시 비활성화했으므로, 빈 카드나 잘못된 설명을
  // 표시하지 않고 기능 상태를 명확히 안내한다.
  if (status === "not_applicable") {
    return (
      <section className="p-5 sm:p-6 lg:p-8">
        <div className="rounded-xl border border-[#DBEAFE] bg-[#F8FBFF] p-5 sm:p-6">
          <p className="text-lg font-bold text-[#1E3A8A]">상세 정보 준비 중</p>
          <p className="mt-2 text-sm leading-6 text-[#475569]">후보 구간을 가려 2차 모델 점수 변화를 확인하는 기능은 현재 비활성화되어 있습니다.</p>
          <p className="mt-3 text-sm leading-6 text-[#64748B]">파일의 PE 검증, 1차 분석, 2차 패밀리 분류 결과는 ‘분석 결과’ 탭에서 확인할 수 있습니다.</p>
        </div>
      </section>
    );
  }

  return (
    <section className="p-5 sm:p-6 lg:p-8">
      <div className="rounded-xl border border-[#DBEAFE] bg-[#F8FBFF] p-5">
        <p className="text-lg font-bold text-[#1E3A8A]">모델 판단 근거</p>
        <p className="mt-2 text-sm leading-6 text-[#475569]">검사한 최대 12개 후보 구간 중, 2차 모델의 예측 클래스 점수를 가장 크게 낮춘 상위 구간을 표시한다.</p>
        <div className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
          <div><p className="text-[#64748B]">파일</p><p className="mt-1 font-semibold text-[#1E293B]">{result.filename}</p></div>
          <div><p className="text-[#64748B]">예측 클래스</p><p className="mt-1 font-semibold text-[#BE123C]">{result.family_class}</p></div>
          <div><p className="text-[#64748B]">기준 예측 점수</p><p className="mt-1 font-semibold text-[#1E293B]">{percent(result.family_confidence)}</p></div>
        </div>
      </div>

      {status === "failed" && <p className="mt-5 rounded-lg border border-[#FECACA] bg-[#FFF1F2] p-4 text-sm text-[#B91C1C]">{result.evidence_error_reason || "모델 판단 근거를 만들지 못했습니다."}</p>}
      {status === "no_clear_evidence" && <p className="mt-5 rounded-lg border border-[#FDE68A] bg-[#FFFBEB] p-4 text-sm text-[#92400E]">검사한 후보 구간에서 뚜렷한 영향 구간을 찾지 못했습니다.</p>}

      <div className="mt-5 space-y-4">
        {regions.map((region, index) => (
          <article key={`${region.offset_start}-${region.offset_end}`} className="rounded-xl border border-[#E5E7EB] bg-white p-5 shadow-sm">
            <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
              <div><p className="text-sm font-semibold text-[#BE123C]">주요 영향 구간 #{index + 1}</p><p className="mt-1 font-mono text-base font-bold text-[#111827]">{offset(region.offset_start)} ~ {offset(region.offset_end)}</p></div>
              <span className="w-fit rounded-full bg-[#FFF1F2] px-3 py-1.5 text-sm font-bold text-[#BE123C]">-{(region.score_drop * 100).toFixed(2)}%p</span>
            </div>
            <dl className="mt-5 grid gap-x-8 gap-y-4 border-t border-[#F3F4F6] pt-4 text-sm sm:grid-cols-2">
              <div><dt className="text-[#6B7280]">영역</dt><dd className="mt-1 font-semibold text-[#374151]">{region.section_name || "확인 불가"}</dd></div>
              <div><dt className="text-[#6B7280]">점수 변화</dt><dd className="mt-1 font-semibold text-[#374151]">{percent(region.baseline_confidence)} → {percent(region.occluded_confidence)}</dd></div>
              <div className="sm:col-span-2"><dt className="text-[#6B7280]">관찰 내용</dt><dd className="mt-1 leading-6 text-[#374151]">{region.observation}</dd></div>
              <div className="sm:col-span-2"><dt className="text-[#6B7280]">주변 문자열</dt><dd className="mt-1 leading-6 text-[#374151]">{region.nearby_strings?.length ? region.nearby_strings.join(" · ") : "추출 가능한 문자열 없음"}</dd></div>
              <div className="sm:col-span-2"><dt className="text-[#6B7280]">해석</dt><dd className="mt-1 leading-6 text-[#374151]">{region.interpretation}</dd></div>
            </dl>
          </article>
        ))}
      </div>

      <p className="mt-6 rounded-lg border border-[#FDE68A] bg-[#FFFBEB] p-4 text-sm leading-6 text-[#92400E]">이 정보는 모델의 예측 근거를 설명하기 위한 후보이며, 파일의 악성 행위 또는 악성 여부를 확정하는 증거는 아닙니다.</p>
    </section>
  );
}
