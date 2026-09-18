import { useState } from "react";

import AppHeader from "../components/AppHeader";
import FamilyGuidancePanel from "../components/FamilyGuidancePanel";
import GeminiExpertAdvicePanel from "../components/GeminiExpertAdvicePanel";
import StatusBadge from "../components/StatusBadge";

function probability(value) {
  // XGBoost의 0~1 출력값을 사용자가 읽기 쉬운 백분율로 바꾼다. 이 값은
  // 별도의 확률 보정(calibration)을 거치지 않은 모델 추정치라는 점을 UI에 함께 알린다.
  return value === null || value === undefined ? "-" : `${(value * 100).toFixed(2)}%`;
}

function stageTone(result) {
  // 색은 최종 확정 판정이 아니라 1차 모델의 라우팅 결과를 구분하는 보조 수단이다.
  if (result === "Normal") return "border-[#BBF7D0] bg-[#F0FDF4] text-[#166534]";
  if (result === "Malware") return "border-[#FECDD3] bg-[#FFF1F2] text-[#9F1239]";
  return "border-[#FDE68A] bg-[#FFFBEB] text-[#92400E]";
}

function stageDescription(result) {
  // 1차 모델 결과를 점수 임계값과 함께 짧게 해석해 표시한다.
  if (result === "Normal") return "1차 점수가 Normal 기준(0.10 미만)입니다.";
  if (result === "Malware") return "1차 점수가 Malware 기준(0.90 이상)입니다.";
  return "1차 점수가 추가 확인 구간(0.10 이상 0.90 미만)입니다.";
}

function stageTheme(result) {
  // 1차 결과의 의미는 유지하면서 카드 배경/아이콘만 결과별로 바꾼다.
  if (result === "Malware") {
    return { card: "border-[#FECACA] bg-gradient-to-br from-[#FFF7F7] to-[#FFF1F2]", icon: "bg-[#FEE2E2] text-[#BE123C]", value: "text-[#BE123C]" };
  }
  if (result === "Suspicious") {
    return { card: "border-[#FDE68A] bg-gradient-to-br from-[#FFFBEB] to-[#FFF7ED]", icon: "bg-[#FEF3C7] text-[#B45309]", value: "text-[#B45309]" };
  }
  return { card: "border-[#BFDBFE] bg-gradient-to-br from-[#F0F7FF] to-[#EFF6FF]", icon: "bg-[#DBEAFE] text-[#1D4ED8]", value: "text-[#1D4ED8]" };
}

function CardIcon({ type, className }) {
  // 외부 아이콘 라이브러리 없이 인라인 SVG를 써서 결과 카드의 시각적 구분을 준다.
  const paths = {
    check: <path d="m5 12 4 4L19 6" />,
    alert: <><path d="M12 8v4" /><path d="M12 16h.01" /><path d="m10.3 3.6-7 12.1A2 2 0 0 0 5 18.7h14a2 2 0 0 0 1.7-3l-7-12.1a2 2 0 0 0-3.4 0Z" /></>,
    shield: <path d="M12 3 5 6v5c0 4.6 3 8 7 10 4-2 7-5.4 7-10V6l-7-3Z" />,
  };
  return <span className={`grid size-11 shrink-0 place-items-center rounded-full ${className}`}><svg className="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.3" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[type]}</svg></span>;
}

function MetricCard({ label, hint, icon, iconClassName, badge, children, className = "", contentClassName = "" }) {
  // 카드 헤더를 아이콘·제목·배지로 통일해 세 결과의 중요도를 한눈에 비교한다.
  return (
    <section className={`flex min-h-[300px] flex-col rounded-xl border p-6 sm:p-7 ${className}`}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <CardIcon type={icon} className={iconClassName} />
          <div>
            <p className="text-lg font-bold tracking-[-0.03em] text-[#1F2937]">{label}</p>
            {hint && <p className="mt-0.5 text-xs text-[#6B7280]">{hint}</p>}
          </div>
        </div>
        {badge}
      </div>
      <div className={`mt-6 ${contentClassName}`}>{children}</div>
    </section>
  );
}

export default function SingleResultScreen({ jobId, result, onReset, onBack }) {
  // 이 화면은 유효한 단일 PE 결과만 받는다. 비-PE/오류 행은 App.jsx에서
  // UnsupportedScreen으로 분기되어 분석 불가 사유를 별도로 보여준다.
  const isNormal = result.stage1_result === "Normal";
  const familyName = String(result.family_class || "").trim();
  const normalizedFamily = familyName.toLowerCase();
  const isConflict = !isNormal && normalizedFamily === "benign";
  const isUncertain = !isNormal && (result.is_unknown || !normalizedFamily || normalizedFamily === "unknown");
  const firstStageTheme = stageTheme(result.stage1_result);
  // benign은 악성 패밀리명으로 표시하지 않고 1·2차 모델의 판정 충돌로 표현한다.
  const stage2Theme = isConflict
    ? { card: "border-[#FDE68A] bg-gradient-to-br from-[#FFFBEB] to-[#FFF7ED]", icon: "bg-[#FEF3C7] text-[#B45309]", value: "text-[#92400E]" }
    : isUncertain
      ? { card: "border-[#D6D3D1] bg-gradient-to-br from-[#FAFAF9] to-[#F5F5F4]", icon: "bg-[#E7E5E4] text-[#57534E]", value: "text-[#44403C]" }
      : { card: "border-[#FECACA] bg-gradient-to-br from-[#FFF7F7] to-[#FFF1F2]", icon: "bg-[#FEE2E2] text-[#BE123C]", value: "text-[#BE123C]" };
  // 정상·분석 불가 행에는 조언 탭을 보이지 않는다. 위험 의심·판정 충돌·유형
  // 불확실 행만 서버 제공 안내와 Gemini 조언을 추가로 확인할 수 있다.
  const showAdvisoryTabs = ["malware_suspected", "conflict", "uncertain"].includes(result.status);
  // 폴더 표의 상세 정보 버튼도 우선 기존 분석 결과를 보여 준다.
  const [activeTab, setActiveTab] = useState("result");
  const returnToPrevious = onBack || onReset;

  return (
    <main className="min-h-screen bg-[#F9FAFB] font-sans text-[#111827]">
      <AppHeader onNewAnalysis={onReset} />

      <section className="mx-auto w-full max-w-6xl px-5 py-9 sm:px-8 lg:py-12">
        <div className="flex items-center gap-2 text-sm text-[#9CA3AF]">
          <button className="font-medium text-[#6B7280] hover:text-[#1D4ED8]" onClick={returnToPrevious}>← {onBack ? "폴더 결과" : "새 분석"}</button>
          <span>/</span>
          <span>단일 파일 결과</span>
        </div>

        <div className="mt-4 flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
          <div>
            <p className="text-sm text-[#9CA3AF]">분석 결과 / 단일 파일</p>
            <h1 className="mt-2 text-[32px] font-bold tracking-[-0.04em] text-[#111827]">파일 분석 결과</h1>
            <p className="mt-2 text-base text-[#6B7280]">PE 구조 검증과 모델 분석 결과를 함께 확인한다.</p>
          </div>
          <StatusBadge result={result} />
        </div>

        <article className="mt-7 overflow-hidden rounded-2xl border border-[#E5E7EB] bg-white shadow-[0_12px_30px_rgba(15,23,42,0.06)]">
          <header className="flex flex-col gap-4 border-b border-[#E5E7EB] px-6 py-7 sm:flex-row sm:items-center sm:justify-between sm:px-8">
            <div className="flex min-w-0 items-center gap-4">
              <span className="grid size-14 shrink-0 place-items-center rounded-xl bg-[#EFF6FF] text-base font-bold text-[#1D4ED8]">PE</span>
              <div className="min-w-0">
                <p className="text-sm font-medium text-[#6B7280]">분석 대상 파일</p>
                <h2 className="mt-1 truncate text-2xl font-bold tracking-[-0.03em]">{result.filename}</h2>
                <p className="mt-1 truncate font-mono text-sm text-[#9CA3AF]" title={result.relative_path || result.filename}>{result.relative_path || result.filename}</p>
              </div>
            </div>
          </header>

          {showAdvisoryTabs && <nav className="border-b border-[#E5E7EB] bg-[#F8FAFC] px-5 py-3 sm:px-8" aria-label="파일 결과 탭">
            <div className="grid w-full grid-cols-3 rounded-lg border border-[#E5E7EB] bg-white p-1 sm:w-[520px]">
              <button className={`rounded-md px-4 py-2.5 text-sm font-semibold transition-colors ${activeTab === "result" ? "bg-[#1D4ED8] text-white shadow-sm" : "text-[#64748B] hover:bg-[#F1F5F9] hover:text-[#334155]"}`} onClick={() => setActiveTab("result")}>분석 결과</button>
              <button className={`rounded-md px-4 py-2.5 text-sm font-semibold transition-colors ${activeTab === "guidance" ? "bg-[#1D4ED8] text-white shadow-sm" : "text-[#64748B] hover:bg-[#F1F5F9] hover:text-[#334155]"}`} onClick={() => setActiveTab("guidance")}>악성 유형 안내</button>
              <button className={`rounded-md px-4 py-2.5 text-sm font-semibold transition-colors ${activeTab === "expert" ? "bg-[#1D4ED8] text-white shadow-sm" : "text-[#64748B] hover:bg-[#F1F5F9] hover:text-[#334155]"}`} onClick={() => setActiveTab("expert")}>AI 전문가 조언</button>
            </div>
          </nav>}

          {activeTab === "result" ? <div className="grid gap-5 p-6 sm:p-8 lg:grid-cols-12 lg:p-8">
            <MetricCard label="PE 검증" hint="헤더 구조 확인" icon="check" iconClassName="bg-[#DCFCE7] text-[#15803D]" className={`bg-gradient-to-br from-[#F2FCF6] to-[#ECFDF5] ${isNormal ? "lg:col-span-4" : "lg:col-span-3"}`} contentClassName="flex flex-1 flex-col">
              <p className="text-2xl font-bold tracking-[-0.04em] text-[#15803D]">유효한 PE 파일</p>
              <div className="mt-auto grid min-h-[96px] grid-cols-[auto_1fr] content-start items-center gap-x-4 gap-y-3 border-t border-[#BBE8CF] pt-4 text-sm">
                <span className="whitespace-nowrap text-[#6B7280]">아키텍처</span><span className="justify-self-end whitespace-nowrap font-semibold text-[#374151]">{result.pe_validation.machine || "Unknown"}</span>
                <span className="whitespace-nowrap text-[#6B7280]">파일 형식</span><span className="justify-self-end whitespace-nowrap font-semibold text-[#374151]">Windows PE</span>
              </div>
            </MetricCard>

            <MetricCard label="1차 분석 결과" hint="XGBoost 정적 특징 분석" icon="alert" iconClassName={firstStageTheme.icon} badge={<span className={`rounded-full border px-3 py-1 text-sm font-bold ${stageTone(result.stage1_result)}`}>{result.stage1_result}</span>} className={`${firstStageTheme.card} ${isNormal ? "lg:col-span-8" : "lg:col-span-5"}`} contentClassName="flex flex-1 flex-col">
              <div className="flex flex-1 flex-col items-center justify-center gap-1 text-center">
                {!isNormal && <div className="text-center">
                  <p className="text-sm font-medium text-[#6B7280]">모델 추정 악성 확률</p>
                  <p className={`mt-1 text-4xl font-bold tracking-[-0.05em] ${firstStageTheme.value}`}>{probability(result.stage1_confidence)}</p>
                </div>}
                {isNormal && <p className={`text-2xl font-bold tracking-[-0.04em] ${firstStageTheme.value}`}>정상 범위</p>}
              </div>
              <div className="min-h-[96px] border-t border-black/10 pt-4">
                <p className="text-sm leading-6 text-[#4B5563]">{stageDescription(result.stage1_result)}</p>
                {!isNormal && <p className="mt-2 text-xs leading-5 text-[#6B7280]">표시된 확률은 1차 모델 점수를 백분율로 환산한 추정값이며, 확정 판정이 아닙니다.</p>}
              </div>
            </MetricCard>

            {!isNormal && <MetricCard
              label={isConflict ? "판정 충돌" : isUncertain ? "분류 불확실" : "2차 패밀리 분류"}
              hint={isConflict ? "1차·2차 결과 불일치" : isUncertain ? "2차 유형 특정 불가" : "MalConv2 패밀리 분류"}
              icon="shield"
              iconClassName={stage2Theme.icon}
              className={`${stage2Theme.card} lg:col-span-4`}
              contentClassName="flex flex-1 flex-col"
            >
              {isConflict ? (
                <>
                  <div className="flex flex-1 items-center justify-center text-center"><p className={`text-2xl font-bold tracking-[-0.04em] ${stage2Theme.value}`}>모델 결과가 일치하지 않습니다.</p></div>
                  <p className="min-h-[96px] border-t border-[#FDE68A] pt-4 text-sm leading-6 text-[#57534E]">1차 모델은 위험 구간으로 분류했지만, 2차 모델의 최고 클래스는 benign입니다.</p>
                </>
              ) : isUncertain ? (
                <>
                  <div className="flex flex-1 items-center justify-center text-center"><p className={`text-2xl font-bold tracking-[-0.04em] ${stage2Theme.value}`}>유형을 특정하지 못했습니다.</p></div>
                  <p className="min-h-[96px] border-t border-[#D6D3D1] pt-4 text-sm leading-6 text-[#57534E]">2차 점수가 임계값에 미달했거나 분류 결과가 없어 특정 악성 유형을 표시하지 않습니다.</p>
                </>
              ) : (
                <>
                  <div className="flex flex-1 flex-col items-center justify-center text-center">
                    <p className={`text-3xl font-bold tracking-[-0.04em] ${stage2Theme.value}`}>{familyName}</p>
                    <p className="mt-3 text-base font-medium text-[#4B5563]">예측 신뢰도 <b className={`ml-1 ${stage2Theme.value}`}>{probability(result.family_confidence)}</b></p>
                  </div>
                  <p className="min-h-[96px] border-t border-[#FECACA] pt-4 text-sm leading-6 text-[#6B7280]">1·2차 모델이 모두 위험 방향의 결과를 보였습니다.</p>
                </>
              )}
            </MetricCard>}
          </div> : activeTab === "guidance"
            ? <FamilyGuidancePanel jobId={jobId} result={result} />
            : <GeminiExpertAdvicePanel jobId={jobId} result={result} />}

          <footer className="flex flex-col gap-3 border-t border-[#E5E7EB] bg-[#FAFAFA] px-6 py-5 sm:flex-row sm:items-center sm:justify-between sm:px-8">
            <p className="text-sm text-[#9CA3AF]">파일을 실행하거나 수정하지 않았으며, 업로드한 원본은 분석 후 삭제됩니다.</p>
            <button className="shrink-0 rounded-md bg-[#1D4ED8] px-5 py-3 text-sm font-semibold text-white hover:bg-[#1E40AF]" onClick={onReset}>새 분석</button>
          </footer>
        </article>
      </section>
    </main>
  );
}
