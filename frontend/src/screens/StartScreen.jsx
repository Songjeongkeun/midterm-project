import { useEffect, useRef } from "react";

import AppHeader from "../components/AppHeader";

export default function StartScreen({ onSingleFile, onFolder, message }) {
  // 실제 input은 숨기고, Figma 스타일 버튼이 click()으로 파일 선택 창을 연다.
  // 이렇게 하면 브라우저의 기본 파일 input 모양에 디자인이 종속되지 않는다.
  const fileInput = useRef(null);
  const folderInput = useRef(null);

  useEffect(() => {
    // 폴더 선택은 표준 HTML 속성이 아니라 Chromium 계열의 webkitdirectory
    // 확장 기능이다. 지원 브라우저에서는 하위 폴더 파일도 FileList로 받는다.
    const input = folderInput.current;
    input?.setAttribute("webkitdirectory", "");
    input?.setAttribute("directory", "");
  }, []);

  function pickSingle(event) {
    // 같은 파일을 다시 고를 수 있도록 처리 직후 input 값을 비운다.
    const file = event.target.files?.[0];
    event.target.value = "";
    if (file) onSingleFile(file);
  }

  function pickFolder(event) {
    // FileList는 배열이 아니므로 API 전송 전에 일반 배열로 변환한다.
    const files = Array.from(event.target.files || []);
    event.target.value = "";
    if (files.length) onFolder(files);
  }

  return (
    <main className="min-h-screen bg-[#F9FAFB] font-sans text-[#111827]">
      <AppHeader onNewAnalysis={() => fileInput.current?.click()} />
      <section className="mx-auto w-full max-w-7xl px-6 pb-16 pt-14 sm:px-10">
        <p className="text-xs text-[#9CA3AF]">새 분석</p>
        <h1 className="mt-3 text-[30px] font-bold tracking-[-0.04em]">PE 파일 정적 분석</h1>
        <p className="mt-2 text-sm text-[#6B7280]">파일을 실행하지 않고 PE 구조와 모델 점수를 읽기 전용으로 분석한다.</p>

        <div className="mt-10 grid gap-5 lg:grid-cols-2">
          <ChoiceCard index="01" eyebrow="SINGLE FILE" title="단일 파일 분석" description="Windows PE 파일 한 개의 검증 및 모델 분석 결과를 확인한다." button="파일 선택" onClick={() => fileInput.current?.click()} />
          <ChoiceCard index="02" eyebrow="FOLDER" title="폴더 분석" description="선택한 폴더 안의 파일을 탐색 순서대로 일괄 분석한다." button="폴더 선택" onClick={() => folderInput.current?.click()} />
        </div>

        <input ref={fileInput} type="file" hidden onChange={pickSingle} />
        <input ref={folderInput} type="file" hidden multiple onChange={pickFolder} />
        {message && <p className="mt-5 rounded-md border border-[#FCA5A5] bg-[#FEF2F2] p-3 text-sm text-[#B91C1C]">{message}</p>}


        <div className="mt-10 grid gap-3 md:grid-cols-3">
          <Scope label="PE 형식 검증" value="MZ · PE 헤더 · COFF 정보" />
          <Scope label="1차 분류" value="XGBoost 정적 특징 분석" />
          <Scope label="결과 해석" value="정상 · 의심 · 충돌 · 오류 상태 표시" />
        </div>
      </section>
    </main>
  );
}

function ChoiceCard({ index, eyebrow, title, description, button, onClick }) {
  // 단일/폴더 선택은 데이터만 다르고 카드 UI 구조가 같아서 공통 컴포넌트로 둔다.
  return (
    <article className="rounded-xl border border-[#E5E7EB] bg-white p-8 shadow-[0_1px_3px_rgba(0,0,0,0.08)]">
      <span className="grid size-10 place-items-center rounded-md bg-[#EFF6FF] text-sm font-bold text-[#1D4ED8]">{index}</span>
      <p className="mt-5 text-[11px] font-semibold tracking-[0.12em] text-[#9CA3AF]">{eyebrow}</p>
      <h2 className="mt-1 text-xl font-bold tracking-[-0.03em]">{title}</h2>
      <p className="mt-2 text-sm leading-6 text-[#6B7280]">{description}</p>
      <button className="mt-5 rounded bg-[#1D4ED8] px-4 py-2 text-[13px] font-semibold text-white hover:bg-[#1E40AF]" onClick={onClick}>{button}</button>
    </article>
  );
}

function Scope({ label, value }) {
  // 시작 화면 하단의 분석 범위 안내 카드. 클릭/분석 기능은 없다.
  return <div className="rounded-lg border border-[#E5E7EB] bg-white p-4"><p className="text-xs text-[#9CA3AF]">{label}</p><p className="mt-1 text-sm font-medium text-[#374151]">{value}</p></div>;
}
