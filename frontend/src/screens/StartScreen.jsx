import { useEffect, useRef } from "react";

const primaryButton = "rounded-xl bg-sky-300 px-5 py-3 font-bold text-slate-950 transition hover:bg-sky-200";
const secondaryButton = "rounded-xl border border-slate-600 px-5 py-3 font-bold text-slate-100 transition hover:border-slate-400";

export default function StartScreen({ onSingleFile, onFolder, message }) {
  const fileInput = useRef(null);
  const folderInput = useRef(null);

  useEffect(() => {
    // 폴더 선택은 Chromium 계열 브라우저의 표준화 전 속성을 사용한다.
    const input = folderInput.current;
    input?.setAttribute("webkitdirectory", "");
    input?.setAttribute("directory", "");
  }, []);

  function pickSingle(event) {
    const file = event.target.files?.[0];
    event.target.value = ""; // 같은 파일도 다시 선택할 수 있게 한다.
    if (file) onSingleFile(file);
  }

  function pickFolder(event) {
    const files = event.target.files;
    event.target.value = "";
    if (files?.length) onFolder(files);
  }

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_80%_10%,#12395a_0,transparent_34%),#07111f] px-5 py-12 text-slate-100">
      <section className="mx-auto grid min-h-[78vh] max-w-3xl place-items-center">
        <div className="w-full rounded-3xl border border-slate-700 bg-slate-950/75 p-8 shadow-2xl shadow-black/30 sm:p-12">
          <p className="text-xs font-extrabold tracking-[0.18em] text-sky-300">STATIC PE ANALYSIS</p>
          <h1 className="mt-3 text-4xl font-black tracking-tight sm:text-5xl">Malware Detection</h1>
          <p className="mt-5 max-w-xl text-lg leading-8 text-slate-300">Windows PE 파일을 실행하지 않고, 파일 구조와 원시 바이트 시퀀스를 읽기 전용으로 분석합니다.</p>
          <div className="mt-8 flex flex-col gap-3 sm:flex-row">
            <button className={primaryButton} onClick={() => fileInput.current?.click()}>파일 선택</button>
            <button className={secondaryButton} onClick={() => folderInput.current?.click()}>폴더 선택</button>
          </div>
          <input ref={fileInput} type="file" hidden onChange={pickSingle} />
          <input ref={folderInput} type="file" hidden multiple onChange={pickFolder} />
          {message && <p className="mt-5 rounded-lg bg-[#FEE2E2] p-3 text-sm font-medium text-[#B91C1C]">{message}</p>}
          <ul className="mt-8 list-disc space-y-2 pl-5 text-sm leading-6 text-slate-400">
            <li>확장자 대신 MZ, PE 오프셋, PE 시그니처를 확인합니다.</li>
            <li>업로드된 파일을 실행하거나 수정하지 않습니다.</li>
            <li>AI 예측은 안전을 확정하지 않으므로 모든 결과에 검토 필요 상태를 표시합니다.</li>
          </ul>
        </div>
      </section>
    </main>
  );
}
