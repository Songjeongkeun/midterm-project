// Figma의 공통 상단 바를 모든 분석 상태에서 재사용한다.
export default function AppHeader() {
  // 상단은 서비스 식별만 담당한다. 새 분석은 각 화면의 맥락에 맞는 버튼으로
  // 제공하므로 헤더 오른쪽의 중복 버튼은 두지 않는다.
  return (
    <header className="flex h-[88px] items-center border-b border-[#E5E7EB] bg-white px-6 sm:px-10">
      {/* 사용자가 제공한 로고에 서비스명과 버전이 이미 포함되어 있어 기존
          아이콘·텍스트·별도 버전 배지 대신 하나의 이미지로 표시한다. */}
      <img className="h-14 w-auto object-contain sm:h-[60px]" src="/figma-assets/malware-detector-logo.png" alt="너의 악성코드가 보여 - Malware Detector v1.0" />
    </header>
  );
}
