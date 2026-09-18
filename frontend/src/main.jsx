import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./App";
import "./styles.css";

// StrictMode는 개발 중 안전하지 않은 부수 효과를 더 빨리 찾도록 도와준다.
// 실제 UI는 index.html의 root 요소 하나에서 시작한다.
createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
