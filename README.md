# PE Static Analysis Web

Windows PE 파일을 **실행하거나 수정하지 않고**, 헤더와 원시 바이트를 읽기 전용으로 분석하는 React + FastAPI 웹 애플리케이션이다. 1차 분류는 XGBoost 번들을 사용하고, 2차 패밀리 분류는 MalConv2 모델을 사용한다. 위험 의심 결과에는 서버 제공 유형 안내와 선택 사항인 Gemini Flash AI 전문가 조언을 표시한다.

전체 설계와 API 계약은 [문서](docs/fastapi-react-design.md)에 저장한다.

## 폴더 구조와 역할

```text
midterm-project/
├── docs/
│   └── fastapi-react-design.md       # 확정한 설계, 제약, API, 모델 교체 가이드
├── frontend/                         # React (JavaScript/JSX만 사용)
│   └── src/
│       ├── App.jsx                   # 작업 상태에 따른 SC-01~SC-05 전환
│       ├── api/analysis.js           # 업로드, SSE 진행 이벤트, 취소 요청
│       ├── components/               # 배지, 통계, 결과 표 공통 UI
│       └── screens/                  # 시작·진행·단일·폴더·오류 화면
└── backend/
    └── app/
        ├── main.py                   # FastAPI 앱, CORS, 라우터 등록
        ├── routers/analyze.py        # 파일/폴더 분석 API와 SSE
        ├── services/
        │   ├── pe_validator.py       # MZ, e_lfanew, PE 시그니처 검증
        │   ├── byte_preprocessor.py  # 바이트 시퀀스 자르기·0 패딩
│   ├── stage1_xgboost_service.py  # 실제 XGBoost 번들 로더·추론 어댑터
│   ├── model_inference_service.py # 2차 Mock 패밀리 분류 어댑터
        │   └── analysis_service.py   # 임시 업로드, 순차 분석, 집계·정리
        ├── schemas/                  # API 응답 형식
        └── storage/job_store.py      # 현재 세션용 인메모리 작업 저장소
```

## 실행

백엔드:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

프런트엔드(다른 터미널):

```bash
cd frontend
npm install
npm run dev
```

브라우저에서 `http://localhost:5173`을 연다. API 문서는 백엔드 실행 후 `http://localhost:8000/docs`에서 확인한다.

## Gemini Flash AI 전문가 조언 설정

AI 전문가 조언은 악성 의심·판정 충돌·분류 불확실 결과에서만 요청한다. Gemini 키가 없어도 파일 검증, 1차 분류, 2차 패밀리 분류, 서버 제공 악성 유형 안내는 그대로 사용할 수 있다.

```bash
cd backend
cp .env.example .env
```

`backend/.env` 파일의 `GEMINI_API_KEY=` 뒤에 Google AI Studio에서 발급한 키를 입력한다. 기본 모델은 짧은 방어 조언에 적합한 `gemini-flash-lite-latest`이며, 더 높은 성능의 Flash 모델을 시험할 경우에만 `GEMINI_MODEL` 값을 변경한다. `.env`는 Git에 포함되지 않는다.

Gemini에는 원본 파일 바이트, 추출 문자열, 파일명, 상대 경로를 보내지 않는다. 1·2차 분류 결과와 서버가 제공하는 일반 대응 안내만 전달한다. 같은 분석 파일에서 다시 탭을 열면 서버 메모리 캐시를 사용하고, **다시 생성**을 눌렀을 때만 새 API 요청을 보낸다.

## 모델을 넣을 위치

실제 모델 파일은 Git에 올리지 말고 `backend/models/`에 둔다.

```text
backend/
├── models/
│   ├── stage1_xgboost.json           # 1차 Normal/Malware 모델 예시
│   └── stage2_malconv2.pt            # 2차 패밀리 모델 예시
└── app/services/model_inference_service.py
```

`stage1_xgboost_bundle/`은 모델 JSON뿐 아니라 341개 PE 특징의 순서, 추출기 코드, 임계값, 무결성 목록을 포함한다. 파일을 수정하거나 일부만 복사하지 않는다. 2차 모델을 연결할 때는 `model_inference_service.py`의 `MockModelInferenceService.predict_stage2()`를 교체한다.

## 주의사항

- 확장자는 판별 근거가 아니다. MZ, PE 오프셋, `PE\0\0`, COFF 헤더 범위를 확인한다.
- 업로드 파일은 분석 작업 중에만 서버 임시 디렉터리에 저장하고, 종료 시 삭제한다. 결과 메타데이터도 서버 재시작 시 사라진다.
- 폴더 결과는 선택된 순서를 유지하며 정렬·검색·필터·내보내기 기능을 제공하지 않는다.
- 1차 모델은 `Normal`, `Suspicious`, `Malware`를 반환한다. `Suspicious`와 `Malware`는 2차 분석 대상으로 전달한다.
- 모델 결과는 악성 여부를 확정하지 않는다. 이 앱은 파일을 치료·격리·삭제하지 않으며, 위험 의심 파일은 신뢰할 수 있는 보안 도구 또는 보안 담당자와 함께 확인한다.
