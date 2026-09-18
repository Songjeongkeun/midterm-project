# 너의 악성코드가 보여

Windows PE 파일을 실행하거나 수정하지 않고 정적으로 분석하는 React + FastAPI 웹 애플리케이션이다. PE 구조를 먼저 검증하고, XGBoost 1차 분류와 MalConv2 2차 패밀리 분류를 순서대로 수행한다. 위험 의심 결과에는 악성 유형 안내와 Gemini 기반 AI 전문가 조언을 제공한다.

> 이 프로젝트의 결과는 보안 판단을 돕는 참고 정보이며, 악성 여부·감염 여부를 확정하지 않는다. 파일을 치료·격리·삭제하거나 실행하지 않는다.

## 주요 기능

- 단일 Windows PE 파일 또는 폴더 내 다중 파일을 업로드해 탐색 순서대로 분석한다.
- 확장자가 아닌 `MZ` 서명, PE 오프셋, `PE\0\0` 시그니처, COFF 헤더를 확인해 PE 형식을 검증한다.
- 비-PE 파일은 `미지원`, 손상되었거나 모델 분석을 끝내지 못한 파일은 `오류`로 분리한다.
- 1차 XGBoost가 `Normal`, `Suspicious`, `Malware`를 분류한다.
- `Suspicious` 또는 `Malware` 결과만 2차 MalConv2 패밀리 모델로 전달한다.
- 2차 최고 클래스가 `benign`이면 `판정 충돌`, 유형을 특정하지 못하면 `분류 불확실`로 표시한다.
- 폴더 결과는 업로드 순서를 유지하며 정렬·검색·필터·내보내기 기능을 제공하지 않는다.
- 위험 의심·판정 충돌·분류 불확실 결과에는 서버 제공 대응 안내와 선택 사항인 Gemini AI 전문가 조언을 표시한다.

## 분석 흐름

```text
파일 또는 폴더 업로드
        ↓
PE 헤더 검증
        ↓
1차 XGBoost 분류
        ↓
Normal ─────────────────────→ Normal 표시
Suspicious / Malware
        ↓
2차 MalConv2 패밀리 분류
        ↓
악성 유형 / benign(판정 충돌) / Unknown(분류 불확실)
```

1차 점수의 현재 라우팅 기준은 다음과 같다.

| 1차 점수 | 1차 결과 | 2차 모델 실행 |
| --- | --- | --- |
| 0.10 미만 | `Normal` | 실행하지 않음 |
| 0.10 이상 0.90 미만 | `Suspicious` | 실행함 |
| 0.90 이상 | `Malware` | 실행함 |

## 프로젝트 구조

```text
midterm-project/
├── frontend/                              # React + Vite, JavaScript/JSX만 사용
│   ├── src/
│   │   ├── App.jsx                        # 화면 상태 전환과 분석 작업 상태 관리
│   │   ├── api/analysis.js                # FastAPI 요청, SSE 진행률 수신
│   │   ├── components/                    # 공통 헤더·표·배지·안내 패널
│   │   └── screens/                       # 시작·진행·단일 결과·폴더 결과·오류 화면
│   └── public/figma-assets/               # 서비스 로고 등 정적 자산
├── backend/
│   ├── app/
│   │   ├── main.py                        # FastAPI 시작점과 CORS 설정
│   │   ├── routers/analyze.py             # 분석·유형 안내·AI 조언 API
│   │   ├── schemas/                       # API 요청·응답 Pydantic 모델
│   │   ├── services/
│   │   │   ├── analysis_service.py        # 업로드·순차 분석·작업 메모리 관리
│   │   │   ├── pe_validator.py            # PE 헤더 검증
│   │   │   ├── stage1_xgboost_service.py  # 1차 XGBoost 모델 어댑터
│   │   │   ├── stage2_malconv2_service.py # 2차 MalConv2 모델 어댑터
│   │   │   ├── family_guidance_service.py # 유형별 서버 제공 대응 안내
│   │   │   └── gemini_expert_advice_service.py # Gemini AI 조언 생성
│   │   └── storage/job_store.py           # 세션 동안만 유지하는 작업 저장소
│   ├── models/                            # 로컬 모델 번들·가중치 위치
│   ├── tests/                             # PE 검증·모델 흐름 테스트
│   ├── requirements.txt                   # Python 의존성
│   └── .env.example                       # Gemini 환경 변수 예시
└── docs/fastapi-react-design.md           # 초기 설계와 화면 요구사항
```

## 실행 방법

### 1. 백엔드 실행

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

백엔드는 `http://127.0.0.1:8000`에서 실행한다. API 문서는 `http://127.0.0.1:8000/docs`에서 확인한다.

### 2. 프런트엔드 실행

새 터미널에서 다음을 실행한다.

```bash
cd frontend
npm install
npm run dev
```

브라우저에서 `http://localhost:5173`을 연다. 프런트엔드는 기본적으로 `http://127.0.0.1:8000/api/v1`을 호출한다. 다른 백엔드 주소를 쓸 때는 `frontend/.env.local`에 다음처럼 설정한다.

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
```

## 모델 파일 배치

모델 가중치는 용량과 라이선스 문제로 Git에 포함하지 않는다. 다른 컴퓨터에서 실행할 때는 저장소를 내려받은 뒤 아래 파일을 별도로 받아 같은 위치에 넣어야 한다.

```text
backend/models/
├── stage1_xgboost_bundle/
│   ├── xgb_model.json                    # 1차 XGBoost 가중치
│   ├── feature_names.json                # 341개 특징 순서
│   ├── xgb_threshold.json                # 1차 분류 임계값
│   └── stage1/                           # 특징 추출·런타임 코드
└── stage2/
    ├── best_model.pth                    # 2차 MalConv2 가중치
    ├── class_mapping.txt                 # 클래스 번호와 패밀리명
    ├── config.json                       # 모델 구조 설정
    ├── threshold.json                    # 2차 패밀리 신뢰도 임계값
    └── source/                           # MalConv2 추론 구조 코드
```

`stage1_xgboost_bundle`은 파일 일부만 복사하지 않고 번들 전체를 유지한다. `best_model.pth`가 없으면 2차 분석이 필요한 파일에서 오류가 표시된다. 모델 가중치는 사용자 업로드 파일이 아닌 신뢰할 수 있는 팀 제공본만 사용한다.

## Gemini AI 전문가 조언 설정

Gemini 기능은 선택 사항이다. API 키가 없어도 PE 검증, 1차·2차 모델 분석, 서버 제공 악성 유형 안내는 그대로 동작한다.

```bash
cd backend
cp .env.example .env
```

`backend/.env`에 API 키를 설정한다.

```env
GEMINI_API_KEY=발급받은_API_키
GEMINI_MODEL=gemini-flash-lite-latest
```

- 기본 모델은 짧은 방어 조언에 적합한 `gemini-flash-lite-latest`이다.
- Gemini에는 원본 PE 바이트, 추출 문자열, 파일명, 상대 경로를 보내지 않는다.
- 1·2차 분류 결과와 서버 제공 유형 안내만 전달한다.
- 동일 파일의 조언은 서버 메모리에 캐시하며, **다시 생성**을 누를 때만 새 요청을 보낸다.
- `.env`는 Git에 포함하지 않는다. API 키는 공유하거나 커밋하지 않는다.

## API 요약

| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| `POST` | `/api/v1/analyses/file` | 단일 파일 분석 작업 생성 |
| `POST` | `/api/v1/analyses/folder` | 다중 파일 폴더 분석 작업 생성 |
| `GET` | `/api/v1/analyses/{job_id}` | 현재 작업 결과 조회 |
| `GET` | `/api/v1/analyses/{job_id}/events` | SSE 진행률 이벤트 수신 |
| `DELETE` | `/api/v1/analyses/{job_id}` | 실행 중인 작업 취소 요청 |
| `GET` | `/api/v1/analyses/{job_id}/results/{index}/family-guidance` | 서버 제공 유형 안내 조회 |
| `POST` | `/api/v1/analyses/{job_id}/results/{index}/expert-advice` | Gemini AI 전문가 조언 생성 또는 캐시 조회 |

## 테스트와 빌드

백엔드 테스트는 다음과 같이 실행한다.

```bash
cd backend
source .venv/bin/activate
python -m pytest -q
```

프런트엔드 프로덕션 빌드는 다음과 같이 확인한다.

```bash
cd frontend
npm run build
```

## 보안 및 데이터 처리 원칙

- 업로드 파일은 분석 중에만 시스템 임시 디렉터리에 보관하고 작업 종료 후 삭제한다.
- 분석 결과와 Gemini 조언 캐시는 서버 메모리에만 보관하므로 서버 재시작 시 사라진다.
- 폴더 분석 중 한 파일이 실패해도 나머지 파일 분석은 계속 진행한다.
- `NaN`, `Infinity`처럼 유효하지 않은 2차 모델 점수는 결과로 노출하지 않고 안전한 오류 상태로 처리한다.
- 정적 분석 결과만으로 파일의 안전성이나 악성 여부를 확정하지 않는다. 위험 의심 파일은 실행하지 말고 신뢰할 수 있는 보안 도구 또는 보안 담당자와 함께 검토한다.
