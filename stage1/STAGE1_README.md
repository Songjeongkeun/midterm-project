# 1차 XGBoost 학습 노트북

실행 파일: `stage1_xgboost_training.ipynb` (57개 셀).
기존 `xgboost_stage1_pe_classifier_colab.ipynb`와 데이터셋은 변경하지 않았습니다.

## 실행

1. 정상 동작하는 Python 3.12 커널에서 새 노트북을 엽니다.
   현재 `venv`는 존재하지 않는 기존 Python312 설치 경로를 참조합니다.
   해당 가상환경을 그대로 선택하면 커널 실행에 실패할 수 있습니다.
2. 필요한 경우 1번 환경 설치 셀의 `%pip install` 주석을 해제하고 설치 후 커널을 재시작합니다.
3. 2번 설정에서 `PROJECT_ROOT`, `DATASET_ROOT`를 확인합니다.
   Windows 기본 경로는 현재 프로젝트이고, Colab은 데이터 경로를 바꿉니다.
4. 처음에는 `RUN_MODE = "smoke"`로 흐름을 확인할 수 있습니다.
   실제 학습은 `RUN_MODE = "full"`로 설정한 후 위에서부터 실행합니다.
5. 13번에서 LOW/HIGH를 변경하며 **validation만** 비교합니다.
   기본 0.10/0.90은 첫 실험용이며 최적 임계값이 아닙니다.
6. 14번에서 모델과 임계값을 확정한 후 15번부터 최종 test 평가·저장·재로딩을 실행합니다.
   모델을 재학습하면 validation 점수부터 다시 계산해야 합니다.
   Test를 본 뒤 그 결과에 맞춰 임계값을 바꾸면 독립적인 최종 평가가 아닙니다.

파일을 실행하지 않고 PE를 읽어서만 특징을 추출합니다. BODMAS의 비실행화된 바이너리도
그대로 유지하며 Machine/Subsystem **특징값만** CSV의 원래 값으로 대체합니다.

## 데이터와 모델

사용자 확정 80/10/10을 그대로 사용합니다. 실제 파일 위치는
`dataset/training_dataset`이며, 매니페스트의 `training_path`를 읽습니다.
이전 원본 위치를 기록한 `raw_path`는 파일 접근에 사용하지 않습니다.

| 분할 | PEMML 정상 | PEMML 악성 | BODMAS 악성 | 합계 |
|---|---:|---:|---:|---:|
| Train | 69,450 | 91,789 | 45,834 | 207,073 |
| Validation | 8,681 | 11,474 | 5,729 | 25,884 |
| Test | 8,681 | 11,474 | 5,729 | 25,884 |

PEMML-only 기준 모델과 PEMML+BODMAS 통합 모델을 각각 학습하고 같은 테스트셋에서 비교합니다.
특징은 고정 순서의 수치 341개입니다. source, label, family, hash, timestamp, imphash,
AV 탐지 수는 모델 입력이 아닙니다. NaN은 XGBoost가 처리하므로 별도 scaler는 없습니다.

주요 지표는 악성을 2차로 전달하는 recall과 놓치는 비율(FNR)입니다.
정상 오탐/2차 전달량, AP, ROC-AUC, F1, 높은 임계값의 악성 precision도 함께 봅니다.
전체·PEMML·BODMAS를 분리하며 악성만 있는 BODMAS의 검증 불가능한 지표는 NaN입니다.
치명적 추출 오류도 원래 평가 분모와 별도 오류 목록에 남습니다.

## 저장과 2차 연결

산출물은 `artifacts/stage1_xgboost/runs/<실행 ID>/`에 저장됩니다.

- `reports/`: 지표 CSV, 점수, 학습/threshold/혼동행렬 그래프, 오류 목록.
- `combined_bundle/`: 통합 모델의 프로그램용 패키지.
- `pemml_only_bundle/`: 기준 모델의 프로그램용 패키지.
- 공통 특징 캐시는 `artifacts/stage1_xgboost/feature_cache/`에 저장됩니다.

각 패키지에는 모델 JSON, threshold JSON, 특징 순서/버전/설정, 전처리 정책,
동일 특징 추출기와 추론 코드, 라벨 매핑, 환경 버전, 데이터 이력, 파일 무결성 목록,
2차 입력 계약과 `INTEGRATION.md`가 들어갑니다.

정상/악성 이진 학습 점수를 Normal / Suspicious / Malware로 표시합니다.
**Suspicious와 Malware만** `stage2_pending`으로 전달합니다. Normal과 Error는 제외합니다.
2차 전달 정보는 ID·파일 경로·실제 content SHA·1차 점수/판정이며 정답 label/family는 없습니다.
2차 전처리나 모델은 구현하지 않았고 노트북에 병합 위치만 주석으로 표시했습니다.

## 검증 기록 — 2026-09-16

- 단위 테스트 33개 통과: 특징 추출, 라우팅/평가, 캐시, 저장/추론.
- 전체 258,841행의 메타데이터/폴더 구성/분할 검증 통과.
- 실제 PE 72개(각 split/source/label별 8개)로 노트북의 필수 코드 셀 25개 순차 실행 통과.
- 추출 결과는 ok 45개, partial 27개. partial은 경고/결측 특징을 기록한 채 유효 특징을 사용합니다.
- 두 모델 학습, 그래프 생성, 저장/재로딩 점수 일치, 실제 파일 재추출 점수 일치 확인.
- 별도 Python 프로세스에서 저장된 패키지만 import하여 실제 PE 추론 확인.
- 최종 확정 이후 임계값/모델 변경 거부, 누락 파일 Error 처리 및 2차 제외 확인.
- 혼동행렬과 threshold 그래프의 표시 상태 확인.

전체 특징 추출과 전체 데이터 학습은 아직 실행하지 않았습니다.
`*_smoke` 폴더의 모델과 수치는 기능 검사용이며 최종 성능이나 실사용 모델이 아닙니다.
노트북은 실행 출력이 비어 있고 기본 설정은 `full`입니다.

개발용 공통 소스는 `stage1/`에 있으며 같은 내용이 노트북 내부에도 포함됩니다.
이 소스를 수정한 경우 `scripts/create_stage1_notebook.py`로 새 노트북의 모듈 셀을 동기화할 수 있습니다.
