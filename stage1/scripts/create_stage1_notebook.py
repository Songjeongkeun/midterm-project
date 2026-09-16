"""공유 모듈의 정확한 소스를 포함한 단독 실행 노트북을 생성한다."""
from pathlib import Path
import json
import textwrap

ROOT = Path(__file__).resolve().parents[1]
cells = []


def md(source):
    cells.append(dict(cell_type="markdown", metadata={}, source=textwrap.dedent(source).strip() + "\n"))


def code(source, tag=None):
    metadata = {"tags": [tag]} if tag else {}
    cells.append(dict(cell_type="code", metadata=metadata, execution_count=None, outputs=[],
                      source=textwrap.dedent(source).strip() + "\n"))


md("""
# 1차 PE 정적 특징 기반 XGBoost 분류기

**범위:** 파일의 정상/악성 점수와 3단계 결과를 출력하고, Normal을 제외한
Suspicious·Malware의 **파일 경로 목록**까지 2차로 전달합니다. 2차 전처리·학습·예측은 구현하지 않습니다.

모델 학습 정답은 0=Normal, 1=Malware 두 개입니다. Suspicious는 세 번째 학습 클래스가 아니라
두 임계값 사이의 표시 구간입니다.

| 점수/상태 | 화면 결과 | 2차 전달 |
|---|---|---|
| score < LOW | Normal | 아니요 |
| LOW ≤ score < HIGH | Suspicious | 예 |
| score ≥ HIGH | Malware | 예 |
| 점수 산출 실패 | 별도 Error | 아니요 |

사용자 확정: Windows 로컬 중심/Colab 경로 변경 가능, 현재 80/10/10 유지, 파싱 실패는 별도 기록.
현재 실제 파일은 dataset/training_dataset 안에 있으므로 manifests의 training_path를 사용합니다.

## 실행 순서

1. 환경 설치·경로·실험 설정 → 공통 모듈 셀
2. 매니페스트 검증 → EDA → 파일 특징 미리 보기 → 전체 특징 캐시
3. PEMML-only / PEMML+BODMAS XGBoost 학습 → 학습 곡선
4. **Validation에서만** LOW/HIGH 실험 → 최종 임계값 확정
5. Test 최종 평가 → 출처별 비교 → 모델 패키지 저장/재로딩 검증
6. 새 파일 추론 → Normal/Error 제외 → 2차 연결용 목록

이 파일은 필요한 공통 모듈 소스를 모두 포함합니다. 각 writefile 셀이 이번 실행의 code/stage1에
코드를 생성하므로 이 ipynb와 데이터셋만 있어도 실행할 수 있습니다.
기존 노트북이나 데이터셋 원본을 수정하지 않습니다.
""")
md("""
## 0. 참고한 설계 대화와 확정 사항

- [전체 프로그램/1차 구조](https://chatgpt.com/s/t_6aa7f3f4337081918f3591dc70ae30a7)
- [두 데이터셋의 활용과 출처 편향](https://chatgpt.com/s/t_6aa95d99d460819184601e0c524d4d60)
- [최종 데이터 구성: 양쪽 80/10/10](https://chatgpt.com/s/t_6aa9645f346881919c179a2189386e29)
- [입력 특징/전처리 규칙](https://chatgpt.com/s/t_6aa959bf6d988191a89b507d84829f73)
- [프로그램에 저장/로드할 자산](https://chatgpt.com/s/t_6aa952817c0c8191a924e691fcc8b5a9)

이전 제안의 PEMML 70/15/15·BODMAS 80/20 대신 사용자 확인을 받은 최종 80/10/10을 사용합니다.
원본 SHA-256 교차 중복 1개는 BODMAS에서 제외됐습니다.
PEMML은 label-stratified(random_state=42), BODMAS는 timestamp 순서로 만든 기존 split을 그대로 읽습니다.
imphash는 동일 계열을 보장하지 않으므로 분석만 하고 그룹 단위로 다시 나누지 않습니다.

XGBoost API: [학습/early stopping](https://xgboost.readthedocs.io/en/stable/python/python_api.html),
[모델 JSON 저장](https://xgboost.readthedocs.io/en/stable/tutorials/saving_model.html).
AP 정의: [Average Precision](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.average_precision_score.html).
""")
md("""
## 1. 환경 준비

Python 3.12 커널을 권장합니다. 아래 설치 셀은 **처음 한 번만** 실행하고 이미 설치돼 있다면 건너뜁니다.
설치 후에는 커널을 재시작하고 2번부터 진행합니다. 설치 명령 앞의 주석을 해제하면 됩니다.
Windows에서는 실행 가능한 Python으로 Jupyter 커널을 선택하세요. 현재 프로젝트의 기존 venv는
원래 Python312 경로가 없어 실행에 실패하는 상태였으므로 새 환경을 선택해야 할 수 있습니다.
Colab에서는 데이터가 /content 또는 마운트한 Drive에 존재해야 하며 아래 DATASET_ROOT를 해당 위치로 바꿉니다.
""")
code("""
# 선택 실행: 현재 노트북 커널에 설치합니다. 시스템 전체 환경을 자동 변경하지 않습니다.
# %pip install "numpy>=1.26,<3" "pandas>=2.2,<4" "scikit-learn>=1.5,<2" "xgboost>=3.0,<4" "pefile==2024.8.26" "matplotlib>=3.8,<4"
# 선택: 시각적 임계값 슬라이더를 쓸 때만 설치합니다.
# %pip install ipywidgets
""", "install")
md("## 2. 경로와 실험 설정 — 보통 이 셀부터 수정합니다")
code("""
from pathlib import Path
from datetime import datetime, timezone
import os
import sys
import json
import hashlib
import importlib

PROJECT_ROOT = Path.cwd().resolve()
DATASET_ROOT = PROJECT_ROOT / "dataset"
# Colab 예: DATASET_ROOT = Path("/content/drive/MyDrive/M_Project/dataset")
# Colab의 원격 Drive는 수십만 작은 파일 읽기가 느릴 수 있습니다.
# 이미 로컬 디스크에 준비된 데이터/특징 캐시를 쓰면 더 빠릅니다.
ARTIFACT_ROOT = PROJECT_ROOT / "artifacts" / "stage1_xgboost"
RUN_MODE = "full"  # "smoke": 실행 흐름 확인용 소수 표본. 성능 결과로 사용하지 않습니다.
SMOKE_PER_GROUP = 8  # smoke일 때 split/source/label 각 그룹당 개수
SEED = 42
DEVICE = "cpu"  # GPU 환경은 "cuda". 자동 장치 변경 대신 실험 설정으로 남깁니다.
EXTRACTION_WORKERS = 2  # PE 읽기/파싱 병렬 수. 메모리를 확인하고 늘립니다.
CACHE_CHUNK_SIZE = 512

# 첫 실험용 값입니다. 최적값이나 성능 보장을 의미하지 않습니다.
# 뒤의 '임계값 실험' 셀에서 바꾸면 모델을 재학습하지 않고 즉시 비교할 수 있습니다.
LOW = 0.10
HIGH = 0.90
TARGET_SCREENING_RECALL = 0.99
TARGET_MALWARE_PRECISION = 0.99
ERROR_FORWARD = False  # 사용자가 확정: 파싱 실패는 별도 목록, 2차 전달 없음

if RUN_MODE not in {"full", "smoke"}:
    raise ValueError("RUN_MODE는 full 또는 smoke여야 합니다.")
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ") + "_" + RUN_MODE
RUN_DIR = ARTIFACT_ROOT / "runs" / RUN_ID
CODE_DIR = RUN_DIR / "code"
(CODE_DIR / "stage1").mkdir(parents=True, exist_ok=False)
REPORT_DIR = RUN_DIR / "reports"
REPORT_DIR.mkdir()
# 다음 writefile 셀은 실행 전용 폴더 안에 공유 모듈을 만듭니다.
os.chdir(CODE_DIR)
print("데이터:", DATASET_ROOT)
print("이번 실험:", RUN_DIR)
""", "configuration")
md("""
## 3. 학습·프로그램에서 공유할 특징 추출기

아래 코드를 그대로 배포 패키지에 저장합니다. 특징 이름·순서·계산법이 학습과 추론에서 일치합니다.
341개 수치 특징을 사용하며 원본 바이트 배열을 XGBoost에 그대로 넣지 않습니다.

- General 5, Header/Entry point 20, Section 통계 19, Import/Export 5,
  Data directory 32, Overlay 4, 정규화 Byte histogram 256.
- 없는 구조는 0, 읽을 수 없는 특징은 NaN. fatal error는 학습/예측에서 제외하고 기록.
- 경고가 있는 partial PE는 유효한 특징과 NaN으로 학습합니다. partial을 모두 제거하면
  패킹/RWX 구조가 많은 악성을 선택적으로 제외할 수 있습니다.
- BODMAS는 Machine/Subsystem **특징만** 제공 CSV로 보정합니다. PE 바이트는 수정하지 않습니다.
- original reference SHA와 실제 content SHA를 따로 기록합니다.
- 서명/체크섬 유효성, AV 탐지 수, source·hash·family·timestamp·imphash는 특징에서 제외합니다.
  Certificate table presence는 서명이 유효하다는 뜻이 아닙니다.
- 파일 크기/섹션 등 한도는 설정으로 남깁니다. 한도 초과도 Error로 집계되므로 평가에서 드러납니다.
""")


def module_cell(filename, heading):
    md(heading)
    source = (ROOT / "stage1" / filename).read_text(encoding="utf-8")
    code('%%writefile "{CODE_DIR.as_posix()}/stage1/' + filename + '"\n' + source, "module")


code('%%writefile "{CODE_DIR.as_posix()}/stage1/__init__.py"\n"""Stage1 shared code."""', "module")
module_cell("feature_extractor.py", "### 3-1. PE → 고정 길이 특징")
module_cell("data_pipeline.py", """
### 3-2. 기존 split 검증과 청크 특징 캐시

원본 메타데이터와 라벨/파일 ID/BODMAS 보정값을 대조합니다.
특징 캐시는 코드·버전·설정·행 순서가 달라지면 다른 폴더를 사용하며,
같은 실행을 다시 시작하면 완료된 청크를 재사용합니다.
원본 파일이 변경되면 크기/수정시간으로 기존 청크를 무효화합니다.
""")
module_cell("evaluation.py", """
### 3-3. 3단계 라우팅·지표·임계값 비교·그래프

**주 지표:** 전체 악성 중 2차로 보낸 비율(screening recall), 보낼 기회를 놓친 비율(screening FNR).
Error 악성은 2차에 보내지 않으므로 전체 FNR에도 포함합니다.
모델 점수가 나온 파일만의 recall/FNR도 별도로 보여 파싱 문제와 모델 문제를 구분합니다.

**비용 지표:** 정상 중 2차에 전달한 비율(FPR/benign forward rate), 전체 전달 비율, 정상 필터율.
**보조 지표:** Average Precision(AP), ROC-AUC, logloss, 이진 F1, high 경계의 Malware precision.
AP는 PR 곡선의 사다리꼴 면적과 다른 정의라 명확히 구분합니다.
BODMAS는 악성만 있으므로 정상 오탐/precision/AUC를 검증할 수 없는 값은 NaN으로 표시합니다.
2×3 혼동행렬은 정답 2종과 표시 3단계를 비교하며 Error는 별도 막대로 표시합니다.
""")
module_cell("runtime.py", """
### 3-4. 모델 저장·재로딩·2차 연결 API

모델 JSON과 임계값, 특징 규칙, 동일 추출 코드, 라벨 매핑, 환경 버전, split 이력,
전처리 설정과 2차 입력 계약을 함께 저장합니다.
이 구성은 scaler/encoder를 학습하지 않으므로 불필요한 scaler.pkl 대신 identity 설정을 저장합니다.
""")
md("## 4. 모듈 불러오기와 환경 기록")
code("""
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(CODE_DIR))
# 셀을 다시 실행해도 이전 실험의 stage1 모듈을 참조하지 않도록 명시적으로 비웁니다.
for name in list(sys.modules):
    if name == "stage1" or name.startswith("stage1."):
        del sys.modules[name]
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from IPython.display import display
from xgboost import XGBClassifier
from stage1 import feature_extractor as fe
from stage1.data_pipeline import load_dataset, cache_features, json_write, sha256_file
from stage1.evaluation import (
    route_scores, evaluate_scores, threshold_curve, recommend_thresholds,
    plot_score_curves, plot_score_histogram, plot_three_way_confusion, plot_threshold_tradeoffs,
)
from stage1.runtime import Stage1Detector, save_bundle
import importlib.metadata

plt.rcParams.update({"figure.dpi": 110, "axes.grid": True, "grid.alpha": 0.2})
FEATURE_NAMES = list(fe.FEATURE_NAMES)
EXTRACTOR_CONFIG = fe.ExtractorConfig()
ENVIRONMENT = {p: importlib.metadata.version(p) for p in
               ["numpy", "pandas", "scikit-learn", "xgboost", "pefile", "matplotlib"]}
json_write(RUN_DIR / "environment.json", {"python": sys.version, "packages": ENVIRONMENT})
print("특징 수:", len(FEATURE_NAMES))
display(pd.Series(ENVIRONMENT, name="version"))
""")
md("## 5. 데이터와 CSV 검증 — 파일을 이동하거나 다시 split하지 않습니다")
code("""
manifest, dataset_audit = load_dataset(DATASET_ROOT)
json_write(REPORT_DIR / "dataset_audit.json", dataset_audit)
split_table = manifest.groupby(["split", "source", "label"]).size().unstack(["source", "label"], fill_value=0)
display(split_table.reindex(["train", "validation", "test"]))
display(pd.DataFrame(dataset_audit["bodmas_time_bounds"], index=["start_utc", "end_utc"]).T)
print("원본 SHA 식별자 중복:", manifest.sha256.duplicated().sum())
print("split을 공유하는 imphash 그룹:", dataset_audit["imphash_groups_spanning_splits"])

if RUN_MODE == "smoke":
    manifest = (manifest.groupby(["split", "source", "label"], group_keys=False)
                .sample(n=SMOKE_PER_GROUP, random_state=SEED).sort_index().reset_index(drop=True))
    print("SMOKE 전용 표본:", len(manifest), "개 — 실제 성능으로 보고하지 마세요.")
manifest.to_csv(RUN_DIR / "used_manifest.csv", index=False)
""")
md("""
## 6. 학습 데이터의 기본 분포 확인

전체 행 수와 split은 검증했지만 특징 분포의 탐색은 Train만 사용합니다.
학습/검증/테스트 모두 정상 출처는 PEMML뿐이라는 한계가 있으므로 출처별 평가가 필요합니다.
""")
code("""
train_manifest = manifest[manifest.split.eq("train")]
fig, axes = plt.subplots(1, 2, figsize=(11, 4))
train_manifest.groupby(["source", "label"]).size().plot.bar(ax=axes[0], color="#2563eb")
axes[0].set(title="Train composition", ylabel="Files")
# stat의 file size는 출처 CSV의 length가 아니라 현재 실제 파일 크기입니다.
eda_rows = train_manifest.groupby(["source", "label"], group_keys=False).head(500)
size_frame = eda_rows[["source", "label"]].copy()
size_frame["bytes"] = [Path(p).stat().st_size for p in eda_rows.path]
for (source, label), group in size_frame.groupby(["source", "label"]):
    axes[1].hist(np.log10(group.bytes.clip(lower=1)), bins=30, alpha=.5, label=f"{source}/{label}")
axes[1].set(title="Train size sample (up to 500 per group)", xlabel="log10(bytes)", ylabel="Files")
axes[1].legend()
fig.tight_layout()
fig.savefig(REPORT_DIR / "train_composition.png", bbox_inches="tight")
plt.show()
""")
md("## 7. 파일 3개로 특징 추출 미리 보기")
code("""
preview = []
for row in train_manifest.groupby(["source", "label"]).head(1).itertuples():
    record = fe.extract_pe_features(
        row.path, source=row.source, reference_sha256=row.sha256,
        machine_override=row.machine if row.source == "BODMAS" else None,
        subsystem_override=row.subsystem if row.source == "BODMAS" else None,
        config=EXTRACTOR_CONFIG,
    )
    preview.append({
        "sample_id": row.sample_id, "source": row.source, "parse_status": record["parse_status"],
        "feature_count": 0 if record["vector"] is None else len(record["vector"]),
        "reference_sha256": row.sha256, "content_sha256": record["content_sha256"],
        "error_reason": record["error_reason"],
    })
display(pd.DataFrame(preview))
# BODMAS의 두 해시가 다른 것은 비실행화된 제공 파일의 특성입니다.
# PEMML처럼 '원본 해시와 반드시 같음'을 강제하지 않습니다.
""")
md("""
## 8. PE 특징 캐시 생성/재사용

전체 모드는 약 258,841개 파일을 읽기 때문에 최초 추출에 시간이 걸립니다.
이후 모델/threshold 실험은 캐시를 재사용합니다. 추출 중 중단되면 이 셀을 다시 실행하세요.
청크 완료 시에만 저장하므로 미완료 청크는 다시 계산합니다.
파싱 실패는 전체 목록에서 사라지지 않고 기록으로 유지됩니다.
""")
code("""
X, metadata, CACHE_DIR = cache_features(
    manifest, ARTIFACT_ROOT / "feature_cache", EXTRACTOR_CONFIG,
    workers=EXTRACTION_WORKERS, chunk_size=CACHE_CHUNK_SIZE,
)
if X.shape != (len(metadata), len(FEATURE_NAMES)) or np.isinf(X).any():
    raise ValueError("특징 형태/무한값 오류")
valid = metadata.parse_status.isin(["ok", "partial"]).to_numpy()
status_table = metadata.groupby(["split", "source", "label", "parse_status"]).size().rename("count").reset_index()
display(status_table)
status_table.to_csv(REPORT_DIR / "extraction_status.csv", index=False)
metadata.loc[~valid].to_csv(REPORT_DIR / "extraction_errors.csv", index=False)
print("X:", X.shape, X.dtype, "| RAM for matrix:", round(X.nbytes / 1024**2, 1), "MiB")
print("캐시:", CACHE_DIR, "| 예측 가능한 파일:", int(valid.sum()), "/", len(metadata))
""")
md("""
## 9. Train 특징 검사와 출처 편향 진단

NaN은 XGBoost가 직접 처리하며, 0은 실제 구조 부재입니다. scaler는 사용하지 않습니다.
출처별 byte histogram을 비교해 BODMAS 제공 방식에 따른 차이가 큰지 확인합니다.
보정은 Machine/Subsystem 두 특징에만 적용했으므로 히스토그램은 제공된 바이트를 반영합니다.
""")
code("""
train_valid = metadata.split.eq("train").to_numpy() & valid
train_X = pd.DataFrame(X[train_valid], columns=FEATURE_NAMES)
display(train_X.isna().mean().sort_values(ascending=False).head(15).rename("missing_fraction"))
fig, axes = plt.subplots(1, 2, figsize=(12, 4))
for source, color in [("PEMML", "#2563eb"), ("BODMAS", "#f97316")]:
    mask = train_valid & metadata.source.eq(source).to_numpy() & metadata.label.eq(1).to_numpy()
    axes[0].plot(range(256), np.nanmean(X[mask][:, -256:], axis=0), label=f"{source} malware", color=color)
    axes[1].hist(X[mask, FEATURE_NAMES.index("file_entropy")], bins=40, alpha=.5, label=source, color=color)
axes[0].set(title="Train malware: mean byte histogram", xlabel="Byte value", ylabel="Ratio")
axes[1].set(title="Train malware: file entropy", xlabel="Entropy", ylabel="Files")
for ax in axes:
    ax.legend()
fig.tight_layout()
fig.savefig(REPORT_DIR / "train_source_features.png", bbox_inches="tight")
plt.show()
""")
md("""
## 10. XGBoost 설정과 학습 함수

Model A는 PEMML train만, Model B는 통합 train을 학습합니다.
각각 해당 validation으로 early stopping하며 **test는 사용하지 않습니다**.
binary:logistic은 이진 logloss를 최적화합니다. 적당한 트리 깊이와 낮은 학습률로 시작하고,
early stopping으로 필요한 트리 수를 결정합니다. 아래 값은 조정 가능한 첫 실험 설정입니다.
SMOTE/무조건적인 클래스 가중치 없이 원래 분포의 baseline을 먼저 만듭니다.
""")
code("""
MODEL_PARAMS = dict(
    objective="binary:logistic", eval_metric="logloss",
    n_estimators=2000 if RUN_MODE == "full" else 20,
    learning_rate=0.05, max_depth=6, min_child_weight=2,
    subsample=0.8, colsample_bytree=0.8,
    reg_alpha=0.0, reg_lambda=1.0, scale_pos_weight=1.0,
    tree_method="hist", device=DEVICE, n_jobs=min(8, os.cpu_count() or 2),
    random_state=SEED, early_stopping_rounds=50 if RUN_MODE == "full" else 3,
)

def feature_frame(mask):
    # 명시적인 whitelist 열만 DataFrame으로 만든다. source/label/hash 열을 join하지 않는다.
    return pd.DataFrame(X[mask], columns=FEATURE_NAMES)

def train_xgb(source_filter=None):
    source_mask = np.ones(len(metadata), dtype=bool) if source_filter is None else metadata.source.eq(source_filter).to_numpy()
    tr = train_valid & source_mask
    va = metadata.split.eq("validation").to_numpy() & valid & source_mask
    if metadata.loc[tr, "label"].nunique() != 2 or metadata.loc[va, "label"].nunique() != 2:
        raise ValueError("학습/검증에 유효한 정상·악성이 모두 필요합니다.")
    model = XGBClassifier(**MODEL_PARAMS)
    model.fit(
        feature_frame(tr), metadata.loc[tr, "label"].to_numpy(),
        eval_set=[(feature_frame(tr), metadata.loc[tr, "label"].to_numpy()),
                  (feature_frame(va), metadata.loc[va, "label"].to_numpy())],
        verbose=100 if RUN_MODE == "full" else False,
    )
    return model
""")
md("### 10-1. Model A — PEMML-only 기준 모델")
code("""
model_pemml = train_xgb("PEMML")
model_pemml.save_model(RUN_DIR / "pemml_checkpoint.json")
print("PEMML-only best iteration:", model_pemml.best_iteration)
""")
md("### 10-2. Model B — PEMML + BODMAS 통합 모델")
code("""
model_combined = train_xgb()
model_combined.save_model(RUN_DIR / "combined_checkpoint.json")
print("Combined best iteration:", model_combined.best_iteration)
""")
md("## 11. 학습 곡선과 특징 중요도")
code("""
models = {"PEMML-only": model_pemml, "PEMML+BODMAS": model_combined}
fig, axes = plt.subplots(1, 2, figsize=(12, 4))
histories = {}
for ax, (name, model) in zip(axes, models.items()):
    history = model.evals_result()
    histories[name] = history
    ax.plot(history["validation_0"]["logloss"], label="Train")
    ax.plot(history["validation_1"]["logloss"], label="Validation")
    ax.axvline(model.best_iteration, linestyle="--", color="black", label="Best iteration")
    ax.set(title=name, xlabel="Boosting round", ylabel="Logloss")
    ax.legend()
fig.tight_layout()
fig.savefig(REPORT_DIR / "learning_curves.png", bbox_inches="tight")
json_write(REPORT_DIR / "learning_history.json", histories)
plt.show()

# 중요도는 인과 설명이 아닙니다. 파일 크기 등 출처 단서가 지배하는지 점검하는 용도입니다.
importance = pd.Series(model_combined.feature_importances_, index=FEATURE_NAMES, name="gain_importance").sort_values()
fig, ax = plt.subplots(figsize=(9, 6))
importance.tail(20).plot.barh(ax=ax, color="#2563eb")
ax.set(title="Combined XGBoost: top 20 features", xlabel="Normalized gain importance")
fig.tight_layout()
fig.savefig(REPORT_DIR / "feature_importance.png", bbox_inches="tight")
importance.to_csv(REPORT_DIR / "feature_importance.csv")
plt.show()
""")
md("""
## 12. Validation 점수 계산 — 이 셀은 모델별 한 번이면 됩니다

점수는 보정되지 않은 XGBoost 출력입니다. 0.9를 운영 환경에서 실제 악성 확률 90%라고 단정하지 않습니다.
임계값을 바꾸는 동안 이 점수를 재사용하므로 PE 재파싱/모델 재학습이 필요 없습니다.
""")
code("""
def predict_split(model, split):
    mask = metadata.split.eq(split).to_numpy()
    rows = metadata.loc[mask].reset_index(drop=True)
    values = np.full(mask.sum(), np.nan, dtype=float)
    usable = valid[mask]
    if usable.any():
        values[usable] = model.predict_proba(pd.DataFrame(X[mask][usable], columns=FEATURE_NAMES))[:, 1]
    return rows, values

def model_fingerprint(model):
    # 임시 파일 없이 트리와 best_iteration 속성을 함께 지문으로 만든다.
    return hashlib.sha256(model.get_booster().save_raw(raw_format="json")).hexdigest()

val_meta, val_scores = predict_split(model_combined, "validation")
_, val_scores_pemml = predict_split(model_pemml, "validation")
VALIDATION_MODEL_HASHES = {"combined": model_fingerprint(model_combined),
                           "pemml": model_fingerprint(model_pemml)}
val_score_frame = val_meta.assign(combined_score=val_scores, pemml_only_score=val_scores_pemml)
val_score_frame.to_csv(REPORT_DIR / "validation_scores.csv", index=False)
grid = np.linspace(0, 1, 1001)
val_curve = threshold_curve(val_meta, val_scores, grid, error_forward=ERROR_FORWARD)
val_curve.to_csv(REPORT_DIR / "validation_threshold_curve.csv", index=False)
recommendation = recommend_thresholds(
    val_meta, val_scores, error_forward=ERROR_FORWARD,
    target_screening_recall=TARGET_SCREENING_RECALL,
    target_malware_precision=TARGET_MALWARE_PRECISION, thresholds=grid,
)
display(pd.Series(recommendation, name="validation proposal"))
json_write(REPORT_DIR / "threshold_recommendation.json", recommendation)
# feasible=False이면 목표를 달성했다고 간주하지 않습니다.
# 추천은 자동 적용하지 않습니다. 아래 LOW/HIGH 셀에서 그래프/수치를 보고 선택합니다.
""")
md("""
## 13. 임계값 실험 — 이 셀과 다음 셀만 반복 실행합니다

LOW를 낮추면 악성 누락이 줄어드는 대신 정상도 2차로 많이 갑니다.
HIGH는 Suspicious와 Malware의 표시를 나누며, LOW가 같다면 2차 전달량에는 영향을 주지 않습니다.
목표 recall/precision 0.99는 제안용 설정값이며 보장된 성능이 아닙니다.
""")
code("""
LOW = 0.10
HIGH = 0.90
# 추천을 채택하고 싶다면 feasible을 확인한 뒤 직접 아래를 실행합니다.
# assert recommendation["feasible"], recommendation["reason"]
# LOW, HIGH = recommendation["low"], recommendation["high"]

def inspect_thresholds(low, high, save=False):
    table = evaluate_scores(val_meta, val_scores, low, high, error_forward=ERROR_FORWARD)
    columns = ["n_total", "n_errors", "score_coverage", "screening_recall", "screening_fnr",
               "benign_forward_rate", "overall_forward_rate", "malware_precision",
               "average_precision_scored", "roc_auc_scored"]
    display(table[columns])
    figures = {
        "validation_thresholds": plot_threshold_tradeoffs(val_curve, low=low, high=high),
        "validation_score_histogram": plot_score_histogram(val_meta, val_scores, low, high),
        "validation_three_way": plot_three_way_confusion(val_meta, val_scores, low, high, error_forward=ERROR_FORWARD),
    }
    for name, fig in figures.items():
        if save:
            fig.savefig(REPORT_DIR / (name + ".png"), bbox_inches="tight")
        plt.show()
        plt.close(fig)
    return table

validation_metrics = inspect_thresholds(LOW, HIGH, save=True)
validation_metrics.to_csv(REPORT_DIR / "validation_metrics.csv")
""")
md("### 선택: 버튼으로 적용하는 LOW/HIGH 슬라이더")
code("""
# ipywidgets가 없으면 위의 숫자 설정 셀만 사용해도 모든 실험이 가능합니다.
# 슬라이더는 미리 보기만 수행합니다. 최종 값은 LOW/HIGH 변수에 직접 반영하세요.
try:
    import ipywidgets as widgets
    control = widgets.interactive(
        lambda low, high: inspect_thresholds(low, high) if low < high else print("LOW < HIGH가 필요합니다."),
        {"manual": True, "manual_name": "Validation 비교"},
        low=widgets.FloatSlider(value=LOW, min=0, max=0.999, step=0.001),
        high=widgets.FloatSlider(value=HIGH, min=0.001, max=1, step=0.001),
    )
    display(control)
except ImportError:
    print("ipywidgets 미설치: 위의 LOW/HIGH 숫자를 바꿔 실험하세요.")
""", "widgets")
md("""
## 14. Validation 최종 확정

Test를 보기 전에 두 임계값과 모델을 확정합니다.
두 모델은 우선 동일 LOW/HIGH로 비교해 정책 차이와 데이터 추가 효과를 섞지 않습니다.
Test 결과를 보고 값을 다시 조절하면 그 Test는 더 이상 최종 독립 평가가 아닙니다.
""")
code("""
route_scores([], LOW, HIGH, error_forward=ERROR_FORWARD)  # 경계 유효성 검사
def current_policy():
    return {"low": float(LOW), "high": float(HIGH), "error_forward": False,
            "combined_booster_sha256": model_fingerprint(model_combined),
            "pemml_booster_sha256": model_fingerprint(model_pemml)}

candidate_policy = current_policy()
if (candidate_policy["combined_booster_sha256"] != VALIDATION_MODEL_HASHES["combined"] or
        candidate_policy["pemml_booster_sha256"] != VALIDATION_MODEL_HASHES["pemml"]):
    raise RuntimeError("Validation 점수 계산 이후 모델이 변경됐습니다. Validation부터 다시 평가하세요.")
lock_path = REPORT_DIR / "test_evaluation_lock.json"
if lock_path.exists() and json.loads(lock_path.read_text()) != candidate_policy:
    raise RuntimeError("이미 본 Test에 새 임계값/모델을 맞추지 마세요. 최종 평가 계획을 다시 정해야 합니다.")
# 잠금 검사를 통과하기 전에는 기존 확정 모델/정책을 덮어쓰지 않는다.
FROZEN_POLICY = candidate_policy
model_combined.save_model(RUN_DIR / "frozen_combined.json")
model_pemml.save_model(RUN_DIR / "frozen_pemml.json")

def assert_frozen_policy():
    if current_policy() != FROZEN_POLICY:
        raise RuntimeError("최종 확정 이후 모델/임계값이 변경됐습니다. 확정 정책과 다른 결과를 저장할 수 없습니다.")
    if lock_path.exists() and json.loads(lock_path.read_text()) != FROZEN_POLICY:
        raise RuntimeError("기존 Test 평가 정책과 다릅니다.")

json_write(REPORT_DIR / "selected_thresholds.json", FROZEN_POLICY)
validation_metrics = evaluate_scores(val_meta, val_scores, LOW, HIGH, error_forward=False)
display(validation_metrics)
""")
md("## 15. Test 최종 평가 — 전체 / PEMML / BODMAS를 분리해 봅니다")
code("""
assert_frozen_policy()
json_write(lock_path, FROZEN_POLICY)
test_meta, test_scores = predict_split(model_combined, "test")
_, test_scores_pemml = predict_split(model_pemml, "test")
test_metrics = evaluate_scores(test_meta, test_scores, LOW, HIGH, error_forward=False)
baseline_metrics = evaluate_scores(test_meta, test_scores_pemml, LOW, HIGH, error_forward=False)
display(test_metrics)
comparison = pd.concat({"PEMML-only": baseline_metrics, "PEMML+BODMAS": test_metrics}, names=["model", "source"])
display(comparison[["screening_recall", "screening_fnr", "benign_forward_rate",
                    "overall_forward_rate", "average_precision_scored", "roc_auc_scored"]])
comparison.to_csv(REPORT_DIR / "test_model_comparison.csv")
test_metrics.to_csv(REPORT_DIR / "test_metrics.csv")
test_meta.assign(combined_score=test_scores, pemml_only_score=test_scores_pemml).to_csv(
    REPORT_DIR / "test_scores.csv", index=False)
# BODMAS 단독 행의 FPR/AP/ROC-AUC=NaN은 정상입니다. 정상 표본이 없기 때문입니다.
""")
md("## 16. Test 그래프와 운영 비용 비교")
code("""
assert_frozen_policy()
for name, fig in {
    "test_roc_pr": plot_score_curves(test_meta, test_scores),
    "test_three_way": plot_three_way_confusion(test_meta, test_scores, LOW, HIGH, error_forward=False),
    "test_score_histogram": plot_score_histogram(test_meta, test_scores, LOW, HIGH),
}.items():
    fig.savefig(REPORT_DIR / (name + ".png"), bbox_inches="tight")
    plt.show()
    plt.close(fig)
fig, axes = plt.subplots(1, 2, figsize=(11, 4))
for ax, source in zip(axes, ["PEMML", "BODMAS"]):
    part = comparison.xs(source, level="source")
    columns = ["screening_recall", "screening_fnr"] if source == "BODMAS" else ["screening_recall", "benign_forward_rate"]
    part[columns].plot.bar(ax=ax)
    ax.set(title=f"Same {source} test / same thresholds", ylim=(0, 1.05), ylabel="Rate")
    ax.tick_params(axis="x", rotation=10)
fig.tight_layout()
fig.savefig(REPORT_DIR / "baseline_comparison.png", bbox_inches="tight")
plt.show()
""")
md("""
## 17. 2차 전달 목록 — 여기서 1차 처리 흐름이 끝납니다

Normal과 Error는 제외합니다. Suspicious·Malware만 입력 ID, 경로, 실제 해시,
1차 점수/판정으로 전달합니다. 이 목록에 정답 label/family를 넣으면 운영 입력과 달라지므로 제외합니다.
아래 코드는 테스트셋 결과를 저장하는 예시이며 2차 모델을 호출하지 않습니다.
""")
code("""
assert_frozen_policy()
routing = route_scores(test_scores, LOW, HIGH, error_forward=False)
result_frame = test_meta[["sample_id", "path", "content_sha256", "parse_status", "error_reason"]].copy()
result_frame = pd.concat([result_frame.reset_index(drop=True), routing], axis=1)
result_frame.to_csv(REPORT_DIR / "stage1_results.csv", index=False)
stage2_pending = result_frame.loc[result_frame.needs_stage2,
    ["sample_id", "path", "content_sha256", "malware_score", "stage1_result"]].rename(
    columns={"sample_id": "input_id", "malware_score": "stage1_score"})
stage2_pending.insert(0, "handoff_version", "1.0")
stage2_pending.to_csv(REPORT_DIR / "stage2_pending.csv", index=False)
error_list = result_frame[result_frame.stage1_result.eq("Error")]
error_list.to_csv(REPORT_DIR / "stage1_errors.csv", index=False)
assert not stage2_pending.stage1_result.isin(["Normal", "Error"]).any()
display(result_frame.head(10))
print("2차 전달 후보:", len(stage2_pending), "| 별도 오류:", len(error_list))

# ================== 향후 2차 코드 병합 지점 ==================
# for item in stage2_pending.itertuples(index=False):
#     stage2_preprocess_and_predict(item.path)  # 별도로 작성할 2차 함수에 연결
# stage1_score를 2차 학습 특징으로 자동 추가하지 않습니다.
# 2차 family 클래스/입력 길이/padding 등은 2차 팀이 자기 설정에 저장합니다.
# ============================================================
""")
md("""
## 18. 프로그램 배포용 패키지 저장

통합 모델과 PEMML-only 모델을 모두 별도 저장합니다. 이번 실행은 통합 모델을 1차 프로그램 대상으로
사용하며 테스트 수치로 모델을 자동 교체하지 않습니다.
실제 성능 검토 후 모델 선택을 바꾸려면 별도의 validation 선택 계획을 사용하세요.
smoke 모드 패키지는 기능 검사 전용이며 실사용 모델이 아닙니다.
""")
code("""
assert_frozen_policy()
training_config = {
    "run_id": RUN_ID, "run_mode": RUN_MODE, "params": MODEL_PARAMS,
    "seed": SEED, "threshold_policy": FROZEN_POLICY,
    "feature_cache": str(CACHE_DIR), "score_calibrated": False,
}
# 단일 클래스 지표의 NaN을 JSON null로 변환해 올바른 JSON으로 저장합니다.
validation_json = json.loads(validation_metrics.to_json(orient="index"))
BUNDLE_DIR = save_bundle(
    RUN_DIR / "combined_bundle", model_combined, low=LOW, high=HIGH,
    extractor_config=EXTRACTOR_CONFIG, data_audit=dataset_audit,
    training_config=training_config, validation_summary=validation_json,
)
baseline_val_metrics = evaluate_scores(val_meta, val_scores_pemml, LOW, HIGH, error_forward=False)
BASELINE_BUNDLE_DIR = save_bundle(
    RUN_DIR / "pemml_only_bundle", model_pemml, low=LOW, high=HIGH,
    extractor_config=EXTRACTOR_CONFIG, data_audit=dataset_audit,
    training_config={**training_config, "training_source": "PEMML only"},
    validation_summary=json.loads(baseline_val_metrics.to_json(orient="index")),
)
print("프로그램용 통합 패키지:", BUNDLE_DIR)
display(pd.Series(sorted(p.name for p in BUNDLE_DIR.iterdir()), name="saved assets"))
""")
md("## 19. 저장 → 로드 결과 일치 검사")
code("""
detector = Stage1Detector(BUNDLE_DIR)
probe_mask = metadata.split.eq("validation").to_numpy() & valid
probe_frame = feature_frame(probe_mask).head(64)
before = model_combined.predict_proba(probe_frame)[:, 1]
after = detector.model.predict_proba(probe_frame)[:, 1]
np.testing.assert_allclose(before, after, rtol=1e-6, atol=1e-7)

# 실제 PE를 한 번 재추출해서도 학습 캐시와 같은 점수가 나오는지 확인합니다.
probe = metadata.loc[probe_mask].iloc[0]
loaded_result = detector.analyze_file(
    probe.path, input_id=probe.sample_id, source=probe.source,
    reference_sha256=probe.sha256,
    machine_override=probe.machine if probe.source == "BODMAS" else None,
    subsystem_override=probe.subsystem if probe.source == "BODMAS" else None,
)
np.testing.assert_allclose(before[0], loaded_result["malware_score"], rtol=1e-6, atol=1e-7)
print("64개 이내 특징 점수 및 실제 파일 재추출 점수 일치 확인")
display(loaded_result)
""")
md("""
## 20. 새 프로그램 파일 입력 예시

새 PE에는 데이터셋 source·label·family가 필요 없습니다. 저장한 패키지를 로드한 뒤 파일 경로만 넘깁니다.
별도 프로그램에서는 BUNDLE_DIR를 sys.path에 추가해 저장된 stage1.runtime을 가져옵니다.
여기서는 동일 코드를 이미 로드했으므로 위 detector를 재사용합니다.
""")
code("""
INPUT_FILES = []  # 예: [Path(r"C:\\analysis\\unknown.exe")]
if INPUT_FILES:
    batch = detector.analyze_files(INPUT_FILES)
    display(pd.DataFrame([{k: v for k, v in r.items() if k != "stage2_pending"} for r in batch["results"]]))
    display(pd.DataFrame(batch["stage2_pending"]))
    display(pd.DataFrame(batch["errors"]))
    json_write(REPORT_DIR / "new_file_results.json", batch)
    # 후속 2차 코드 연결:
    # for item in batch["stage2_pending"]:
    #     second_stage_result = second_stage_predict(item["path"])
else:
    print("INPUT_FILES에 분석할 파일 경로를 넣으면 새 파일 추론을 수행합니다.")
""")
md("""
## 산출물 안내

- feature_cache: 수치 특징/행 순서/실제 content SHA/오류의 재사용 캐시.
- runs/<실행 ID>/reports: 데이터 검증, 학습 곡선, 특징 중요도, threshold 곡선,
  validation/test 지표·점수·그래프, 3단계 판정, 2차 대기 목록, 오류 목록.
- combined_bundle 및 pemml_only_bundle: 모델·threshold·특징 순서/규칙·전처리 설정·
  동일 Python 추출/추론 코드·패키지 버전·데이터 이력·2차 입력 계약.

전체 데이터 학습 후에만 최종 성능을 보고합니다. 추출 오류가 발생하면 유효 특징 행의 수는
258,841보다 적어질 수 있으며, 원래 평가 분모와 오류 목록은 함께 남습니다.
실행 중간에서 설정/코드를 바꾼 경우 위쪽 설정 셀부터 다시 실행해 새 run을 생성하세요.
""")

notebook = dict(cells=cells, nbformat=4, nbformat_minor=5, metadata={
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python", "version": "3.12"},
})
for index, cell in enumerate(cells):
    cell["id"] = f"stage1-{index:03d}"
path = ROOT / "stage1_xgboost_training.ipynb"
path.write_text(json.dumps(notebook, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"Created {path.name}: {len(cells)} cells")
