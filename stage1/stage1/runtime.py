"""저장된 1차 모델을 불러오는 추론 API와 2차 연결 경계.

이 모듈은 학습을 실행하지 않는다. 2차 모델 구현도 포함하지 않는다.
후속 팀은 stage2_pending의 path를 읽는 부분에 자기 전처리/모델을 연결하면 된다.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from xgboost import XGBClassifier

from . import feature_extractor as fe
from .evaluation import route_scores


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class Stage1Detector:
    """Normal은 종료, Suspicious/Malware만 2차 대기열로 전달한다.

    분석 실패는 결과의 errors에 남기고 정상으로 간주하거나 2차로 전달하지 않는다.
    """

    def __init__(self, bundle_dir: str | Path):
        self.bundle_dir = Path(bundle_dir).expanduser().resolve()
        read_json = lambda name: json.loads((self.bundle_dir / name).read_text(encoding="utf-8"))
        bundle = read_json("bundle_manifest.json")
        for relative, expected_hash in bundle["files"].items():
            path = (self.bundle_dir / relative).resolve()
            if not path.is_relative_to(self.bundle_dir) or _digest(path) != expected_hash:
                raise ValueError(f"모델 패키지 파일 무결성 불일치: {relative}")
        self.names = read_json("feature_names.json")
        self.feature_config = read_json("feature_config.json")
        self.thresholds = read_json("xgb_threshold.json")
        self.model_config = read_json("model_config.json")
        if self.feature_config["extractor_version"] != fe.FEATURE_VERSION:
            raise ValueError("학습 당시 특징 추출기 버전과 다릅니다.")
        if self.names != list(fe.FEATURE_NAMES):
            raise ValueError("모델 특징 이름/순서와 현재 추출기 코드가 다릅니다.")
        if _digest(Path(fe.__file__)) != self.feature_config["extractor_source_sha256"]:
            raise ValueError("학습 당시의 feature_extractor.py를 사용해야 합니다.")
        if str(fe.pefile.__version__) != self.feature_config["pefile_version"]:
            raise ValueError("학습 당시 pefile 버전과 다릅니다. requirements.txt를 확인하세요.")
        self.extractor_config = fe.ExtractorConfig(**self.feature_config["extractor_config"])
        self.model = XGBClassifier()
        self.model.load_model(self.bundle_dir / "xgb_model.json")
        # GPU로 학습해도 CPU에서 로드/추론할 수 있다.
        self.model.set_params(device="cpu")
        booster = self.model.get_booster()
        if booster.num_features() != len(self.names) or booster.feature_names != self.names:
            raise ValueError("저장 모델과 feature_names.json이 일치하지 않습니다.")
        self.set_thresholds(self.thresholds["low"], self.thresholds["high"])

    def set_thresholds(self, low: float, high: float):
        """트리의 재학습 없이 화면 표시/2차 전달 기준만 변경한다."""
        route_scores(np.array([], dtype=float), low, high, error_forward=False)
        self.low, self.high = float(low), float(high)

    def analyze_file(self, path, *, input_id=None, source=None, reference_sha256=None,
                     machine_override=None, subsystem_override=None) -> dict:
        """새 PE 입력에는 path만 필요하다. BODMAS 실험 시에만 보정 메타데이터를 준다."""
        path = Path(path).expanduser().resolve()
        result = fe.extract_pe_features(
            path, source=source, reference_sha256=reference_sha256,
            machine_override=machine_override, subsystem_override=subsystem_override,
            config=self.extractor_config,
        )
        common = {
            "input_id": str(input_id) if input_id is not None else str(path),
            "path": str(path),
            "content_sha256": result["content_sha256"],
            "parse_status": result["parse_status"],
            "error_reason": result["error_reason"],
            "parse_warnings": result["parse_warnings"],
        }
        if result["parse_status"] == "error":
            return {**common, "malware_score": None, "stage1_result": "Error",
                    "needs_stage2": False, "stage2_pending": None}
        vector = np.asarray(result["vector"], dtype=np.float32)
        if vector.shape != (len(self.names),) or np.isinf(vector).any():
            raise ValueError("추출된 특징의 형태/숫자 범위가 올바르지 않습니다.")
        score = float(self.model.predict_proba(pd.DataFrame([vector], columns=self.names))[0, 1])
        routed = route_scores(np.array([score]), self.low, self.high, error_forward=False).iloc[0]
        # 이 목록이 2차 팀과의 계약이다. 정답 label/family나 특징 벡터를 넣지 않는다.
        # 2차가 raw byte, image 중 무엇을 쓸지는 2차 구현에서 결정한다.
        handoff = None
        if bool(routed.needs_stage2):
            handoff = {
                "handoff_version": "1.0",
                "input_id": common["input_id"], "path": common["path"],
                "content_sha256": common["content_sha256"],
                "stage1_score": score, "stage1_result": str(routed.stage1_result),
            }
        return {**common, "malware_score": score, "stage1_result": str(routed.stage1_result),
                "needs_stage2": bool(routed.needs_stage2), "stage2_pending": handoff}

    def analyze_files(self, paths) -> dict:
        """하나의 파일에서 발생한 파싱 오류가 전체 배치를 멈추지 않는다."""
        results = [self.analyze_file(path, input_id=f"input_{i:06d}") for i, path in enumerate(paths)]
        return {
            "results": results,
            "stage2_pending": [r["stage2_pending"] for r in results if r["needs_stage2"]],
            "errors": [r for r in results if r["stage1_result"] == "Error"],
        }


def save_bundle(output_dir, model, *, low, high, extractor_config, data_audit,
                training_config, validation_summary) -> Path:
    """프로그램에서 다시 불러오는 데 필요한 모든 1차 자산을 저장한다."""
    import importlib.metadata
    import platform
    import shutil
    from datetime import datetime, timezone
    from . import evaluation

    out = Path(output_dir)
    if out.exists():
        raise FileExistsError(f"기존 실험을 덮어쓰지 않습니다: {out}")
    route_scores(np.array([], dtype=float), low, high, error_forward=False)
    out.mkdir(parents=True)
    write_json = lambda name, value: (out / name).write_text(
        json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")
    params = asdict(extractor_config) if is_dataclass(extractor_config) else dict(extractor_config)
    model.save_model(out / "xgb_model.json")
    write_json("feature_names.json", list(fe.FEATURE_NAMES))
    write_json("feature_config.json", {
        "schema_version": "1.0", "n_features": len(fe.FEATURE_NAMES),
        "extractor_version": fe.FEATURE_VERSION,
        "dtype": "float32", "feature_names": list(fe.FEATURE_NAMES),
        "extractor_config": params, "pefile_version": str(fe.pefile.__version__),
        "extractor_source_sha256": _digest(Path(fe.__file__)),
        "missing_policy": {"absent_structure": 0, "unavailable_feature": "NaN",
                           "fatal_parse": "Error; excluded from training and stage2"},
        "bodmas_policy": "Override Machine/Subsystem features from metadata; do not alter raw bytes",
        "hash_policy": "reference_sha256=original identity; content_sha256=actual bytes",
    })
    write_json("xgb_threshold.json", {
        "low": float(low), "high": float(high),
        "normal_rule": "score < low", "suspicious_rule": "low <= score < high",
        "malware_rule": "score >= high", "error_forward": False,
        "selected_using": "validation only", "score_calibrated": False,
    })
    write_json("preprocessing.json", {
        "type": "identity", "scaler": None, "encoder": None,
        "why": "Fixed numeric PE features; native XGBoost NaN handling; no fitted scaling",
    })
    write_json("label_mapping.json", {"0": "Normal", "1": "Malware",
                                      "Suspicious": "score interval; not a training class"})
    write_json("model_config.json", {
        # 조기 종료를 끈 추가 실험에서도 전체 트리를 쓰는 정책을 기록한다.
        "objective": "binary:logistic", "best_iteration": int(getattr(
            model, "best_iteration", model.get_booster().num_boosted_rounds() - 1)),
        "num_boosted_rounds": model.get_booster().num_boosted_rounds(),
        "training_config": training_config, "validation_summary": validation_summary,
        "saved_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
    })
    write_json("dataset_audit.json", data_audit)
    write_json("stage2_contract.json", {
        "version": "1.0", "eligible_results": ["Suspicious", "Malware"],
        "excluded_results": ["Normal", "Error"],
        "fields": ["handoff_version", "input_id", "path", "content_sha256", "stage1_score", "stage1_result"],
        "implementation": "No stage2 preprocessing, model, or prediction is included.",
    })
    versions = {name: importlib.metadata.version(name) for name in
                ("numpy", "pandas", "pefile", "scikit-learn", "xgboost", "matplotlib")}
    write_json("environment.json", {"python": platform.python_version(), "packages": versions})
    (out / "requirements.txt").write_text("\n".join(f"{n}=={v}" for n, v in versions.items()) + "\n", encoding="utf-8")
    src = out / "stage1"
    src.mkdir()
    (src / "__init__.py").write_text('"""Saved stage1 inference package."""\n', encoding="utf-8")
    for module in (fe, evaluation):
        shutil.copy2(module.__file__, src / Path(module.__file__).name)
    shutil.copy2(__file__, src / "runtime.py")
    (out / "INTEGRATION.md").write_text(
        "# 1차 모델 사용\n\n"
        "패키지 폴더를 sys.path의 첫 위치에 넣은 새 Python 프로세스에서 실행합니다.\n\n"
        "    from stage1.runtime import Stage1Detector\n"
        "    detector = Stage1Detector(BUNDLE_DIR)\n"
        "    result = detector.analyze_file(PE_PATH)\n"
        "    print(result['stage1_result'], result['malware_score'])\n"
        "    stage2_input = result['stage2_pending']\n"
        "    # stage2_input이 None이 아닐 때만 별도로 구현한 2차 코드를 연결합니다.\n\n"
        "이 패키지는 1차 추론만 수행합니다. Error는 점수 없음/2차 제외로 기록됩니다.\n"
        "score는 보정되지 않은 모델 점수이며 실제 운영 악성 확률을 보장하지 않습니다.\n",
        encoding="utf-8")
    files = {p.relative_to(out).as_posix(): _digest(p) for p in out.rglob("*") if p.is_file()}
    write_json("bundle_manifest.json", {"version": "1.0", "files": files})
    return out
