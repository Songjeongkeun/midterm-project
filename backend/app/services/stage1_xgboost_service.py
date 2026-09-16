"""Adapter for the exported first-stage XGBoost bundle.

The training project exported a self-contained bundle: model JSON, feature
schema, feature extractor, thresholds and a manifest of their hashes.  This
adapter deliberately imports that bundle as-is instead of reimplementing the
341-feature extractor, because even a changed feature order would invalidate
the trained XGBoost model.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path


DEFAULT_BUNDLE_DIR = Path(__file__).resolve().parents[2] / "models" / "stage1_xgboost_bundle"


class Stage1ModelLoadError(RuntimeError):
    """Raised when the exported bundle cannot be used safely."""


@dataclass(frozen=True)
class Stage1Prediction:
    """The web-facing subset of the bundle's stable stage-1 result."""

    result: str
    malware_score: float | None
    needs_stage2: bool
    error_reason: str | None = None


class Stage1XGBoostService:
    """Load the verified XGBoost bundle once and classify a PE file by path."""

    def __init__(self, bundle_dir: Path = DEFAULT_BUNDLE_DIR) -> None:
        self.bundle_dir = bundle_dir.resolve()
        if not (self.bundle_dir / "bundle_manifest.json").is_file():
            raise Stage1ModelLoadError(f"1차 모델 번들을 찾을 수 없습니다: {self.bundle_dir}")

        # The copied bundle contains a `stage1` Python package. Put its parent
        # first so runtime.py imports the exact extractor whose hash it verifies.
        bundle_path = str(self.bundle_dir)
        if bundle_path not in sys.path:
            sys.path.insert(0, bundle_path)

        try:
            from stage1.runtime import Stage1Detector

            self.detector = Stage1Detector(self.bundle_dir)
        except Exception as error:  # Includes manifest, dependency and version checks.
            raise Stage1ModelLoadError(f"1차 XGBoost 모델을 로드할 수 없습니다: {error}") from error

    def analyze_file(self, file_path: Path) -> Stage1Prediction:
        """Extract the exported 341 PE features and return the routing decision."""
        raw = self.detector.analyze_file(file_path)
        result = str(raw["stage1_result"])
        if result == "Error":
            return Stage1Prediction(
                result=result,
                malware_score=None,
                needs_stage2=False,
                error_reason=raw.get("error_reason") or "PE 특징을 추출할 수 없습니다.",
            )
        if result not in {"Normal", "Suspicious", "Malware"}:
            raise ValueError(f"알 수 없는 1차 모델 결과: {result}")
        return Stage1Prediction(
            result=result,
            malware_score=float(raw["malware_score"]),
            needs_stage2=bool(raw["needs_stage2"]),
        )
