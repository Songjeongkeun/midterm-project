"""내보낸 1차 XGBoost 번들을 웹 분석 흐름에 연결한다.

학습 프로젝트는 모델 JSON, 특징 스키마, 특징 추출기, 임계값, 파일 해시 목록을
하나의 번들로 내보냈다. 이 어댑터는 341개 특징의 순서가 조금만 달라져도 학습된
모델을 무효화할 수 있으므로, 특징을 웹 앱에서 다시 구현하지 않고 번들 그대로 쓴다.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path


DEFAULT_BUNDLE_DIR = Path(__file__).resolve().parents[2] / "models" / "stage1_xgboost_bundle"


class Stage1ModelLoadError(RuntimeError):
    """내보낸 1차 번들을 안전하게 사용할 수 없을 때 발생한다."""


@dataclass(frozen=True)
class Stage1Prediction:
    """번들의 안정된 1차 결과 중 웹 화면에 필요한 값만 보관한다.

    ``needs_stage2``는 별도의 모델 점수가 아니라, 내보낸 임계값 규칙으로 만든
    2차 분류 전달 여부다. ``Error`` 결과에는 숫자 점수가 없다.
    """

    result: str
    malware_score: float | None
    needs_stage2: bool
    error_reason: str | None = None


class Stage1XGBoostService:
    """검증된 XGBoost 번들을 한 번 불러와 PE 파일 경로를 1차 분류한다.

    341개 특징 이름과 순서는 학습 모델의 계약에 포함된다. 따라서 웹 앱에서
    특징을 새로 만들면 호환되지 않는 열을 XGBoost에 조용히 전달할 위험이 있다.
    """

    def __init__(self, bundle_dir: Path = DEFAULT_BUNDLE_DIR) -> None:
        self.bundle_dir = bundle_dir.resolve()
        # 알 수 없는 특징 정의를 가진 임의의 JSON 모델을 받지 않고, 완전한 내보내기
        # 결과를 뜻하는 manifest가 있는 번들만 사용한다.
        if not (self.bundle_dir / "bundle_manifest.json").is_file():
            raise Stage1ModelLoadError(f"1차 모델 번들을 찾을 수 없습니다: {self.bundle_dir}")

        # 복사한 번들에는 `stage1` Python 패키지가 있다. runtime.py가 해시로
        # 검증하는 정확한 특징 추출기를 가져오도록 패키지 상위 경로를 앞에 둔다.
        bundle_path = str(self.bundle_dir)
        if bundle_path not in sys.path:
            sys.path.insert(0, bundle_path)

        try:
            from stage1.runtime import Stage1Detector

            self.detector = Stage1Detector(self.bundle_dir)
        except Exception as error:  # Includes manifest, dependency and version checks.
            raise Stage1ModelLoadError(f"1차 XGBoost 모델을 로드할 수 없습니다: {error}") from error

    def analyze_file(self, file_path: Path) -> Stage1Prediction:
        """번들이 정의한 PE 특징을 추출하고 2차 전달 여부까지 반환한다.

        번들은 낮은 임계값 미만이면 ``Normal``, 두 임계값 사이는 ``Suspicious``,
        높은 임계값 이상이면 ``Malware``를 반환한다. 이 앱은 뒤의 두 결과를
        모두 2차 모델로 전달한다.
        """
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
