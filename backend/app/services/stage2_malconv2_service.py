"""내보낸 BODMAS MalConv2 패밀리 분류 모델을 웹 서버에 연결한다.

체크포인트에는 가중치만 있고, 일치하는 모델 구조는
``backend/models/stage2/source``에 있다. 이 어댑터는 가중치·라벨·구조를
엄격히 확인해, 맞지 않는 파일이 그럴듯하지만 잘못된 패밀리명을 반환하지 않게 한다.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .byte_preprocessor import PreparedByteSequence


# XGBoost와 PyTorch는 모두 OpenMP를 사용한다. macOS에서 두 라이브러리가 기본
# 스레드 수로 함께 동작하면 PyTorch의 가중치 CPU 복사 단계가 서로를 기다릴 수 있다.
# 사용자가 미리 지정한 값은 존중하고, 없을 때만 안전한 단일 스레드 기본값을 둔다.
for _thread_setting in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
    os.environ.setdefault(_thread_setting, "1")


DEFAULT_STAGE2_DIR = Path(__file__).resolve().parents[2] / "models" / "stage2"
# 검증 데이터 기반 보정값을 별도 파일로 내보내기 전까지 쓰는 임시 기준이다.
# 화면에 숨긴 규칙이 아니라 설정으로 두어, 나중에 API를 바꾸지 않고
# threshold.json 값만 교체할 수 있게 한다.
DEFAULT_FAMILY_CONFIDENCE_THRESHOLD = 0.70


class Stage2ModelLoadError(RuntimeError):
    """전달받은 2차 모델 파일을 안전하게 사용할 수 없을 때 발생한다."""


class Stage2InferenceError(RuntimeError):
    """2차 모델이 유효한 숫자 점수를 반환하지 못했을 때 발생한다."""


class Stage2MalConvService:
    """한 번만 모델을 불러와 원시 PE 바이트를 읽기 전용으로 분류한다."""

    def __init__(
        self,
        model_dir: Path = DEFAULT_STAGE2_DIR,
        confidence_threshold: float | None = None,
    ) -> None:
        if confidence_threshold is None:
            confidence_threshold = self._load_threshold(model_dir / "threshold.json")
        if not 0.0 <= confidence_threshold <= 1.0:
            raise ValueError("2차 분류 임계값은 0과 1 사이여야 합니다.")

        self.model_dir = model_dir
        self.confidence_threshold = confidence_threshold
        # PyTorch는 여기에서 늦게 불러온다. 배포 환경에 의존성이 빠져도
        # FastAPI 전체가 시작 전에 종료되지 않고, 해당 파일 행에 오류를 남긴다.
        try:
            self.torch = importlib.import_module("torch")
            self.numpy = importlib.import_module("numpy")
        except ImportError as error:
            raise Stage2ModelLoadError("2차 모델 실행에 필요한 PyTorch 또는 NumPy가 없습니다.") from error

        # 환경 변수와 같은 값을 PyTorch 런타임에도 명시한다. 이 호출은 텐서를
        # 만들기 전에 실행해야 CPU 연산이 다수의 OpenMP 작업 스레드를 만들지 않는다.
        self.torch.set_num_threads(1)
        try:
            self.torch.set_num_interop_threads(1)
        except RuntimeError:
            # 같은 프로세스에서 이전 분석이 이미 PyTorch 병렬 작업을 시작했다면
            # inter-op 수는 다시 바꿀 수 없다. 일반 CPU 스레드 제한은 유지된다.
            pass

        self.labels = self._load_labels(model_dir / "class_mapping.txt")
        file_config = self._load_json(model_dir / "config.json", "2차 모델 config.json")
        checkpoint = self._load_checkpoint(model_dir / "best_model.pth")
        checkpoint_config = checkpoint.get("config")
        if not isinstance(checkpoint_config, Mapping):
            raise Stage2ModelLoadError("체크포인트에 학습 설정(config)이 없습니다.")
        self._validate_config(file_config, checkpoint_config)
        self._validate_checkpoint_labels(checkpoint.get("class_names"))

        state_dict = checkpoint.get("model_state_dict")
        if not isinstance(state_dict, Mapping):
            raise Stage2ModelLoadError("체크포인트에 model_state_dict 가 없습니다.")
        self.model = self._build_and_load_model(state_dict, checkpoint_config)
        # CPU를 기본으로 선택해 CUDA 전용 학습 체크포인트도 macOS/일반 노트북에서
        # 동일하게 재현한다. 성능 검증 뒤 MPS/CUDA 선택 옵션은 별도로 추가할 수 있다.
        self.device = self.torch.device("cpu")
        self.model.to(self.device)
        self.model.eval()

    @staticmethod
    def _load_json(path: Path, display_name: str) -> dict[str, Any]:
        try:
            with path.open(encoding="utf-8") as file:
                value = json.load(file)
        except (OSError, json.JSONDecodeError) as error:
            raise Stage2ModelLoadError(f"{display_name}을 읽을 수 없습니다: {error}") from error
        if not isinstance(value, dict):
            raise Stage2ModelLoadError(f"{display_name}은 JSON 객체여야 합니다.")
        return value

    def _load_threshold(self, path: Path) -> float:
        """별도로 조절 가능한 임계값을 읽고, 없으면 임시 기본값을 사용한다."""
        if not path.exists():
            return DEFAULT_FAMILY_CONFIDENCE_THRESHOLD
        value = self._load_json(path, "2차 모델 threshold.json")
        threshold = value.get("family_confidence_threshold")
        if not isinstance(threshold, (int, float)):
            raise Stage2ModelLoadError("threshold.json에 family_confidence_threshold 숫자가 없습니다.")
        return float(threshold)

    @staticmethod
    def _load_labels(path: Path) -> list[str]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise Stage2ModelLoadError(f"2차 클래스 맵을 읽을 수 없습니다: {error}") from error

        indexed_labels: dict[int, str] = {}
        for line in lines:
            if not line.strip():
                continue
            try:
                raw_index, label = line.split(maxsplit=1)
                index = int(raw_index)
            except ValueError as error:
                raise Stage2ModelLoadError(f"잘못된 클래스 맵 행입니다: {line!r}") from error
            if index in indexed_labels or not label.strip():
                raise Stage2ModelLoadError(f"중복되었거나 비어 있는 클래스 맵 행입니다: {line!r}")
            indexed_labels[index] = label.strip()

        expected_indices = list(range(len(indexed_labels)))
        if sorted(indexed_labels) != expected_indices:
            raise Stage2ModelLoadError("클래스 맵 번호는 0부터 빈틈없이 이어져야 합니다.")
        if not indexed_labels:
            raise Stage2ModelLoadError("클래스 맵이 비어 있습니다.")
        return [indexed_labels[index] for index in expected_indices]

    def _load_checkpoint(self, path: Path) -> Mapping[str, Any]:
        if not path.is_file():
            raise Stage2ModelLoadError(f"2차 모델 가중치 파일이 없습니다: {path.name}")
        try:
            # weights_only=True는 신뢰할 수 없는 pickle 내부의 임의 Python 객체를
            # 막는다. 그래도 모델 파일은 사용자 업로드가 아닌 팀 제공본만 사용한다.
            checkpoint = self.torch.load(path, map_location="cpu", weights_only=True)
        except Exception as error:
            raise Stage2ModelLoadError(f"2차 모델 가중치를 안전하게 읽을 수 없습니다: {error}") from error
        if not isinstance(checkpoint, Mapping):
            raise Stage2ModelLoadError("2차 체크포인트는 사전(dict) 형식이어야 합니다.")
        return checkpoint

    def _validate_config(self, file_config: Mapping[str, Any], checkpoint_config: Mapping[str, Any]) -> None:
        # 이 값은 텐서 형태와 스캔 방식을 결정한다. 다르면 같은 가중치라도
        # 학습 때와 다른 구조에 들어가므로 추론을 중단해야 한다.
        required = ("CHANNELS", "WINDOW_SIZE", "STRIDE", "EMBEDDING_DIM", "SCAN_CHUNK_BYTES")
        for key in required:
            if key not in file_config or key not in checkpoint_config:
                raise Stage2ModelLoadError(f"2차 모델 설정에 {key} 값이 없습니다.")
            if file_config[key] != checkpoint_config[key]:
                raise Stage2ModelLoadError(f"config.json과 체크포인트의 {key} 값이 다릅니다.")

    def _validate_checkpoint_labels(self, checkpoint_labels: Any) -> None:
        if not isinstance(checkpoint_labels, (list, tuple)):
            raise Stage2ModelLoadError("체크포인트에 class_names 목록이 없습니다.")
        normalized_checkpoint = [str(label).strip() for label in checkpoint_labels]
        if normalized_checkpoint != self.labels:
            raise Stage2ModelLoadError("class_mapping.txt의 순서가 체크포인트 class_names와 다릅니다.")

    def _build_and_load_model(self, state_dict: Mapping[str, Any], config: Mapping[str, Any]):
        state = {str(key): value for key, value in state_dict.items()}
        # 이 체크포인트는 네트워크 키 앞에 ``net.``을 붙여 저장했다. 알려진 이
        # 접두사만 제거하면 strict 로딩이 나머지 모든 불일치를 찾아낼 수 있다.
        if state and all(key.startswith("net.") for key in state):
            state = {key.removeprefix("net."): value for key, value in state.items()}

        source_dir = self.model_dir / "source"
        if not source_dir.is_dir():
            raise Stage2ModelLoadError("2차 모델 source 폴더가 없습니다.")
        source_path = str(source_dir)
        if source_path not in sys.path:
            sys.path.insert(0, source_path)

        # context_net 가중치가 있는 이 체크포인트는 Global Context 기반
        # MalConvGCT 구조다. 직접 MalConvML로 읽으면 일부 가중치가 누락된다.
        is_gct = any(key.startswith("context_net.") for key in state)
        try:
            if is_gct:
                model_module = importlib.import_module("MalConvGCT_nocat")
                model_class = model_module.MalConvGCT
            else:
                model_module = importlib.import_module("MalConvML")
                model_class = model_module.MalConvML
        except (ImportError, AttributeError) as error:
            raise Stage2ModelLoadError(f"2차 모델 구조 코드를 불러올 수 없습니다: {error}") from error

        layer_indexes = {
            int(key.split(".")[1])
            for key in state
            if key.startswith("convs.") and key.endswith(".weight") and key.split(".")[1].isdigit()
        }
        if not layer_indexes:
            raise Stage2ModelLoadError("체크포인트에서 합성곱 레이어 수를 확인할 수 없습니다.")
        layers = max(layer_indexes) + 1
        model_kwargs = {
            "out_size": len(self.labels),
            "channels": int(config["CHANNELS"]),
            "window_size": int(config["WINDOW_SIZE"]),
            "stride": int(config["STRIDE"]),
            "layers": layers,
            "embd_size": int(config["EMBEDDING_DIM"]),
        }
        # Gradient checkpointing은 학습에서만 메모리 절약 효과가 있다. 추론에서는
        # 끄더라도 학습된 순전파 계산 결과가 바뀌지 않아 처리가 단순해진다.
        if is_gct:
            model_kwargs["low_mem"] = False
        model = model_class(**model_kwargs)
        if int(config["SCAN_CHUNK_BYTES"]) != model.chunk_size:
            raise Stage2ModelLoadError("SCAN_CHUNK_BYTES가 모델 소스의 청크 크기와 다릅니다.")
        try:
            model.load_state_dict(state, strict=True)
        except Exception as error:
            raise Stage2ModelLoadError(f"체크포인트 가중치가 모델 구조와 일치하지 않습니다: {error}") from error
        return model

    def predict_stage2(self, sequence: PreparedByteSequence) -> tuple[str, float, bool]:
        """최고 패밀리, 원시 softmax 점수, Unknown 여부를 반환한다.

        점수는 보정된 현실 확률이 아니라 모델 신뢰도다. 설정된 임계값보다
        낮을 때만 Unknown을 반환하며, 이때는 최고 클래스를 의도적으로 숨긴다.
        """
        if not sequence.values:
            raise ValueError("빈 바이트 시퀀스는 2차 분류할 수 없습니다.")

        probabilities = self._predict_probabilities(sequence)
        # softmax 결과에 NaN 또는 Infinity가 있으면 최고 클래스나 신뢰도를 만들면
        # 안 된다. 이후 Pydantic 응답 검증까지 오류가 전파되는 대신 여기에서
        # 명확하게 중단해 분석 서비스가 안전한 오류 행으로 바꾸게 한다.
        if not bool(self.torch.isfinite(probabilities).all().item()):
            raise Stage2InferenceError("2차 모델 출력에 유효하지 않은 숫자가 포함되었습니다.")
        confidence_tensor, class_tensor = self.torch.max(probabilities, dim=1)

        class_index = int(class_tensor.item())
        confidence = round(float(confidence_tensor.item()), 4)
        if confidence < self.confidence_threshold:
            return "Unknown", confidence, True
        return self.labels[class_index], confidence, False

    def predict_class_confidence(self, sequence: PreparedByteSequence, target_class: str) -> float:
        """지정한 2차 클래스의 softmax 점수를 반환한다.

        판단 근거 분석은 Top-1 결과가 바뀌는지보다, 원래 예측된 클래스의 점수가
        가림 전후 얼마나 변했는지를 비교해야 하므로 이 함수를 사용한다.
        """
        try:
            class_index = self.labels.index(target_class.strip())
        except ValueError as error:
            raise ValueError(f"2차 모델에 없는 클래스입니다: {target_class}") from error
        probabilities = self._predict_probabilities(sequence)
        if not bool(self.torch.isfinite(probabilities).all().item()):
            raise Stage2InferenceError("2차 모델 출력에 유효하지 않은 숫자가 포함되었습니다.")
        return round(float(probabilities[0, class_index].item()), 4)

    def _predict_probabilities(self, sequence: PreparedByteSequence):
        """원시 바이트 시퀀스를 한 번 추론해 클래스별 softmax 텐서를 반환한다."""
        if not sequence.values:
            raise ValueError("빈 바이트 시퀀스는 2차 분류할 수 없습니다.")

        # 더하기 전에 NumPy 자료형을 바꾼다. uint8(255)에 1을 더하면 0으로
        # 넘쳐 nn.Embedding(257)이 이를 패딩으로 오해할 수 있기 때문이다.
        token_values = self.numpy.frombuffer(sequence.values, dtype=self.numpy.uint8).astype(self.numpy.int64)
        token_values += 1
        tokens = self.torch.from_numpy(token_values).unsqueeze(0).to(self.device)
        with self.torch.inference_mode():
            logits, _, _ = self.model(tokens)
            return self.torch.softmax(logits, dim=1)
