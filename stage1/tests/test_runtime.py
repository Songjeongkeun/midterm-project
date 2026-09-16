"""저장 자산의 실제 재로딩과 1차→2차 연결 경계를 검증합니다.

실제 악성 파일을 읽을 필요가 없는 계약 테스트입니다. 재현 가능한 작은
XGBoost 모델을 실제로 학습/저장/로드하고, PE 추출 결과만 가짜 입력으로
바꿉니다. 따라서 파일 추출기 자체의 검증과 모델 배포 계약 검증을 분리합니다.
"""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd
from xgboost import XGBClassifier

from stage1 import feature_extractor as fe
from stage1.runtime import Stage1Detector, save_bundle


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.names = list(fe.FEATURE_NAMES)
        # 각 묶음의 악성 비율을 10%/50%/90%로 고정합니다. 두 임계값
        # 사이의 점수도 나오게 하여 세 표시 단계 전체를 실제 모델로 시험합니다.
        matrix = np.zeros((60, len(cls.names)), dtype=np.float32)
        matrix[:, 0] = np.repeat([0, 1, 2], 20)
        cls.x = pd.DataFrame(matrix, columns=cls.names)
        cls.y = np.array([0] * 18 + [1] * 2 + [0] * 10 + [1] * 10 + [0] * 2 + [1] * 18)
        cls.model = XGBClassifier(
            n_estimators=50, max_depth=2, learning_rate=0.3,
            objective="binary:logistic", eval_metric="logloss", tree_method="hist",
            random_state=42, n_jobs=1, early_stopping_rounds=5,
        )
        cls.model.fit(cls.x, cls.y, eval_set=[(cls.x, cls.y)], verbose=False)
        cls.vectors = [matrix[index].copy() for index in [0, 20, 40]]
        cls.expected_scores = cls.model.predict_proba(
            pd.DataFrame(cls.vectors, columns=cls.names)
        )[:, 1]
        # 학습이 달라져 세 구간이 안 나오면 mock 점수로 감추지 않고 실패시킵니다.
        assert cls.expected_scores[0] < 0.3 < cls.expected_scores[1] < 0.7 < cls.expected_scores[2]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="stage1-runtime-test-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.config = fe.ExtractorConfig(max_file_bytes=123456)
        self.bundle = save_bundle(
            self.folder / "bundle", self.model, low=0.3, high=0.7,
            extractor_config=self.config,
            data_audit={"fixture": "synthetic", "n_samples": len(self.y)},
            training_config={"seed": 42, "purpose": "unit test"},
            validation_summary={"fixture_only": True},
        )

    @staticmethod
    def extracted(vector, *, error=False):
        """추출기의 공개 반환 필드만 맞춥니다. 정답은 전달 객체에 넣지 않습니다."""
        return {
            "vector": None if error else vector,
            "content_sha256": "a" * 64,
            "parse_status": "error" if error else "ok",
            "error_reason": "fixture parse failure" if error else None,
            "parse_warnings": [],
        }

    def test_saved_model_and_configuration_roundtrip(self):
        detector = Stage1Detector(self.bundle)
        restored = detector.model.predict_proba(self.x)[:, 1]
        np.testing.assert_allclose(restored, self.model.predict_proba(self.x)[:, 1], rtol=0, atol=0)
        self.assertEqual(len(detector.names), 341)
        self.assertEqual(detector.names, self.names)
        self.assertEqual(detector.extractor_config, self.config)
        self.assertEqual((detector.low, detector.high), (0.3, 0.7))
        self.assertFalse(detector.thresholds["error_forward"])
        self.assertEqual(detector.model.get_params()["device"], "cpu")

        # 추론뿐 아니라 실험 재현/병합에 필요한 설정·소스·계약까지 존재합니다.
        required_files = {
            "xgb_model.json", "feature_names.json", "feature_config.json",
            "xgb_threshold.json", "preprocessing.json", "label_mapping.json",
            "model_config.json", "dataset_audit.json", "stage2_contract.json",
            "environment.json", "requirements.txt", "bundle_manifest.json",
            "INTEGRATION.md", "stage1/__init__.py", "stage1/runtime.py",
            "stage1/feature_extractor.py", "stage1/evaluation.py",
        }
        self.assertTrue(all((self.bundle / name).is_file() for name in required_files))
        manifest = json.loads((self.bundle / "bundle_manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(required_files - {"bundle_manifest.json"} <= set(manifest["files"]))
        for relative, expected in manifest["files"].items():
            actual = hashlib.sha256((self.bundle / relative).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, relative)

    def test_actual_model_routes_all_three_bands_and_separate_errors(self):
        detector = Stage1Detector(self.bundle)
        extracted_results = [self.extracted(vector) for vector in self.vectors]
        extracted_results += [self.extracted(None, error=True)]
        paths = [self.folder / name for name in ["normal", "suspicious", "malware", "bad_pe"]]
        with patch("stage1.runtime.fe.extract_pe_features", side_effect=extracted_results) as extractor:
            batch = detector.analyze_files(paths)
        rows = batch["results"]
        self.assertEqual([row["stage1_result"] for row in rows], ["Normal", "Suspicious", "Malware", "Error"])
        self.assertEqual([row["needs_stage2"] for row in rows], [False, True, True, False])
        np.testing.assert_allclose([row["malware_score"] for row in rows[:3]], self.expected_scores, rtol=0, atol=0)
        self.assertIsNone(rows[0]["stage2_pending"])
        self.assertIsNone(rows[3]["stage2_pending"])
        self.assertIsNone(rows[3]["malware_score"])
        self.assertEqual(batch["errors"], [rows[3]])
        self.assertEqual(extractor.call_count, 4)
        self.assertEqual(len(batch["stage2_pending"]), 2)

        allowed = {"handoff_version", "input_id", "path", "content_sha256", "stage1_score", "stage1_result"}
        for index, payload in enumerate(batch["stage2_pending"], start=1):
            self.assertEqual(set(payload), allowed)
            self.assertNotIn("label", payload)
            self.assertNotIn("family", payload)
            self.assertNotIn("vector", payload)
            self.assertEqual(payload["input_id"], f"input_{index:06d}")
            self.assertEqual(payload["path"], str(paths[index].resolve()))
            self.assertEqual(payload["stage1_result"], rows[index]["stage1_result"])
            self.assertEqual(payload["stage1_score"], rows[index]["malware_score"])

    def test_error_does_not_attempt_model_prediction(self):
        detector = Stage1Detector(self.bundle)
        with patch("stage1.runtime.fe.extract_pe_features", return_value=self.extracted(None, error=True)), patch.object(detector.model, "predict_proba") as predict:
            result = detector.analyze_file(self.folder / "bad_pe")
        predict.assert_not_called()
        self.assertEqual(result["stage1_result"], "Error")
        self.assertIsNone(result["malware_score"])
        self.assertFalse(result["needs_stage2"])

    def test_threshold_updates_change_routing_without_retraining_or_score_changes(self):
        detector = Stage1Detector(self.bundle)
        with patch("stage1.runtime.fe.extract_pe_features", return_value=self.extracted(self.vectors[1])):
            original = detector.analyze_file(self.folder / "middle")
            detector.set_thresholds(0.6, 0.9)
            adjusted = detector.analyze_file(self.folder / "middle")
        self.assertEqual(original["stage1_result"], "Suspicious")
        self.assertEqual(adjusted["stage1_result"], "Normal")
        self.assertEqual(original["malware_score"], adjusted["malware_score"])
        self.assertIsNone(adjusted["stage2_pending"])
        with self.assertRaises(ValueError):
            detector.set_thresholds(0.9, 0.3)
        self.assertEqual((detector.low, detector.high), (0.6, 0.9))
        # 수동 실험이 디스크의 원본 설정을 바꾸지 않습니다.
        loaded_again = Stage1Detector(self.bundle)
        self.assertEqual((loaded_again.low, loaded_again.high), (0.3, 0.7))

    def test_bodmas_feature_overrides_reach_extractor_but_not_handoff(self):
        detector = Stage1Detector(self.bundle)
        path = self.folder / "bodmas_file"
        with patch("stage1.runtime.fe.extract_pe_features", return_value=self.extracted(self.vectors[2])) as extractor:
            result = detector.analyze_file(
                path, input_id="known_sample", source="BODMAS", reference_sha256="b" * 64,
                machine_override=332, subsystem_override=3,
            )
        extractor.assert_called_once_with(
            path, source="BODMAS", reference_sha256="b" * 64,
            machine_override=332, subsystem_override=3, config=self.config,
        )
        self.assertEqual(result["input_id"], "known_sample")
        self.assertEqual(result["stage2_pending"]["content_sha256"], "a" * 64)
        self.assertNotIn("reference_sha256", result["stage2_pending"])
        self.assertNotIn("source", result["stage2_pending"])

    def test_tampered_saved_asset_fails_integrity_check(self):
        threshold_path = self.bundle / "xgb_threshold.json"
        # 유효 JSON 그대로 유지해도 한 바이트 변경을 로딩 시 감지해야 합니다.
        original = threshold_path.read_text(encoding="utf-8")
        threshold_path.write_text(original + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "무결성"):
            Stage1Detector(self.bundle)

    def test_runtime_rejects_incompatible_feature_schema(self):
        # 패키지 내부 파일은 정상이더라도 실행 중인 추출기 특징 순서가 다르면
        # 같은 숫자가 다른 의미로 들어갈 수 있으므로 재로딩을 거부해야 합니다.
        with patch("stage1.runtime.fe.FEATURE_NAMES", tuple(reversed(self.names))):
            with self.assertRaisesRegex(ValueError, "특징"):
                Stage1Detector(self.bundle)

    def test_save_never_overwrites_an_existing_experiment(self):
        original_manifest = (self.bundle / "bundle_manifest.json").read_bytes()
        with self.assertRaises(FileExistsError):
            save_bundle(
                self.bundle, self.model, low=0.2, high=0.8,
                extractor_config=self.config, data_audit={},
                training_config={}, validation_summary={},
            )
        self.assertEqual((self.bundle / "bundle_manifest.json").read_bytes(), original_manifest)


if __name__ == "__main__":
    unittest.main()
