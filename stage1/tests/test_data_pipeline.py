"""임시 파일로 특징 캐시의 재시작·무효화·실패 보존·누수 검사를 검증합니다.

PE 파서 대신 공개 반환 계약을 구현한 mock을 사용합니다. 테스트 입력과 캐시는
각 테스트의 TemporaryDirectory 안에만 만들며 실제 dataset을 읽거나 바꾸지 않습니다.
"""

import contextlib
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

from stage1 import data_pipeline as pipeline
from stage1 import feature_extractor as fe


class FeatureCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="stage1-cache-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = [self.root / "first.bin", self.root / "second.bin"]
        self.inputs[0].write_bytes(b"first fixture")
        self.inputs[1].write_bytes(b"second fixture data")
        self.manifest = pd.DataFrame({
            "sample_id": ["fixture_0", "fixture_1"],
            "source": ["PEMML", "BODMAS"],
            "sha256": ["a" * 64, "b" * 64],
            "path": [str(path) for path in self.inputs],
            "machine": [np.nan, 332], "subsystem": [np.nan, 2],
            "label": [0, 1], "split": ["train", "train"],
        })
        self.config = fe.ExtractorConfig()
        # 실제 모듈을 편집하지 않고 코드 내용 변경에 따른 cache key를 시험합니다.
        self.fake_source = self.root / "fixture_extractor.py"
        self.fake_source.write_text("# fixture extractor version 1\n", encoding="utf-8")
        source_patch = patch.object(fe, "__file__", str(self.fake_source))
        source_patch.start()
        self.addCleanup(source_patch.stop)

    @staticmethod
    def extract_fixture(path, **kwargs):
        """파일 내용에 따라 달라지는 특징을 돌려줘 재추출 여부를 관측합니다."""
        try:
            content = Path(path).read_bytes()
        except OSError as error:
            return {
                "vector": None, "parse_status": "error",
                "error_reason": f"{type(error).__name__}: {error}",
                "parse_warnings": [], "content_sha256": None,
                "elapsed_seconds": 0.0,
            }
        vector = np.full(len(fe.FEATURE_NAMES), len(content), dtype=np.float32)
        vector[1] = sum(content)
        return {
            "vector": vector, "parse_status": "ok", "error_reason": None,
            "parse_warnings": [],
            "content_sha256": hashlib.sha256(content).hexdigest(),
            "elapsed_seconds": 0.001,
        }

    def cache(self, *, config=None, manifest=None):
        # 청크별 호출 개수를 확인하기 위해 한 행씩 저장합니다.
        # stdout 진행률은 테스트 결과와 관계없으므로 출력만 억제합니다.
        with contextlib.redirect_stdout(io.StringIO()):
            return pipeline.cache_features(
                self.manifest if manifest is None else manifest,
                self.root / "cache", self.config if config is None else config,
                workers=1, chunk_size=1,
            )

    def test_completed_chunks_are_reused_without_reextracting(self):
        with patch.object(fe, "extract_pe_features", side_effect=self.extract_fixture) as extract:
            first, first_meta, folder = self.cache()
            self.assertEqual(extract.call_count, 2)
            # 출처별 헤더 보정 인자도 기존 추출기 계약대로 전달되어야 합니다.
            self.assertIsNone(extract.call_args_list[0].kwargs["machine_override"])
            self.assertEqual(extract.call_args_list[1].kwargs["machine_override"], 332)
            self.assertEqual(extract.call_args_list[1].kwargs["subsystem_override"], 2)
            extract.reset_mock()
            second, second_meta, second_folder = self.cache()
            extract.assert_not_called()
        self.assertEqual(folder, second_folder)
        np.testing.assert_array_equal(first, second)
        pd.testing.assert_frame_equal(first_meta, second_meta)
        self.assertEqual(second_meta.sample_id.tolist(), self.manifest.sample_id.tolist())
        self.assertEqual(second.dtype, np.float32)
        self.assertEqual(len(list(folder.glob("chunk_*.npz"))), 2)

    def test_extractor_code_change_creates_a_new_cache(self):
        with patch.object(fe, "extract_pe_features", side_effect=self.extract_fixture) as extract:
            _, _, first_folder = self.cache()
            # 이 파일은 setUp에서 만든 임시 fixture이며 프로젝트 소스가 아닙니다.
            self.fake_source.write_text("# fixture extractor version 2\n", encoding="utf-8")
            extract.reset_mock()
            _, _, second_folder = self.cache()
            self.assertEqual(extract.call_count, 2)
        self.assertNotEqual(first_folder, second_folder)
        self.assertTrue((first_folder / "chunk_0000000.npz").is_file())

    def test_extractor_configuration_change_creates_a_new_cache(self):
        with patch.object(fe, "extract_pe_features", side_effect=self.extract_fixture) as extract:
            _, _, first_folder = self.cache()
            extract.reset_mock()
            _, _, second_folder = self.cache(config=fe.ExtractorConfig(chunk_bytes=4096))
            self.assertEqual(extract.call_count, 2)
        self.assertNotEqual(first_folder, second_folder)

    def test_size_change_reextracts_only_the_affected_chunk(self):
        with patch.object(fe, "extract_pe_features", side_effect=self.extract_fixture) as extract:
            before, _, folder = self.cache()
            self.inputs[0].write_bytes(b"a longer temporary fixture than before")
            extract.reset_mock()
            after, metadata, new_folder = self.cache()
            extract.assert_called_once()
            self.assertEqual(extract.call_args.args[0], str(self.inputs[0]))
        self.assertEqual(folder, new_folder)
        self.assertNotEqual(before[0, 0], after[0, 0])
        np.testing.assert_array_equal(before[1], after[1])
        self.assertEqual(metadata.content_sha256.iloc[0],
                         hashlib.sha256(self.inputs[0].read_bytes()).hexdigest())

    def test_mtime_change_invalidates_a_same_size_input(self):
        with patch.object(fe, "extract_pe_features", side_effect=self.extract_fixture) as extract:
            before, _, folder = self.cache()
            old_stat = self.inputs[0].stat()
            content = self.inputs[0].read_bytes()
            self.inputs[0].write_bytes(b"Z" + content[1:])
            # 파일시스템의 시간 해상도에 기대지 않고 변경을 명시합니다.
            os.utime(self.inputs[0], ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns + 1_000_000_000))
            extract.reset_mock()
            after, _, new_folder = self.cache()
            extract.assert_called_once()
        self.assertEqual(folder, new_folder)
        self.assertEqual(before[0, 0], after[0, 0])
        self.assertNotEqual(before[0, 1], after[0, 1])
        np.testing.assert_array_equal(before[1], after[1])

    def test_missing_input_keeps_its_error_row_and_nan_features(self):
        with patch.object(fe, "extract_pe_features", side_effect=self.extract_fixture) as extract:
            _, _, folder = self.cache()
            # 캐시를 만든 뒤 테스트 소유 입력을 없애 stale success 재사용도 검사합니다.
            self.inputs[0].unlink()
            extract.reset_mock()
            matrix, metadata, new_folder = self.cache()
            extract.assert_called_once()
            self.assertEqual(new_folder, folder)
            self.assertEqual(matrix.shape, (2, len(fe.FEATURE_NAMES)))
            self.assertTrue(np.isnan(matrix[0]).all())
            self.assertTrue(np.isfinite(matrix[1]).all())
            self.assertEqual(metadata.sample_id.tolist(), self.manifest.sample_id.tolist())
            self.assertEqual(metadata.parse_status.tolist(), ["error", "ok"])
            self.assertIn("FileNotFoundError", metadata.error_reason.iloc[0])
            self.assertEqual(metadata.content_sha256.iloc[0], "")
            errors = pd.read_csv(folder / "extraction_errors.csv")
            self.assertEqual(errors.sample_id.tolist(), ["fixture_0"])
            # missing 상태를 완료 성공 캐시로 간주하지 않고 다음 실행에도 재시도합니다.
            extract.reset_mock()
            self.cache()
            extract.assert_called_once()

    def test_actual_content_hash_overlap_across_splits_is_rejected(self):
        self.inputs[1].write_bytes(self.inputs[0].read_bytes())
        manifest = self.manifest.copy()
        # 식별자 SHA는 다르더라도 실제 바이트가 같으면 split 누수를 잡아야 합니다.
        # 라벨을 같게 설정하여 이번 실패가 label 충돌이 아닌 split 충돌임을 고정합니다.
        manifest["label"] = 1
        manifest["split"] = ["train", "test"]
        with patch.object(fe, "extract_pe_features", side_effect=self.extract_fixture):
            with self.assertRaisesRegex(ValueError, "split/label"):
                self.cache(manifest=manifest)
        reports = list((self.root / "cache").glob("*/content_hash_conflicts.csv"))
        self.assertEqual(len(reports), 1)
        report = pd.read_csv(reports[0])
        self.assertEqual(len(report), 1)
        self.assertEqual(report["splits"].iloc[0], 2)
        self.assertEqual(report["labels"].iloc[0], 1)
        self.assertEqual(report.content_sha256.iloc[0],
                         hashlib.sha256(self.inputs[0].read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
