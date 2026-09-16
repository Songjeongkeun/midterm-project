"""합성 PE로 추출기의 입력 계약을 검사한다. 어떤 샘플도 실행하지 않는다.

실행: python -m unittest discover -s tests -p test_feature_extractor.py -v
"""
from dataclasses import replace
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

import numpy as np

from stage1.feature_extractor import DEFAULT_CONFIG, FEATURE_NAMES, extract_pe_features


def minimal_pe(*, malformed_import=False, disarmed=False, overlay=b""):
    """PE32 헤더/섹션 1개를 갖는 테스트 전용 byte 배열을 직접 만든다."""
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0 if disarmed else 0x14C, 1, 0, 0, 0, 224, 0x102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 4, 512)
    struct.pack_into("<III", data, optional + 16, 0x1000, 0x1000, 0)
    struct.pack_into("<III", data, optional + 28, 0x400000, 4096, 512)
    struct.pack_into("<HH", data, optional + 40, 6, 0)
    struct.pack_into("<II", data, optional + 56, 8192, 512)
    struct.pack_into("<HH", data, optional + 68, 0 if disarmed else 3, 0x140)
    struct.pack_into("<IIIII", data, optional + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 224
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", data, section + 8, 512, 4096, 512, 512, 0, 0, 0, 0, 0x60000020)
    data[512:] = bytes(range(256)) * 2
    if malformed_import:
        # 디렉터리가 범위 밖을 가리킨다. 'import 없음=0'과 구분해야 한다.
        struct.pack_into("<II", data, optional + 96 + 8, 0xFFFFFF00, 40)
    return bytes(data) + overlay


class FeatureExtractorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "sample"  # 확장자가 없어도 헤더로 판별한다.

    def tearDown(self):
        self.directory.cleanup()

    def write(self, data):
        self.path.write_bytes(data)
        return self.path

    def test_schema_histogram_and_absent_import(self):
        data = minimal_pe()
        result = extract_pe_features(self.write(data), reference_sha256=hashlib.sha256(data).hexdigest(), source="pemml")
        self.assertIn(result["parse_status"], ("ok", "partial"), result)
        self.assertEqual(result["vector"].dtype, np.float32)
        self.assertEqual(result["vector"].shape, (341,))
        self.assertEqual(tuple(result["features"]), FEATURE_NAMES)
        self.assertAlmostEqual(float(result["vector"][-256:].sum()), 1.0, places=6)
        self.assertEqual(result["features"]["import_symbol_count"], 0.0)
        self.assertEqual(result["features"]["section_executable_count"], 1.0)
        self.assertEqual(result["features"]["section_writable_count"], 0.0)
        self.assertEqual(result["features"]["header_entrypoint_in_section"], 1.0)
        self.assertEqual(result["content_sha256"], hashlib.sha256(data).hexdigest())

    def test_streaming_is_chunk_size_independent(self):
        self.write(minimal_pe(overlay=bytes(range(32)) * 19))
        first = extract_pe_features(self.path, config=replace(DEFAULT_CONFIG, chunk_bytes=7))
        second = extract_pe_features(self.path)
        np.testing.assert_allclose(first["vector"], second["vector"], equal_nan=True)
        self.assertEqual(first["content_sha256"], second["content_sha256"])
        self.assertEqual(first["features"]["overlay_size"], 608.0)
        self.assertAlmostEqual(first["features"]["overlay_entropy"], 5.0)

    def test_malformed_import_is_nan_and_partial(self):
        result = extract_pe_features(self.write(minimal_pe(malformed_import=True)))
        self.assertEqual(result["parse_status"], "partial")
        for name in ("import_dll_count", "import_symbol_count", "directory_import_present", "directory_import_size"):
            self.assertTrue(np.isnan(result["features"][name]), name)
        self.assertTrue(result["parse_warnings"])

    def test_bodmas_metadata_does_not_modify_bytes(self):
        original = minimal_pe()
        disarmed = minimal_pe(disarmed=True)
        self.write(disarmed)
        reference = hashlib.sha256(original).hexdigest()
        result = extract_pe_features(self.path, source="BODMAS", reference_sha256=reference,
                                     machine_override=332.0, subsystem_override=3)
        self.assertNotEqual(result["parse_status"], "error", result)
        self.assertEqual(result["features"]["header_machine"], 332.0)
        self.assertEqual(result["features"]["header_subsystem"], 3.0)
        self.assertEqual(result["reference_sha256"], reference)
        self.assertEqual(result["content_sha256"], hashlib.sha256(disarmed).hexdigest())
        self.assertNotEqual(reference, result["content_sha256"])
        self.assertEqual(self.path.read_bytes(), disarmed)

    def test_bodmas_requires_both_original_headers(self):
        result = extract_pe_features(self.write(minimal_pe()), source="bodmas", machine_override=332)
        self.assertEqual(result["parse_status"], "error")
        self.assertIsNone(result["vector"])
        self.assertIn("requires original", result["error_reason"])

    def test_pemml_hash_mismatch_is_fatal(self):
        result = extract_pe_features(self.write(minimal_pe()), source="pemml", reference_sha256="0" * 64)
        self.assertEqual(result["parse_status"], "error")
        self.assertIsNone(result["vector"])
        self.assertIn("does not match", result["error_reason"])

    def test_non_pe_and_oversize_have_no_score_or_vector(self):
        for data, config in ((b"not a PE file", DEFAULT_CONFIG),
                             (minimal_pe(), replace(DEFAULT_CONFIG, max_file_bytes=1023))):
            with self.subTest(size=len(data)):
                result = extract_pe_features(self.write(data), config=config)
                self.assertEqual(result["parse_status"], "error")
                self.assertIsNone(result["vector"])
                self.assertIsNone(result["features"])
                self.assertIsNotNone(result["error_reason"])
                self.assertNotIn("score", result)

    def test_region_budget_reports_partial(self):
        result = extract_pe_features(self.write(minimal_pe()), config=replace(DEFAULT_CONFIG, max_region_read_bytes=10))
        self.assertEqual(result["parse_status"], "partial")
        self.assertTrue(np.isnan(result["features"]["section_entropy_mean"]))
        self.assertIsNotNone(result["vector"])


if __name__ == "__main__":
    unittest.main()
