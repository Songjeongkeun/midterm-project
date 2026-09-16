"""학습/배포에서 함께 사용하는 읽기 전용 PE 정적 특징 추출기.

여기에는 XGBoost 예측이나 임계값 정책이 없다. 같은 버전의 이 파일과 설정을
학습/배포에 그대로 사용해야 특징 의미가 일치한다. 분석 대상 파일을 실행하거나
헤더를 복원하지 않는다. BODMAS의 원래 Machine/Subsystem은 특징 값만 대체한다.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import math
from pathlib import Path
import re
import stat
import struct
import time
from typing import Any

import numpy as np
import pefile


FEATURE_VERSION = "pe_static_341_v2"
GENERAL_FEATURES = (
    "file_size", "file_entropy", "file_zero_ratio", "file_printable_ratio",
    "file_high_byte_ratio",
)
HEADER_FEATURES = (
    "header_machine", "header_section_count", "header_characteristics", "header_is_dll",
    "header_optional_magic", "header_entrypoint_rva", "header_size_code",
    "header_size_initialized_data", "header_size_uninitialized_data", "header_size_image",
    "header_size_headers", "header_subsystem", "header_dll_characteristics",
    "header_file_alignment", "header_section_alignment", "header_directory_count",
    "header_entrypoint_in_section", "header_entrypoint_section_executable",
    "header_entrypoint_section_entropy", "header_entrypoint_file_ratio",
)
SECTION_FEATURES = (
    "section_entropy_min", "section_entropy_mean", "section_entropy_max", "section_entropy_std",
    "section_raw_size_min", "section_raw_size_mean", "section_raw_size_max", "section_raw_size_sum",
    "section_virtual_size_min", "section_virtual_size_mean", "section_virtual_size_max",
    "section_virtual_size_sum", "section_readable_count", "section_writable_count",
    "section_executable_count", "section_write_exec_count", "section_rwx_count",
    "section_zero_raw_count", "section_raw_virtual_ratio_mean",
)
IMPORT_EXPORT_FEATURES = (
    "import_dll_count", "import_symbol_count", "import_ordinal_count",
    "export_symbol_count", "export_forwarder_count",
)
# PE/COFF에 정의된 인덱스 순서다. Security의 주소만 RVA가 아닌 파일 offset이다.
# 이름에 security가 있어도 '인증서 테이블 존재/선언 크기'일 뿐 서명 검증이 아니다.
DIRECTORY_NAMES = (
    "export", "import", "resource", "exception", "security", "reloc", "debug",
    "architecture", "globalptr", "tls", "load_config", "bound_import", "iat",
    "delay_import", "com_descriptor", "reserved",
)
DIRECTORY_FEATURES = tuple(
    f"directory_{name}_{measure}"
    for name in DIRECTORY_NAMES for measure in ("present", "size")
)
OVERLAY_FEATURES = ("overlay_present", "overlay_size", "overlay_ratio", "overlay_entropy")
BYTE_FEATURES = tuple(f"byte_hist_{value:03d}" for value in range(256))
FEATURE_NAMES = (
    GENERAL_FEATURES + HEADER_FEATURES + SECTION_FEATURES + IMPORT_EXPORT_FEATURES
    + DIRECTORY_FEATURES + OVERLAY_FEATURES + BYTE_FEATURES
)
assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES)) == 341


@dataclass(frozen=True)
class ExtractorConfig:
    """설정도 모델과 저장한다. 한도를 넘긴 입력은 '정상'으로 치환하지 않는다.

    전체 파일은 chunk 단위로 한 번 읽어 SHA-256/히스토그램을 계산한다. 섹션과
    overlay는 추가로 읽되 누적 읽기 한도를 두어 중첩 섹션의 반복 읽기를 제한한다.
    pefile은 파일 경로를 받아 read-only mmap으로 헤더를 읽고 import/export만 푼다.
    이 제한은 크기/반복량 제한이며 엄격한 CPU timeout이나 격리 환경은 아니다.
    """

    max_file_bytes: int = 512 * 1024**2
    chunk_bytes: int = 1024**2
    max_region_read_bytes: int = 1024 * 1024**2
    max_sections: int = 128
    max_directory_bytes: int = 16 * 1024**2
    max_export_symbols: int = 8192

    def __post_init__(self):
        for name, value in asdict(self).items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


DEFAULT_CONFIG = ExtractorConfig()


def extractor_config_dict(config: ExtractorConfig | None = None) -> dict:
    """JSON 저장 가능한 설정. 순서 목록/버전은 따로 저장해 재로딩 시 비교한다."""
    return asdict(config or DEFAULT_CONFIG)


def _entropy(counts: np.ndarray) -> float:
    total = int(counts.sum())
    if total == 0:
        return 0.0  # 실제 길이가 0인 영역: 내용이 없다는 관측값이다.
    probabilities = counts[counts > 0].astype(np.float64) / total
    return float(-np.sum(probabilities * np.log2(probabilities)))


def _counts(stream, start: int, size: int, chunk_bytes: int, digest=None) -> np.ndarray:
    """구간 전체를 읽지만 복사본은 chunk 크기로 제한한다. 짧은 읽기는 오류다."""
    stream.seek(start)
    counts = np.zeros(256, dtype=np.int64)
    remaining = size
    while remaining:
        block = stream.read(min(chunk_bytes, remaining))
        if not block:
            raise OSError("unexpected EOF while reading file")
        counts += np.bincount(np.frombuffer(block, dtype=np.uint8), minlength=256)
        if digest is not None:
            digest.update(block)
        remaining -= len(block)
    return counts


def _set_stats(features, prefix, values, *, entropy=False):
    values = np.asarray(values, dtype=np.float64)
    # 일부 섹션을 읽지 못했으면 전체 통계를 작게 왜곡하지 않고 NaN으로 유지한다.
    if len(values) == 0:
        if not entropy:
            features[f"{prefix}_sum"] = 0.0
        return
    if not np.isfinite(values).all():
        return
    for suffix, value in (("min", values.min()), ("mean", values.mean()), ("max", values.max())):
        features[f"{prefix}_{suffix}"] = float(value)
    features[f"{prefix}_{'std' if entropy else 'sum'}"] = float(values.std() if entropy else values.sum())


def _identity(file_stat):
    return (file_stat.st_dev, file_stat.st_ino, file_stat.st_size, file_stat.st_mtime_ns)


def _override_integer(value, name):
    # pandas가 정수 CSV 열을 332.0 형태로 전달해도 같은 값으로 받아들인다.
    number = float(value)
    if not math.isfinite(number) or number != int(number) or not 0 <= number <= 65535:
        raise ValueError(f"invalid BODMAS {name} metadata: {value!r}")
    return int(number)


def extract_pe_features(
    path,
    *,
    source: str | None = None,
    reference_sha256: str | None = None,
    machine_override=None,
    subsystem_override=None,
    config: ExtractorConfig | dict | None = None,
) -> dict[str, Any]:
    """파일 하나를 분석해 고정 341차원 float32 vector와 추적 metadata를 반환한다.

    source='bodmas': machine_override/subsystem_override가 반드시 있어야 한다.
    이것은 메타데이터 기반 특징 정정이며 파일/메모리의 PE 바이트 변경이 아니다.
    reference_sha256는 원본 식별자이고 content_sha256는 읽은 실제 파일 해시다.
    BODMAS는 비무장화로 이 둘이 다를 수 있다. PEMML/일반 입력에 reference가
    있으면 실제 해시와 대조한다. 새 파일 추론은 source/override 없이 호출한다.

    반환 키:
      vector: FEATURE_NAMES 순서의 np.float32 배열. fatal error이면 None.
      features: 같은 순서의 float 딕셔너리. fatal error이면 None.
      parse_status: 'ok' / 'partial'(일부 특징 결측 또는 parser 경고) / 'error'.
      error_reason: fatal 원인 문자열 또는 None; parse_warnings: 부분 오류 목록.
      path, size, source, reference_sha256, content_sha256, imphash,
      elapsed_seconds, feature_version: 진단/추적용이며 모델 입력에 넣지 않는다.

    읽을 수 없는 특징은 NaN, 실제로 없는 구조는 0을 사용한다. fatal error는
    점수를 만들 수 없으므로 호출자가 학습 제외/재검토/2차 전달 정책을 적용한다.
    이 함수는 어떠한 경우에도 정상/악성 판정이나 확률을 만들어 반환하지 않는다.
    """
    started = time.perf_counter()
    cfg = ExtractorConfig(**config) if isinstance(config, dict) else (config or DEFAULT_CONFIG)
    if not isinstance(cfg, ExtractorConfig):
        raise TypeError("config must be ExtractorConfig, dict, or None")
    file_path = Path(path).expanduser()
    source_name = str(source or "inference").strip().lower()
    reference = str(reference_sha256).strip().lower() if reference_sha256 is not None else None
    record = dict(
        path=str(file_path), size=None, source=source_name, reference_sha256=reference,
        content_sha256=None, imphash="", vector=None, features=None,
        parse_status="error", error_reason=None, parse_warnings=[],
        elapsed_seconds=0.0, feature_version=FEATURE_VERSION,
    )
    features = dict.fromkeys(FEATURE_NAMES, float("nan"))
    warnings = record["parse_warnings"]
    pe = None
    try:
        if reference is not None and not re.fullmatch(r"[0-9a-f]{64}", reference):
            raise ValueError("reference_sha256 must be 64 hexadecimal characters")
        if source_name == "bodmas":
            if machine_override is None or subsystem_override is None:
                raise ValueError("BODMAS requires original Machine and Subsystem metadata")
            machine = _override_integer(machine_override, "Machine")
            subsystem = _override_integer(subsystem_override, "Subsystem")
        elif machine_override is not None or subsystem_override is not None:
            raise ValueError("metadata header overrides are allowed only for source='bodmas'")

        before = file_path.stat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("input must be a regular file")
        size = before.st_size
        record["size"] = size
        if size == 0 or size > cfg.max_file_bytes:
            raise ValueError(f"file size {size} outside range 1..{cfg.max_file_bytes}")

        with file_path.open("rb") as stream:
            # 해시와 byte histogram을 같은 한 번의 스트리밍 패스로 산출한다.
            digest = hashlib.sha256()
            counts = _counts(stream, 0, size, cfg.chunk_bytes, digest)
            record["content_sha256"] = digest.hexdigest()
            if reference is not None and source_name != "bodmas" and reference != record["content_sha256"]:
                raise ValueError("content_sha256 does not match reference_sha256")
            histogram = counts.astype(np.float64) / size
            features.update(zip(BYTE_FEATURES, histogram))
            features.update(file_size=size, file_entropy=_entropy(counts), file_zero_ratio=histogram[0],
                            file_printable_ratio=histogram[32:127].sum(), file_high_byte_ratio=histogram[128:].sum())

            # name=경로를 주면 pefile이 read-only mmap을 사용한다. data=전체 bytes
            # 방식처럼 큰 파일을 통째로 Python bytes에 복사하지 않는다.
            pe = pefile.PE(name=str(file_path), fast_load=True)
            if not hasattr(pe, "OPTIONAL_HEADER") or pe.OPTIONAL_HEADER.Magic not in (0x10B, 0x20B):
                raise ValueError("not a PE32 or PE32+ executable image")
            header, optional = pe.FILE_HEADER, pe.OPTIONAL_HEADER
            if header.NumberOfSections > cfg.max_sections:
                raise ValueError(f"section count exceeds {cfg.max_sections}")
            for name, obj, attribute in (
                ("machine", header, "Machine"), ("section_count", header, "NumberOfSections"),
                ("characteristics", header, "Characteristics"), ("optional_magic", optional, "Magic"),
                ("entrypoint_rva", optional, "AddressOfEntryPoint"), ("size_code", optional, "SizeOfCode"),
                ("size_initialized_data", optional, "SizeOfInitializedData"),
                ("size_uninitialized_data", optional, "SizeOfUninitializedData"),
                ("size_image", optional, "SizeOfImage"), ("size_headers", optional, "SizeOfHeaders"),
                ("subsystem", optional, "Subsystem"), ("dll_characteristics", optional, "DllCharacteristics"),
                ("file_alignment", optional, "FileAlignment"), ("section_alignment", optional, "SectionAlignment"),
                ("directory_count", optional, "NumberOfRvaAndSizes"),
            ):
                features[f"header_{name}"] = float(getattr(obj, attribute, float("nan")))
            features["header_is_dll"] = float(bool(header.Characteristics & 0x2000))
            if source_name == "bodmas":
                features["header_machine"], features["header_subsystem"] = float(machine), float(subsystem)
            # timestamp, 파일명, 경로, hash, raw checksum, 서명 유효성은 학습 특징에 없다.

            region_read_bytes = 0

            def region_entropy(offset, length):
                nonlocal region_read_bytes
                if offset < 0 or length < 0 or offset + length > size:
                    raise ValueError("declared raw range is outside the file")
                if region_read_bytes + length > cfg.max_region_read_bytes:
                    raise ValueError("section/overlay cumulative read budget exceeded")
                region_read_bytes += length
                return _entropy(_counts(stream, offset, length, cfg.chunk_bytes))

            sections = pe.sections
            section_complete = len(sections) == header.NumberOfSections
            if not section_complete:
                warnings.append("section: declared and parsed section counts differ")
            entropies, raw_sizes, virtual_sizes, characteristics, ratios = [], [], [], [], []
            for index, section in enumerate(sections):
                raw, virtual = int(section.SizeOfRawData), int(section.Misc_VirtualSize)
                raw_sizes.append(raw)
                virtual_sizes.append(virtual)
                characteristics.append(int(section.Characteristics))
                # 양쪽 길이가 0이면 비율도 0; virtual=0/raw>0은 정의되지 않은 값이다.
                ratios.append(raw / virtual if virtual else (0.0 if raw == 0 else float("nan")))
                try:
                    entropies.append(region_entropy(int(section.PointerToRawData), raw) if raw else 0.0)
                except (OSError, ValueError) as exc:
                    entropies.append(float("nan"))
                    warnings.append(f"section[{index}]: {exc}")
            if section_complete:
                _set_stats(features, "section_entropy", entropies, entropy=True)
                _set_stats(features, "section_raw_size", raw_sizes)
                _set_stats(features, "section_virtual_size", virtual_sizes)
                for name, mask in (("readable", 0x40000000), ("writable", 0x80000000),
                                   ("executable", 0x20000000), ("write_exec", 0xA0000000), ("rwx", 0xE0000000)):
                    features[f"section_{name}_count"] = float(sum(c & mask == mask for c in characteristics))
                features["section_zero_raw_count"] = float(sum(value == 0 for value in raw_sizes))
                if ratios and np.isfinite(ratios).all():
                    features["section_raw_virtual_ratio_mean"] = float(np.mean(ratios))

            entry = int(optional.AddressOfEntryPoint)
            matches = [i for i, s in enumerate(sections)
                       if s.VirtualAddress <= entry < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)]
            if section_complete:
                features["header_entrypoint_in_section"] = float(bool(matches))
            if len(matches) == 1:
                index, section = matches[0], sections[matches[0]]
                features["header_entrypoint_section_executable"] = float(bool(section.Characteristics & 0x20000000))
                features["header_entrypoint_section_entropy"] = entropies[index]
                displacement = entry - section.VirtualAddress
                offset = section.PointerToRawData + displacement
                if displacement < section.SizeOfRawData and 0 <= offset < size:
                    features["header_entrypoint_file_ratio"] = offset / size
            elif len(matches) > 1:
                warnings.append("entrypoint: overlapping sections make entrypoint section ambiguous")
            elif entry == 0:
                features["header_entrypoint_section_executable"] = 0.0
                features["header_entrypoint_section_entropy"] = 0.0
                features["header_entrypoint_file_ratio"] = 0.0
            elif entry < optional.SizeOfHeaders and entry < size:
                features["header_entrypoint_file_ratio"] = entry / size

            # 선언값이 0/0이면 부재(0), 손상/범위 오류는 unavailable(NaN)이다.
            # import/export의 내용만 파싱한다. 그 외 디렉터리는 위치/크기 구조를
            # 검사하지만 내부 의미/인증서 서명 유효성까지 검사했다는 뜻은 아니다.
            directories = getattr(optional, "DATA_DIRECTORY", [])
            states = {}
            for index, name in enumerate(DIRECTORY_NAMES):
                columns = (f"directory_{name}_present", f"directory_{name}_size")
                if index >= optional.NumberOfRvaAndSizes:
                    features.update(dict.fromkeys(columns, 0.0))
                    states[name] = "absent"
                    continue
                if index >= len(directories):
                    warnings.append(f"{name}: declared directory entry could not be read")
                    states[name] = "unavailable"
                    continue
                directory = directories[index]
                rva, length = int(directory.VirtualAddress), int(directory.Size)
                if rva == length == 0:
                    features.update(dict.fromkeys(columns, 0.0))
                    states[name] = "absent"
                    continue
                try:
                    # GlobalPtr는 PE 규격상 Size=0이다. 나머지는 위치/크기가 필요하다.
                    if rva == 0 or (length == 0 and name != "globalptr"):
                        raise ValueError("inconsistent directory address/size")
                    offset = rva if name == "security" else pe.get_offset_from_rva(rva)
                    if offset < 0 or offset >= size or offset + length > size:
                        raise ValueError("directory range is outside the file")
                    features[columns[0]], features[columns[1]] = 1.0, float(length)
                    states[name] = "present"
                except (pefile.PEFormatError, ValueError) as exc:
                    warnings.append(f"{name}: {exc}")
                    states[name] = "unavailable"

            for index, name, attribute, columns in (
                (1, "import", "DIRECTORY_ENTRY_IMPORT", IMPORT_EXPORT_FEATURES[:3]),
                (0, "export", "DIRECTORY_ENTRY_EXPORT", IMPORT_EXPORT_FEATURES[3:]),
            ):
                if states[name] == "absent":
                    features.update(dict.fromkeys(columns, 0.0))
                    continue
                if states[name] != "present":
                    continue
                try:
                    directory = directories[index]
                    if directory.Size > cfg.max_directory_bytes:
                        raise ValueError("directory parsing size budget exceeded")
                    if name == "export":
                        # Export 테이블 수가 비정상적으로 크면 pefile이 배열을 만들기
                        # 전에 중단한다. get_data도 40-byte 구조체만 요청한다.
                        data = pe.get_data(directory.VirtualAddress, 40)
                        if len(data) != 40 or directory.Size < 40:
                            raise ValueError("truncated export directory")
                        functions, names = struct.unpack_from("<II", data, 20)
                        if max(functions, names) > cfg.max_export_symbols:
                            raise ValueError("export symbol budget exceeded")
                    previous_warnings = len(pe.get_warnings())
                    pe.parse_data_directories(directories=[index])
                    new_warnings = pe.get_warnings()[previous_warnings:]
                    if new_warnings or not hasattr(pe, attribute):
                        # pefile은 예외 없이 일부만 읽고 경고를 내기도 한다. 이때
                        # 잘린 개수를 사실인 것처럼 제공하지 않고 해당 묶음을 NaN 유지.
                        raise ValueError("directory parser produced warnings or no parsed table")
                    if name == "import":
                        imports = pe.DIRECTORY_ENTRY_IMPORT
                        total = sum(len(dll.imports) for dll in imports)
                        if not imports or total == 0:
                            raise ValueError("declared import directory contains no readable imports")
                        ordinals = sum(bool(symbol.import_by_ordinal) for dll in imports for symbol in dll.imports)
                        values = (len(imports), total, ordinals)
                        # imphash는 유사 그룹 진단용 metadata이며 FEATURE_NAMES에 없다.
                        try:
                            record["imphash"] = pe.get_imphash() or ""
                        except Exception as exc:
                            warnings.append(f"imphash metadata: {type(exc).__name__}: {exc}")
                    else:
                        exports = pe.DIRECTORY_ENTRY_EXPORT.symbols
                        values = (len(exports), sum(bool(symbol.forwarder) for symbol in exports))
                    features.update(zip(columns, map(float, values)))
                except Exception as exc:
                    features[f"directory_{name}_present"] = float("nan")
                    features[f"directory_{name}_size"] = float("nan")
                    warnings.append(f"{name}: {type(exc).__name__}: {exc}")

            # overlay는 마지막 헤더/섹션 raw 영역 뒤의 데이터로 명시적으로 정의한다.
            # 설치 데이터와 인증서도 들어갈 수 있다. 서명 여부/악성 여부와 동일하지 않다.
            try:
                if not section_complete:
                    raise ValueError("incomplete section table prevents overlay calculation")
                image_end = max([int(optional.SizeOfHeaders)] +
                                [int(s.PointerToRawData) + int(s.SizeOfRawData) for s in sections if s.SizeOfRawData])
                if not 0 <= image_end <= size:
                    raise ValueError("declared image raw end is outside the file")
                overlay_size = size - image_end
                overlay_entropy = region_entropy(image_end, overlay_size) if overlay_size else 0.0
                features.update(overlay_present=float(overlay_size > 0), overlay_size=float(overlay_size),
                                overlay_ratio=overlay_size / size, overlay_entropy=overlay_entropy)
            except (OSError, ValueError) as exc:
                warnings.append(f"overlay: {exc}")

        # 파일이 분석 중 바뀌면 서로 다른 내용에서 얻은 해시/특징을 합치지 않는다.
        if _identity(before) != _identity(file_path.stat()):
            raise ValueError("file changed during feature extraction")
        warnings.extend(str(message) for message in pe.get_warnings())
        values = np.asarray([features[name] for name in FEATURE_NAMES], dtype=np.float64)
        invalid = np.isinf(values) | (np.abs(values) > np.finfo(np.float32).max)
        if invalid.any():
            warnings.append("nonfinite/float32 overflow values replaced by NaN")
            values[invalid] = np.nan
        vector = values.astype(np.float32)
        record["vector"] = vector
        record["features"] = dict(zip(FEATURE_NAMES, map(float, vector)))
        record["parse_status"] = "partial" if warnings else "ok"
    except Exception as exc:
        # 한 손상 파일 때문에 대규모 추출을 중단하지 않되 실패는 별도 기록한다.
        record["error_reason"] = f"{type(exc).__name__}: {exc}"
    finally:
        if pe is not None:
            pe.close()
        record["parse_warnings"] = list(dict.fromkeys(warnings))
        record["elapsed_seconds"] = time.perf_counter() - started
    return record
