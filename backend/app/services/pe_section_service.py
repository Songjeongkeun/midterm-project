"""PE 파일 오프셋을 섹션과 연결하고, 근거 분석 후보를 고른다.

이 모듈은 입력 파일을 실행하거나 수정하지 않는다. PE 헤더의 섹션 테이블을
읽어 파일 내부 위치를 해석하며, 후보 선정은 모델 판정이 아니라 가림 재추론을
어디에서 수행할지 정하는 제한된 탐색 규칙이다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.schemas.analysis import PeValidationResult


WINDOW_BYTES = 256
MODEL_STRIDE_BYTES = 64
MAX_CANDIDATES = 12
STANDARD_SECTION_NAMES = {".text", ".rdata", ".data", ".rsrc", ".idata", ".reloc"}
ASCII_STRING = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


@dataclass(frozen=True)
class PeSection:
    """PE 섹션 테이블의 파일 오프셋 기준 정보다."""

    name: str
    raw_start: int
    raw_end: int

    @property
    def size(self) -> int:
        return self.raw_end - self.raw_start


@dataclass(frozen=True)
class EvidenceCandidate:
    """256바이트 가림 재추론을 수행할 파일 내부 후보 구간이다."""

    offset_start: int
    offset_end: int
    section_name: str | None


def read_pe_sections(file_bytes: bytes, validation: PeValidationResult) -> list[PeSection]:
    """검증된 PE의 섹션 테이블을 읽고 파일 범위 안 섹션만 반환한다."""
    if not validation.is_valid or validation.pe_offset is None:
        return []

    coff_offset = validation.pe_offset + 4
    if coff_offset + 20 > len(file_bytes):
        return []
    number_of_sections = int.from_bytes(file_bytes[coff_offset + 2 : coff_offset + 4], "little")
    optional_header_size = int.from_bytes(file_bytes[coff_offset + 16 : coff_offset + 18], "little")
    section_table_offset = coff_offset + 20 + optional_header_size

    sections: list[PeSection] = []
    for index in range(number_of_sections):
        offset = section_table_offset + (index * 40)
        if offset + 40 > len(file_bytes):
            break
        raw_name = file_bytes[offset : offset + 8].split(b"\x00", 1)[0]
        name = raw_name.decode("ascii", errors="replace").strip() or f"섹션-{index + 1}"
        raw_size = int.from_bytes(file_bytes[offset + 16 : offset + 20], "little")
        raw_start = int.from_bytes(file_bytes[offset + 20 : offset + 24], "little")
        if not raw_size or raw_start >= len(file_bytes):
            continue
        raw_end = min(raw_start + raw_size, len(file_bytes))
        if raw_end > raw_start:
            sections.append(PeSection(name=name, raw_start=raw_start, raw_end=raw_end))
    return sections


def find_section_at_offset(sections: list[PeSection], offset: int) -> str | None:
    """파일 오프셋이 포함된 섹션 이름을 반환한다."""
    for section in sections:
        if section.raw_start <= offset < section.raw_end:
            return section.name
    return None


def select_evidence_candidates(file_bytes: bytes, validation: PeValidationResult) -> list[EvidenceCandidate]:
    """PE 구조를 고르게 덮는 최대 12개 256바이트 후보를 고른다.

    헤더 1개, 실행 코드 4개, 데이터 2개, 리소스·Import 1개, 비표준·Overlay
    2개, 나머지 2개를 우선 배정한다. 없는 영역의 몫은 다른 섹션에 분배한다.
    """
    if not file_bytes:
        return []

    sections = read_pe_sections(file_bytes, validation)
    candidates: list[EvidenceCandidate] = []
    seen_starts: set[int] = set()

    def add_from_regions(regions: list[PeSection], amount: int, fallback_name: str | None = None) -> None:
        for candidate in _candidates_for_regions(regions, amount, fallback_name):
            if len(candidates) >= MAX_CANDIDATES or candidate.offset_start in seen_starts:
                continue
            seen_starts.add(candidate.offset_start)
            candidates.append(candidate)

    # PE 헤더는 섹션이 아니지만 구조 위변조 단서가 있을 수 있어 한 번 확인한다.
    header_end = min(WINDOW_BYTES, len(file_bytes))
    candidates.append(EvidenceCandidate(0, header_end, "PE 헤더"))
    seen_starts.add(0)

    text_sections = [section for section in sections if section.name.lower() == ".text"]
    data_sections = [section for section in sections if section.name.lower() in {".rdata", ".data"}]
    resource_sections = [section for section in sections if section.name.lower() in {".rsrc", ".idata"}]
    unusual_sections = [section for section in sections if section.name.lower() not in STANDARD_SECTION_NAMES]

    overlay_start = max((section.raw_end for section in sections), default=0)
    overlay_sections = []
    if overlay_start < len(file_bytes):
        overlay_sections.append(PeSection("Overlay", overlay_start, len(file_bytes)))

    add_from_regions(text_sections, 4)
    add_from_regions(data_sections, 2)
    add_from_regions(resource_sections, 1)
    add_from_regions(unusual_sections + overlay_sections, 2)

    # 우선 영역이 없었을 때도 12개에 가깝게 채우기 위해 전체 일반 영역을 사용한다.
    all_regions = sections + overlay_sections
    add_from_regions(all_regions, MAX_CANDIDATES - len(candidates))

    # 섹션 정보가 거의 없는 PE는 파일 전체를 균등 분할한 후보로 보완한다.
    if len(candidates) < MAX_CANDIDATES:
        whole_file = PeSection("파일 전체", 0, len(file_bytes))
        add_from_regions([whole_file], MAX_CANDIDATES - len(candidates))

    # 앞선 우선 배정에서 같은 시작 위치가 겹치면 후보 수가 줄 수 있다. 이 경우
    # 64바이트 간격의 비중첩 창으로 보완해, 파일 크기가 충분하면 정확히 12개를
    # 검사한다. 이 보완 후보도 실제 영향도는 이후 가림 재추론으로만 판정한다.
    max_start = max(0, len(file_bytes) - WINDOW_BYTES)
    for raw_start in range(0, max_start + 1, MODEL_STRIDE_BYTES):
        if len(candidates) >= MAX_CANDIDATES:
            break
        raw_end = min(raw_start + WINDOW_BYTES, len(file_bytes))
        overlaps_existing = any(
            raw_start < existing.offset_end and raw_end > existing.offset_start
            for existing in candidates
        )
        if raw_start in seen_starts or overlaps_existing:
            continue
        seen_starts.add(raw_start)
        candidates.append(
            EvidenceCandidate(raw_start, raw_end, find_section_at_offset(sections, raw_start) or "파일 전체")
        )

    return candidates[:MAX_CANDIDATES]


def extract_nearby_strings(file_bytes: bytes, candidate: EvidenceCandidate) -> list[str]:
    """후보 구간 앞뒤 512바이트에서 짧은 ASCII·UTF-16LE 문자열을 뽑는다."""
    start = max(0, candidate.offset_start - 512)
    end = min(len(file_bytes), candidate.offset_end + 512)
    around = file_bytes[start:end]
    found: list[str] = []

    for match in ASCII_STRING.finditer(around):
        found.append(match.group().decode("ascii", errors="replace"))
    for match in UTF16LE_STRING.finditer(around):
        found.append(match.group().decode("utf-16le", errors="replace"))

    unique: list[str] = []
    for value in found:
        normalized = value.strip()
        if normalized and normalized not in unique:
            unique.append(normalized[:80])
        if len(unique) == 5:
            break
    return unique


def _candidates_for_regions(
    regions: list[PeSection], amount: int, fallback_name: str | None = None
) -> list[EvidenceCandidate]:
    """여러 섹션의 크기에 비례해 후보 수를 배정하고 균등 간격으로 배치한다."""
    valid_regions = [region for region in regions if region.size > 0]
    if not valid_regions or amount <= 0:
        return []
    if len(valid_regions) > amount:
        # 한 후보만 배정할 수 있는 경우에는 가장 큰 섹션부터 선택해, 모든 섹션에
        # 하나씩 준 뒤 예산을 초과하는 일을 막는다.
        valid_regions = sorted(valid_regions, key=lambda region: region.size, reverse=True)[:amount]

    total_size = sum(region.size for region in valid_regions)
    allocation = {region: max(1, (amount * region.size) // total_size) for region in valid_regions}
    while sum(allocation.values()) > amount:
        largest = max(allocation, key=lambda region: (allocation[region], region.size))
        if allocation[largest] == 1:
            break
        allocation[largest] -= 1
    while sum(allocation.values()) < amount:
        largest = max(valid_regions, key=lambda region: region.size / allocation[region])
        allocation[largest] += 1

    candidates: list[EvidenceCandidate] = []
    for region in valid_regions:
        count = allocation[region]
        available = max(0, region.size - WINDOW_BYTES)
        positions = [0] if count == 1 else [round(available * index / (count - 1)) for index in range(count)]
        for relative_start in positions:
            raw_start = region.raw_start + (relative_start // MODEL_STRIDE_BYTES) * MODEL_STRIDE_BYTES
            raw_start = min(raw_start, max(region.raw_start, region.raw_end - WINDOW_BYTES))
            raw_end = min(raw_start + WINDOW_BYTES, region.raw_end)
            if raw_end > raw_start:
                candidates.append(EvidenceCandidate(raw_start, raw_end, fallback_name or region.name))
    return candidates
