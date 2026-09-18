from __future__ import annotations

from app.schemas.analysis import PeValidationResult


# COFF Machine field values that the UI can render in a human-readable form.
# Unknown values remain valid PE files; the architecture is simply reported as
# unknown rather than rejected.
MACHINE_TYPES = {
    0x014C: ("Intel 386", "x86"),
    0x8664: ("AMD64", "x64"),
    0xAA64: ("ARM64", "unknown"),
}


def validate_pe(file_bytes: bytes) -> PeValidationResult:
    """Perform minimum structural PE validation using bytes only.

    The validator deliberately checks the DOS ``MZ`` signature, the ``e_lfanew``
    offset, the NT ``PE\\0\\0`` signature and enough of the COFF header to read
    the machine field.  It does not execute, load, repair or modify the input.
    """
    if len(file_bytes) < 0x40:
        return PeValidationResult(
            is_valid=False,
            error_code="FILE_TOO_SHORT",
            error_reason="PE 헤더를 확인하기에 파일이 너무 짧습니다.",
        )
    if file_bytes[:2] != b"MZ":
        return PeValidationResult(
            is_valid=False,
            error_code="NOT_MZ",
            error_reason="PE 파일이 아닙니다.",
        )

    # The DOS header stores e_lfanew at byte 0x3C.  PE is little-endian, so the
    # 4 bytes must be interpreted accordingly before indexing the byte string.
    pe_offset = int.from_bytes(file_bytes[0x3C:0x40], byteorder="little", signed=False)
    if pe_offset > len(file_bytes) - 4:
        return PeValidationResult(
            is_valid=False,
            error_code="INVALID_PE_OFFSET",
            error_reason="PE 헤더 위치가 파일 범위를 벗어났습니다.",
        )
    if file_bytes[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return PeValidationResult(
            is_valid=False,
            error_code="INVALID_PE_SIGNATURE",
            error_reason="PE 시그니처가 올바르지 않습니다.",
        )
    if pe_offset + 24 > len(file_bytes):
        return PeValidationResult(
            is_valid=False,
            error_code="TRUNCATED_COFF_HEADER",
            error_reason="COFF 헤더가 파일 끝에서 잘렸습니다.",
        )

    # The COFF header begins immediately after ``PE\\0\\0``; its first WORD is
    # the target Machine type, useful context but not an authenticity guarantee.
    machine_code = int.from_bytes(file_bytes[pe_offset + 4 : pe_offset + 6], "little")
    machine, bitness = MACHINE_TYPES.get(machine_code, (f"Unknown (0x{machine_code:04X})", "unknown"))
    return PeValidationResult(is_valid=True, pe_offset=pe_offset, machine=machine, bitness=bitness)
