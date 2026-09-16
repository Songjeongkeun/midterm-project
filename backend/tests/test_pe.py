import asyncio
from io import BytesIO

from fastapi import UploadFile

from app.services.analysis_service import AnalysisManager
from app.services.byte_preprocessor import prepare_raw_byte_sequence
from app.services.pe_validator import validate_pe


def valid_pe() -> bytes:
    data = bytearray(0x100)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x8664).to_bytes(2, "little")
    return bytes(data)


def test_accepts_minimally_valid_pe() -> None:
    result = validate_pe(valid_pe())
    assert result.is_valid is True
    assert result.machine == "AMD64"


def test_rejects_extension_like_non_pe_bytes() -> None:
    result = validate_pe(b"#!/bin/sh\necho never execute uploaded files")
    assert result.is_valid is False
    assert result.error_code == "FILE_TOO_SHORT"


def test_rejects_out_of_range_pe_offset() -> None:
    data = bytearray(0x80)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0xFFFF).to_bytes(4, "little")
    assert validate_pe(bytes(data)).is_valid is False


def test_byte_sequence_keeps_fixed_length_and_zero_padding() -> None:
    prepared = prepare_raw_byte_sequence(b"\x01\x02\x03", max_length=5)
    assert prepared.values == b"\x01\x02\x03\x00\x00"
    assert prepared.original_length == 3


def test_manager_analyzes_a_valid_pe_without_executing_it() -> None:
    """Exercise upload storage, validation and mock stages with synthetic bytes."""

    async def scenario() -> None:
        manager = AnalysisManager()
        upload = UploadFile(file=BytesIO(valid_pe()), filename="sample.exe")
        job = await manager.create_job(
            input_kind="file",
            uploads=[upload],
            relative_paths=["sample.exe"],
        )
        # The mock worker uses a thread. Yield briefly until it stores the row.
        for _ in range(20):
            current = manager.snapshot(job.job_id)
            if current.state.value in {"completed", "failed"}:
                break
            await asyncio.sleep(0.01)

        current = manager.snapshot(job.job_id)
        assert current.state.value == "completed"
        assert current.progress.completed_files == 1
        assert current.results[0].pe_validation.is_valid is True
        assert current.results[0].status.value == "review_required"

    asyncio.run(scenario())
