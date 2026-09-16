from __future__ import annotations

from dataclasses import dataclass


# This is a conservative mock-pipeline size. Replace it with the chosen model's
# verified input length before loading a real model.
MAX_SEQUENCE_LENGTH = 65_536
PADDING_VALUE = 0


@dataclass(frozen=True)
class PreparedByteSequence:
    values: bytes
    original_length: int
    truncated: bool


def prepare_raw_byte_sequence(
    file_bytes: bytes, max_length: int = MAX_SEQUENCE_LENGTH
) -> PreparedByteSequence:
    """Truncate or right-pad raw bytes without decoding or executing the file."""
    if max_length <= 0:
        raise ValueError("max_length는 0보다 커야 합니다.")
    original_length = len(file_bytes)
    truncated = original_length > max_length
    sequence = file_bytes[:max_length]
    if len(sequence) < max_length:
        sequence += bytes([PADDING_VALUE]) * (max_length - len(sequence))
    return PreparedByteSequence(
        values=sequence,
        original_length=original_length,
        truncated=truncated,
    )
