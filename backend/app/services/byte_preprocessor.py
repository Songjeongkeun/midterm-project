from __future__ import annotations

from dataclasses import dataclass


# Mock 모델을 테스트할 때만 사용하는 고정 길이다. 실제 MalConv2는 LowMemConv가
# 파일 전체를 청크로 순회하므로, 이 길이로 파일을 자르면 안 된다.
MAX_SEQUENCE_LENGTH = 65_536
PADDING_VALUE = 0


@dataclass(frozen=True)
class PreparedByteSequence:
    """원시 바이트 모델 입력과 화면·점검에 필요한 메타데이터를 담는다.

    기존 Mock 경로의 ``values``는 항상 ``MAX_SEQUENCE_LENGTH`` 길이다.
    원본 길이와 잘림 여부를 따로 보관해 고정 길이 입력 과정에서 사라진
    정보를 확인할 수 있다.
    """
    values: bytes
    original_length: int
    truncated: bool


def prepare_raw_byte_sequence(
    file_bytes: bytes, max_length: int = MAX_SEQUENCE_LENGTH
) -> PreparedByteSequence:
    """파일을 해석·실행하지 않고 원시 바이트를 자르거나 오른쪽에 채운다.

    각 바이트는 바이트 시퀀스 모델이 쓰는 0~255 범위에 이미 있다. 패딩은
    오른쪽에 넣어 파일 앞부분의 위치를 보존한다. 이미지 변환이나 수작업
    특징 추출은 수행하지 않는다.
    """
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


def prepare_malconv2_byte_sequence(file_bytes: bytes) -> PreparedByteSequence:
    """실제 LowMemConv/MalConv2에 원본 바이트 전체를 보존해 전달한다.

    ``SCAN_CHUNK_BYTES``는 모델 내부 스캔 크기이지 입력 최대 길이가 아니다.
    PyTorch 어댑터는 원시 바이트 ``0..255``을 토큰 ``1..256``으로 바꾸고,
    토큰 ``0``은 모델 패딩에만 사용한다. 이 변환을 어댑터 안에 두어 바이트
    값이 넘치는 실수를 방지한다.
    """
    return PreparedByteSequence(
        values=file_bytes,
        original_length=len(file_bytes),
        truncated=False,
    )
