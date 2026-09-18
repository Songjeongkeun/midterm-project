from __future__ import annotations

import hashlib

from app.schemas.analysis import InferenceResult

from .byte_preprocessor import PreparedByteSequence


# A future real stage-2 model should load this threshold from its validated
# training/export metadata instead of inheriting this UI-only mock constant.
FAMILY_CONFIDENCE_THRESHOLD = 0.70
# These labels are mock UI values. Replace this list with the approved BODMAS
# family labels when the real second-stage model and its label map are finalized.
MOCK_FAMILY_CLASSES = (
    "Adware",
    "Backdoor",
    "Botnet",
    "Dropper",
    "Ransomware",
    "Spyware",
    "Trojan",
)


class MockModelInferenceService:
    """Deterministic placeholder for the future MalConv2 family adapter.

    It exists only to exercise the API and UI path until a real second-stage
    artifact is delivered.  Its labels and scores are not malware detections.
    """

    @staticmethod
    def _digest(sequence: PreparedByteSequence) -> bytes:
        # Hashing avoids random UI changes: identical bytes always receive the
        # same mock result, while no file is executed or sent outside the server.
        return hashlib.sha256(sequence.values).digest()

    def predict_stage1(self, sequence: PreparedByteSequence) -> tuple[str, float]:
        """Legacy mock helper retained for tests; production uses XGBoost stage 1."""
        digest = self._digest(sequence)
        stage1_confidence = 0.55 + (digest[0] / 255) * 0.44
        is_malware = digest[1] % 2 == 1
        return ("Malware" if is_malware else "Normal", round(stage1_confidence, 4))

    def predict_stage2(self, sequence: PreparedByteSequence) -> tuple[str, float, bool]:
        """Produce a repeatable fake family result without executing the file."""
        digest = self._digest(sequence)
        family_confidence = 0.45 + (digest[2] / 255) * 0.53
        if family_confidence < FAMILY_CONFIDENCE_THRESHOLD:
            return ("Unknown", round(family_confidence, 4), True)
        return (
            MOCK_FAMILY_CLASSES[digest[3] % len(MOCK_FAMILY_CLASSES)],
            round(family_confidence, 4),
            False,
        )

    def predict(self, sequence: PreparedByteSequence) -> InferenceResult:
        """Test convenience wrapper; the production service calls stages separately."""
        stage1_result, stage1_confidence = self.predict_stage1(sequence)
        if stage1_result == "Normal":
            return InferenceResult(stage1_result="Normal", stage1_confidence=stage1_confidence)
        family_class, family_confidence, is_unknown = self.predict_stage2(sequence)
        return InferenceResult(
            stage1_result="Malware",
            stage1_confidence=stage1_confidence,
            family_class=family_class,
            family_confidence=family_confidence,
            is_unknown=is_unknown,
            stage2_executed=True,
        )
