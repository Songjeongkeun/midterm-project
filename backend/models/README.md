# 실제 모델 파일 위치

이 폴더는 Mock 추론을 실제 모델로 바꿀 때 모델 파일을 두는 자리입니다.

```text
models/
├── stage1_xgboost.json
├── stage1_encoder.json
├── stage2_malconv2.pt
└── family_labels.json
```

큰 모델 파일은 Git에 커밋하지 마세요. `app/services/model_inference_service.py`의
`MockModelInferenceService`를 교체할 때, `predict_stage1()`과
`predict_stage2()`의 반환 형식은 그대로 유지해야 프런트엔드 API를 바꾸지 않아도 됩니다.

XGBoost에는 학습과 동일한 고정 길이 인코더가 반드시 필요합니다. MalConv2에는
`byte_preprocessor.py`의 바이트 순서·최대 길이·패딩 규칙을 학습 때와 일치시켜야 합니다.
