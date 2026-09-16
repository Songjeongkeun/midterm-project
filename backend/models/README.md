# 실제 모델 파일 위치

이 폴더는 실제 모델 파일을 두는 자리다. 현재 1차 XGBoost 모델은
`stage1_xgboost_bundle/`에 연결되어 있다.

```text
models/
├── stage1_xgboost_bundle/       # 모델·341개 특징 추출기·임계값·무결성 목록 전체
│   ├── xgb_model.json
│   ├── xgb_threshold.json
│   ├── feature_names.json
│   ├── feature_config.json
│   └── stage1/
└── stage2/                      # 추후 MalConv2 모델·라벨 파일을 둔다
    ├── stage2_malconv2.pt
    └── family_labels.json
```

큰 모델 파일은 Git에 커밋하지 않는다. 1차 번들은 일부 파일만 복사하거나 수정하면
안 된다. `stage1_xgboost_service.py`가 번들의 파일 해시, 특징 이름·순서, 추출기
버전을 검사한다.

2차 MalConv2를 연결할 때는 `model_inference_service.py`의 Mock 2차 구현을 교체한다.
`byte_preprocessor.py`의 바이트 순서·최대 길이·패딩 규칙은 학습 때와 일치시켜야 한다.
