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
└── stage2/                      # 실제 BODMAS MalConv2 패밀리 분류 모델
    ├── best_model.pth           # Git 제외: 최고 검증 epoch 가중치
    ├── class_mapping.txt         # 출력 번호와 17개 클래스 순서
    ├── config.json               # 학습 구조·청크 설정
    ├── threshold.json            # Unknown 처리 임계값
    └── source/                   # 체크포인트와 일치하는 MalConv 모델 구조
```

큰 모델 파일은 Git에 커밋하지 않는다. 1차 번들은 일부 파일만 복사하거나 수정하면
안 된다. `stage1_xgboost_service.py`가 번들의 파일 해시, 특징 이름·순서, 추출기
버전을 검사한다.

2차 모델은 `stage2_malconv2_service.py`가 안전 모드로 가중치를 읽고, 클래스 맵·설정
순서를 검증한 뒤 사용한다. 이 모델은 원본 바이트를 `1~256` 토큰으로 옮기고 `0`을
패딩으로만 사용한다. 65,536 bytes는 파일 자르기 길이가 아니라 내부 스캔 청크 크기다.
