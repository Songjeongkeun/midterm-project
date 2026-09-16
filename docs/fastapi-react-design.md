# Windows PE Static Analysis Web Design

## Goal

Users upload one Windows PE file or the files contained in a selected folder. The system reads bytes only, verifies the PE format, prepares a fixed-length raw-byte sequence, and displays a two-stage mock prediction. Files are never executed, deleted, quarantined, exported, or retained after analysis.

## Confirmed constraints

- Backend: Python FastAPI
- Frontend: React with JavaScript and JSX only
- UI states: SC-01 start, SC-02 progress, SC-03 single result, SC-04 folder result, SC-05 unsupported input
- No sorting, search, filtering, export, scan history, automatic deletion, or quarantine
- Folder rows preserve the browser upload order
- Normal results retain the review-required badge because a model result is not a safety guarantee

## Project layout and file responsibilities

```text
midterm-project/
├── frontend/
│   └── src/
│       ├── App.jsx                       # API job state → SC-01~SC-05 route decision
│       ├── api/analysis.js                # multipart, SSE, cancellation client
│       ├── components/                    # StatusBadge, ProgressSummary, ResultTable
│       └── screens/                       # each of the five display states
└── backend/
    ├── requirements.txt                   # minimal runtime/test dependencies
    └── app/
        ├── main.py                        # FastAPI entry point, CORS and lifespan
        ├── routers/analyze.py             # HTTP and Server-Sent Event endpoints
        ├── schemas/analysis.py            # stable response models
        ├── services/pe_validator.py       # byte-only MZ/PE validation
        ├── services/byte_preprocessor.py  # truncate/right-pad raw byte input
        ├── services/model_inference_service.py # replaceable two-stage adapter
        ├── services/analysis_service.py   # sequential job orchestration/cleanup
        └── storage/job_store.py           # non-persistent, in-memory job snapshots
```

All React files use `.js`/`.jsx`; TypeScript is not used.

## Backend flow

```text
multipart upload
  -> temporary job directory
  -> PE header validation
  -> stage 1 XGBoost: extract 341 static PE features and score
  -> Normal / Suspicious / Malware threshold routing
  -> truncate/pad raw bytes + stage 2 mock family prediction for Suspicious/Malware
  -> in-memory job result + SSE progress event
  -> delete temporary uploaded bytes
```

The browser uploads the file list for a selected folder. A web server cannot inspect a user's local filesystem directly. The browser-provided relative path is display-only and is never used as a server filesystem path.

## PE validation

1. Check that at least 64 bytes are available.
2. Check the first two bytes for `MZ`.
3. Read the little-endian `e_lfanew` value from offset `0x3C`.
4. Verify that the PE-header offset is in range.
5. Verify `PE\0\0` at that offset.
6. Read the COFF machine field only for display metadata.

## Model adapter contract

```json
{
  "stage1_result": "Normal",
  "stage1_confidence": 0.91,
  "family_class": null,
  "family_confidence": null,
  "is_unknown": false,
  "stage2_executed": false
}
```

The imported stage-1 XGBoost bundle uses 341 fixed static PE features (headers,
sections, imports/exports, directories, overlay and byte histogram). It ships
the exact feature extractor, feature order, thresholds and file hashes in one
bundle, which the backend verifies when it starts. Its score is uncalibrated;
with the exported thresholds, score `< 0.10` is `Normal`, `0.10–<0.90` is
`Suspicious`, and `≥ 0.90` is `Malware`. Both `Suspicious` and `Malware` are
passed to stage 2. The current stage-2 SHA-256 mock is an interface test only.

### Connecting real models later

Store model artifacts outside Git under `backend/models/`, for example:

```text
backend/models/
├── stage1_xgboost.json
├── stage1_encoder.json
├── stage2_malconv2.pt
└── family_labels.json
```

The actual stage-1 bundle is stored as `backend/models/stage1_xgboost_bundle/`.
Do not modify or flatten it: `runtime.py` validates the bundle manifest and the
feature-extractor source hash. Replace only
`MockModelInferenceService.predict_stage2()` when the MalConv2 artifact is
ready. Stage 2 must run for `Suspicious` or `Malware`; if its maximum
score is below the configured threshold it must return `Unknown` and set
`is_unknown` to `true`.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/analyses/file` | Create a single-file analysis job |
| POST | `/api/v1/analyses/folder` | Create a sequential multi-file analysis job |
| GET | `/api/v1/analyses/{job_id}` | Fetch a job snapshot |
| GET | `/api/v1/analyses/{job_id}/events` | Receive SSE progress snapshots |
| DELETE | `/api/v1/analyses/{job_id}` | Request cancellation |

The single-file endpoint receives multipart field `file`. The folder endpoint
receives repeated `files` and same-index `relative_paths` fields. A successful
creation response returns HTTP 202 and an `AnalysisJob`; progress snapshots use
the same structure, so the UI needs no separate progress schema.

## UI mapping

| State | Screen | Trigger |
|---|---|---|
| SC-01 | Start | Initial load or new analysis |
| SC-02 | Progress | A file or folder job is queued/running |
| SC-03 | Single result | Valid one-file job completes |
| SC-04 | Folder result | Folder job completes |
| SC-05 | Unsupported | One-file job completes with a PE/read/inference error |
