"""분할 매니페스트 검증과 재시작 가능한 PE 특징 캐시.

원본 PE/메타데이터에는 쓰지 않는다. 캐시에만 특징과 실패 기록을 저장한다.
CSV의 label/source/hash 등은 추적 정보이며 XGBoost 입력에 합치지 않는다.
"""

from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, is_dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from . import feature_extractor as fe


EXPECTED = {
    ("train", "PEMML", 0): 69450, ("train", "PEMML", 1): 91789,
    ("train", "BODMAS", 1): 45834,
    ("validation", "PEMML", 0): 8681, ("validation", "PEMML", 1): 11474,
    ("validation", "BODMAS", 1): 5729,
    ("test", "PEMML", 0): 8681, ("test", "PEMML", 1): 11474,
    ("test", "BODMAS", 1): 5729,
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def json_write(path: Path, payload) -> None:
    """중간에 중단돼도 완성되지 않은 JSON을 완료 파일로 착각하지 않게 교체한다."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")
    temp.replace(path)


def load_dataset(dataset_root: Path) -> tuple[pd.DataFrame, dict]:
    """사용자가 확정한 80/10/10을 재사용하고 원본 CSV와 대조한다."""
    root = Path(dataset_root).resolve()
    training_root = (root / "training_dataset").resolve()
    manifest_path = training_root / "manifests" / "all_samples.csv"
    manifest = pd.read_csv(manifest_path, dtype={
        "sample_id": str, "source": str, "training_path": str, "sha256": str,
        "family": "string", "imphash": "string", "timestamp": str,
    }, low_memory=False)
    required = {"sample_id", "source", "training_path", "sha256", "label",
                "family", "timestamp", "machine", "subsystem", "split"}
    if required - set(manifest):
        raise ValueError(f"매니페스트 필수 열 누락: {required - set(manifest)}")
    if len(manifest) != 258841:
        raise ValueError(f"확정 데이터셋은 258,841행이어야 합니다: {len(manifest):,}")
    for column in ("sample_id", "sha256", "training_path"):
        if manifest[column].isna().any() or manifest[column].duplicated().any():
            raise ValueError(f"{column} 결측/중복: 원본 매니페스트를 확인하세요.")
    counts = manifest.groupby(["split", "source", "label"]).size().to_dict()
    if counts != EXPECTED:
        raise ValueError(f"확정된 split/source/label별 개수와 다릅니다: {counts}")
    if not manifest.sha256.str.fullmatch(r"[0-9a-f]{64}").all():
        raise ValueError("SHA-256 식별자는 소문자 64자리 hex여야 합니다.")

    # training_path가 실제 학습 폴더의 파일을 가리킨다.
    # raw_path는 과거 원본 경로이므로 파일 접근에 쓰지 않는다.
    # Windows에서는 파일별 resolve가 반복적인 파일시스템 호출을 일으킨다.
    # 6개 디렉터리만 resolve하고, 파일은 정확히 split/class/name 3단계인지
    # 검증한 뒤 scandir에서 symlink/파일 종류를 확인해 안전성과 속도를 함께 유지한다.
    folders = {}
    for split in ("train", "validation", "test"):
        for class_name in ("benign", "malware"):
            folder = (training_root / split / class_name).resolve()
            if not folder.is_relative_to(training_root):
                raise ValueError(f"학습 폴더 밖으로 연결된 디렉터리: {folder}")
            folders[(split, class_name)] = folder
    resolved = []
    for row in manifest.itertuples():
        rel = Path(row.training_path)
        expected_class = "benign" if row.label == 0 else "malware"
        if rel.is_absolute() or len(rel.parts) != 3 or ".." in rel.parts:
            raise ValueError(f"학습 폴더 밖의 경로: {rel}")
        if rel.parts[:2] != (row.split, expected_class):
            raise ValueError(f"경로/라벨/split 불일치: {rel}")
        resolved.append(str(folders[(row.split, expected_class)] / rel.name))
    manifest["path"] = resolved
    # 대량 파일 검사도 디렉터리별 목록으로 수행해 파일당 stat 호출 비용을 줄인다.
    for (split, label), group in manifest.groupby(["split", "label"]):
        folder = folders[(split, "benign" if label == 0 else "malware")]
        with os.scandir(folder) as entries:
            actual = set()
            for entry in entries:
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    raise ValueError(f"일반 파일이 아닌 데이터 항목: {entry.path}")
                actual.add(entry.name)
        expected = {Path(p).name for p in group.training_path}
        if actual != expected:
            raise ValueError(f"{folder}: 누락 {len(expected-actual)}, 추가 {len(actual-expected)}")

    csv_paths = {
        "pemml": root / "samples-augmented.csv",
        "bodmas": root / "bodmas_metadata.csv",
        "disarm": root / "bodmas_meta_disarm.csv",
    }
    # 프로젝트 루트에도 같은 이름의 BODMAS CSV가 있을 수 있다.
    # 서로 다른 사본이면 자동 선택하지 않고 명시적으로 중단한다.
    for key in ("bodmas", "disarm"):
        alternative = root.parent / csv_paths[key].name
        if not csv_paths[key].exists() and alternative.exists():
            csv_paths[key] = alternative
        elif alternative.exists() and sha256_file(alternative) != sha256_file(csv_paths[key]):
            raise ValueError(f"프로젝트/데이터 폴더 CSV 내용이 다릅니다: {alternative.name}")
    pemml = pd.read_csv(csv_paths["pemml"], dtype=str).set_index("sha256")
    bm = pd.read_csv(csv_paths["bodmas"], dtype=str).set_index("sha")
    disarm = pd.read_csv(csv_paths["disarm"], dtype=str).set_index("sha256")
    for source in (pemml, bm, disarm):
        if not source.index.is_unique:
            raise ValueError("원본 메타데이터에 중복 SHA가 있습니다.")
    p = manifest[manifest.source.eq("PEMML")]
    b = manifest[manifest.source.eq("BODMAS")]
    matched_p = pemml.loc[p.sha256]
    if not np.array_equal(matched_p["list"].map({"Whitelist": 0, "Blacklist": 1}), p.label):
        raise ValueError("PEMML 원본 CSV 라벨 불일치")
    expected_ids = "P_" + matched_p.id.str.zfill(6)
    if not np.array_equal(expected_ids, p.sample_id):
        raise ValueError("PEMML 파일 ID 불일치")
    matched_b, matched_d = bm.loc[b.sha256], disarm.loc[b.sha256]
    if not np.array_equal(matched_b.family.fillna(""), b.family.fillna("")):
        raise ValueError("BODMAS family 불일치")
    if not np.array_equal(pd.to_datetime(matched_b.timestamp, utc=True),
                          pd.to_datetime(b.timestamp, utc=True)):
        raise ValueError("BODMAS timestamp 불일치")
    for col, original in (("machine", "FILE_HEADER.Machine"),
                          ("subsystem", "OPTIONAL_HEADER.Subsystem")):
        if not np.array_equal(pd.to_numeric(matched_d[original]), b[col]):
            raise ValueError(f"BODMAS {col} 보정값 불일치")
    original_malware = bm[bm.family.notna()]
    overlap = sorted(set(pemml.index) & set(original_malware.index))
    if len(overlap) != 1 or set(b.sha256) != set(original_malware.index) - set(overlap):
        raise ValueError("PEMML/BODMAS 중복 제거 내역이 최종 계획과 다릅니다.")
    if pemml.loc[overlap, "list"].ne("Blacklist").any():
        raise ValueError("출처 간 중복 SHA의 라벨 충돌")

    bounds = {}
    for split in ("train", "validation", "test"):
        time = pd.to_datetime(b.loc[b.split.eq(split), "timestamp"], utc=True)
        bounds[split] = [time.min().isoformat(), time.max().isoformat()]
    if not (bounds["train"][1] <= bounds["validation"][0] <= bounds["validation"][1] <= bounds["test"][0]):
        raise ValueError("BODMAS 시간 분할 순서 위반")
    # imphash는 같은 family라는 뜻이 아니므로 분석만 하고 다시 split하지 않는다.
    present = p[p.imphash.notna() & p.imphash.ne("")]
    cross = present.groupby("imphash").split.nunique().gt(1)
    audit = {
        "manifest_sha256": sha256_file(manifest_path),
        "source_csv_sha256": {key: sha256_file(path) for key, path in csv_paths.items()},
        "rows": len(manifest), "bodmas_time_bounds": bounds,
        "cross_source_duplicate_excluded": overlap,
        "imphash_groups_spanning_splits": int(cross.sum()),
        "imphash_samples_spanning_splits": int(present.imphash.isin(cross[cross].index).sum()),
        "path_base": str(training_root),
    }
    manifest.index.name = "row_id"
    return manifest, audit


def config_dict(config) -> dict:
    return asdict(config) if is_dataclass(config) else dict(config or {})


def cache_features(manifest: pd.DataFrame, cache_root: Path, config,
                   *, workers=2, chunk_size=512) -> tuple[np.ndarray, pd.DataFrame, Path]:
    """청크 단위 저장: 재실행 시 완료 청크만 읽고 미완료 청크를 다시 처리한다.

    캐시 키에는 행 순서·추출 코드·설정·pefile 버전이 들어간다.
    기존 청크의 파일 크기/수정시간도 비교한다. 원본을 덮어쓰지 않는 데이터셋을 전제로 한다.
    """
    if len(manifest) == 0 or chunk_size < 1 or workers < 1:
        raise ValueError("비어 있지 않은 데이터와 양의 workers/chunk_size가 필요합니다.")
    serialized = manifest[["sample_id", "source", "sha256", "path", "machine", "subsystem"]].to_csv(index=False)
    key_config = {
        "extractor_source_sha256": sha256_file(Path(fe.__file__)),
        "config": config_dict(config), "features": list(fe.FEATURE_NAMES),
        "pefile_version": fe.pefile.__version__, "chunk_size": chunk_size,
    }
    digest = hashlib.sha256((serialized + json.dumps(key_config, sort_keys=True)).encode()).hexdigest()
    folder = Path(cache_root) / digest[:24]
    folder.mkdir(parents=True, exist_ok=True)
    json_write(folder / "cache_config.json", {**key_config, "manifest_fingerprint": digest})

    def extract(row):
        return fe.extract_pe_features(
            row.path, source=row.source, reference_sha256=row.sha256,
            machine_override=row.machine if row.source == "BODMAS" else None,
            subsystem_override=row.subsystem if row.source == "BODMAS" else None,
            config=config,
        )

    matrices, records = [], []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for start in range(0, len(manifest), chunk_size):
            chunk = manifest.iloc[start:start+chunk_size]
            path = folder / f"chunk_{start:07d}.npz"
            # 파일이 검증 이후 격리/삭제되거나 접근 불가가 되어도 배치를 중단하지 않는다.
            # stat 실패 청크는 캐시를 재사용하지 않고 추출기에 넘겨 개별 Error로 기록한다.
            stats = []
            for input_path in chunk.path:
                try:
                    stats.append(Path(input_path).stat())
                except OSError:
                    stats.append(None)
            sizes = np.array([s.st_size if s else -1 for s in stats], dtype=np.int64)
            mtimes = np.array([s.st_mtime_ns if s else -1 for s in stats], dtype=np.int64)
            cached = None
            if path.exists() and all(s is not None for s in stats):
                # allow_pickle=False: 데이터 캐시를 읽으면서 코드를 역직렬화하지 않는다.
                with np.load(path, allow_pickle=False) as z:
                    if (np.array_equal(z["sizes"], sizes) and np.array_equal(z["mtimes"], mtimes)
                            and np.array_equal(z["sample_id"], chunk.sample_id.to_numpy(str))):
                        cached = {key: z[key].copy() for key in z.files}
            if cached is None:
                outputs = list(executor.map(extract, chunk.itertuples()))
                cached = {
                    # fatal 오류도 행을 유지해야 원래 테스트 분모가 사라지지 않는다.
                    # 이 NaN 행은 아래 학습 코드가 제외하고 평가에서는 Error로 센다.
                    "X": np.stack([r["vector"] if r["vector"] is not None else
                                   np.full(len(fe.FEATURE_NAMES), np.nan, dtype=np.float32)
                                   for r in outputs]).astype(np.float32),
                    "sample_id": chunk.sample_id.to_numpy(str), "sizes": sizes, "mtimes": mtimes,
                    "parse_status": np.array([r["parse_status"] for r in outputs], dtype=str),
                    "error_reason": np.array([r["error_reason"] or "" for r in outputs], dtype=str),
                    "parse_warnings": np.array([json.dumps(r["parse_warnings"], ensure_ascii=False) for r in outputs], dtype=str),
                    "content_sha256": np.array([r["content_sha256"] or "" for r in outputs], dtype=str),
                    "elapsed_seconds": np.array([r["elapsed_seconds"] for r in outputs]),
                }
                temp = path.with_suffix(".tmp")
                with temp.open("wb") as stream:
                    np.savez_compressed(stream, **cached)
                temp.replace(path)
            matrices.append(cached["X"])
            records.append(pd.DataFrame({k: cached[k] for k in (
                "sample_id", "parse_status", "error_reason", "parse_warnings",
                "content_sha256", "elapsed_seconds")}))
            print(f"특징 캐시: {min(start+chunk_size, len(manifest)):,}/{len(manifest):,}", flush=True)
    X = np.concatenate(matrices)
    extracted = pd.concat(records, ignore_index=True)
    if not np.array_equal(extracted.sample_id, manifest.sample_id):
        raise RuntimeError("특징/메타데이터 행 정렬 불일치")
    metadata = manifest.reset_index(drop=True).copy()
    for name in extracted.columns.difference(["sample_id"]):
        metadata[name] = extracted[name].to_numpy()
    metadata.index.name = "row_id"
    # 서로 다른 원본 식별자가 실제 동일한 바이트로 나타나는 경우도 누수 검사한다.
    valid_hash = metadata.content_sha256.ne("")
    collisions = metadata[valid_hash].groupby("content_sha256").agg(
        splits=("split", "nunique"), labels=("label", "nunique"))
    if (collisions.splits.gt(1) | collisions.labels.gt(1)).any():
        collisions[collisions.splits.gt(1) | collisions.labels.gt(1)].to_csv(folder / "content_hash_conflicts.csv")
        raise ValueError("실제 바이트 해시의 split/label 충돌: content_hash_conflicts.csv를 확인하세요.")
    metadata.to_csv(folder / "metadata.csv", index=False)
    metadata[metadata.parse_status.eq("error")].to_csv(folder / "extraction_errors.csv", index=False)
    return X, metadata, folder
