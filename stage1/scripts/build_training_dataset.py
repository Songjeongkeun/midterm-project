"""Restore the raw layout and create a merged, split-ready PE training dataset.

The resulting ``dataset/training_dataset`` contains train/validation/test
directories with NTFS hard links, so it is directly consumable by a training
loader without duplicating the approximately 268 GiB raw corpus.
"""

from __future__ import annotations

import argparse
import filecmp
import json
import math
import os
import shutil
import sys
from pathlib import Path

import numpy as np
import pandas as pd


PEMML_ROWS = 201_549
BODMAS_MALWARE_ROWS = 57_293
BODMAS_AFTER_DEDUP_ROWS = 57_292
MANIFEST_COLUMNS = [
    "sample_id",
    "source",
    "raw_path",
    "training_path",
    "sha256",
    "label",
    "family",
    "timestamp",
    "imphash",
    "machine",
    "subsystem",
    "split",
]


def fail(message: str) -> None:
    raise RuntimeError(message)


def first_existing(*paths: Path) -> Path:
    for path in paths:
        if path.exists():
            return path
    checked = "\n  ".join(str(path) for path in paths)
    fail(f"Required input was not found. Checked:\n  {checked}")


def require_columns(frame: pd.DataFrame, expected: set[str], path: Path) -> None:
    missing = expected.difference(frame.columns)
    if missing:
        fail(f"{path.name} is missing required columns: {sorted(missing)}")


def raw_names(directory: Path) -> set[str]:
    if not directory.is_dir():
        fail(f"Raw-data directory does not exist: {directory}")
    return {item.name for item in directory.iterdir() if item.is_file()}


def approximate_mode(class_counts: np.ndarray, n_draws: int, rng: np.random.RandomState) -> np.ndarray:
    """Allocate per-class counts with the stratified-shuffle rule."""
    continuous = class_counts / class_counts.sum() * n_draws
    allocation = np.floor(continuous).astype(int)
    remaining = n_draws - allocation.sum()
    for remainder in np.sort(np.unique(continuous - allocation))[::-1]:
        if remaining == 0:
            break
        candidates = np.where((continuous - allocation) == remainder)[0]
        selected = rng.choice(candidates, size=min(len(candidates), remaining), replace=False)
        allocation[selected] += 1
        remaining -= len(selected)
    return allocation


def stratified_split(
    indices: np.ndarray,
    labels: np.ndarray,
    *,
    test_fraction: float,
    random_state: int,
) -> tuple[np.ndarray, np.ndarray]:
    """Deterministic 2-way stratified split without requiring scikit-learn."""
    if len(indices) != len(labels) or not 0 < test_fraction < 1:
        fail("Invalid request for a stratified split.")
    classes, encoded = np.unique(labels, return_inverse=True)
    class_counts = np.bincount(encoded)
    if len(classes) < 2 or class_counts.min() < 2:
        fail("PEMML labels cannot be stratified.")

    n_test = math.ceil(len(indices) * test_fraction)
    n_train = len(indices) - n_test
    rng = np.random.RandomState(random_state)
    train_counts = approximate_mode(class_counts, n_train, rng)
    test_counts = approximate_mode(class_counts - train_counts, n_test, rng)
    class_positions = np.split(np.argsort(encoded, kind="mergesort"), np.cumsum(class_counts)[:-1])

    train_positions: list[int] = []
    test_positions: list[int] = []
    for class_number, positions in enumerate(class_positions):
        shuffled = positions[rng.permutation(len(positions))]
        train_positions.extend(shuffled[: train_counts[class_number]])
        test_positions.extend(
            shuffled[train_counts[class_number] : train_counts[class_number] + test_counts[class_number]]
        )
    return indices[rng.permutation(train_positions)], indices[rng.permutation(test_positions)]


def load_manifest_inputs(dataset_root: Path) -> tuple[pd.DataFrame, pd.DataFrame, Path, Path, Path, Path]:
    pemml_csv = first_existing(
        dataset_root / "samples-augmented.csv",
        dataset_root / "metadata" / "source" / "pemml_samples_augmented.csv",
    )
    bodmas_metadata_csv = first_existing(
        dataset_root / "bodmas_metadata.csv",
        dataset_root / "metadata" / "source" / "bodmas_metadata.csv",
    )
    bodmas_disarm_csv = first_existing(
        dataset_root / "bodmas_meta_disarm.csv",
        dataset_root / "meta_disarm.csv",
        dataset_root / "metadata" / "source" / "bodmas_meta_disarm.csv",
        dataset_root / "metadata" / "source" / "meta_disarm.csv",
    )
    pemml_raw = first_existing(dataset_root / "samples", dataset_root / "raw" / "pemml")
    bodmas_raw = first_existing(
        dataset_root / "BODMAS_disarmed_malware_binaries" / "altered",
        dataset_root / "BODMAS_disarmed_malware_binaries" / "binaries",
        dataset_root / "raw" / "bodmas" / "binaries",
        dataset_root / "raw" / "bodmas" / "altered",
    )

    pemml = pd.read_csv(
        pemml_csv,
        dtype={"id": "string", "sha256": "string", "list": "string", "imphash": "string"},
    )
    metadata = pd.read_csv(
        bodmas_metadata_csv,
        dtype={"sha": "string", "timestamp": "string", "family": "string"},
    )
    disarm = pd.read_csv(
        bodmas_disarm_csv,
        dtype={"sha256": "string", "OPTIONAL_HEADER.Subsystem": "Int64", "FILE_HEADER.Machine": "Int64"},
    )
    require_columns(pemml, {"id", "sha256", "list", "submitted", "imphash"}, pemml_csv)
    require_columns(metadata, {"sha", "timestamp", "family"}, bodmas_metadata_csv)
    require_columns(disarm, {"sha256", "OPTIONAL_HEADER.Subsystem", "FILE_HEADER.Machine"}, bodmas_disarm_csv)
    return pemml, metadata, pemml_raw, bodmas_raw, bodmas_metadata_csv, bodmas_disarm_csv


def build_manifest(dataset_root: Path) -> tuple[pd.DataFrame, str, dict[str, object]]:
    pemml, metadata, pemml_raw, bodmas_raw, _metadata_csv, disarm_csv = load_manifest_inputs(dataset_root)
    disarm = pd.read_csv(
        disarm_csv,
        dtype={"sha256": "string", "OPTIONAL_HEADER.Subsystem": "Int64", "FILE_HEADER.Machine": "Int64"},
    )

    if len(pemml) != PEMML_ROWS or pemml["sha256"].duplicated().any():
        fail("PEMML augmented metadata does not match the expected 201,549 unique records.")
    label_map = {"Whitelist": 0, "Blacklist": 1}
    pemml["label"] = pemml["list"].map(label_map)
    if pemml["label"].isna().any():
        fail("PEMML metadata contains an unknown list label.")
    pemml["label"] = pemml["label"].astype(int)

    malware_metadata = metadata.loc[metadata["family"].notna()].copy()
    if len(malware_metadata) != BODMAS_MALWARE_ROWS or metadata["sha"].duplicated().any():
        fail("BODMAS metadata does not contain the expected 57,293 malware rows.")
    if disarm["sha256"].duplicated().any():
        fail("BODMAS disarm metadata contains duplicate SHA-256 values.")
    bodmas = malware_metadata.merge(
        disarm,
        how="inner",
        left_on="sha",
        right_on="sha256",
        validate="one_to_one",
    ).drop(columns="sha")
    if len(bodmas) != BODMAS_MALWARE_ROWS:
        fail("BODMAS family and disarm metadata could not be matched one-to-one.")

    expected_blacklist = set(pemml.loc[pemml["list"] == "Blacklist", "id"].astype(str))
    expected_whitelist = set(pemml.loc[pemml["list"] == "Whitelist", "id"].astype(str))
    if raw_names(pemml_raw / "blacklist") != expected_blacklist:
        fail("PEMML blacklist binaries do not match the augmented metadata.")
    if raw_names(pemml_raw / "whitelist") != expected_whitelist:
        fail("PEMML whitelist binaries do not match the augmented metadata.")
    if raw_names(bodmas_raw) != set(bodmas["sha256"]):
        fail("BODMAS raw binaries do not match the two BODMAS metadata files.")

    duplicate_hashes = sorted(set(pemml["sha256"]) & set(bodmas["sha256"]))
    if len(duplicate_hashes) != 1:
        fail(f"Expected one PEMML/BODMAS SHA-256 overlap, found {len(duplicate_hashes)}.")
    duplicate_sha256 = duplicate_hashes[0]
    bodmas = bodmas.loc[bodmas["sha256"] != duplicate_sha256].copy()
    if len(bodmas) != BODMAS_AFTER_DEDUP_ROWS:
        fail("BODMAS deduplication did not produce 57,292 rows.")

    pemml_train, pemml_holdout = stratified_split(
        pemml.index.to_numpy(), pemml["label"].to_numpy(), test_fraction=0.20, random_state=42
    )
    pemml_validation, pemml_test = stratified_split(
        pemml_holdout,
        pemml.loc[pemml_holdout, "label"].to_numpy(),
        test_fraction=0.50,
        random_state=42,
    )
    pemml["split"] = pd.Series("", index=pemml.index, dtype="string")
    pemml.loc[pemml_train, "split"] = "train"
    pemml.loc[pemml_validation, "split"] = "validation"
    pemml.loc[pemml_test, "split"] = "test"

    bodmas["_sort_timestamp"] = pd.to_datetime(bodmas["timestamp"], utc=True, errors="coerce")
    if bodmas["_sort_timestamp"].isna().any():
        fail("BODMAS metadata contains an invalid malware timestamp.")
    bodmas = bodmas.sort_values(["_sort_timestamp", "sha256"], kind="stable").reset_index(drop=True)
    train_count = round(len(bodmas) * 0.80)
    validation_count = round(len(bodmas) * 0.10)
    bodmas["split"] = "test"
    bodmas.loc[: train_count - 1, "split"] = "train"
    bodmas.loc[train_count : train_count + validation_count - 1, "split"] = "validation"

    pemml_frame = pd.DataFrame(
        {
            "sample_id": "P_" + pemml["id"].astype(str).str.zfill(6),
            "source": "PEMML",
            "raw_path": "samples/" + pemml["list"].str.lower() + "/" + pemml["id"].astype(str),
            "sha256": pemml["sha256"],
            "label": pemml["label"],
            "family": pd.NA,
            "timestamp": pemml["submitted"],
            "imphash": pemml["imphash"],
            "machine": pd.NA,
            "subsystem": pd.NA,
            "split": pemml["split"],
        }
    )
    bodmas_frame = pd.DataFrame(
        {
            "sample_id": "B_" + bodmas["sha256"],
            "source": "BODMAS",
            "raw_path": "BODMAS_disarmed_malware_binaries/altered/" + bodmas["sha256"],
            "sha256": bodmas["sha256"],
            "label": 1,
            "family": bodmas["family"],
            "timestamp": bodmas["timestamp"],
            "imphash": pd.NA,
            "machine": bodmas["FILE_HEADER.Machine"],
            "subsystem": bodmas["OPTIONAL_HEADER.Subsystem"],
            "split": bodmas["split"],
        }
    )
    manifest = pd.concat([pemml_frame, bodmas_frame], ignore_index=True)
    class_name = pd.Series(np.where(manifest["label"].eq(0), "benign", "malware"), index=manifest.index)
    manifest["training_path"] = manifest["split"] + "/" + class_name + "/" + manifest["sample_id"]
    manifest = manifest[MANIFEST_COLUMNS]

    expected_totals = {"train": 207_073, "validation": 25_884, "test": 25_884}
    actual_totals = {key: int(value) for key, value in manifest["split"].value_counts().items()}
    if actual_totals != expected_totals:
        fail(f"Unexpected merged split totals: {actual_totals}")
    expected_labels = {
        ("train", 0): 69_450,
        ("train", 1): 137_623,
        ("validation", 0): 8_681,
        ("validation", 1): 17_203,
        ("test", 0): 8_681,
        ("test", 1): 17_203,
    }
    actual_labels = {
        (split, int(label)): int(count)
        for (split, label), count in manifest.groupby(["split", "label"]).size().items()
    }
    if actual_labels != expected_labels:
        fail(f"Unexpected merged class counts: {actual_labels}")

    summary: dict[str, object] = {
        "total_samples": int(len(manifest)),
        "excluded_bodmas_duplicate_sha256": duplicate_sha256,
        "split_counts": actual_totals,
        "split_label_counts": {f"{split}_label_{label}": count for (split, label), count in actual_labels.items()},
        "link_type": "NTFS hard link",
    }
    return manifest, duplicate_sha256, summary


def move_directory(source: Path, destination: Path) -> None:
    if destination.exists():
        if source.exists():
            fail(f"Both source and destination directories exist: {source} / {destination}")
        return
    if not source.exists():
        fail(f"Missing directory while restoring layout: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))


def relocate_file(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if not filecmp.cmp(source, destination, shallow=False):
            fail(f"Conflicting CSV files: {source} / {destination}")
        try:
            source.unlink()
        except PermissionError:
            print(f"Kept locked duplicate CSV in place: {source}")
        return
    try:
        shutil.move(str(source), str(destination))
    except PermissionError:
        shutil.copy2(source, destination)
        print(f"Copied locked CSV into restored location: {destination}")


def remove_if_ours(path: Path) -> None:
    if path.exists() and path.is_file():
        path.unlink()


def remove_empty(path: Path) -> None:
    if path.is_dir() and not any(path.iterdir()):
        path.rmdir()


def restore_original_layout(dataset_root: Path) -> None:
    """Undo only the previous layout change, preserving user-provided data."""
    raw_root = dataset_root / "raw"
    move_directory(raw_root / "pemml", dataset_root / "samples")
    move_directory(raw_root / "bodmas", dataset_root / "BODMAS_disarmed_malware_binaries")
    bodmas_root = dataset_root / "BODMAS_disarmed_malware_binaries"
    binaries = bodmas_root / "binaries"
    altered = bodmas_root / "altered"
    if binaries.exists() and not altered.exists():
        binaries.rename(altered)
    elif binaries.exists() and altered.exists():
        fail(f"Both BODMAS binary directories exist: {binaries} / {altered}")

    metadata_root = dataset_root / "metadata"
    relocate_file(metadata_root / "source" / "pemml_samples_augmented.csv", dataset_root / "samples-augmented.csv")
    relocate_file(metadata_root / "source" / "bodmas_metadata.csv", dataset_root / "bodmas_metadata.csv")
    relocate_file(metadata_root / "source" / "bodmas_meta_disarm.csv", dataset_root / "bodmas_meta_disarm.csv")
    relocate_file(metadata_root / "source" / "meta_disarm.csv", dataset_root / "bodmas_meta_disarm.csv")

    for artifact in (
        metadata_root / "unified_metadata.csv",
        metadata_root / "split_summary.json",
        metadata_root / "splits" / "train.csv",
        metadata_root / "splits" / "validation.csv",
        metadata_root / "splits" / "test.csv",
        metadata_root / "archive" / "pemml_samples_legacy.csv",
    ):
        remove_if_ours(artifact)
    for directory in (metadata_root / "splits", metadata_root / "archive", metadata_root / "source", metadata_root, raw_root):
        remove_empty(directory)

    previous_readme = dataset_root / "README.md"
    if previous_readme.exists() and previous_readme.read_text(encoding="utf-8", errors="replace").startswith("# Unified PE malware dataset"):
        previous_readme.unlink()


def write_csv(frame: pd.DataFrame, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    frame.to_csv(temporary, index=False, na_rep="")
    temporary.replace(destination)


def build_hardlink_dataset(dataset_root: Path, manifest: pd.DataFrame, duplicate_sha256: str, summary: dict[str, object]) -> Path:
    output = dataset_root / "training_dataset"
    staging = dataset_root / "training_dataset.__building__"
    if output.exists():
        fail(f"Training dataset already exists: {output}")
    if staging.exists():
        fail(f"An incomplete training build already exists: {staging}")

    staging.mkdir()
    try:
        for row_number, row in enumerate(manifest.itertuples(index=False), start=1):
            source = dataset_root / row.raw_path
            destination = staging / row.training_path
            if not source.is_file():
                fail(f"Raw file disappeared before linking: {source}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.link(source, destination)
            if row_number % 10_000 == 0:
                print(f"Hard links created: {row_number:,}/{len(manifest):,}", flush=True)

        manifests = staging / "manifests"
        write_csv(manifest, manifests / "all_samples.csv")
        for split in ("train", "validation", "test"):
            write_csv(manifest.loc[manifest["split"] == split], manifests / f"{split}.csv")
        write_csv(
            pd.DataFrame(
                [{"source": "BODMAS", "sha256": duplicate_sha256, "reason": "duplicate SHA-256 retained from PEMML"}]
            ),
            manifests / "excluded_cross_source_duplicate.csv",
        )
        (manifests / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (staging / "README.md").write_text(
            "# Merged training dataset\n\n"
            "This folder is ready for a file-based training loader. Files are NTFS hard links to the original raw data, "
            "so they do not consume a second copy of the corpus.\n\n"
            "- `train/`, `validation/`, and `test/` each contain `benign/` and `malware/`.\n"
            "- PEMML is stratified 80/10/10 with `random_state=42`.\n"
            "- BODMAS malware is split temporally 80/10/10 by timestamp.\n"
            "- The one SHA-256 shared by PEMML and BODMAS is retained only from PEMML.\n"
            "- `manifests/` is the authoritative metadata; do not use source, hashes, family, timestamp, imphash, or split as model features.\n"
            "- For BODMAS, use `machine` and `subsystem` from the manifest rather than parsing those values from the disarmed raw binary.\n",
            encoding="utf-8",
        )
        staging.rename(output)
    except Exception:
        # Preserve the staging folder for diagnosis instead of deleting a large
        # partially linked corpus automatically.
        raise
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=Path("dataset"))
    parser.add_argument("--apply", action="store_true", help="Restore the raw layout and build the hard-linked training dataset.")
    args = parser.parse_args()
    dataset_root = args.dataset_root.resolve()

    manifest, duplicate_sha256, summary = build_manifest(dataset_root)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not args.apply:
        print("Dry run passed. Re-run with --apply to restore the raw layout and create training_dataset.")
        return 0

    restore_original_layout(dataset_root)
    output = build_hardlink_dataset(dataset_root, manifest, duplicate_sha256, summary)
    print(f"Created training dataset: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
