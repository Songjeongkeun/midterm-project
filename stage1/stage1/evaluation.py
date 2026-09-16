"""1차 분류기의 점수, 3단계 판정, 2차 전달량을 함께 평가하는 함수.

모델은 정상/악성 이진 분류를 학습하고, 두 임계값이 표시 결과를 3단계로
나눕니다. Suspicious는 세 번째 학습 정답이 아닙니다. 실제 정답은 label=0/1
뿐이므로 혼동행렬도 실제 2개 클래스 × 표시 3개 단계로 만듭니다.

NaN은 추출/예측 오류를 나타내며 악성 확률이 아닙니다. 오류를 0이나 1로
채워 모델 성능을 부풀리지 않습니다. 오류 정책은 error_forward로 반드시
명시합니다. 이 프로젝트에서는 False를 사용하여 오류를 따로 보관합니다.
"""

from __future__ import annotations

from typing import Any, Iterable

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    log_loss,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)


BAND_ORDER = ("Normal", "Suspicious", "Malware")


def _validate_thresholds(low: float, high: float) -> tuple[float, float]:
    """두 경계가 뒤집히거나 의심 구간이 사라지는 설정을 조기에 잡습니다."""
    low, high = float(low), float(high)
    if not (np.isfinite(low) and np.isfinite(high) and 0 <= low < high <= 1):
        raise ValueError("임계값은 0 <= low < high <= 1이어야 합니다.")
    return low, high


def _validate_scores(scores: Iterable[float]) -> np.ndarray:
    values = np.asarray(scores, dtype=float)
    if values.ndim != 1:
        raise ValueError("scores는 행 순서에 맞춘 1차원 악성 확률 배열이어야 합니다.")
    # NaN만 오류 표기로 허용합니다. inf/범위 밖 숫자는 파이프라인 버그일 수
    # 있으므로 조용히 오류로 바꾸지 않고 원인을 고치도록 예외를 발생시킵니다.
    if np.isinf(values).any() or ((values < 0) | (values > 1)).any():
        raise ValueError("점수는 [0, 1] 또는 오류를 뜻하는 NaN이어야 합니다.")
    return values


def _validate_inputs(metadata: pd.DataFrame, scores: Iterable[float]) -> tuple[np.ndarray, np.ndarray]:
    if "label" not in metadata:
        raise ValueError("metadata에 label 열(정상=0, 악성=1)이 필요합니다.")
    values = _validate_scores(scores)
    if len(metadata) != len(values):
        raise ValueError("metadata와 scores의 행 수가 다릅니다. 같은 행 순서를 유지하세요.")
    if metadata["label"].isna().any() or not metadata["label"].isin([0, 1]).all():
        raise ValueError("평가 정답 label은 결측 없는 0/1이어야 합니다.")
    return metadata["label"].to_numpy(dtype=np.int8), values


def _validate_error_policy(error_forward: bool) -> None:
    if not isinstance(error_forward, (bool, np.bool_)):
        raise ValueError("error_forward는 명시적인 bool이어야 합니다.")


def _ratio(numerator: Any, denominator: Any) -> np.ndarray:
    """분모가 없는 지표는 0/100%를 만들지 않고 NaN으로 둡니다."""
    numerator, denominator = np.broadcast_arrays(
        np.asarray(numerator, dtype=float), np.asarray(denominator, dtype=float)
    )
    result = np.full(numerator.shape, np.nan, dtype=float)
    np.divide(numerator, denominator, out=result, where=denominator != 0)
    return result


def route_scores(
    scores: Iterable[float], low: float, high: float, *, error_forward: bool
) -> pd.DataFrame:
    """점수를 3단계로 표시하고 2차 전달 여부를 결정합니다(2차 모델 호출 없음).

    경계와 같은 값은 위쪽 단계에 포함합니다. 즉 low는 Suspicious,
    high는 Malware입니다. 정상 외 두 단계 모두 2차 전달 후보입니다.
    Error는 별도 상태이므로 3단계 모델 판정으로 계산하지 않습니다.
    """
    low, high = _validate_thresholds(low, high)
    _validate_error_policy(error_forward)
    values = _validate_scores(scores)
    scored = np.isfinite(values)
    bands = np.full(len(values), "Error", dtype=object)
    bands[scored & (values < low)] = "Normal"
    bands[scored & (values >= low) & (values < high)] = "Suspicious"
    bands[scored & (values >= high)] = "Malware"
    return pd.DataFrame(
        {
            "malware_score": values,
            "stage1_result": bands,
            "needs_stage2": (scored & (values >= low)) | (~scored & error_forward),
            "score_valid": scored,
        }
    )


def threshold_curve(
    metadata: pd.DataFrame,
    scores: Iterable[float],
    thresholds: Iterable[float],
    *,
    error_forward: bool,
) -> pd.DataFrame:
    """한 번 정렬한 누적 개수로 여러 threshold를 빠르게 비교합니다.

    매 threshold마다 전체 데이터를 다시 예측/순회하지 않습니다.
    시간 복잡도는 O(N log N + G log N)입니다(N=파일 수, G=경계 후보 수).
    오류를 별도 처리하는 정책에서는 오류 악성을 전체 recall의 분모에
    포함하고 분자에는 넣지 않아, 추출 실패로 누락된 악성을 숨기지 않습니다.

    *_scored는 정상적으로 점수가 나온 파일에 한정한 모델 지표입니다.
    접미사가 없는 screening/forward 지표의 분모는 오류를 포함한 전체입니다.
    malware_*는 score>=threshold 표시 성능이며 오류를 Malware로 세지 않습니다.
    """
    labels, values = _validate_inputs(metadata, scores)
    _validate_error_policy(error_forward)
    grid = np.asarray(list(thresholds), dtype=float)
    if grid.ndim != 1 or not np.isfinite(grid).all() or ((grid < 0) | (grid > 1)).any():
        raise ValueError("thresholds는 [0, 1] 내 유한한 1차원 값이어야 합니다.")

    valid = np.isfinite(values)
    order = np.argsort(values[valid], kind="stable")
    sorted_scores = values[valid][order]
    sorted_labels = labels[valid][order]
    # prefix[k]는 정렬된 앞쪽 k개 중 악성의 수입니다. side='left' 덕분에
    # score==threshold인 동점 파일은 모두 전달/악성 후보에 포함됩니다.
    prefix_positive = np.concatenate(([0], np.cumsum(sorted_labels, dtype=np.int64)))
    cut = np.searchsorted(sorted_scores, grid, side="left")
    positive_scored = int(sorted_labels.sum())
    negative_scored = len(sorted_labels) - positive_scored
    tp = positive_scored - prefix_positive[cut]
    n_predicted = len(sorted_labels) - cut
    fp = n_predicted - tp
    fn = positive_scored - tp
    tn = negative_scored - fp
    positive_total = int(labels.sum())
    negative_total = len(labels) - positive_total
    positive_errors = positive_total - positive_scored
    negative_errors = negative_total - negative_scored
    forwarded_positive = tp + (positive_errors if error_forward else 0)
    forwarded_negative = fp + (negative_errors if error_forward else 0)

    # BODMAS처럼 악성만 있는 집합에서는 precision=1이나 AP=1을 출력해도
    # 정상 오탐을 검증한 적이 없습니다. precision/F1은 양 클래스가 있는
    # scored 집합에서만 제공하고, 악성 recall 자체는 계속 제공합니다.
    both_classes = positive_scored > 0 and negative_scored > 0
    precision = _ratio(tp, n_predicted) if both_classes else np.full(len(grid), np.nan)
    f1 = _ratio(2 * tp, 2 * tp + fp + fn) if both_classes else np.full(len(grid), np.nan)
    return pd.DataFrame(
        {
            "threshold": grid,
            "n_scored_positive_predictions": n_predicted,
            "n_true_positive_scored": tp,
            "n_false_positive_scored": fp,
            "n_false_negative_scored": fn,
            "n_true_negative_scored": tn,
            "n_forward": forwarded_positive + forwarded_negative,
            "screening_recall": _ratio(forwarded_positive, positive_total),
            "screening_fnr": _ratio(positive_total - forwarded_positive, positive_total),
            "benign_forward_rate": _ratio(forwarded_negative, negative_total),
            "benign_filter_rate": _ratio(tn, negative_total),
            "overall_forward_rate": _ratio(forwarded_positive + forwarded_negative, len(labels)),
            "screening_recall_scored": _ratio(tp, positive_scored),
            "screening_fnr_scored": _ratio(fn, positive_scored),
            "benign_forward_rate_scored": _ratio(fp, negative_scored),
            "benign_filter_rate_scored": _ratio(tn, negative_scored),
            "malware_precision": precision,
            "malware_recall": _ratio(tp, positive_total),
            "malware_recall_scored": _ratio(tp, positive_scored),
            "malware_fpr": _ratio(fp, negative_total),
            "malware_fpr_scored": _ratio(fp, negative_scored),
            "binary_f1_scored": f1,
        }
    )


def evaluate_scores(
    metadata: pd.DataFrame,
    scores: Iterable[float],
    low: float,
    high: float,
    *,
    error_forward: bool,
) -> pd.DataFrame:
    """전체 및 각 출처별 평가표를 반환합니다. 파일 저장은 호출자가 결정합니다.

    주 지표는 screening_recall/FNR입니다. 1차에서 놓친 악성은 2차가
    검사할 기회가 없기 때문입니다. benign_forward_rate와 전달량은 그
    recall을 얻기 위해 정상 파일을 얼마나 2차로 보내는지 보여줍니다.
    accuracy는 다수 클래스 비율에 가려질 수 있어 대표 지표로 쓰지 않습니다.
    """
    low, high = _validate_thresholds(low, high)
    labels, values = _validate_inputs(metadata, scores)
    _validate_error_policy(error_forward)
    if "source" not in metadata or metadata["source"].isna().any():
        raise ValueError("출처별 평가를 위해 결측 없는 source 열이 필요합니다.")
    source_values = metadata["source"].astype(str).to_numpy()
    masks = [("overall", np.ones(len(metadata), dtype=bool))]
    masks += [(source, source_values == source) for source in pd.unique(source_values)]
    rows = []
    for source, mask in masks:
        group = metadata.loc[mask]
        y, p = labels[mask], values[mask]
        valid = np.isfinite(p)
        y_scored, p_scored = y[valid], p[valid]
        both_classes = len(np.unique(y_scored)) == 2
        curve = threshold_curve(group, p, [low, high], error_forward=error_forward)
        lo, hi = curve.iloc[0], curve.iloc[1]
        routing = route_scores(p, low, high, error_forward=error_forward)
        row = {
            "source": source,
            "n_total": len(y),
            "n_benign": int((y == 0).sum()),
            "n_malware": int((y == 1).sum()),
            "n_scored": int(valid.sum()),
            "n_errors": int((~valid).sum()),
            "n_error_benign": int(((~valid) & (y == 0)).sum()),
            "n_error_malware": int(((~valid) & (y == 1)).sum()),
            "score_coverage": float(_ratio(valid.sum(), len(y))),
            "score_coverage_benign": float(_ratio((valid & (y == 0)).sum(), (y == 0).sum())),
            "score_coverage_malware": float(_ratio((valid & (y == 1)).sum(), (y == 1).sum())),
            "low": low,
            "high": high,
            "error_forward": bool(error_forward),
            "n_normal": int((routing.stage1_result == "Normal").sum()),
            "n_suspicious": int((routing.stage1_result == "Suspicious").sum()),
            "n_malware_band": int((routing.stage1_result == "Malware").sum()),
            "n_forward": int(lo.n_forward),
        }
        for name in (
            "screening_recall", "screening_fnr", "benign_forward_rate", "benign_filter_rate",
            "overall_forward_rate", "screening_recall_scored", "screening_fnr_scored",
            "benign_forward_rate_scored", "benign_filter_rate_scored",
        ):
            row[name] = float(lo[name])
        for name in (
            "malware_precision", "malware_recall", "malware_recall_scored",
            "malware_fpr", "malware_fpr_scored",
        ):
            row[name] = float(hi[name])
        row["binary_f1_scored_at_low"] = float(lo.binary_f1_scored)
        row["binary_f1_scored_at_high"] = float(hi.binary_f1_scored)
        # AP는 Average Precision입니다. PR 곡선을 사다리꼴로 적분한 면적과
        # 계산 방식이 다르므로 'PR-AUC'로 뭉뚱그려 이름 붙이지 않습니다.
        row["average_precision_scored"] = float(average_precision_score(y_scored, p_scored)) if both_classes else np.nan
        row["roc_auc_scored"] = float(roc_auc_score(y_scored, p_scored)) if both_classes else np.nan
        # Log loss는 단일 클래스에서도 정의됩니다. labels를 명시하여
        # sklearn이 관측되지 않은 클래스를 누락해 예외를 내지 않게 합니다.
        row["log_loss_scored"] = float(log_loss(y_scored, p_scored, labels=[0, 1])) if len(y_scored) else np.nan
        rows.append(row)
    return pd.DataFrame(rows).set_index("source")


def recommend_thresholds(
    metadata: pd.DataFrame,
    scores: Iterable[float],
    *,
    error_forward: bool,
    target_screening_recall: float = 0.99,
    target_malware_precision: float = 0.99,
    thresholds: Iterable[float] | None = None,
) -> dict[str, Any]:
    """validation에서만 임계값 후보를 제안합니다. 설정을 자동 변경하지 않습니다.

    목표를 만족하는 쌍 중 low를 크게 하여 2차 전달을 줄이고, 그 low보다
    큰 high 중 가장 작은 값을 골라 Malware 표시 recall을 확보합니다.
    그리드 밖 해답이나 실제 배포 성능을 보장하지 않습니다. 오류/점수 때문에
    목표가 불가능하면 low/high=None과 이유를 반환하여 수동 판단을 요청합니다.
    """
    _validate_inputs(metadata, scores)
    _validate_error_policy(error_forward)
    # test에서 임계값을 고르면 최종 평가를 이미 본 데이터에 맞추게 됩니다.
    # 파일 이름 추측 대신 매니페스트의 split 열로 validation임을 확인합니다.
    if "split" not in metadata or metadata.empty or not metadata["split"].eq("validation").all():
        raise ValueError("임계값 추천에는 split='validation'인 매니페스트만 사용할 수 있습니다.")
    if not (0 < target_screening_recall <= 1 and 0 < target_malware_precision <= 1):
        raise ValueError("목표 recall/precision은 0보다 크고 1 이하여야 합니다.")
    grid = np.linspace(0, 1, 1001) if thresholds is None else list(thresholds)
    curve = threshold_curve(metadata, scores, grid, error_forward=error_forward)
    curve = curve.sort_values("threshold").drop_duplicates("threshold").reset_index(drop=True)
    result = {
        "feasible": False,
        "low": None,
        "high": None,
        "reason": "",
        "selection_split": "validation",
        "target_screening_recall": float(target_screening_recall),
        "target_malware_precision": float(target_malware_precision),
        "error_forward": bool(error_forward),
        "candidate_count": len(curve),
    }
    low_candidates = curve.loc[curve.screening_recall >= target_screening_recall]
    high_candidates = curve.loc[curve.malware_precision >= target_malware_precision]
    if low_candidates.empty:
        maximum = curve.screening_recall.max()
        result["reason"] = (
            "validation에서 목표 screening recall을 만족하는 low가 없습니다. "
            f"그리드 내 최대 전체 recall={maximum!r}; 추출/예측 오류도 분모에 포함합니다."
        )
        return result
    if high_candidates.empty:
        result["reason"] = (
            "validation에서 목표 Malware precision을 만족하는 high가 없습니다. "
            "양 클래스의 유효 점수와 실제 Malware 판정 표본이 필요합니다."
        )
        return result
    # 가능한 최대 high보다 작은 low만 고르면 쌍 탐색에 이중 루프가 필요 없습니다.
    low_candidates = low_candidates.loc[low_candidates.threshold < high_candidates.threshold.max()]
    if low_candidates.empty:
        result["reason"] = "두 목표를 만족하면서 low < high인 임계값 쌍이 그리드에 없습니다."
        return result
    lo = low_candidates.iloc[-1]
    hi = high_candidates.loc[high_candidates.threshold > lo.threshold].iloc[0]
    result.update(
        feasible=True,
        low=float(lo.threshold),
        high=float(hi.threshold),
        reason="validation 그리드의 경험적 목표를 만족하는 제안입니다. 설정에 수동 적용하세요.",
        validation_screening_recall=float(lo.screening_recall),
        validation_benign_forward_rate=float(lo.benign_forward_rate),
        validation_overall_forward_rate=float(lo.overall_forward_rate),
        validation_malware_precision=float(hi.malware_precision),
        validation_malware_band_count=int(hi.n_scored_positive_predictions),
    )
    return result


def plot_score_curves(metadata: pd.DataFrame, scores: Iterable[float]):
    """ROC/Precision-Recall 곡선. 유효 점수의 커버리지를 제목에 표시합니다."""
    import matplotlib.pyplot as plt

    labels, values = _validate_inputs(metadata, scores)
    valid = np.isfinite(values)
    y, p = labels[valid], values[valid]
    figure, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    if len(np.unique(y)) == 2:
        fpr, tpr, _ = roc_curve(y, p)
        precision, recall, _ = precision_recall_curve(y, p)
        axes[0].plot(fpr, tpr, label=f"ROC-AUC = {roc_auc_score(y, p):.4f}")
        axes[0].plot([0, 1], [0, 1], "--", color="gray", alpha=0.5)
        axes[1].step(recall, precision, where="post", label=f"Average Precision = {average_precision_score(y, p):.4f}")
        axes[1].axhline(y.mean(), linestyle="--", color="gray", label=f"Malware prevalence = {y.mean():.3f}")
        for axis in axes:
            axis.legend(loc="lower left")
    else:
        for axis in axes:
            axis.text(0.5, 0.5, "Unavailable: scored data need both classes", ha="center", va="center", transform=axis.transAxes)
    axes[0].set(xlabel="False positive rate", ylabel="True positive rate", title="ROC (scored files)")
    axes[1].set(xlabel="Recall", ylabel="Precision", title="Precision-Recall (scored files)")
    for axis in axes:
        axis.set(xlim=(0, 1), ylim=(0, 1.02))
        axis.grid(alpha=0.2)
    figure.suptitle(f"Scored coverage: {valid.sum():,}/{len(values):,}; errors excluded from score curves")
    figure.tight_layout()
    return figure


def plot_three_way_confusion(
    metadata: pd.DataFrame, scores: Iterable[float], low: float, high: float, *, error_forward: bool
):
    """2×3 판정 표와 오류 개수를 따로 그립니다. 오류는 3단계 칸에 섞지 않습니다."""
    import matplotlib.pyplot as plt

    labels, values = _validate_inputs(metadata, scores)
    routing = route_scores(values, low, high, error_forward=error_forward)
    table = np.array([[np.sum((labels == label) & (routing.stage1_result.to_numpy() == band)) for band in BAND_ORDER] for label in (0, 1)])
    errors = np.array([np.sum((labels == label) & ~routing.score_valid.to_numpy()) for label in (0, 1)])
    figure, axes = plt.subplots(1, 2, figsize=(11, 4), gridspec_kw={"width_ratios": [3, 1]})
    picture = axes[0].imshow(table, cmap="Blues", aspect="auto")
    axes[0].set(xticks=range(3), xticklabels=BAND_ORDER, yticks=range(2), yticklabels=["True benign (0)", "True malware (1)"], title="True label × stage-1 result (scored only)")
    midpoint = table.max(initial=0) / 2
    for row in range(2):
        for col in range(3):
            axes[0].text(col, row, f"{table[row, col]:,}", ha="center", va="center", color="white" if table[row, col] > midpoint else "black")
    figure.colorbar(picture, ax=axes[0], fraction=0.04)
    axes[1].bar(["Benign", "Malware"], errors, color=["#3b82f6", "#ef4444"])
    axes[1].set(title="Errors (separate)", ylabel="Files")
    for index, count in enumerate(errors):
        axes[1].text(index, count, f"{count:,}", ha="center", va="bottom")
    figure.suptitle(f"low={low:g}, high={high:g}; error_forward={error_forward}")
    figure.tight_layout()
    return figure


def plot_score_histogram(metadata: pd.DataFrame, scores: Iterable[float], low: float, high: float):
    """정답별 점수 분포에 현재의 두 경계를 겹쳐 표시합니다."""
    import matplotlib.pyplot as plt

    low, high = _validate_thresholds(low, high)
    labels, values = _validate_inputs(metadata, scores)
    valid = np.isfinite(values)
    figure, axis = plt.subplots(figsize=(10, 4))
    bins = np.linspace(0, 1, 51)
    for label, name, color in [(0, "True benign", "#3b82f6"), (1, "True malware", "#ef4444")]:
        subset = values[valid & (labels == label)]
        if len(subset):
            axis.hist(subset, bins=bins, alpha=0.5, label=f"{name} (n={len(subset):,})", color=color)
    axis.axvline(low, color="#ca8a04", linestyle="--", label=f"low = {low:g}")
    axis.axvline(high, color="#7c3aed", linestyle="--", label=f"high = {high:g}")
    axis.set(xlabel="Predicted malware score", ylabel="Files", title=f"Score distribution; errors excluded: {(~valid).sum():,}", xlim=(0, 1))
    axis.legend()
    figure.tight_layout()
    return figure


def plot_threshold_tradeoffs(curve: pd.DataFrame, *, low: float | None = None, high: float | None = None):
    """validation의 low별 누락/오탐/전달량과 high별 precision을 비교합니다."""
    import matplotlib.pyplot as plt

    figure, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    ordered = curve.sort_values("threshold")
    for name, title in (
        ("screening_recall", "Screening recall (all malware)"),
        ("benign_forward_rate", "Benign forward rate"),
        ("overall_forward_rate", "Overall stage-2 workload"),
    ):
        axes[0].plot(ordered.threshold, ordered[name], label=title)
    for name, title in (("malware_precision", "Malware precision"), ("malware_recall", "Malware recall"), ("malware_fpr", "Malware FPR")):
        axes[1].plot(ordered.threshold, ordered[name], label=title)
    for axis, selected, title in zip(axes, [low, high], ["Validation: low threshold", "Validation: high threshold"]):
        if selected is not None:
            axis.axvline(selected, color="black", linestyle="--", alpha=0.6, label=f"Selected = {selected:g}")
        axis.set(xlabel="Threshold", ylabel="Rate", xlim=(0, 1), ylim=(0, 1.02), title=title)
        axis.grid(alpha=0.2)
        axis.legend()
    figure.tight_layout()
    return figure
