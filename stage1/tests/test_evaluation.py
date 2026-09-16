"""경계·추출 오류·단일 클래스·검증 전용 추천의 의미를 작은 정답으로 검증합니다."""

import unittest

import numpy as np
import pandas as pd

from stage1.evaluation import (
    evaluate_scores,
    plot_score_curves,
    plot_score_histogram,
    plot_three_way_confusion,
    plot_threshold_tradeoffs,
    recommend_thresholds,
    route_scores,
    threshold_curve,
)


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.meta = pd.DataFrame(
            {"label": [0, 0, 1, 1, 0, 1], "source": ["PEMML"] * 4 + ["PEMML", "BODMAS"], "split": ["validation"] * 6}
        )
        self.scores = np.array([0.1, 0.2, 0.8, 0.9, np.nan, np.nan])

    def test_boundaries_and_errors_remain_separate(self):
        result = route_scores([0.199, 0.2, 0.8, 1.0, np.nan], 0.2, 0.8, error_forward=False)
        self.assertEqual(result.stage1_result.tolist(), ["Normal", "Suspicious", "Malware", "Malware", "Error"])
        self.assertEqual(result.needs_stage2.tolist(), [False, True, True, True, False])
        self.assertTrue(np.isnan(result.malware_score.iloc[-1]))
        forwarded = route_scores([np.nan], 0.2, 0.8, error_forward=True)
        self.assertEqual(forwarded.stage1_result.iloc[0], "Error")
        self.assertTrue(forwarded.needs_stage2.iloc[0])

    def test_failure_coverage_and_operational_recall_are_visible(self):
        report = evaluate_scores(self.meta, self.scores, 0.2, 0.8, error_forward=False)
        overall = report.loc["overall"]
        self.assertAlmostEqual(overall.screening_recall, 2 / 3)
        self.assertEqual(overall.screening_recall_scored, 1)
        self.assertAlmostEqual(overall.screening_fnr, 1 / 3)
        self.assertAlmostEqual(overall.score_coverage, 4 / 6)
        self.assertAlmostEqual(overall.benign_forward_rate, 1 / 3)
        self.assertAlmostEqual(overall.benign_filter_rate, 1 / 3)
        self.assertEqual(overall.n_forward, 3)
        self.assertEqual(overall.overall_forward_rate, 0.5)
        self.assertEqual(overall.n_malware_band, 2)
        self.assertEqual(overall.malware_precision, 1)
        self.assertEqual(overall.average_precision_scored, 1)
        # error_forward를 켜도 오류가 Malware 표시로 계산되면 안 됩니다.
        forwarded = evaluate_scores(self.meta, self.scores, 0.2, 0.8, error_forward=True).loc["overall"]
        self.assertEqual(forwarded.screening_recall, 1)
        self.assertEqual(forwarded.n_forward, 5)
        self.assertEqual(forwarded.n_malware_band, 2)
        self.assertEqual(forwarded.malware_precision, 1)

    def test_single_class_does_not_report_unverified_perfect_quality(self):
        meta = pd.DataFrame({"label": [1, 1], "source": ["BODMAS"] * 2})
        row = evaluate_scores(meta, [0.5, 0.9], 0.2, 0.8, error_forward=False).loc["BODMAS"]
        self.assertEqual(row.screening_recall, 1)
        self.assertEqual(row.malware_recall, 0.5)
        for name in ["benign_forward_rate", "malware_fpr", "roc_auc_scored", "average_precision_scored", "malware_precision", "binary_f1_scored_at_low"]:
            self.assertTrue(np.isnan(row[name]), name)
        self.assertTrue(np.isfinite(row.log_loss_scored))

    def test_all_errors_and_empty_data_are_defined(self):
        report = evaluate_scores(self.meta, np.full(6, np.nan), 0.2, 0.8, error_forward=False)
        self.assertEqual(report.loc["overall"].screening_recall, 0)
        self.assertEqual(report.loc["overall"].score_coverage, 0)
        self.assertTrue(np.isnan(report.loc["overall"].roc_auc_scored))
        empty = evaluate_scores(self.meta.iloc[:0], [], 0.2, 0.8, error_forward=False)
        self.assertEqual(empty.loc["overall"].n_total, 0)
        self.assertTrue(np.isnan(empty.loc["overall"].screening_recall))

    def test_fast_threshold_counts_match_independent_brute_force(self):
        rng = np.random.default_rng(203)
        y = rng.integers(0, 2, size=300)
        p = np.round(rng.random(300), 1)  # 동점과 정확한 경계를 많이 만듭니다.
        p[::17] = np.nan
        meta = pd.DataFrame({"label": y})
        grid = np.linspace(0, 1, 51)
        for policy in [False, True]:
            curve = threshold_curve(meta, p, grid, error_forward=policy)
            for index, threshold in enumerate(grid):
                scored = np.isfinite(p)
                predicted = scored & (p >= threshold)
                forward = predicted | (~scored & policy)
                row = curve.iloc[index]
                self.assertEqual(row.n_forward, forward.sum())
                self.assertEqual(row.n_true_positive_scored, (predicted & (y == 1)).sum())
                self.assertEqual(row.n_false_positive_scored, (predicted & (y == 0)).sum())
                self.assertAlmostEqual(row.screening_recall, (forward & (y == 1)).sum() / (y == 1).sum())
                self.assertAlmostEqual(row.malware_precision, (predicted & (y == 1)).sum() / predicted.sum())

    def test_recommendation_reports_infeasible_recall_due_to_errors(self):
        result = recommend_thresholds(self.meta, self.scores, error_forward=False)
        self.assertFalse(result["feasible"])
        self.assertIsNone(result["low"])
        self.assertIsNone(result["high"])
        self.assertIn("오류", result["reason"])

    def test_recommendation_is_validation_only_and_does_not_mutate_inputs(self):
        meta = pd.DataFrame({"label": [0, 0, 1, 1], "source": ["PEMML"] * 4, "split": ["validation"] * 4})
        scores = np.array([0.01, 0.02, 0.8, 0.9])
        original = meta.copy(deep=True)
        result = recommend_thresholds(meta, scores, error_forward=False, thresholds=[0.01, 0.1, 0.5, 0.8, 0.9, 1.0])
        self.assertTrue(result["feasible"])
        self.assertEqual(result["low"], 0.8)
        self.assertEqual(result["high"], 0.9)
        self.assertEqual(result["validation_screening_recall"], 1)
        pd.testing.assert_frame_equal(meta, original)
        with self.assertRaises(ValueError):
            recommend_thresholds(meta.assign(split="test"), scores, error_forward=False)
        with self.assertRaises(ValueError):
            recommend_thresholds(meta.drop(columns="split"), scores, error_forward=False)

    def test_no_feasible_precision_or_order_is_reported(self):
        meta = pd.DataFrame({"label": [0, 1], "split": ["validation"] * 2})
        no_precision = recommend_thresholds(meta, [0.9, 0.1], error_forward=False)
        self.assertFalse(no_precision["feasible"])
        self.assertIn("precision", no_precision["reason"])
        # 각 목표를 따로 만족하는 경계가 있어도 low==high는 허용하지 않습니다.
        no_pair = recommend_thresholds(meta, [0.1, 0.9], error_forward=False, thresholds=[0.9])
        self.assertFalse(no_pair["feasible"])
        self.assertIn("low < high", no_pair["reason"])

    def test_invalid_inputs_fail_before_evaluation(self):
        for scores in [[-0.1], [1.1], [np.inf], [[0.1]]]:
            with self.assertRaises(ValueError):
                route_scores(scores, 0.2, 0.8, error_forward=False)
        for low, high in [(0.8, 0.2), (0.5, 0.5), (-1, 0.8), (0.2, np.nan)]:
            with self.assertRaises(ValueError):
                route_scores([0.5], low, high, error_forward=False)
        with self.assertRaises(ValueError):
            evaluate_scores(self.meta, [0.1], 0.2, 0.8, error_forward=False)
        with self.assertRaises(ValueError):
            evaluate_scores(self.meta.assign(label=2), self.scores, 0.2, 0.8, error_forward=False)
        with self.assertRaises(ValueError):
            route_scores([0.5], 0.2, 0.8, error_forward=None)

    def test_plots_handle_single_class_and_errors(self):
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        curve = threshold_curve(self.meta, self.scores, [0, 0.2, 0.8, 1], error_forward=False)
        figures = [
            plot_score_curves(self.meta, self.scores),
            plot_score_curves(self.meta.iloc[-1:], self.scores[-1:]),
            plot_three_way_confusion(self.meta, self.scores, 0.2, 0.8, error_forward=False),
            plot_score_histogram(self.meta, self.scores, 0.2, 0.8),
            plot_threshold_tradeoffs(curve, low=0.2, high=0.8),
        ]
        for figure in figures:
            figure.canvas.draw()
            plt.close(figure)


if __name__ == "__main__":
    unittest.main()
