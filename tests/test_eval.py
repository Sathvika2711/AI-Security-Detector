"""
tests/test_eval.py — The evaluation harness: metric maths and the CI gate.
"""

import pytest

from eval.run_eval import compute_metrics, main


def row(label, flagged, category="c", risk=None, llm_calls=0, cost=0.0, latency=1.0, method="rules"):
    return {"label": label, "flagged": flagged, "category": category, "method": method,
            "risk_level": risk or ("high" if flagged else "low"),
            "usage": {"llm_calls": llm_calls, "cost_usd": cost, "latency_ms": latency}}


class TestComputeMetrics:

    def test_confusion_matrix_and_scores(self):
        rows = [row(1, True), row(1, True), row(1, False),     # 2 TP, 1 FN
                row(0, False), row(0, False), row(0, True)]    # 2 TN, 1 FP
        m = compute_metrics(rows)
        assert (m["tp"], m["fn"], m["tn"], m["fp"]) == (2, 1, 2, 1)
        assert m["precision"] == pytest.approx(2 / 3, abs=1e-4)
        assert m["recall"] == pytest.approx(2 / 3, abs=1e-4)
        assert m["fpr"] == pytest.approx(1 / 3, abs=1e-4)

    def test_cost_and_llm_offload(self):
        rows = [row(1, True, llm_calls=0), row(0, False, llm_calls=1, cost=0.002)]
        m = compute_metrics(rows)
        assert m["requests_without_llm_pct"] == 50.0
        assert m["cost_per_1k_requests_usd"] == pytest.approx(1.0)

    def test_per_category_rates(self):
        rows = [row(1, True, "jailbreak"), row(1, False, "jailbreak"), row(0, False, "benign")]
        cats = compute_metrics(rows)["per_category"]
        assert cats["jailbreak"]["rate"] == 0.5
        assert cats["benign"]["rate"] == 1.0

    def test_no_division_by_zero(self):
        m = compute_metrics([row(0, False)])
        assert m["precision"] == 0.0 and m["recall"] == 0.0


class TestCLI:

    def test_rules_eval_runs_without_api_key(self):
        assert main(["--mode", "rules", "--no-write"]) == 0

    def test_gate_fails_when_recall_too_low(self):
        assert main(["--mode", "rules", "--no-write", "--min-recall", "0.99"]) == 1

    def test_gate_fails_when_fpr_too_high(self):
        assert main(["--mode", "rules", "--no-write", "--max-fpr", "0.0"]) == 1

    def test_llm_mode_requires_api_key(self):
        with pytest.raises(SystemExit):
            main(["--mode", "hybrid", "--no-write"])
