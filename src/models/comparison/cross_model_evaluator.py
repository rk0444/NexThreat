"""
NexThreat Phase 4.5 — Cross-Model Evaluation and Benchmarking Engine.

Provides:
1. Harvesting and dynamic verification of frozen individual model benchmarks (Scope A):
   - Autoencoder Test Benchmark (N=408)
   - XGBoost Test Benchmark (N=319)
   - LSTM Test Benchmark (N=286)
2. Synchronized Concordance Evaluation on Scope A (N=45).
3. Scope B Operational Replay metrics with strict quarantine from Scope A test benchmarks.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from src.models.comparison.config import (
    AUTOENCODER_EVALUATION_REPORT_PATH,
    AUTOENCODER_RECONSTRUCTION_STATS_PATH,
    XGBOOST_TEST_REPORT_PATH,
    LSTM_TEST_REPORT_PATH,
    load_dynamic_thresholds,
)


def load_individual_benchmarks() -> Dict[str, Any]:
    """
    Harvest authoritative test benchmarks from prior phase reports.
    """
    ae_thresh, lstm_thresh = load_dynamic_thresholds()

    # 1. Autoencoder Benchmark (N=408)
    with open(AUTOENCODER_EVALUATION_REPORT_PATH, "r", encoding="utf-8") as f:
        ae_rep = json.load(f)
    with open(AUTOENCODER_RECONSTRUCTION_STATS_PATH, "r", encoding="utf-8") as f:
        ae_stats = json.load(f)

    ae_test = ae_rep["test"]
    ae_conf = ae_test["confusion_matrix_convention"]
    ae_detected = int(ae_conf["tp"] + ae_conf["fp"])
    ae_total = int(ae_test["error_analysis"]["benign_test_samples"] + ae_test["error_analysis"]["attack_test_samples"])
    ae_benchmark = {
        "sample_count": ae_total,
        "reconstruction_error_mean": float(ae_stats["test"]["mean"]),
        "reconstruction_error_std": float(ae_stats["test"]["std"]),
        "threshold": ae_thresh,
        "precision": float(ae_test["precision"]),
        "recall": float(ae_test["recall"]),
        "f1_score": float(ae_test["f1"]),
        "roc_auc": float(ae_test["roc_auc"]),
        "pr_auc": float(ae_test["pr_auc"]),
        "anomalies_detected": ae_detected,
        "anomaly_rate": float(ae_detected / ae_total) if ae_total > 0 else 0.0,
    }

    # 2. XGBoost Benchmark (N=319)
    with open(XGBOOST_TEST_REPORT_PATH, "r", encoding="utf-8") as f:
        xgb_rep = json.load(f)

    xgb_total = int(xgb_rep["total_samples"])
    # Attack samples detected: any predicted class != 0 (BENIGN)
    # Sum predictions across non-benign classes from per_class_metrics or confusion matrix
    xgb_attacks_detected = 0
    if "confusion_matrix" in xgb_rep:
        # Sum column sums for classes 1..7
        cm = np.array(xgb_rep["confusion_matrix"])
        xgb_attacks_detected = int(np.sum(cm[:, 1:]))
    else:
        # Calculate from support and per-class metrics
        benign_metric = next((m for m in xgb_rep["per_class_metrics"] if m["class_index"] == 0), None)
        if benign_metric and "support" in benign_metric and "recall" in benign_metric:
            benign_tn = int(round(benign_metric["support"] * benign_metric["recall"]))
            # false positives for benign means predicted attack when benign
            # total attacks detected = total_samples - total predicted benign
            # from precision: benign_tn / total_predicted_benign = precision
            if benign_metric.get("precision", 0) > 0:
                pred_benign = int(round(benign_tn / benign_metric["precision"]))
                xgb_attacks_detected = xgb_total - pred_benign

    xgb_benchmark = {
        "sample_count": xgb_total,
        "accuracy": float(xgb_rep["accuracy"]),
        "macro_f1": float(xgb_rep["macro_f1"]),
        "weighted_f1": float(xgb_rep["weighted_f1"]),
        "macro_precision": float(xgb_rep.get("macro_precision", 0.0)),
        "macro_recall": float(xgb_rep.get("macro_recall", 0.0)),
        "attacks_detected": xgb_attacks_detected,
        "attack_rate": float(xgb_attacks_detected / xgb_total) if xgb_total > 0 else 0.0,
    }

    # 3. LSTM Benchmark (N=286)
    with open(LSTM_TEST_REPORT_PATH, "r", encoding="utf-8") as f:
        lstm_rep = json.load(f)

    lstm_metrics = lstm_rep["metrics"]
    lstm_conf = lstm_metrics["confusion_matrix"]
    lstm_pos = int(lstm_conf["tp"] + lstm_conf["fp"])
    lstm_total = int(lstm_metrics["total_samples"])
    lstm_benchmark = {
        "sample_count": lstm_total,
        "threshold": lstm_thresh,
        "precision": float(lstm_metrics["attack_class_metrics"]["precision"]),
        "recall": float(lstm_metrics["attack_class_metrics"]["recall"]),
        "f1_score": float(lstm_metrics["attack_class_metrics"]["f1"]),
        "auc_pr": float(lstm_metrics["overall_metrics"]["pr_auc"]),
        "roc_auc": float(lstm_metrics["overall_metrics"]["roc_auc"]),
        "accuracy": float(lstm_metrics["overall_metrics"]["accuracy"]),
        "forecasts_positive": lstm_pos,
        "forecast_positive_rate": float(lstm_pos / lstm_total) if lstm_total > 0 else 0.0,
    }

    return {
        "autoencoder": ae_benchmark,
        "xgboost": xgb_benchmark,
        "lstm": lstm_benchmark,
    }


def evaluate_cross_model(
    synchronized_data: Dict[str, Any],
    pairwise_scope_a_metrics: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build the complete cross-model evaluation report dictionary.
    """
    master_df: pd.DataFrame = synchronized_data["master_df"]
    n_master = synchronized_data["n_master"]
    n_eligible = synchronized_data["n_eligible"]
    n_ineligible = synchronized_data["n_ineligible"]

    individual_benchmarks = load_individual_benchmarks()

    # Scope B operational metrics across all N_master windows
    ae_pos = int((master_df["ae_prediction"] == 1).sum())
    xgb_pos = int((master_df["xgb_prediction"] == 1).sum())

    # LSTM in Scope B: rate over eligible windows
    eligible_mask = master_df["is_eligible_for_threat_state"] == True
    eligible_lstm_preds = master_df.loc[eligible_mask, "lstm_prediction"].astype(int)
    lstm_pos = int((eligible_lstm_preds == 1).sum())

    scope_b_metrics = {
        "sample_count": n_master,
        "total_master_timeline_windows": n_master,
        "eligible_windows_count": n_eligible,
        "ineligible_windows_count": n_ineligible,
        "autoencoder_positive_count": ae_pos,
        "autoencoder_positive_rate": float(ae_pos / n_master) if n_master > 0 else 0.0,
        "xgboost_positive_count": xgb_pos,
        "xgboost_positive_rate": float(xgb_pos / n_master) if n_master > 0 else 0.0,
        "lstm_positive_count": lstm_pos,
        "lstm_positive_rate": float(lstm_pos / n_eligible) if n_eligible > 0 else 0.0,
        "lstm_positive_rate_over_eligible": float(lstm_pos / n_eligible) if n_eligible > 0 else 0.0,
        "lstm_unavailable_count": n_ineligible,
    }

    return {
        "phase": "4.5",
        "report_name": "Cross-Model Evaluation & Benchmark Report",
        "timestamp": pd.Timestamp.now().isoformat(),
        "scope_a_individual_benchmarks": individual_benchmarks,
        "scope_a_synchronized_benchmark": {
            "sample_count": len(synchronized_data["synchronized_test_positions"]),
            "mutual_overlap_positions": len(synchronized_data["manifest_overlap_positions"]),
            "excluded_positions": synchronized_data["excluded_positions"],
            "pairwise_metrics": pairwise_scope_a_metrics,
        },
        "scope_b_operational_replay": scope_b_metrics,
    }
