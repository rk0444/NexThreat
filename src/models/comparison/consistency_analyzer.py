"""
NexThreat Phase 4.5 — Pairwise Model Consistency and Concordance Engine.

Computes:
- Cohen's Kappa (kappa)
- Jaccard similarity index (J) with strict zero-positive-union null guardrail
- Matthews Correlation Coefficient (MCC) with strict zero-marginal-variance null guardrail
- Raw agreement and disagreement rates
- 2x2 binary confusion matrices

Edge-Case Guardrails (Check O Compliance):
- When TP + FP + FN == 0: jaccard_similarity = null, jaccard_undefined_reason = "zero_positive_union"
- When denominator == 0 in MCC: matthews_corrcoef = null, mcc_undefined_reason = "zero_marginal_variance"
- Substituting fake 0.0 or 1.0 is strictly prohibited.
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd


def compute_pairwise_binary_metrics(
    y1: np.ndarray,
    y2: np.ndarray,
    name1: str = "model1",
    name2: str = "model2",
) -> Dict[str, Any]:
    """
    Calculate complete pairwise consistency metrics between two binary decision vectors.
    y1, y2: binary 1D numpy arrays of same length N with values in {0, 1}.
    """
    assert len(y1) == len(y2), "Binary arrays must have identical length"
    n = len(y1)
    if n == 0:
        return {
            "sample_count": 0,
            "error": "Empty input array",
        }

    # Confusion matrix components:
    # y1: rows (predicted 0, 1), y2: columns (predicted 0, 1)
    # TN: (0, 0), FP: (0, 1), FN: (1, 0), TP: (1, 1)
    tn = int(np.sum((y1 == 0) & (y2 == 0)))
    fp = int(np.sum((y1 == 0) & (y2 == 1)))
    fn = int(np.sum((y1 == 1) & (y2 == 0)))
    tp = int(np.sum((y1 == 1) & (y2 == 1)))

    confusion_matrix_2x2 = [
        [tn, fp],
        [fn, tp],
    ]

    # Raw agreement / disagreement
    agreement_count = tp + tn
    raw_agreement_rate = float(agreement_count / n)
    raw_disagreement_rate = float(1.0 - raw_agreement_rate)

    # 1. Cohen's Kappa
    p_o = raw_agreement_rate
    p_e = float(((tp + fp) * (tp + fn) + (tn + fp) * (tn + fn)) / (n * n))
    if math.isclose(1.0 - p_e, 0.0, abs_tol=1e-12):
        cohens_kappa = 1.0 if math.isclose(p_o, 1.0, abs_tol=1e-12) else 0.0
    else:
        cohens_kappa = float((p_o - p_e) / (1.0 - p_e))

    # 2. Jaccard Similarity with Deterministic Null Guardrail (Check O)
    pos_union = tp + fp + fn
    if pos_union == 0:
        jaccard_similarity = None
        jaccard_undefined_reason = "zero_positive_union"
    else:
        jaccard_similarity = float(tp / pos_union)
        jaccard_undefined_reason = None

    # 3. Matthews Correlation Coefficient (MCC) with Deterministic Null Guardrail (Check O)
    denom_sq = float((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    if denom_sq <= 0.0 or math.isclose(denom_sq, 0.0, abs_tol=1e-12):
        matthews_corrcoef = None
        mcc_undefined_reason = "zero_marginal_variance"
    else:
        num = float(tp * tn - fp * fn)
        matthews_corrcoef = float(num / math.sqrt(denom_sq))
        mcc_undefined_reason = None

    return {
        "sample_count": n,
        "cohens_kappa": cohens_kappa,
        "jaccard_similarity": jaccard_similarity,
        "jaccard_undefined_reason": jaccard_undefined_reason,
        "matthews_corrcoef": matthews_corrcoef,
        "mcc_undefined_reason": mcc_undefined_reason,
        "raw_agreement_rate": raw_agreement_rate,
        "raw_disagreement_rate": raw_disagreement_rate,
        "confusion_matrix": confusion_matrix_2x2,
        "confusion_matrix_labels": {
            "rows": f"{name1} (0=Benign, 1=Attack)",
            "columns": f"{name2} (0=Benign, 1=Attack)",
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        },
    }


def analyze_consistency(synchronized_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute pairwise consistency across both Scope A (N=45) and Scope B (N=2,454).
    """
    master_df: pd.DataFrame = synchronized_data["master_df"]
    scope_a_df: pd.DataFrame = synchronized_data["scope_a_df"]

    # -------------------------------------------------------------
    # Scope A: Synchronized Test Intersection (N=45)
    # -------------------------------------------------------------
    sa_ae = scope_a_df["ae_prediction"].values.astype(int)
    sa_xgb = scope_a_df["xgb_prediction"].values.astype(int)
    sa_lstm = scope_a_df["lstm_prediction"].values.astype(int)

    sa_ae_vs_xgb = compute_pairwise_binary_metrics(sa_ae, sa_xgb, "Autoencoder", "XGBoost")
    sa_xgb_vs_lstm = compute_pairwise_binary_metrics(sa_xgb, sa_lstm, "XGBoost", "LSTM")
    sa_ae_vs_lstm = compute_pairwise_binary_metrics(sa_ae, sa_lstm, "Autoencoder", "LSTM")

    scope_a_results = {
        "sample_count": len(scope_a_df),
        "ae_vs_xgboost": sa_ae_vs_xgb,
        "xgboost_vs_lstm": sa_xgb_vs_lstm,
        "ae_vs_lstm": sa_ae_vs_lstm,
    }

    # -------------------------------------------------------------
    # Scope B: Operational Replay
    # - ae_vs_xgboost evaluates all represented windows (N=2,454)
    # - xgboost_vs_lstm & ae_vs_lstm evaluate eligible windows (N=2,404)
    # -------------------------------------------------------------
    sb_ae = master_df["ae_prediction"].values.astype(int)
    sb_xgb = master_df["xgb_prediction"].values.astype(int)
    sb_ae_vs_xgb = compute_pairwise_binary_metrics(sb_ae, sb_xgb, "Autoencoder", "XGBoost")

    eligible_mask = master_df["is_eligible_for_threat_state"] == True
    el_ae = master_df.loc[eligible_mask, "ae_prediction"].values.astype(int)
    el_xgb = master_df.loc[eligible_mask, "xgb_prediction"].values.astype(int)
    el_lstm = master_df.loc[eligible_mask, "lstm_prediction"].values.astype(int)

    sb_xgb_vs_lstm = compute_pairwise_binary_metrics(el_xgb, el_lstm, "XGBoost", "LSTM")
    sb_ae_vs_lstm = compute_pairwise_binary_metrics(el_ae, el_lstm, "Autoencoder", "LSTM")

    scope_b_results = {
        "sample_count": synchronized_data["n_master"],
        "total_master_timeline_windows": synchronized_data["n_master"],
        "eligible_windows_count": synchronized_data["n_eligible"],
        "ineligible_windows_count": synchronized_data["n_ineligible"],
        "ae_vs_xgboost": sb_ae_vs_xgb,
        "xgboost_vs_lstm": sb_xgb_vs_lstm,
        "ae_vs_lstm": sb_ae_vs_lstm,
    }

    return {
        "phase": "4.5",
        "report_name": "Pairwise Model Consistency & Concordance Report",
        "timestamp": pd.Timestamp.now().isoformat(),
        "scope_a_pairwise_consistency": scope_a_results,
        "scope_b_pairwise_consistency": scope_b_results,
    }
