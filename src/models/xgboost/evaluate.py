"""
NexThreat Phase 4.3 — Multiclass Evaluation Engine.

Provides rigorous, support-aware multiclass evaluation:
- Standard classification metrics: Accuracy, Precision, Recall, F1 (macro & weighted).
- Per-class metrics with support and zero_division=0 protection.
- 8x8 multiclass confusion matrix.
- Multiclass log loss over all 8 class probability distributions.
- One-vs-Rest (OvR) ROC-AUC with explicit undefined handling for zero-support classes.
- One-vs-Rest (OvR) PR-AUC (Average Precision) with explicit undefined handling.
- Class-wise prediction distributions and error analysis.

Distinguishes:
1. Metric = 0.0 (model truly failed on that class)
2. Metric = undefined (data lacks required positive/negative support to compute metric)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    log_loss,
    roc_auc_score,
    average_precision_score,
)

from src.models.xgboost.config import (
    NUM_CLASSES,
    CLASS_MAPPING,
    INDEX_TO_CLASS,
    CLASS_NAMES,
)


def evaluate_multiclass(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    predictions: Optional[np.ndarray] = None,
    split_name: str = "evaluation",
) -> Dict[str, Any]:
    """
    Execute complete multiclass evaluation across all 8 classes.

    Parameters
    ----------
    y_true : np.ndarray
        Ground-truth integer labels of shape (N,).
    probabilities : np.ndarray
        Predicted class probability distribution of shape (N, 8).
    predictions : Optional[np.ndarray]
        Predicted discrete class indices of shape (N,).
        If None, computed as argmax(probabilities, axis=1).
    split_name : str
        Name of split being evaluated (e.g. 'training', 'validation', 'test').

    Returns
    -------
    Dict[str, Any]
        Complete evaluation diagnostics and metric reports.
    """
    y_true = np.asarray(y_true, dtype=np.int64)
    probabilities = np.asarray(probabilities, dtype=np.float64)
    # Ensure row sums strictly equal 1.0 to guard against float32 roundoff
    row_sums = probabilities.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1.0
    probabilities = probabilities / row_sums

    if predictions is None:
        predictions = np.argmax(probabilities, axis=1).astype(np.int64)
    else:
        predictions = np.asarray(predictions, dtype=np.int64)

    total_samples = int(len(y_true))
    all_class_indices = list(range(NUM_CLASSES))

    # 1. Standard Global Metrics
    acc = float(accuracy_score(y_true, predictions))
    macro_prec = float(precision_score(y_true, predictions, average="macro", zero_division=0))
    weighted_prec = float(precision_score(y_true, predictions, average="weighted", zero_division=0))
    macro_rec = float(recall_score(y_true, predictions, average="macro", zero_division=0))
    weighted_rec = float(recall_score(y_true, predictions, average="weighted", zero_division=0))
    macro_f1 = float(f1_score(y_true, predictions, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, predictions, average="weighted", zero_division=0))

    # 2. Multiclass Log Loss
    # Use full label set 0..7
    try:
        loss = float(log_loss(y_true, probabilities, labels=all_class_indices))
    except Exception as e:
        loss = float("nan")

    # 3. Per-Class Precision, Recall, F1, Support
    per_class_metrics: List[Dict[str, Any]] = []
    supported_classes_list: List[int] = []
    zero_support_classes_list: List[int] = []

    for c in range(NUM_CLASSES):
        c_name = INDEX_TO_CLASS[c]
        c_mask = (y_true == c)
        c_support = int(c_mask.sum())

        c_prec = float(precision_score(y_true == c, predictions == c, zero_division=0))
        c_rec = float(recall_score(y_true == c, predictions == c, zero_division=0))
        c_f1 = float(f1_score(y_true == c, predictions == c, zero_division=0))

        if c_support > 0:
            supported_classes_list.append(c)
        else:
            zero_support_classes_list.append(c)

        per_class_metrics.append({
            "class_index": c,
            "class_name": c_name,
            "support": c_support,
            "precision": round(c_prec, 6),
            "recall": round(c_rec, 6),
            "f1": round(c_f1, 6),
            "has_support": c_support > 0,
        })

    # Metrics computed strictly over classes with non-zero support
    supported_f1s = [m["f1"] for m in per_class_metrics if m["has_support"]]
    supported_recalls = [m["recall"] for m in per_class_metrics if m["has_support"]]
    supported_precisions = [m["precision"] for m in per_class_metrics if m["has_support"]]

    macro_f1_supported = float(np.mean(supported_f1s)) if supported_f1s else 0.0
    macro_recall_supported = float(np.mean(supported_recalls)) if supported_recalls else 0.0
    macro_precision_supported = float(np.mean(supported_precisions)) if supported_precisions else 0.0

    # 4. Confusion Matrix (8x8)
    cm = confusion_matrix(y_true, predictions, labels=all_class_indices)
    cm_list = cm.tolist()

    # 5. One-vs-Rest (OvR) ROC-AUC (Support-Aware)
    per_class_roc: List[Dict[str, Any]] = []
    supported_roc_scores: List[float] = []
    supported_roc_weights: List[int] = []
    roc_excluded: List[int] = []
    roc_exclusion_reasons: Dict[str, str] = {}

    for c in range(NUM_CLASSES):
        c_name = INDEX_TO_CLASS[c]
        y_c = (y_true == c).astype(int)
        pos_count = int(y_c.sum())
        neg_count = int((1 - y_c).sum())

        if pos_count == 0:
            per_class_roc.append({
                "class_index": c,
                "class_name": c_name,
                "support": pos_count,
                "roc_auc": None,
                "roc_auc_status": "undefined",
                "reason": "zero positive samples in split",
            })
            roc_excluded.append(c)
            roc_exclusion_reasons[str(c)] = "zero positive samples in split"
        elif neg_count == 0:
            per_class_roc.append({
                "class_index": c,
                "class_name": c_name,
                "support": pos_count,
                "roc_auc": None,
                "roc_auc_status": "undefined",
                "reason": "zero negative samples in split",
            })
            roc_excluded.append(c)
            roc_exclusion_reasons[str(c)] = "zero negative samples in split"
        else:
            try:
                score = float(roc_auc_score(y_c, probabilities[:, c]))
                per_class_roc.append({
                    "class_index": c,
                    "class_name": c_name,
                    "support": pos_count,
                    "roc_auc": round(score, 6),
                    "roc_auc_status": "computed",
                    "reason": None,
                })
                supported_roc_scores.append(score)
                supported_roc_weights.append(pos_count)
            except Exception as roc_err:
                per_class_roc.append({
                    "class_index": c,
                    "class_name": c_name,
                    "support": pos_count,
                    "roc_auc": None,
                    "roc_auc_status": "error",
                    "reason": str(roc_err),
                })
                roc_excluded.append(c)
                roc_exclusion_reasons[str(c)] = f"Calculation error: {roc_err}"

    macro_roc_auc = (
        float(np.mean(supported_roc_scores)) if supported_roc_scores else None
    )
    total_roc_weight = sum(supported_roc_weights)
    weighted_roc_auc = (
        float(np.average(supported_roc_scores, weights=supported_roc_weights))
        if total_roc_weight > 0
        else None
    )

    roc_auc_report = {
        "split_name": split_name,
        "averaging_method": "one-vs-rest (OvR)",
        "macro_roc_auc": round(macro_roc_auc, 6) if macro_roc_auc is not None else None,
        "weighted_roc_auc": round(weighted_roc_auc, 6) if weighted_roc_auc is not None else None,
        "supported_classes": [p["class_index"] for p in per_class_roc if p["roc_auc_status"] == "computed"],
        "excluded_classes": roc_excluded,
        "exclusion_reasons": roc_exclusion_reasons,
        "per_class_roc_auc": per_class_roc,
        "note": "Classes with zero positive samples are recorded strictly as 'undefined' and excluded from averaging; never converted to 0.0.",
    }

    # 6. One-vs-Rest (OvR) PR-AUC (Average Precision, Support-Aware)
    per_class_pr: List[Dict[str, Any]] = []
    supported_pr_scores: List[float] = []
    supported_pr_weights: List[int] = []
    pr_excluded: List[int] = []
    pr_exclusion_reasons: Dict[str, str] = {}

    for c in range(NUM_CLASSES):
        c_name = INDEX_TO_CLASS[c]
        y_c = (y_true == c).astype(int)
        pos_count = int(y_c.sum())

        if pos_count == 0:
            per_class_pr.append({
                "class_index": c,
                "class_name": c_name,
                "support": pos_count,
                "pr_auc": None,
                "pr_auc_status": "undefined",
                "reason": "zero positive samples in split",
            })
            pr_excluded.append(c)
            pr_exclusion_reasons[str(c)] = "zero positive samples in split"
        else:
            try:
                score = float(average_precision_score(y_c, probabilities[:, c]))
                per_class_pr.append({
                    "class_index": c,
                    "class_name": c_name,
                    "support": pos_count,
                    "pr_auc": round(score, 6),
                    "pr_auc_status": "computed",
                    "reason": None,
                })
                supported_pr_scores.append(score)
                supported_pr_weights.append(pos_count)
            except Exception as pr_err:
                per_class_pr.append({
                    "class_index": c,
                    "class_name": c_name,
                    "support": pos_count,
                    "pr_auc": None,
                    "pr_auc_status": "error",
                    "reason": str(pr_err),
                })
                pr_excluded.append(c)
                pr_exclusion_reasons[str(c)] = f"Calculation error: {pr_err}"

    macro_pr_auc = (
        float(np.mean(supported_pr_scores)) if supported_pr_scores else None
    )
    total_pr_weight = sum(supported_pr_weights)
    weighted_pr_auc = (
        float(np.average(supported_pr_scores, weights=supported_pr_weights))
        if total_pr_weight > 0
        else None
    )

    pr_auc_report = {
        "split_name": split_name,
        "averaging_method": "one-vs-rest (OvR) average_precision_score",
        "macro_pr_auc": round(macro_pr_auc, 6) if macro_pr_auc is not None else None,
        "weighted_pr_auc": round(weighted_pr_auc, 6) if weighted_pr_auc is not None else None,
        "supported_classes": [p["class_index"] for p in per_class_pr if p["pr_auc_status"] == "computed"],
        "excluded_classes": pr_excluded,
        "exclusion_reasons": pr_exclusion_reasons,
        "per_class_pr_auc": per_class_pr,
        "note": "Classes with zero positive samples are recorded strictly as 'undefined' and excluded from averaging; never converted to 0.0.",
    }

    # 7. Prediction Distribution & Error Analysis
    pred_counts: List[Dict[str, Any]] = []
    error_analysis: List[Dict[str, Any]] = []

    for c in range(NUM_CLASSES):
        c_name = INDEX_TO_CLASS[c]
        p_count = int((predictions == c).sum())
        p_pct = float(p_count / total_samples * 100.0) if total_samples > 0 else 0.0
        pred_counts.append({
            "class_index": c,
            "class_name": c_name,
            "predicted_count": p_count,
            "predicted_percentage": round(p_pct, 4),
        })

        # TP, FP, FN
        tp = int(((y_true == c) & (predictions == c)).sum())
        fp = int(((y_true != c) & (predictions == c)).sum())
        fn = int(((y_true == c) & (predictions != c)).sum())
        support_c = int((y_true == c).sum())

        error_analysis.append({
            "class_index": c,
            "class_name": c_name,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "support": support_c,
            "class_error_rate": round(float(fn / support_c), 6) if support_c > 0 else None,
        })

    # 8. Complete Consolidated Report
    return {
        "split_name": split_name,
        "total_samples": total_samples,
        "accuracy": round(acc, 6),
        "log_loss": round(loss, 6),
        "macro_precision": round(macro_prec, 6),
        "weighted_precision": round(weighted_prec, 6),
        "macro_recall": round(macro_rec, 6),
        "weighted_recall": round(weighted_rec, 6),
        "macro_f1": round(macro_f1, 6),
        "weighted_f1": round(weighted_f1, 6),
        "macro_f1_supported": round(macro_f1_supported, 6),
        "macro_recall_supported": round(macro_recall_supported, 6),
        "macro_precision_supported": round(macro_precision_supported, 6),
        "per_class_metrics": per_class_metrics,
        "confusion_matrix": cm_list,
        "roc_auc": roc_auc_report,
        "pr_auc": pr_auc_report,
        "prediction_distribution": pred_counts,
        "error_analysis": error_analysis,
    }
