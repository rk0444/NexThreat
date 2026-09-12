"""
NexThreat Phase 4.4 — Binary Attack Forecasting Evaluation Engine.

Provides evaluation metrics computation (Accuracy, Precision, Recall, F1,
Confusion Matrix, FPR, FNR, ROC-AUC, PR-AUC, Log Loss) and the deterministic
4-tier validation threshold optimization sweep engine.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
    log_loss,
)

from src.models.lstm.config import (
    THRESHOLD_CANDIDATES,
    THRESHOLD_TIE_BREAK_POLICY,
)

logger = logging.getLogger("NexThreat.Models.LSTM.Evaluate")


def evaluate_binary_forecasting(
    y_true: np.ndarray,
    y_probs: np.ndarray,
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """
    Compute comprehensive binary attack forecasting performance metrics.

    Parameters
    ----------
    y_true : np.ndarray
        Ground truth binary labels (0=BENIGN, 1=ATTACK), shape (N,).
    y_probs : np.ndarray
        Predicted attack probabilities, shape (N,) or (N, 1).
    threshold : float
        Decision boundary threshold for positive classification (default: 0.5).

    Returns
    -------
    Dict[str, Any]
        Dictionary of computed performance metrics.
    """
    probs = np.asarray(y_probs, dtype=np.float64).ravel()
    labels = np.asarray(y_true, dtype=np.int64).ravel()

    preds = (probs >= threshold).astype(np.int64)

    # Basic counts & confusion matrix
    cm = confusion_matrix(labels, preds, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    total_samples = len(labels)
    total_positives = int(np.sum(labels == 1))
    total_negatives = int(np.sum(labels == 0))

    # Rates
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    # Binary metrics (Class 1 = ATTACK)
    attack_precision = float(precision_score(labels, preds, pos_label=1, zero_division=0))
    attack_recall = float(recall_score(labels, preds, pos_label=1, zero_division=0))
    attack_f1 = float(f1_score(labels, preds, pos_label=1, zero_division=0))

    # Class 0 = BENIGN metrics
    benign_precision = float(precision_score(labels, preds, pos_label=0, zero_division=0))
    benign_recall = float(recall_score(labels, preds, pos_label=0, zero_division=0))
    benign_f1 = float(f1_score(labels, preds, pos_label=0, zero_division=0))

    # Averaged metrics
    acc = float(accuracy_score(labels, preds))
    macro_f1 = float(f1_score(labels, preds, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(labels, preds, average="weighted", zero_division=0))

    # Probabilistic curves & losses
    try:
        roc_auc = float(roc_auc_score(labels, probs))
    except Exception as e:
        logger.warning("ROC-AUC computation failed: %s", e)
        roc_auc = 0.0

    try:
        pr_auc = float(average_precision_score(labels, probs))
    except Exception as e:
        logger.warning("PR-AUC computation failed: %s", e)
        pr_auc = 0.0

    try:
        # Clip probabilities for stable log loss computation
        clipped_probs = np.clip(probs, 1e-15, 1.0 - 1e-15)
        loss = float(log_loss(labels, clipped_probs))
    except Exception as e:
        logger.warning("Log loss computation failed: %s", e)
        loss = float("inf")

    return {
        "threshold": float(threshold),
        "total_samples": total_samples,
        "positive_samples": total_positives,
        "negative_samples": total_negatives,
        "confusion_matrix": {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
            "matrix": [[tn, fp], [fn, tp]],
        },
        "rates": {
            "fpr": fpr,
            "fnr": fnr,
        },
        "attack_class_metrics": {
            "precision": attack_precision,
            "recall": attack_recall,
            "f1": attack_f1,
        },
        "benign_class_metrics": {
            "precision": benign_precision,
            "recall": benign_recall,
            "f1": benign_f1,
        },
        "overall_metrics": {
            "accuracy": acc,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "log_loss": loss,
        },
    }


def run_threshold_sweep(
    y_true: np.ndarray,
    y_probs: np.ndarray,
    candidate_thresholds: List[float] = THRESHOLD_CANDIDATES,
) -> Tuple[float, Dict[str, Any], List[Dict[str, Any]]]:
    """
    Execute deterministic validation threshold tuning sweep across candidate thresholds.

    Selection Priority (Clarification 3 & Guarantee 11):
    1. Maximize Attack Recall
    2. Maximize Attack F1
    3. Minimize FPR (False Positive Rate)
    4. Minimize Threshold value

    Parameters
    ----------
    y_true : np.ndarray
        Validation ground truth binary labels.
    y_probs : np.ndarray
        Validation predicted attack probabilities.
    candidate_thresholds : List[float]
        Candidate thresholds to evaluate (default: 0.30..0.70 in 0.05 increments).

    Returns
    -------
    Tuple[float, Dict[str, Any], List[Dict[str, Any]]]
        Selected threshold, evaluation metrics at selected threshold, and full sweep records.
    """
    sweep_records: List[Dict[str, Any]] = []

    for th in candidate_thresholds:
        metrics = evaluate_binary_forecasting(y_true, y_probs, threshold=th)
        record = {
            "threshold": round(float(th), 4),
            "attack_recall": metrics["attack_class_metrics"]["recall"],
            "attack_f1": metrics["attack_class_metrics"]["f1"],
            "attack_precision": metrics["attack_class_metrics"]["precision"],
            "fpr": metrics["rates"]["fpr"],
            "fnr": metrics["rates"]["fnr"],
            "accuracy": metrics["overall_metrics"]["accuracy"],
            "tn": metrics["confusion_matrix"]["tn"],
            "fp": metrics["confusion_matrix"]["fp"],
            "fn": metrics["confusion_matrix"]["fn"],
            "tp": metrics["confusion_matrix"]["tp"],
        }
        sweep_records.append(record)

    # Sort deterministically by priority:
    # 1. attack_recall descending (-recall)
    # 2. attack_f1 descending (-f1)
    # 3. fpr ascending (+fpr)
    # 4. threshold ascending (+threshold)
    def ranking_key(item: Dict[str, Any]) -> Tuple[float, float, float, float]:
        return (
            -round(item["attack_recall"], 6),
            -round(item["attack_f1"], 6),
            round(item["fpr"], 6),
            round(item["threshold"], 6),
        )

    sorted_records = sorted(sweep_records, key=ranking_key)
    best_record = sorted_records[0]
    selected_threshold = float(best_record["threshold"])
    best_full_metrics = evaluate_binary_forecasting(y_true, y_probs, threshold=selected_threshold)

    logger.info(
        "Validation threshold sweep completed. Selected threshold=%.4f (Attack Recall=%.4f, Attack F1=%.4f, FPR=%.4f)",
        selected_threshold,
        best_record["attack_recall"],
        best_record["attack_f1"],
        best_record["fpr"],
    )

    return selected_threshold, best_full_metrics, sweep_records
