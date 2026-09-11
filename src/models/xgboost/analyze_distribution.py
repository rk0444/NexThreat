"""
NexThreat Phase 4.3B — Class Distribution & Imbalance Analysis.

Analyzes class distributions independently across Train, Validation, and Test splits:
- Quantifies class counts, percentages, majority/minority classes, and imbalance ratios.
- Explicitly flags Validation Class 6 (Web Attack) zero-support asymmetry.
- Computes multiclass balanced sample weights strictly and exclusively from y_train.
- Verifies that validation and test labels are never accessed for weight derivation.

Outputs:
- data/model_reports/xgboost/class_distribution_report.json
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from src.models.config import to_project_relative
from src.models.utils import (
    ensure_directory,
    load_numpy_array,
    save_json_report,
)
from src.models.xgboost.config import (
    SOURCE_DATA_FILES,
    CLASS_MAPPING,
    INDEX_TO_CLASS,
    CLASS_NAMES,
    NUM_CLASSES,
    CLASS_DISTRIBUTION_REPORT_PATH,
    XGBOOST_REPORTS_DIR,
)

logger = logging.getLogger("NexThreat.Models.XGBoost.AnalyzeDistribution")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def compute_balanced_class_weights(y_train: np.ndarray, num_classes: int = NUM_CLASSES) -> Dict[int, float]:
    """
    Compute balanced class weights exclusively from y_train using canonical formula:
    w_c = N / (K * N_c)
    where:
    N = len(y_train)
    K = num_classes (8)
    N_c = count of class c in y_train
    """
    total_samples = len(y_train)
    weights: Dict[int, float] = {}

    for c in range(num_classes):
        n_c = int((y_train == c).sum())
        if n_c == 0:
            raise ValueError(f"Training split missing required class {c} ({INDEX_TO_CLASS[c]})")
        weight_c = float(total_samples / (num_classes * n_c))
        weights[c] = round(weight_c, 6)

    return weights


def analyze_split_distribution(y: np.ndarray, split_name: str) -> Dict[str, Any]:
    """Analyze class distribution for a specific dataset split."""
    total_samples = int(len(y))
    counts = Counter(y.tolist())

    table: List[Dict[str, Any]] = []
    classes_present: List[int] = []
    classes_missing: List[int] = []

    for c in range(NUM_CLASSES):
        c_name = INDEX_TO_CLASS[c]
        c_count = int(counts.get(c, 0))
        c_pct = float(c_count / total_samples * 100.0) if total_samples > 0 else 0.0

        entry = {
            "class_index": c,
            "class_name": c_name,
            "count": c_count,
            "percentage": round(c_pct, 4),
            "present": c_count > 0,
        }
        table.append(entry)

        if c_count > 0:
            classes_present.append(c)
        else:
            classes_missing.append(c)

    present_counts = [t["count"] for t in table if t["count"] > 0]
    majority_entry = max(table, key=lambda x: x["count"])
    minority_entry = min([t for t in table if t["count"] > 0], key=lambda x: x["count"])
    imbalance_ratio = float(majority_entry["count"] / minority_entry["count"]) if minority_entry["count"] > 0 else None

    return {
        "split_name": split_name,
        "total_samples": total_samples,
        "classes_present_count": len(classes_present),
        "classes_present": classes_present,
        "classes_missing": classes_missing,
        "majority_class": {
            "index": majority_entry["class_index"],
            "name": majority_entry["class_name"],
            "count": majority_entry["count"],
            "percentage": majority_entry["percentage"],
        },
        "minority_class": {
            "index": minority_entry["class_index"],
            "name": minority_entry["class_name"],
            "count": minority_entry["count"],
            "percentage": minority_entry["percentage"],
        },
        "imbalance_ratio": round(imbalance_ratio, 4) if imbalance_ratio is not None else None,
        "class_frequency_table": table,
    }


def analyze_distributions() -> Dict[str, Any]:
    """
    Execute Phase 4.3B distribution and imbalance analysis.

    Returns
    -------
    Dict[str, Any]
        Complete distribution report dictionary.
    """
    logger.info("=" * 70)
    logger.info("NexThreat Phase 4.3B — Class Distribution & Imbalance Analysis")
    logger.info("=" * 70)

    ensure_directory(XGBOOST_REPORTS_DIR)

    # 1. Load label arrays
    y_train = load_numpy_array(SOURCE_DATA_FILES["y_train"])
    y_val = load_numpy_array(SOURCE_DATA_FILES["y_validation"])
    y_test = load_numpy_array(SOURCE_DATA_FILES["y_test"])

    # 2. Analyze individual splits independently
    train_dist = analyze_split_distribution(y_train, "TRAINING")
    val_dist = analyze_split_distribution(y_val, "VALIDATION")
    test_dist = analyze_split_distribution(y_test, "TEST")

    # 3. Validation Asymmetry Analysis (Correction 1)
    val_has_class_6 = 6 in val_dist["classes_present"]
    val_class_6_support = int((y_val == 6).sum())

    val_asymmetry = {
        "class_6_index": 6,
        "class_6_name": "Web Attack",
        "validation_support": val_class_6_support,
        "has_zero_support": val_class_6_support == 0,
        "implication": (
            "Web Attack (class 6) contains exactly 0 positive samples in validation. "
            "In validation metrics, its support is reported as 0 with zero_division=0. "
            "Its OvR ROC-AUC and OvR PR-AUC must be documented explicitly as 'undefined' "
            "(never coerced to 0.0). Valid supported classes for validation AUCs: [0, 1, 2, 3, 4, 5, 7]."
        ),
    }

    # 4. Compute balanced class weights strictly from y_train (Correction 6)
    class_weights = compute_balanced_class_weights(y_train, num_classes=NUM_CLASSES)

    class_weights_formatted: List[Dict[str, Any]] = []
    for c in range(NUM_CLASSES):
        class_weights_formatted.append({
            "class_index": c,
            "class_name": INDEX_TO_CLASS[c],
            "training_samples": int((y_train == c).sum()),
            "class_weight": class_weights[c],
        })

    imbalance_strategy = {
        "strategy_name": "balanced_class_weighting",
        "formula": "w_c = N / (K * N_c)",
        "formula_variables": {
            "N": int(len(y_train)),
            "K": NUM_CLASSES,
            "N_c": "Training count for class c",
        },
        "derived_strictly_from": "y_train ONLY",
        "validation_labels_used": False,
        "test_labels_used": False,
        "weights_per_class": class_weights_formatted,
        "candidate_usage": {
            "Candidate_A": "Unweighted (uniform weight = 1.0)",
            "Candidate_B": "Balanced sample weights applied during training",
            "Candidate_C": "Unweighted (regularized tree structure)",
        },
    }

    report: Dict[str, Any] = {
        "report_name": "NexThreat Phase 4.3B Class Distribution & Imbalance Report",
        "phase": "Phase 4.3B",
        "generated_at": datetime.now().isoformat(),
        "training_distribution": train_dist,
        "validation_distribution": val_dist,
        "test_distribution": test_dist,
        "validation_class_6_asymmetry": val_asymmetry,
        "imbalance_strategy": imbalance_strategy,
    }

    save_json_report(report, CLASS_DISTRIBUTION_REPORT_PATH)
    logger.info("Saved class distribution report to: %s", to_project_relative(CLASS_DISTRIBUTION_REPORT_PATH))

    # Console output
    print("\n" + "=" * 70)
    print("NexThreat Phase 4.3B — Class Distribution Summary")
    print("=" * 70)
    print(f"TRAIN : {train_dist['total_samples']} samples across {train_dist['classes_present_count']}/8 classes (Imbalance: {train_dist['imbalance_ratio']}:1)")
    print(f"VAL   : {val_dist['total_samples']} samples across {val_dist['classes_present_count']}/8 classes (Class 6 Web Attack support = {val_class_6_support})")
    print(f"TEST  : {test_dist['total_samples']} samples across {test_dist['classes_present_count']}/8 classes (Imbalance: {test_dist['imbalance_ratio']}:1)")
    print("\nBalanced Class Weights (derived strictly from y_train):")
    for w in class_weights_formatted:
        print(f"  Class {w['class_index']} ({w['class_name']:<12}): N_c={w['training_samples']:<4} weight={w['class_weight']:.6f}")
    print("=" * 70 + "\n")

    return report


if __name__ == "__main__":
    analyze_distributions()
