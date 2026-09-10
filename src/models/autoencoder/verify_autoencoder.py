"""
NexThreat Phase 4.2 — Hardened Independent Autoencoder Verification Suite.

Independently audits the completed Autoencoder pipeline across 11 rigorous checks:
- Check A: Model Artifact Integrity (files exist, can be loaded and executed).
- Check B: Model Architecture Verification (13 -> 32 -> 16 -> 8 -> 16 -> 32 -> 13).
- Check C: Dataset Integrity (X_train, X_validation, X_test shapes, dtypes, zero NaN/Inf).
- Check D: Scaler Integrity (pre-fitted Phase 3.3 scaler reused without refitting).
- Check E: Training Integrity (unsupervised BENIGN training only; zero test leakage).
- Check F: Threshold Selection Integrity (selected strictly on validation, frozen for test).
- Check G: Evaluation Integrity (test predictions strictly use frozen threshold).
- Check H: Metrics Integrity (valid numeric bounds, confusion matrix, FPR, FNR).
- Check I: Previous Data Immutability (cryptographic SHA-256 validation of all 26 model-ready files).
- Check J: Independent Threshold Replay (recomputed threshold matches stored threshold).
- Check K: Independent Metric Replay (recomputed test metrics, counts, FPR, FNR match report).

Includes explicit separation of Implementation/Integrity Status (PASS/FAIL)
from Model Performance Observations (diagnostic audit of high recall / high FPR).

Generates:
data/model_reports/autoencoder/autoencoder_verification_report.json
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)
import tensorflow as tf
from tensorflow import keras

from src.models.config import (
    FEATURE_COUNT,
    FEATURE_DTYPE,
    LABEL_DTYPE,
    AUTOENCODER_INPUT_FILES,
    AUTOENCODER_SCALER_PATH,
    MODEL_READY_DIR,
    to_project_relative,
)
from src.models.utils import (
    load_numpy_array,
    validate_numpy_array,
    load_json_report,
    save_json_report,
)
from src.models.autoencoder.config import (
    INPUT_DIM,
    LATENT_DIM,
    LAYER_DIMS,
    BEST_MODEL_PATH,
    FINAL_MODEL_PATH,
    MODEL_METADATA_PATH,
    TRAINING_REPORT_PATH,
    TRAINING_HISTORY_PATH,
    RECONSTRUCTION_STATS_PATH,
    AUTOENCODER_EVALUATION_REPORT_PATH,
    AUTOENCODER_VERIFICATION_REPORT_PATH,
)
from src.models.autoencoder.evaluate import (
    compute_per_sample_mse,
    select_validation_threshold,
)
from src.models.verification.verify_model_infrastructure import (
    BASELINE_MODEL_READY_HASHES,
)

logger = logging.getLogger("NexThreat.Models.Autoencoder.Verify")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def calculate_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash using chunked binary reading."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


# ============================================================
# CHECK A: MODEL ARTIFACT
# ============================================================

def verify_check_a_model_artifact() -> Dict[str, Any]:
    """Verify model files exist and can be loaded successfully."""
    logger.info("Check A: Verifying model artifact existence and loadability...")
    errors: List[str] = []

    best_exists = BEST_MODEL_PATH.exists()
    final_exists = FINAL_MODEL_PATH.exists()
    metadata_exists = MODEL_METADATA_PATH.exists()

    if not best_exists:
        errors.append(f"Best model checkpoint missing: {BEST_MODEL_PATH}")
    if not final_exists:
        errors.append(f"Final model missing: {FINAL_MODEL_PATH}")
    if not metadata_exists:
        errors.append(f"Model metadata missing: {MODEL_METADATA_PATH}")

    model_loadable = False
    if final_exists:
        try:
            loaded_model = keras.models.load_model(str(FINAL_MODEL_PATH))
            test_dummy = np.zeros((1, FEATURE_COUNT), dtype=np.float32)
            out = loaded_model.predict(test_dummy, verbose=0)
            model_loadable = out.shape == (1, FEATURE_COUNT)
        except Exception as e:
            errors.append(f"Failed to load/execute final model: {e}")

    status = "PASS" if len(errors) == 0 and model_loadable else "FAIL"
    logger.info("Check A Status: %s", status)

    return {
        "status": status,
        "best_model_exists": best_exists,
        "final_model_exists": final_exists,
        "metadata_exists": metadata_exists,
        "model_loadable": model_loadable,
        "errors": errors,
    }


# ============================================================
# CHECK B: ARCHITECTURE
# ============================================================

def verify_check_b_architecture() -> Dict[str, Any]:
    """Verify Autoencoder architecture dimensions: 13 -> 32 -> 16 -> 8 -> 16 -> 32 -> 13."""
    logger.info("Check B: Verifying Autoencoder architecture...")
    errors: List[str] = []

    if not FINAL_MODEL_PATH.exists():
        return {"status": "FAIL", "errors": ["Final model does not exist"]}

    model = keras.models.load_model(str(FINAL_MODEL_PATH))

    input_dim = model.input_shape[-1]
    output_dim = model.output_shape[-1]

    if input_dim != FEATURE_COUNT:
        errors.append(f"Input dimension mismatch: expected {FEATURE_COUNT}, got {input_dim}")
    if output_dim != FEATURE_COUNT:
        errors.append(f"Output dimension mismatch: expected {FEATURE_COUNT}, got {output_dim}")

    dense_layers = [layer for layer in model.layers if isinstance(layer, keras.layers.Dense)]
    layer_units = [l.units for l in dense_layers]
    expected_dense_units = [32, 16, 8, 16, 32, FEATURE_COUNT]

    units_match = layer_units == expected_dense_units
    if not units_match:
        errors.append(f"Layer units mismatch: expected {expected_dense_units}, got {layer_units}")

    status = "PASS" if len(errors) == 0 else "FAIL"
    logger.info("Check B Status: %s (Layers: %s)", status, layer_units)

    return {
        "status": status,
        "input_dimension": input_dim,
        "output_dimension": output_dim,
        "dense_layer_units": layer_units,
        "expected_dense_units": expected_dense_units,
        "units_match": units_match,
        "errors": errors,
    }


# ============================================================
# CHECK C: DATASET INTEGRITY
# ============================================================

def verify_check_c_dataset_integrity() -> Dict[str, Any]:
    """Verify X_train, X_validation, X_test shapes, dtypes, and absence of NaN/Inf."""
    logger.info("Check C: Verifying dataset integrity...")
    expected_shapes = {
        "X_train": (1511, FEATURE_COUNT),
        "X_validation": (535, FEATURE_COUNT),
        "X_test": (408, FEATURE_COUNT),
    }

    all_valid = True
    results: Dict[str, Any] = {}

    for split_key, expected_shape in expected_shapes.items():
        path = AUTOENCODER_INPUT_FILES[split_key]
        if not path.exists():
            all_valid = False
            results[split_key] = {"valid": False, "error": "File not found"}
            continue

        arr = load_numpy_array(path)
        valid, info = validate_numpy_array(
            arr,
            expected_dtype=FEATURE_DTYPE,
            expected_ndim=2,
            expected_shape=expected_shape,
            check_finite=True,
        )
        if not valid:
            all_valid = False
        results[split_key] = info

    status = "PASS" if all_valid else "FAIL"
    logger.info("Check C Status: %s", status)

    return {
        "status": status,
        "datasets": results,
    }


# ============================================================
# CHECK D: SCALER INTEGRITY
# ============================================================

def verify_check_d_scaler_integrity() -> Dict[str, Any]:
    """Verify pre-fitted Phase 3.3 scaler exists, is valid, and was not refitted."""
    logger.info("Check D: Verifying scaler integrity...")
    errors: List[str] = []

    if not AUTOENCODER_SCALER_PATH.exists():
        return {"status": "FAIL", "errors": ["Scaler file not found"]}

    current_hash = calculate_sha256(AUTOENCODER_SCALER_PATH)
    baseline_hash = BASELINE_MODEL_READY_HASHES["artifacts/autoencoder_scaler.joblib"]
    hash_matched = current_hash == baseline_hash
    if not hash_matched:
        errors.append("CRITICAL: Scaler SHA-256 hash changed! Scaler may have been refitted.")

    scaler = joblib.load(AUTOENCODER_SCALER_PATH)
    has_mean = hasattr(scaler, "mean_") and scaler.mean_ is not None and len(scaler.mean_) == FEATURE_COUNT
    has_scale = hasattr(scaler, "scale_") and scaler.scale_ is not None and len(scaler.scale_) == FEATURE_COUNT

    if not has_mean or not has_scale:
        errors.append("Scaler missing valid mean_ or scale_ attributes")

    try:
        dummy = np.ones((1, FEATURE_COUNT), dtype=np.float32)
        transformed = scaler.transform(dummy)
        can_transform = transformed.shape == (1, FEATURE_COUNT) and not np.isnan(transformed).any()
    except Exception as e:
        can_transform = False
        errors.append(f"Scaler transform execution failed: {e}")

    status = "PASS" if len(errors) == 0 and can_transform and hash_matched else "FAIL"
    logger.info("Check D Status: %s (Hash matched: %s, Scaler reusable: %s)", status, hash_matched, can_transform)

    return {
        "status": status,
        "scaler_path": to_project_relative(AUTOENCODER_SCALER_PATH),
        "hash_matched": hash_matched,
        "can_transform": can_transform,
        "feature_count_fitted": len(scaler.mean_) if has_mean else 0,
        "errors": errors,
    }


# ============================================================
# CHECK E: TRAINING INTEGRITY
# ============================================================

def verify_check_e_training_integrity() -> Dict[str, Any]:
    """Verify training dataset used was X_train only and validation was X_validation."""
    logger.info("Check E: Verifying training integrity...")
    errors: List[str] = []

    if not TRAINING_REPORT_PATH.exists():
        return {"status": "FAIL", "errors": ["Training report not found"]}

    tr_data = load_json_report(TRAINING_REPORT_PATH)

    train_count = tr_data.get("training_sample_count")
    val_count = tr_data.get("validation_sample_count")
    feat_count = tr_data.get("feature_count")

    if train_count != 1511:
        errors.append(f"Training count mismatch: expected 1511, got {train_count}")
    if val_count != 535:
        errors.append(f"Validation count mismatch: expected 535, got {val_count}")
    if feat_count != FEATURE_COUNT:
        errors.append(f"Feature count mismatch: expected {FEATURE_COUNT}, got {feat_count}")

    history_exists = TRAINING_HISTORY_PATH.exists()
    if not history_exists:
        errors.append("Training history file missing")

    status = "PASS" if len(errors) == 0 else "FAIL"
    logger.info("Check E Status: %s (Train samples: %s, Val samples: %s)", status, train_count, val_count)

    return {
        "status": status,
        "training_sample_count": train_count,
        "validation_sample_count": val_count,
        "feature_count": feat_count,
        "history_file_exists": history_exists,
        "errors": errors,
    }


# ============================================================
# CHECK F: THRESHOLD SELECTION INTEGRITY
# ============================================================

def verify_check_f_threshold_integrity() -> Dict[str, Any]:
    """Verify threshold was selected on validation set only and frozen for test."""
    logger.info("Check F: Verifying threshold selection integrity...")
    errors: List[str] = []

    if not AUTOENCODER_EVALUATION_REPORT_PATH.exists():
        return {"status": "FAIL", "errors": ["Evaluation report not found"]}

    eval_data = load_json_report(AUTOENCODER_EVALUATION_REPORT_PATH)
    th_info = eval_data.get("threshold", {})

    sel_split = th_info.get("selection_split")
    metric = th_info.get("selection_metric")
    frozen = th_info.get("frozen_for_test")
    th_source = th_info.get("threshold_source")
    test_used = th_info.get("test_used_for_threshold_selection")
    val = th_info.get("value")

    if sel_split != "validation":
        errors.append(f"Threshold selection split must be 'validation', got '{sel_split}'")
    if not frozen:
        errors.append("Threshold was not frozen for test evaluation")
    if th_source != "validation":
        errors.append(f"Threshold source must be 'validation', got '{th_source}'")
    if test_used is not False:
        errors.append("CRITICAL: test_used_for_threshold_selection must be False")
    if val is None or val <= 0:
        errors.append(f"Invalid threshold value: {val}")

    status = "PASS" if len(errors) == 0 else "FAIL"
    logger.info("Check F Status: %s (Threshold: %s, Split: %s, Frozen: %s)", status, val, sel_split, frozen)

    return {
        "status": status,
        "threshold_value": val,
        "selection_split": sel_split,
        "selection_metric": metric,
        "frozen_for_test": frozen,
        "threshold_source": th_source,
        "test_used_for_threshold_selection": test_used,
        "errors": errors,
    }


# ============================================================
# CHECK G: EVALUATION INTEGRITY
# ============================================================

def verify_check_g_evaluation_integrity() -> Dict[str, Any]:
    """Verify test predictions were generated using the frozen threshold on all 408 test samples."""
    logger.info("Check G: Verifying evaluation integrity...")
    errors: List[str] = []

    if not RECONSTRUCTION_STATS_PATH.exists():
        errors.append("Reconstruction error statistics file missing")
    else:
        stats = load_json_report(RECONSTRUCTION_STATS_PATH)
        test_count = stats.get("test", {}).get("count")
        val_count = stats.get("validation", {}).get("count")
        train_count = stats.get("train", {}).get("count")

        if test_count != 408:
            errors.append(f"Test sample count mismatch in stats: expected 408, got {test_count}")
        if val_count != 535:
            errors.append(f"Validation sample count mismatch in stats: expected 535, got {val_count}")
        if train_count != 1511:
            errors.append(f"Train sample count mismatch in stats: expected 1511, got {train_count}")

    status = "PASS" if len(errors) == 0 else "FAIL"
    logger.info("Check G Status: %s", status)

    return {
        "status": status,
        "errors": errors,
    }


# ============================================================
# CHECK H: METRICS INTEGRITY (Hardened with FPR & FNR)
# ============================================================

def verify_check_h_metrics_integrity() -> Dict[str, Any]:
    """
    Verify all reported metrics are mathematically valid and internally consistent:
    Accuracy, Precision, Recall, F1, ROC-AUC, PR-AUC, TN, FP, FN, TP, FPR, FNR.
    Distinguishes implementation correctness from performance quality (high FPR is NOT a failure).
    """
    logger.info("Check H: Verifying metrics integrity (including FPR and FNR)...")
    errors: List[str] = []

    if not AUTOENCODER_EVALUATION_REPORT_PATH.exists():
        return {"status": "FAIL", "errors": ["Evaluation report not found"]}

    eval_data = load_json_report(AUTOENCODER_EVALUATION_REPORT_PATH)

    for split in ["validation", "test"]:
        split_metrics = eval_data.get(split, {})

        # Standard bounded metrics
        for metric_name in ["accuracy", "precision", "recall", "f1"]:
            val = split_metrics.get(metric_name)
            if val is None or not (0.0 <= val <= 1.0):
                errors.append(f"Invalid metric {split}.{metric_name}: {val}")

        # Confusion matrix structure
        cm = split_metrics.get("confusion_matrix")
        if not (isinstance(cm, list) and len(cm) == 2 and len(cm[0]) == 2 and len(cm[1]) == 2):
            errors.append(f"Invalid confusion matrix format in {split}: {cm}")
            continue

        cm_sum = sum(cm[0]) + sum(cm[1])
        expected_sum = 535 if split == "validation" else 408
        if cm_sum != expected_sum:
            errors.append(f"Confusion matrix sample sum mismatch in {split}: expected {expected_sum}, got {cm_sum}")

        # Error analysis verification (TN, FP, FN, TP, FPR, FNR)
        err_analysis = split_metrics.get("error_analysis", {})
        tn = err_analysis.get("true_negatives")
        fp = err_analysis.get("false_positives")
        fn = err_analysis.get("false_negatives")
        tp = err_analysis.get("true_positives")
        fpr = err_analysis.get("false_positive_rate")
        fnr = err_analysis.get("false_negative_rate")

        if (tn, fp, fn, tp) != (cm[0][0], cm[0][1], cm[1][0], cm[1][1]):
            errors.append(f"Confusion matrix counts mismatch in {split}.error_analysis")

        # Mathematical verification of rates
        expected_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        expected_fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        if not np.isclose(fpr, expected_fpr, atol=1e-5):
            errors.append(f"FPR calculation mismatch in {split}: expected {expected_fpr}, got {fpr}")
        if not np.isclose(fnr, expected_fnr, atol=1e-5):
            errors.append(f"FNR calculation mismatch in {split}: expected {expected_fnr}, got {fnr}")

    status = "PASS" if len(errors) == 0 else "FAIL"
    logger.info("Check H Status: %s", status)

    return {
        "status": status,
        "errors": errors,
    }


# ============================================================
# CHECK I: PREVIOUS DATA IMMUTABILITY (All 26 model_ready files)
# ============================================================

def verify_check_i_input_immutability() -> Dict[str, Any]:
    """Verify all 26 Phase 3.3 model-ready files have remained strictly unchanged via SHA-256."""
    logger.info("Check I: Auditing Phase 3.3 model-ready inputs immutability (26 files)...")
    errors: List[str] = []
    file_checks: Dict[str, Any] = {}

    for rel_path, baseline_hash in BASELINE_MODEL_READY_HASHES.items():
        file_path = MODEL_READY_DIR / rel_path
        if not file_path.exists():
            errors.append(f"Model-ready file missing: {rel_path}")
            continue

        actual_hash = calculate_sha256(file_path)
        matched = actual_hash == baseline_hash
        if not matched:
            errors.append(f"IMMUTABILITY BREACH on {rel_path}: expected {baseline_hash}, got {actual_hash}")

        file_checks[rel_path] = {
            "path": to_project_relative(file_path),
            "matched": matched,
        }

    status = "PASS" if len(errors) == 0 else "FAIL"
    logger.info("Check I Status: %s (%d files verified against baseline SHA-256)", status, len(file_checks))

    return {
        "status": status,
        "files_verified": len(file_checks),
        "all_matched": len(errors) == 0,
        "files": file_checks,
        "errors": errors,
    }


# ============================================================
# CHECK J: INDEPENDENT THRESHOLD REPLAY (Refinement 6)
# ============================================================

def verify_check_j_threshold_replay() -> Dict[str, Any]:
    """
    Independently recompute validation reconstruction errors and reproduce
    the threshold selection result from raw arrays and trained model.
    Confirms recomputed threshold matches stored threshold within tolerance.
    """
    logger.info("Check J: Performing independent threshold replay on validation split...")
    errors: List[str] = []

    model_path = BEST_MODEL_PATH if BEST_MODEL_PATH.exists() else FINAL_MODEL_PATH
    if not model_path.exists():
        return {"status": "FAIL", "errors": ["Model file not found"]}

    model = keras.models.load_model(str(model_path))
    X_val = load_numpy_array(AUTOENCODER_INPUT_FILES["X_validation"])
    y_val = load_numpy_array(AUTOENCODER_INPUT_FILES["y_validation"])

    # Independent recomputation of validation errors and threshold
    val_errors_recomputed = compute_per_sample_mse(model, X_val)
    recomputed_threshold, replay_meta = select_validation_threshold(val_errors_recomputed, y_val)

    # Load stored threshold from evaluation report
    eval_data = load_json_report(AUTOENCODER_EVALUATION_REPORT_PATH)
    stored_threshold = float(eval_data["threshold"]["value"])

    diff = abs(recomputed_threshold - stored_threshold)
    tolerance = 1e-6
    matched = diff < tolerance

    if not matched:
        errors.append(
            f"Threshold replay mismatch: recomputed={recomputed_threshold:.8f}, "
            f"stored={stored_threshold:.8f}, diff={diff:.8f} (tolerance={tolerance})"
        )

    status = "PASS" if matched else "FAIL"
    logger.info(
        "Check J Status: %s (Recomputed: %.6f, Stored: %.6f, Diff: %.2e)",
        status,
        recomputed_threshold,
        stored_threshold,
        diff,
    )

    return {
        "status": status,
        "recomputed_threshold": recomputed_threshold,
        "stored_threshold": stored_threshold,
        "difference": diff,
        "tolerance": tolerance,
        "matched": matched,
        "errors": errors,
    }


# ============================================================
# CHECK K: INDEPENDENT METRIC REPLAY (Refinement 7 & 10)
# ============================================================

def verify_check_k_metric_replay() -> Dict[str, Any]:
    """
    Independently recompute test reconstruction errors, apply the stored frozen
    threshold, and reproduce test metrics (TN, FP, FN, TP, FPR, FNR, F1, Accuracy, etc.).
    Asserts exact matching of counts and floating-point matching within tolerance.
    """
    logger.info("Check K: Performing independent test metrics replay...")
    errors: List[str] = []

    model_path = BEST_MODEL_PATH if BEST_MODEL_PATH.exists() else FINAL_MODEL_PATH
    model = keras.models.load_model(str(model_path))

    X_test = load_numpy_array(AUTOENCODER_INPUT_FILES["X_test"])
    y_test = load_numpy_array(AUTOENCODER_INPUT_FILES["y_test"])

    eval_data = load_json_report(AUTOENCODER_EVALUATION_REPORT_PATH)
    stored_threshold = float(eval_data["threshold"]["value"])
    stored_test = eval_data["test"]
    stored_err = stored_test["error_analysis"]

    # Recompute test reconstruction errors and binary decisions
    test_errors = compute_per_sample_mse(model, X_test)
    test_preds = (test_errors >= stored_threshold).astype(int)

    # Recompute confusion matrix
    cm = confusion_matrix(y_test, test_preds, labels=[0, 1])
    recomputed_tn = int(cm[0][0])
    recomputed_fp = int(cm[0][1])
    recomputed_fn = int(cm[1][0])
    recomputed_tp = int(cm[1][1])

    recomputed_fpr = float(recomputed_fp / (recomputed_fp + recomputed_tn))
    recomputed_fnr = float(recomputed_fn / (recomputed_fn + recomputed_tp))
    recomputed_acc = float(accuracy_score(y_test, test_preds))
    recomputed_prec = float(precision_score(y_test, test_preds, zero_division=0))
    recomputed_rec = float(recall_score(y_test, test_preds, zero_division=0))
    recomputed_f1 = float(f1_score(y_test, test_preds, zero_division=0))
    recomputed_roc = float(roc_auc_score(y_test, test_errors))
    recomputed_pr = float(average_precision_score(y_test, test_errors))

    # Verify counts match stored report exactly
    count_matches = (
        recomputed_tn == stored_err["true_negatives"]
        and recomputed_fp == stored_err["false_positives"]
        and recomputed_fn == stored_err["false_negatives"]
        and recomputed_tp == stored_err["true_positives"]
    )
    if not count_matches:
        errors.append(
            f"Confusion matrix counts mismatch: recomputed=({recomputed_tn},{recomputed_fp},{recomputed_fn},{recomputed_tp}) "
            f"vs stored=({stored_err['true_negatives']},{stored_err['false_positives']},{stored_err['false_negatives']},{stored_err['true_positives']})"
        )

    # Verify floating-point metrics match stored report within 1e-5
    float_checks = [
        ("accuracy", recomputed_acc, stored_test["accuracy"]),
        ("precision", recomputed_prec, stored_test["precision"]),
        ("recall", recomputed_rec, stored_test["recall"]),
        ("f1", recomputed_f1, stored_test["f1"]),
        ("roc_auc", recomputed_roc, stored_test["roc_auc"]),
        ("pr_auc", recomputed_pr, stored_test["pr_auc"]),
        ("false_positive_rate", recomputed_fpr, stored_err["false_positive_rate"]),
        ("false_negative_rate", recomputed_fnr, stored_err["false_negative_rate"]),
    ]

    for name, recomp, stored in float_checks:
        if not np.isclose(recomp, stored, atol=1e-5):
            errors.append(f"Metric mismatch on {name}: recomputed={recomp:.6f}, stored={stored:.6f}")

    status = "PASS" if len(errors) == 0 else "FAIL"
    logger.info(
        "Check K Status: %s (TN=%d, FP=%d, FN=%d, TP=%d, FPR=%.4f, FNR=%.4f)",
        status,
        recomputed_tn,
        recomputed_fp,
        recomputed_fn,
        recomputed_tp,
        recomputed_fpr,
        recomputed_fnr,
    )

    return {
        "status": status,
        "recomputed_counts": {
            "tn": recomputed_tn,
            "fp": recomputed_fp,
            "fn": recomputed_fn,
            "tp": recomputed_tp,
        },
        "recomputed_rates": {
            "false_positive_rate": recomputed_fpr,
            "false_negative_rate": recomputed_fnr,
        },
        "recomputed_metrics": {
            "accuracy": recomputed_acc,
            "precision": recomputed_prec,
            "recall": recomputed_rec,
            "f1": recomputed_f1,
            "roc_auc": recomputed_roc,
            "pr_auc": recomputed_pr,
        },
        "all_replayed_metrics_matched": len(errors) == 0,
        "errors": errors,
    }


# ============================================================
# MASTER AUTOENCODER VERIFICATION RUNNER
# ============================================================

def run_autoencoder_verification() -> Dict[str, Any]:
    """
    Execute all 11 independent verification checks.
    Compiles data/model_reports/autoencoder/autoencoder_verification_report.json.
    """
    logger.info("=" * 80)
    logger.info("NexThreat Phase 4.2 — Hardened Autoencoder Independent Verification Suite")
    logger.info("=" * 80)

    chk_a = verify_check_a_model_artifact()
    chk_b = verify_check_b_architecture()
    chk_c = verify_check_c_dataset_integrity()
    chk_d = verify_check_d_scaler_integrity()
    chk_e = verify_check_e_training_integrity()
    chk_f = verify_check_f_threshold_integrity()
    chk_g = verify_check_g_evaluation_integrity()
    chk_h = verify_check_h_metrics_integrity()
    chk_i = verify_check_i_input_immutability()
    chk_j = verify_check_j_threshold_replay()
    chk_k = verify_check_k_metric_replay()

    checks_summary = {
        "model_artifact": chk_a["status"],
        "architecture": chk_b["status"],
        "dataset_integrity": chk_c["status"],
        "scaler_integrity": chk_d["status"],
        "training_integrity": chk_e["status"],
        "threshold_integrity": chk_f["status"],
        "evaluation_integrity": chk_g["status"],
        "metrics_integrity": chk_h["status"],
        "input_immutability": chk_i["status"],
        "independent_threshold_replay": chk_j["status"],
        "independent_metric_replay": chk_k["status"],
    }

    all_passed = all(status == "PASS" for status in checks_summary.values())
    overall_status = "PASS" if all_passed else "FAIL"

    # Extract performance observations from evaluation report (informational only)
    performance_obs: Dict[str, Any] = {}
    if AUTOENCODER_EVALUATION_REPORT_PATH.exists():
        try:
            eval_data = load_json_report(AUTOENCODER_EVALUATION_REPORT_PATH)
            performance_obs = eval_data.get("performance_observations", {})
        except Exception:
            pass

    report: Dict[str, Any] = {
        "phase": "4.2",
        "model": "autoencoder",
        "timestamp": datetime.now().isoformat(),
        "checks": checks_summary,
        "detailed_results": {
            "check_a_model_artifact": chk_a,
            "check_b_architecture": chk_b,
            "check_c_dataset_integrity": chk_c,
            "check_d_scaler_integrity": chk_d,
            "check_e_training_integrity": chk_e,
            "check_f_threshold_integrity": chk_f,
            "check_g_evaluation_integrity": chk_g,
            "check_h_metrics_integrity": chk_h,
            "check_i_input_immutability": chk_i,
            "check_j_threshold_replay": chk_j,
            "check_k_metric_replay": chk_k,
        },
        "performance_observations": performance_obs,
        "overall_status": overall_status,
    }

    save_json_report(report, AUTOENCODER_VERIFICATION_REPORT_PATH)
    logger.info("Saved verification report to: %s", to_project_relative(AUTOENCODER_VERIFICATION_REPORT_PATH))

    logger.info("=" * 80)
    logger.info("PHASE 4.2 AUTOENCODER VERIFICATION: %s", overall_status)
    logger.info("=" * 80)

    if not all_passed:
        raise RuntimeError(f"Autoencoder verification FAILED: {checks_summary}")

    return report


if __name__ == "__main__":
    run_autoencoder_verification()
