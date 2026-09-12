"""
NexThreat Phase 4.4 — LSTM Model Training & Lifecycle Orchestrator.

Orchestrates the 7 deterministic stages:
1. Candidate Training (Candidates A, B, C with balanced y_train class weights).
2. Validation-Only Candidate Selection (4-tier deterministic tie-break).
3. Validation Threshold Optimization Sweep (Attack Recall -> Attack F1 -> Min FPR -> Min Thresh).
4. Model Freeze.
5. Threshold Freeze (threshold_config.json).
6. Single Methodological Test Evaluation (held-out X_test evaluated strictly once).
7. Artifact Finalization (byte-for-byte scaler copy, separate .npy predictions, clean reports, SHA-256 hashes).
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import logging
from pathlib import Path
import shutil
from typing import Any, Dict, List, Tuple

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

from src.models.config import to_project_relative
from src.models.lstm.config import (
    LSTM_FEATURES,
    FEATURE_COUNT,
    SEQUENCE_LENGTH,
    FORECAST_HORIZON,
    RANDOM_SEED,
    MAX_EPOCHS,
    BATCH_SIZE,
    EARLY_STOPPING_PATIENCE,
    EARLY_STOPPING_MONITOR,
    EARLY_STOPPING_MODE,
    RESTORE_BEST_WEIGHTS,
    CANDIDATES,
    CANDIDATE_TIE_BREAK_POLICY,
    THRESHOLD_CANDIDATES,
    THRESHOLD_TIE_BREAK_POLICY,
    EXPECTED_SCALER_SHA256,
    INPUT_FILES,
    AUTHORITATIVE_SCALER_PATH,
    REQUIRED_LSTM_DIRS,
    LSTM_CHECKPOINTS_DIR,
    FINAL_MODEL_PATH,
    MODEL_SCALER_PATH,
    VAL_PREDICTIONS_PATH,
    VAL_PROBABILITIES_PATH,
    TEST_PREDICTIONS_PATH,
    TEST_PROBABILITIES_PATH,
    TRAINING_REPORT_PATH,
    THRESHOLD_REPORT_PATH,
    THRESHOLD_CONFIG_PATH,
    TEST_REPORT_PATH,
    MODEL_HASHES_PATH,
    PHASE_4_4_SUMMARY_PATH,
)
from src.models.lstm.model import (
    build_lstm_candidate,
    set_deterministic_seeds,
)
from src.models.lstm.evaluate import (
    evaluate_binary_forecasting,
    run_threshold_sweep,
)

logger = logging.getLogger("NexThreat.Models.LSTM.Train")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def compute_sha256(path: Path) -> str:
    """Calculate SHA-256 hash using chunked binary reading."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_balanced_weights(y_train: np.ndarray) -> Dict[int, float]:
    """
    Compute balanced class weights exclusively from y_train (Clarification 2 & Guarantee 12):
    w_c = N / (2 * N_c)
    """
    total = len(y_train)
    n_0 = int(np.sum(y_train == 0))
    n_1 = int(np.sum(y_train == 1))
    w_0 = float(total / (2.0 * n_0))
    w_1 = float(total / (2.0 * n_1))
    logger.info(
        "Balanced class weights derived strictly from y_train (N=%d, N0=%d, N1=%d): w0=%.4f, w1=%.4f",
        total,
        n_0,
        n_1,
        w_0,
        w_1,
    )
    return {0: w_0, 1: w_1}


def train_and_evaluate_pipeline() -> Dict[str, Any]:
    """Execute complete deterministic 7-stage LSTM training pipeline."""
    logger.info("================================================================================")
    logger.info("NexThreat Phase 4.4 — LSTM Attack Forecasting Pipeline Execution")
    logger.info("================================================================================")

    # Initialize required directories
    for d in REQUIRED_LSTM_DIRS:
        d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------
    # STAGE 1: TRAIN CANDIDATES
    # ------------------------------------------------------------
    logger.info("--> STAGE 1: Training candidate architectures on pre-scaled training tensors...")

    X_train = np.load(INPUT_FILES["X_train"])
    y_train = np.load(INPUT_FILES["y_train"])
    X_val = np.load(INPUT_FILES["X_validation"])
    y_val = np.load(INPUT_FILES["y_validation"])

    logger.info("Loaded pre-scaled training tensors: X_train=%s, y_train=%s", X_train.shape, y_train.shape)
    logger.info("Loaded pre-scaled validation tensors: X_val=%s, y_val=%s", X_val.shape, y_val.shape)
    logger.info("Authoritative scaler policy: Zero transforms, zero refitting, zero double-scaling.")

    class_weights = compute_balanced_weights(y_train)

    candidate_records: Dict[str, Dict[str, Any]] = {}
    candidate_probs: Dict[str, np.ndarray] = {}
    candidate_models: Dict[str, keras.Model] = {}

    for cand_key, cand_cfg in CANDIDATES.items():
        logger.info("--- Training %s (index %d) ---", cand_cfg["name"], cand_cfg["index"])
        set_deterministic_seeds(RANDOM_SEED)

        model = build_lstm_candidate(cand_cfg, input_shape=(SEQUENCE_LENGTH, FEATURE_COUNT), model_name=cand_key)
        ckpt_path = LSTM_CHECKPOINTS_DIR / f"best_{cand_key}.keras"

        checkpoint_cb = ModelCheckpoint(
            filepath=str(ckpt_path),
            monitor=EARLY_STOPPING_MONITOR,
            mode=EARLY_STOPPING_MODE,
            save_best_only=True,
            verbose=0,
        )
        early_stop_cb = EarlyStopping(
            monitor=EARLY_STOPPING_MONITOR,
            mode=EARLY_STOPPING_MODE,
            patience=EARLY_STOPPING_PATIENCE,
            restore_best_weights=RESTORE_BEST_WEIGHTS,
            verbose=0,
        )

        history = model.fit(
            X_train,
            y_train,
            validation_data=(X_val, y_val),
            epochs=MAX_EPOCHS,
            batch_size=BATCH_SIZE,
            class_weight=class_weights,
            callbacks=[checkpoint_cb, early_stop_cb],
            verbose=0,
        )

        epochs_trained = len(history.history["loss"])
        # Load authoritative best checkpoint to ensure weights match saved artifact
        best_model = keras.models.load_model(ckpt_path)
        candidate_models[cand_key] = best_model

        val_probs = best_model.predict(X_val, batch_size=BATCH_SIZE, verbose=0).ravel()
        candidate_probs[cand_key] = val_probs

        val_eval_default = evaluate_binary_forecasting(y_val, val_probs, threshold=0.5)

        val_loss = float(history.history["val_loss"][-1])
        val_acc = float(history.history["val_accuracy"][-1])
        min_val_loss = float(min(history.history["val_loss"]))

        record = {
            "candidate_id": cand_key,
            "index": cand_cfg["index"],
            "name": cand_cfg["name"],
            "epochs_trained": epochs_trained,
            "final_val_loss": val_loss,
            "best_val_loss": min_val_loss,
            "final_val_accuracy": val_acc,
            "val_attack_f1": val_eval_default["attack_class_metrics"]["f1"],
            "val_attack_recall": val_eval_default["attack_class_metrics"]["recall"],
            "val_attack_precision": val_eval_default["attack_class_metrics"]["precision"],
            "val_fpr": val_eval_default["rates"]["fpr"],
            "checkpoint_path": to_project_relative(ckpt_path),
            "parameters": {k: v for k, v in cand_cfg.items() if k not in ["name", "index"]},
        }
        candidate_records[cand_key] = record

        logger.info(
            "%s finished in %d epochs: Best Val Loss=%.4f, Val Attack F1=%.4f, Val Attack Recall=%.4f",
            cand_key,
            epochs_trained,
            min_val_loss,
            record["val_attack_f1"],
            record["val_attack_recall"],
        )

    # ------------------------------------------------------------
    # STAGE 2: VALIDATION CANDIDATE SELECTION
    # ------------------------------------------------------------
    logger.info("--> STAGE 2: Evaluating validation-only candidate selection with 4-tier tie-break...")

    # Ranking key (Correction 6 & Guarantee 9):
    # 1. Higher Val Attack F1 (-val_attack_f1)
    # 2. Higher Val Attack Recall (-val_attack_recall)
    # 3. Lower Best Val Loss (+best_val_loss)
    # 4. Lower Candidate Index (+index)
    def candidate_ranking_key(cand: Dict[str, Any]) -> Tuple[float, float, float, int]:
        return (
            -round(cand["val_attack_f1"], 6),
            -round(cand["val_attack_recall"], 6),
            round(cand["best_val_loss"], 6),
            cand["index"],
        )

    sorted_candidates = sorted(candidate_records.values(), key=candidate_ranking_key)
    winning_candidate_record = sorted_candidates[0]
    winning_candidate_key = winning_candidate_record["candidate_id"]
    winning_model = candidate_models[winning_candidate_key]
    winning_val_probs = candidate_probs[winning_candidate_key]

    logger.info(
        "Winning candidate selected: %s (%s) [Attack F1=%.4f, Attack Recall=%.4f, Val Loss=%.4f]",
        winning_candidate_key,
        winning_candidate_record["name"],
        winning_candidate_record["val_attack_f1"],
        winning_candidate_record["val_attack_recall"],
        winning_candidate_record["best_val_loss"],
    )

    # ------------------------------------------------------------
    # STAGE 3: VALIDATION THRESHOLD SELECTION
    # ------------------------------------------------------------
    logger.info("--> STAGE 3: Executing validation threshold tuning sweep on %s probabilities...", winning_candidate_key)

    opt_threshold, val_opt_metrics, sweep_records = run_threshold_sweep(
        y_val, winning_val_probs, THRESHOLD_CANDIDATES
    )

    logger.info(
        "Optimal validation threshold selected: %.4f (Attack Recall=%.4f, Attack F1=%.4f, FPR=%.4f)",
        opt_threshold,
        val_opt_metrics["attack_class_metrics"]["recall"],
        val_opt_metrics["attack_class_metrics"]["f1"],
        val_opt_metrics["rates"]["fpr"],
    )

    # ------------------------------------------------------------
    # STAGE 4 & 5: MODEL FREEZE & THRESHOLD FREEZE
    # ------------------------------------------------------------
    logger.info("--> STAGE 4 & 5: Freezing model architecture, weights, and decision threshold...")

    freeze_timestamp = datetime.now().isoformat()
    threshold_config = {
        "selected_threshold": opt_threshold,
        "tie_break_policy": THRESHOLD_TIE_BREAK_POLICY,
        "source_candidate": winning_candidate_key,
        "evaluation_split": "validation",
        "frozen": True,
        "timestamp": freeze_timestamp,
    }
    with open(THRESHOLD_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(threshold_config, f, indent=4)
        f.write("\n")

    # ------------------------------------------------------------
    # STAGE 6: FINAL TEST EVALUATION
    # ------------------------------------------------------------
    logger.info("--> STAGE 6: Executing single methodological test evaluation on held-out test data...")

    X_test = np.load(INPUT_FILES["X_test"])
    y_test = np.load(INPUT_FILES["y_test"])

    test_probs = winning_model.predict(X_test, batch_size=BATCH_SIZE, verbose=0).ravel()
    test_metrics = evaluate_binary_forecasting(y_test, test_probs, threshold=opt_threshold)

    val_preds = (winning_val_probs >= opt_threshold).astype(np.int64)
    test_preds = (test_probs >= opt_threshold).astype(np.int64)

    logger.info(
        "Test evaluation complete: Accuracy=%.4f, Attack Recall=%.4f, Attack Precision=%.4f, Attack F1=%.4f, FPR=%.4f, ROC-AUC=%.4f",
        test_metrics["overall_metrics"]["accuracy"],
        test_metrics["attack_class_metrics"]["recall"],
        test_metrics["attack_class_metrics"]["precision"],
        test_metrics["attack_class_metrics"]["f1"],
        test_metrics["rates"]["fpr"],
        test_metrics["overall_metrics"]["roc_auc"],
    )

    # ------------------------------------------------------------
    # STAGE 7: ARTIFACT FINALIZATION
    # ------------------------------------------------------------
    logger.info("--> STAGE 7: Persisting models, predictions, scaler copy, reports, and SHA-256 hashes...")

    # Save final model
    winning_model.save(FINAL_MODEL_PATH)
    logger.info("Saved final model to: %s", to_project_relative(FINAL_MODEL_PATH))

    # Exact byte-for-byte scaler copy (Clarification 4)
    shutil.copyfile(AUTHORITATIVE_SCALER_PATH, MODEL_SCALER_PATH)
    scaler_copy_hash = compute_sha256(MODEL_SCALER_PATH)
    if scaler_copy_hash != EXPECTED_SCALER_SHA256:
        raise RuntimeError(f"Scaler copy SHA mismatch: exp={EXPECTED_SCALER_SHA256}, act={scaler_copy_hash}")
    logger.info("Saved byte-for-byte identical copy of scaler to: %s", to_project_relative(MODEL_SCALER_PATH))

    # Save dedicated prediction .npy arrays (Clarification 3)
    np.save(VAL_PREDICTIONS_PATH, val_preds)
    np.save(VAL_PROBABILITIES_PATH, winning_val_probs)
    np.save(TEST_PREDICTIONS_PATH, test_preds)
    np.save(TEST_PROBABILITIES_PATH, test_probs)
    logger.info("Saved validation and test predictions/probabilities to: %s", to_project_relative(VAL_PREDICTIONS_PATH.parent))

    # Save clean threshold report without raw array bloat (Clarification 3)
    threshold_report = {
        "report_name": "Phase 4.4 LSTM Validation Threshold Report",
        "timestamp": datetime.now().isoformat(),
        "selected_threshold": opt_threshold,
        "selection_policy": THRESHOLD_TIE_BREAK_POLICY,
        "winning_candidate": winning_candidate_key,
        "validation_metrics_at_selected_threshold": {
            "threshold": opt_threshold,
            "attack_recall": val_opt_metrics["attack_class_metrics"]["recall"],
            "attack_f1": val_opt_metrics["attack_class_metrics"]["f1"],
            "attack_precision": val_opt_metrics["attack_class_metrics"]["precision"],
            "fpr": val_opt_metrics["rates"]["fpr"],
            "fnr": val_opt_metrics["rates"]["fnr"],
            "accuracy": val_opt_metrics["overall_metrics"]["accuracy"],
            "confusion_matrix": val_opt_metrics["confusion_matrix"],
        },
        "threshold_sweep_records": sweep_records,
        "array_storage_locations": {
            "validation_probabilities": to_project_relative(VAL_PROBABILITIES_PATH),
            "validation_predictions": to_project_relative(VAL_PREDICTIONS_PATH),
            "ground_truth_validation_labels": to_project_relative(INPUT_FILES["y_validation"]),
        },
    }
    with open(THRESHOLD_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(threshold_report, f, indent=4)
        f.write("\n")

    # Save test report
    test_report_data = {
        "report_name": "Phase 4.4 LSTM Test Evaluation Report",
        "timestamp": datetime.now().isoformat(),
        "model": winning_candidate_key,
        "threshold": opt_threshold,
        "metrics": test_metrics,
        "predictions_file": to_project_relative(TEST_PREDICTIONS_PATH),
        "probabilities_file": to_project_relative(TEST_PROBABILITIES_PATH),
    }
    with open(TEST_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(test_report_data, f, indent=4)
        f.write("\n")

    # Save training report with full structural evidence
    training_report_data = {
        "report_name": "Phase 4.4 LSTM Training Report",
        "timestamp": datetime.now().isoformat(),
        "stage_lifecycle": {
            "stage_1_train_candidates": "COMPLETED",
            "stage_2_validation_candidate_selection": "COMPLETED",
            "stage_3_validation_threshold_selection": "COMPLETED",
            "stage_4_model_freeze": "COMPLETED",
            "stage_5_threshold_freeze": "COMPLETED",
            "stage_6_final_test_evaluation": "COMPLETED",
            "stage_7_artifact_finalization": "COMPLETED",
        },
        "model_architecture": {
            "winning_candidate": winning_candidate_key,
            "architecture_details": winning_candidate_record["parameters"],
            "input_shape": [SEQUENCE_LENGTH, FEATURE_COUNT],
            "feature_contract": LSTM_FEATURES,
        },
        "training_hyperparameters": {
            "max_epochs": MAX_EPOCHS,
            "batch_size": BATCH_SIZE,
            "patience": EARLY_STOPPING_PATIENCE,
            "random_seed": RANDOM_SEED,
            "loss_function": "binary_crossentropy",
            "optimizer": "adam",
        },
        "class_weighting": {
            "strategy": "balanced_from_y_train_strictly",
            "formula": "w_c = N / (2 * N_c)",
            "weights": class_weights,
            "sample_counts": {"total": len(y_train), "benign_0": int(np.sum(y_train == 0)), "attack_1": int(np.sum(y_train == 1))},
        },
        "candidate_evaluation_summary": sorted_candidates,
        "candidate_tie_break_policy": CANDIDATE_TIE_BREAK_POLICY,
        "selected_candidate": winning_candidate_key,
        "selected_threshold": opt_threshold,
    }
    with open(TRAINING_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(training_report_data, f, indent=4)
        f.write("\n")

    # Save model hashes
    artifacts_to_hash: Dict[str, Path] = {
        "lstm_model": FINAL_MODEL_PATH,
        "lstm_scaler": MODEL_SCALER_PATH,
        "validation_predictions": VAL_PREDICTIONS_PATH,
        "validation_probabilities": VAL_PROBABILITIES_PATH,
        "test_predictions": TEST_PREDICTIONS_PATH,
        "test_probabilities": TEST_PROBABILITIES_PATH,
        "training_report": TRAINING_REPORT_PATH,
        "threshold_report": THRESHOLD_REPORT_PATH,
        "threshold_config": THRESHOLD_CONFIG_PATH,
        "test_report": TEST_REPORT_PATH,
    }
    for cand_key in CANDIDATES:
        ckpt = LSTM_CHECKPOINTS_DIR / f"best_{cand_key}.keras"
        if ckpt.exists():
            artifacts_to_hash[f"checkpoint_{cand_key}"] = ckpt

    hashes_data = {
        "report_name": "Phase 4.4 LSTM Artifact SHA-256 Hashes",
        "timestamp": datetime.now().isoformat(),
        "hashes": {
            k: {
                "relative_path": to_project_relative(p),
                "sha256": compute_sha256(p),
                "size_bytes": p.stat().st_size,
            }
            for k, p in artifacts_to_hash.items()
        },
    }
    with open(MODEL_HASHES_PATH, "w", encoding="utf-8") as f:
        json.dump(hashes_data, f, indent=4)
        f.write("\n")

    # Save summary markdown
    summary_md = f"""# NexThreat Phase 4.4 — LSTM Attack Forecasting Summary

- **Status**: COMPLETED
- **Timestamp**: {datetime.now().isoformat()}
- **Selected Model**: {winning_candidate_record['name']} (`{winning_candidate_key}`)
- **Decision Threshold**: `{opt_threshold:.4f}`
- **Feature Contract**: 13 engineered sequential features (`flow_count` ... `syn_packet_ratio`)
- **Input Tensor Shape**: `(N, 10, 13)`
- **Lookback Windows**: 10 (windows $t-9 \\dots t$)
- **Forecast Horizon**: 1 (window $t+1$)

## Performance Summary

| Split | Metric | Value |
|---|---|---|
| **Validation** | Optimal Threshold | `{opt_threshold:.4f}` |
| **Validation** | Attack Recall | `{val_opt_metrics['attack_class_metrics']['recall']:.4f}` |
| **Validation** | Attack F1 | `{val_opt_metrics['attack_class_metrics']['f1']:.4f}` |
| **Validation** | FPR | `{val_opt_metrics['rates']['fpr']:.4f}` |
| **Validation** | Accuracy | `{val_opt_metrics['overall_metrics']['accuracy']:.4f}` |
| **Test** | Accuracy | `{test_metrics['overall_metrics']['accuracy']:.4f}` |
| **Test** | Attack Recall | `{test_metrics['attack_class_metrics']['recall']:.4f}` |
| **Test** | Attack Precision | `{test_metrics['attack_class_metrics']['precision']:.4f}` |
| **Test** | Attack F1 | `{test_metrics['attack_class_metrics']['f1']:.4f}` |
| **Test** | FPR | `{test_metrics['rates']['fpr']:.4f}` |
| **Test** | FNR | `{test_metrics['rates']['fnr']:.4f}` |
| **Test** | ROC-AUC | `{test_metrics['overall_metrics']['roc_auc']:.4f}` |
| **Test** | PR-AUC | `{test_metrics['overall_metrics']['pr_auc']:.4f}` |
"""
    with open(PHASE_4_4_SUMMARY_PATH, "w", encoding="utf-8") as f:
        f.write(summary_md)

    logger.info("Pipeline training complete. All Phase 4.4 artifacts successfully finalized.")
    return training_report_data


if __name__ == "__main__":
    train_and_evaluate_pipeline()
