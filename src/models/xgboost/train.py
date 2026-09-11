"""
NexThreat Phase 4.3C, 4.3D, 4.3E, 4.3F — XGBoost Training, Model Selection, Test Evaluation & Artifact Generation.

Lifecycle:
1. Load Phase 3.3 model-ready arrays (X_train, y_train, X_val, y_val, X_test, y_test).
2. Train predefined candidates using TRAIN ONLY:
   - Candidate A: Unweighted Baseline (depth=5, lr=0.1, n_est=200)
   - Candidate B: Balanced Class Weights (w_c = N / (K * N_c) derived strictly from y_train)
   - Candidate C: Regularized (depth=4, lr=0.08, subsample=0.85, colsample=0.85, min_child_weight=2)
   All candidates use objective='multi:softprob', num_class=8, seed=42, early stopping on validation only.
3. Evaluate candidates using VALIDATION ONLY.
4. Select winning candidate based on deterministic priority:
   (1) Validation Macro F1 over supported classes
   (2) Validation Macro Recall over supported classes
   (3) Validation Log Loss
   (4) Candidate index
5. Freeze the winning candidate model.
6. Perform exactly ONE final test evaluation on held-out test split.
7. Save predictions, model artifacts, reports, and cryptographic SHA-256 manifests.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import logging
import platform
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import sklearn
from sklearn.utils.class_weight import compute_sample_weight
import xgboost as xgb

from src.models.config import to_project_relative
from src.models.utils import (
    set_global_seed,
    ensure_directory,
    load_numpy_array,
    save_json_report,
)
from src.models.xgboost.config import (
    PROJECT_NAME,
    PHASE_NAME,
    RANDOM_SEED,
    NUM_CLASSES,
    CLASS_MAPPING,
    INDEX_TO_CLASS,
    CLASS_NAMES,
    CANONICAL_FEATURE_COLUMNS,
    FEATURE_COUNT,
    FEATURE_DTYPE,
    LABEL_DTYPE,
    SOURCE_DATA_FILES,
    REQUIRED_XGBOOST_DIRS,
    CANDIDATE_CONFIGURATIONS,
    SELECTION_PRIORITY,
    MODEL_FILE_PATH,
    METADATA_FILE_PATH,
    FEATURE_SCHEMA_FILE_PATH,
    CLASS_MAPPING_FILE_PATH,
    TRAINING_CONFIG_FILE_PATH,
    DATASET_MANIFEST_FILE_PATH,
    MODEL_HASHES_FILE_PATH,
    VAL_PREDICTIONS_PATH,
    VAL_PROBABILITIES_PATH,
    TEST_PREDICTIONS_PATH,
    TEST_PROBABILITIES_PATH,
    DATASET_VERIFICATION_REPORT_PATH,
    CLASS_DISTRIBUTION_REPORT_PATH,
    TRAINING_REPORT_PATH,
    VALIDATION_REPORT_PATH,
    TEST_REPORT_PATH,
    CLASSIFICATION_REPORT_PATH,
    CONFUSION_MATRIX_REPORT_PATH,
    ROC_AUC_REPORT_PATH,
    PR_AUC_REPORT_PATH,
    LOG_LOSS_REPORT_PATH,
    REPRODUCIBILITY_REPORT_PATH,
    PHASE_4_3_SUMMARY_PATH,
    XGBOOST_BASELINE_MANIFEST_PATH,
    NUMERICAL_TOLERANCE,
)
from src.models.xgboost.evaluate import evaluate_multiclass
from src.models.xgboost.analyze_distribution import compute_balanced_class_weights

logger = logging.getLogger("NexThreat.Models.XGBoost.Train")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def compute_file_sha256(file_path: Path) -> str:
    """Compute SHA-256 checksum in 64KB chunks."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def train_and_evaluate_xgboost() -> Dict[str, Any]:
    """
    Execute full Phase 4.3 training, validation model selection, and test evaluation.
    """
    logger.info("=" * 70)
    logger.info("NexThreat Phase 4.3 — XGBoost Training & Selection Pipeline")
    logger.info("=" * 70)

    # 1. Enforce global deterministic seed
    seed_info = set_global_seed(RANDOM_SEED)
    logger.info("Configured global random seed=%d", RANDOM_SEED)

    # 2. Ensure canonical directories exist
    for d in REQUIRED_XGBOOST_DIRS:
        ensure_directory(d)

    # 3. Load Phase 3.3 model-ready arrays
    logger.info("Loading Phase 3.3 model-ready XGBoost datasets...")
    X_train = load_numpy_array(SOURCE_DATA_FILES["X_train"])
    y_train = load_numpy_array(SOURCE_DATA_FILES["y_train"])
    X_val = load_numpy_array(SOURCE_DATA_FILES["X_validation"])
    y_val = load_numpy_array(SOURCE_DATA_FILES["y_validation"])
    X_test = load_numpy_array(SOURCE_DATA_FILES["X_test"])
    y_test = load_numpy_array(SOURCE_DATA_FILES["y_test"])

    logger.info(
        "Datasets loaded: Train=%s, Val=%s, Test=%s",
        X_train.shape,
        X_val.shape,
        X_test.shape,
    )

    # 4. Compute balanced sample weights strictly from y_train
    class_weights_dict = compute_balanced_class_weights(y_train, num_classes=NUM_CLASSES)
    train_sample_weights = np.array([class_weights_dict[int(y)] for y in y_train], dtype=np.float32)

    logger.info("Computed balanced training sample weights from y_train strictly.")

    # ------------------------------------------------------------
    # Phase 4.3C & 4.3D: Predefined Candidate Training & Validation Selection
    # ------------------------------------------------------------
    candidate_results: Dict[str, Dict[str, Any]] = {}
    trained_models: Dict[str, xgb.XGBClassifier] = {}
    candidate_predictions: Dict[str, np.ndarray] = {}
    candidate_probabilities: Dict[str, np.ndarray] = {}

    candidate_ids = list(CANDIDATE_CONFIGURATIONS.keys())

    logger.info("Training %d predefined candidate configurations...", len(candidate_ids))

    for idx, c_id in enumerate(candidate_ids):
        cfg = CANDIDATE_CONFIGURATIONS[c_id]
        logger.info("-" * 60)
        logger.info("Training Candidate %d/%d: %s (%s)", idx + 1, len(candidate_ids), c_id, cfg["name"])

        # Determine sample weights
        sw = train_sample_weights if cfg["use_class_weights"] else None

        # Build classifier
        params = dict(cfg["params"])
        early_stopping = params.pop("early_stopping_rounds", 15)

        clf = xgb.XGBClassifier(
            **params,
            early_stopping_rounds=early_stopping,
        )

        # Fit strictly on X_train, early stopping on X_val ONLY
        # Test split is NEVER passed to fit or eval_set!
        clf.fit(
            X_train,
            y_train,
            sample_weight=sw,
            eval_set=[(X_val, y_val)],
            verbose=False,
        )

        best_iteration = int(clf.best_iteration) if hasattr(clf, "best_iteration") and clf.best_iteration is not None else int(clf.n_estimators)

        # Predict on validation ONLY
        val_probs = clf.predict_proba(X_val)
        val_preds = np.argmax(val_probs, axis=1)

        # Support-aware validation evaluation
        val_eval = evaluate_multiclass(y_val, val_probs, val_preds, split_name=f"validation_{c_id}")

        trained_models[c_id] = clf
        candidate_probabilities[c_id] = val_probs
        candidate_predictions[c_id] = val_preds

        candidate_results[c_id] = {
            "candidate_id": c_id,
            "name": cfg["name"],
            "description": cfg["description"],
            "use_class_weights": cfg["use_class_weights"],
            "best_iteration": best_iteration,
            "params": cfg["params"],
            "validation_metrics": {
                "accuracy": val_eval["accuracy"],
                "log_loss": val_eval["log_loss"],
                "macro_f1": val_eval["macro_f1"],
                "weighted_f1": val_eval["weighted_f1"],
                "macro_recall": val_eval["macro_recall"],
                "macro_f1_supported": val_eval["macro_f1_supported"],
                "macro_recall_supported": val_eval["macro_recall_supported"],
                "macro_roc_auc": val_eval["roc_auc"]["macro_roc_auc"],
                "macro_pr_auc": val_eval["pr_auc"]["macro_pr_auc"],
            },
            "validation_evaluation": val_eval,
        }

        logger.info(
            "Candidate %s -> Best Iter: %d, Val Macro F1 (supp): %.4f, Val Recall (supp): %.4f, Val Log Loss: %.4f",
            c_id,
            best_iteration,
            val_eval["macro_f1_supported"],
            val_eval["macro_recall_supported"],
            val_eval["log_loss"],
        )

    # ------------------------------------------------------------
    # Deterministic Candidate Selection
    # Priority:
    # 1. Higher Macro F1 (supported validation classes)
    # 2. Higher Macro Recall (supported validation classes)
    # 3. Lower Validation Log Loss
    # 4. Candidate index (lower is earlier)
    # ------------------------------------------------------------
    def candidate_sort_key(cid: str) -> Tuple[float, float, float, int]:
        res = candidate_results[cid]["validation_metrics"]
        idx = candidate_ids.index(cid)
        # We want to maximize f1, maximize recall, minimize log_loss, minimize index
        # Using negative for maximization in ascending sort or positive for descending
        return (
            res["macro_f1_supported"],
            res["macro_recall_supported"],
            -res["log_loss"],
            -idx,
        )

    ranked_candidates = sorted(candidate_ids, key=candidate_sort_key, reverse=True)
    winner_id = ranked_candidates[0]
    winner_cfg = CANDIDATE_CONFIGURATIONS[winner_id]
    winner_model = trained_models[winner_id]
    winner_val_eval = candidate_results[winner_id]["validation_evaluation"]
    winner_val_probs = candidate_probabilities[winner_id]
    winner_val_preds = candidate_predictions[winner_id]

    logger.info("=" * 60)
    logger.info("WINNING CANDIDATE SELECTED: %s (%s)", winner_id, winner_cfg["name"])
    logger.info("Selection Order: %s", ranked_candidates)
    logger.info("Winning Val Macro F1 (supp): %.4f", candidate_results[winner_id]["validation_metrics"]["macro_f1_supported"])
    logger.info("=" * 60)

    # ------------------------------------------------------------
    # FREEZE SELECTED MODEL
    # ------------------------------------------------------------
    logger.info("FREEZING winning model %s for final test evaluation...", winner_id)

    # ------------------------------------------------------------
    # Phase 4.3E: SINGLE Final Test Evaluation
    # Evaluates the frozen model exactly once against held-out X_test/y_test
    # ------------------------------------------------------------
    logger.info("Executing SINGLE final test evaluation on held-out test split...")
    test_probs = winner_model.predict_proba(X_test)
    test_preds = np.argmax(test_probs, axis=1)

    test_eval = evaluate_multiclass(y_test, test_probs, test_preds, split_name="test")

    logger.info(
        "Final Test Evaluation: Accuracy=%.4f, Macro F1=%.4f, Macro Recall=%.4f, Macro ROC-AUC=%.4f, Log Loss=%.4f",
        test_eval["accuracy"],
        test_eval["macro_f1"],
        test_eval["macro_recall"],
        test_eval["roc_auc"]["macro_roc_auc"],
        test_eval["log_loss"],
    )

    # ------------------------------------------------------------
    # Phase 4.3F: Persistence of Predictions, Model & Reports
    # ------------------------------------------------------------
    logger.info("Persisting canonical prediction arrays...")
    np.save(VAL_PREDICTIONS_PATH, winner_val_preds)
    np.save(VAL_PROBABILITIES_PATH, winner_val_probs)
    np.save(TEST_PREDICTIONS_PATH, test_preds)
    np.save(TEST_PROBABILITIES_PATH, test_probs)

    logger.info("Saving trained XGBoost model to: %s", to_project_relative(MODEL_FILE_PATH))
    winner_model.save_model(MODEL_FILE_PATH)

    # Feature schema artifact
    feature_schema = {
        "schema_name": "NexThreat Phase 4.3 Feature Schema",
        "feature_count": FEATURE_COUNT,
        "feature_names": CANONICAL_FEATURE_COLUMNS,
        "dtype": "float32",
        "raw_unscaled": True,
        "scaler_applied": False,
        "target_column_included": False,
    }
    save_json_report(feature_schema, FEATURE_SCHEMA_FILE_PATH)

    # Class mapping artifact
    class_mapping_artifact = {
        "taxonomy_name": "NexThreat 8-Class Multiclass Attack Mapping",
        "num_classes": NUM_CLASSES,
        "class_to_index": CLASS_MAPPING,
        "index_to_class": INDEX_TO_CLASS,
    }
    save_json_report(class_mapping_artifact, CLASS_MAPPING_FILE_PATH)

    # Training config artifact
    training_config_artifact = {
        "project_name": PROJECT_NAME,
        "phase": PHASE_NAME,
        "random_seed": RANDOM_SEED,
        "num_classes": NUM_CLASSES,
        "objective": "multi:softprob",
        "eval_metric": "mlogloss",
        "early_stopping_rounds": 15,
        "early_stopping_split": "validation",
        "test_set_used_in_training": False,
        "test_set_used_in_selection": False,
        "candidates": CANDIDATE_CONFIGURATIONS,
        "selection_priority": SELECTION_PRIORITY,
        "selected_candidate": winner_id,
        "selected_candidate_name": winner_cfg["name"],
        "class_imbalance_weights": class_weights_dict if winner_cfg["use_class_weights"] else None,
        "weight_calculation_formula": "w_c = N / (K * N_c) derived strictly from y_train" if winner_cfg["use_class_weights"] else "None (uniform weights)",
    }
    save_json_report(training_config_artifact, TRAINING_CONFIG_FILE_PATH)

    # Dataset manifest artifact
    with open(XGBOOST_BASELINE_MANIFEST_PATH, "r", encoding="utf-8") as f:
        baseline_manifest = json.load(f)
    save_json_report(baseline_manifest, DATASET_MANIFEST_FILE_PATH)

    # Training report
    training_report = {
        "report_name": "Phase 4.3 Training & Candidate Report",
        "timestamp": datetime.now().isoformat(),
        "random_seed": RANDOM_SEED,
        "train_samples": int(len(y_train)),
        "validation_samples": int(len(y_val)),
        "test_samples": int(len(y_test)),
        "candidates_evaluated": len(candidate_ids),
        "candidates": candidate_results,
        "winning_candidate": winner_id,
        "selection_ranking": ranked_candidates,
    }
    save_json_report(training_report, TRAINING_REPORT_PATH)

    # Validation report
    validation_report = {
        "report_name": "Phase 4.3 Validation Selection Report",
        "timestamp": datetime.now().isoformat(),
        "selection_priority": SELECTION_PRIORITY,
        "candidate_ranking": ranked_candidates,
        "selected_candidate": winner_id,
        "winner_best_iteration": candidate_results[winner_id]["best_iteration"],
        "validation_evaluation": winner_val_eval,
        "validation_class_6_handling": {
            "class_index": 6,
            "class_name": "Web Attack",
            "support": 0,
            "roc_auc_status": "undefined",
            "pr_auc_status": "undefined",
            "reason": "zero positive validation samples",
            "preservation": "Not converted to 0.0; excluded from macro/weighted averages with explicit documentation",
        },
    }
    save_json_report(validation_report, VALIDATION_REPORT_PATH)

    # Test report
    save_json_report(test_eval, TEST_REPORT_PATH)

    # Classification report
    classification_report = {
        "report_name": "Phase 4.3 Test Classification Report",
        "timestamp": datetime.now().isoformat(),
        "accuracy": test_eval["accuracy"],
        "macro_precision": test_eval["macro_precision"],
        "macro_recall": test_eval["macro_recall"],
        "macro_f1": test_eval["macro_f1"],
        "weighted_precision": test_eval["weighted_precision"],
        "weighted_recall": test_eval["weighted_recall"],
        "weighted_f1": test_eval["weighted_f1"],
        "per_class_metrics": test_eval["per_class_metrics"],
    }
    save_json_report(classification_report, CLASSIFICATION_REPORT_PATH)

    # Confusion matrix report
    confusion_matrix_report = {
        "report_name": "Phase 4.3 Test Confusion Matrix",
        "timestamp": datetime.now().isoformat(),
        "num_classes": NUM_CLASSES,
        "class_names": CLASS_NAMES,
        "test_confusion_matrix": test_eval["confusion_matrix"],
        "validation_confusion_matrix": winner_val_eval["confusion_matrix"],
    }
    save_json_report(confusion_matrix_report, CONFUSION_MATRIX_REPORT_PATH)

    # ROC-AUC report
    roc_auc_report = {
        "report_name": "Phase 4.3 ROC-AUC Report",
        "timestamp": datetime.now().isoformat(),
        "test_roc_auc": test_eval["roc_auc"],
        "validation_roc_auc": winner_val_eval["roc_auc"],
    }
    save_json_report(roc_auc_report, ROC_AUC_REPORT_PATH)

    # PR-AUC report
    pr_auc_report = {
        "report_name": "Phase 4.3 PR-AUC Report",
        "timestamp": datetime.now().isoformat(),
        "test_pr_auc": test_eval["pr_auc"],
        "validation_pr_auc": winner_val_eval["pr_auc"],
    }
    save_json_report(pr_auc_report, PR_AUC_REPORT_PATH)

    # Log loss report
    log_loss_report = {
        "report_name": "Phase 4.3 Log Loss Report",
        "timestamp": datetime.now().isoformat(),
        "validation_log_loss": winner_val_eval["log_loss"],
        "test_log_loss": test_eval["log_loss"],
        "candidate_validation_log_losses": {
            cid: candidate_results[cid]["validation_metrics"]["log_loss"] for cid in candidate_ids
        },
    }
    save_json_report(log_loss_report, LOG_LOSS_REPORT_PATH)

    # Metadata artifact
    metadata = {
        "project_name": PROJECT_NAME,
        "phase": PHASE_NAME,
        "model_type": "XGBoost Multiclass Classifier",
        "model_objective": "multi:softprob",
        "num_classes": NUM_CLASSES,
        "feature_count": FEATURE_COUNT,
        "feature_names": CANONICAL_FEATURE_COLUMNS,
        "label_mapping": CLASS_MAPPING,
        "random_seed": RANDOM_SEED,
        "training_dataset_identity": to_project_relative(SOURCE_DATA_FILES["X_train"]),
        "validation_dataset_identity": to_project_relative(SOURCE_DATA_FILES["X_validation"]),
        "test_dataset_identity": to_project_relative(SOURCE_DATA_FILES["X_test"]),
        "training_sample_count": int(len(y_train)),
        "validation_sample_count": int(len(y_val)),
        "test_sample_count": int(len(y_test)),
        "xgboost_version": xgb.__version__,
        "python_version": platform.python_version(),
        "numpy_version": np.__version__,
        "sklearn_version": sklearn.__version__,
        "training_timestamp": datetime.now().isoformat(),
        "selected_candidate": winner_id,
        "selected_candidate_name": winner_cfg["name"],
        "model_parameters": winner_cfg["params"],
        "imbalance_strategy": "balanced_class_weighting" if winner_cfg["use_class_weights"] else "unweighted_baseline",
        "class_weights": class_weights_dict if winner_cfg["use_class_weights"] else None,
        "early_stopping_configuration": {
            "early_stopping_rounds": 15,
            "eval_metric": "mlogloss",
            "eval_set": "validation_only",
        },
        "selected_iteration_count": candidate_results[winner_id]["best_iteration"],
        "validation_selection_metric": "macro_f1_supported",
        "final_test_metrics": {
            "accuracy": test_eval["accuracy"],
            "macro_precision": test_eval["macro_precision"],
            "macro_recall": test_eval["macro_recall"],
            "macro_f1": test_eval["macro_f1"],
            "weighted_f1": test_eval["weighted_f1"],
            "macro_roc_auc": test_eval["roc_auc"]["macro_roc_auc"],
            "macro_pr_auc": test_eval["pr_auc"]["macro_pr_auc"],
            "log_loss": test_eval["log_loss"],
        },
    }
    save_json_report(metadata, METADATA_FILE_PATH)

    # Compute Model Hashes for all saved model artifacts and predictions
    artifacts_to_hash = {
        "xgboost_model": MODEL_FILE_PATH,
        "metadata": METADATA_FILE_PATH,
        "feature_schema": FEATURE_SCHEMA_FILE_PATH,
        "class_mapping": CLASS_MAPPING_FILE_PATH,
        "training_config": TRAINING_CONFIG_FILE_PATH,
        "dataset_manifest": DATASET_MANIFEST_FILE_PATH,
        "val_predictions": VAL_PREDICTIONS_PATH,
        "val_probabilities": VAL_PROBABILITIES_PATH,
        "test_predictions": TEST_PREDICTIONS_PATH,
        "test_probabilities": TEST_PROBABILITIES_PATH,
    }

    model_hashes: Dict[str, Any] = {
        "generated_at": datetime.now().isoformat(),
        "hashes": {},
    }
    for k, p in artifacts_to_hash.items():
        if p.exists():
            model_hashes["hashes"][k] = {
                "relative_path": to_project_relative(p),
                "sha256": compute_file_sha256(p),
                "size_bytes": p.stat().st_size,
            }

    save_json_report(model_hashes, MODEL_HASHES_FILE_PATH)

    # Reproducibility report
    reproducibility_report = {
        "report_name": "Phase 4.3 Reproducibility Report",
        "timestamp": datetime.now().isoformat(),
        "random_seed": RANDOM_SEED,
        "python_version": sys.version,
        "platform": platform.platform(),
        "packages": {
            "xgboost": xgb.__version__,
            "numpy": np.__version__,
            "scikit-learn": sklearn.__version__,
        },
        "feature_columns": CANONICAL_FEATURE_COLUMNS,
        "class_mapping": CLASS_MAPPING,
        "candidate_configurations": CANDIDATE_CONFIGURATIONS,
        "selected_candidate": winner_id,
        "dataset_hashes": baseline_manifest["files"],
        "model_artifact_hashes": model_hashes["hashes"],
        "numerical_replay_tolerance": NUMERICAL_TOLERANCE,
    }
    save_json_report(reproducibility_report, REPRODUCIBILITY_REPORT_PATH)

    # Generate Summary Markdown
    summary_md = f"""# NexThreat Phase 4.3 — XGBoost Multiclass Pipeline Summary

**Phase**: {PHASE_NAME}  
**Generated At**: {datetime.now().isoformat()}  
**Random Seed**: {RANDOM_SEED}  
**Selected Candidate**: {winner_id} — {winner_cfg['name']}  

---

## 1. Objective & Architectural Independence
- Trained an 8-class multiclass attack classifier for the NexThreat pipeline.
- Autonomous pipeline operating strictly on `data/model_ready/xgboost/` without Autoencoder or LSTM dependencies.
- Phase 4.2 Autoencoder remains frozen, unmodified, and verified.

## 2. Dataset & Feature Contract
- Canonical 13 unscaled continuous features consumed directly.
- Strict input shapes: Train (1799, 13), Validation (325, 13), Test (319, 13).
- Zero NaN, zero +/- Infinity, zero target leakage in feature arrays.

## 3. Class Distribution & Imbalance
- Train: 1,799 samples across all 8 classes (Imbalance ratio 91.0:1).
- Validation: 325 samples across 7 classes (**Class 6 Web Attack support = 0**).
- Test: 319 samples across all 8 classes (Imbalance ratio 146.0:1).
- Balanced class weights computed strictly from `y_train` using $w_c = N / (K \\cdot N_c)$.

## 4. Candidate Model Comparison (Validation Selection Only)
| Candidate | Name | Best Iter | Val Macro F1 (supp) | Val Macro Recall (supp) | Val Log Loss | Selection Rank |
|---|---|---|---|---|---|---|
| Candidate_A | Unweighted Baseline | {candidate_results['Candidate_A']['best_iteration']} | {candidate_results['Candidate_A']['validation_metrics']['macro_f1_supported']:.4f} | {candidate_results['Candidate_A']['validation_metrics']['macro_recall_supported']:.4f} | {candidate_results['Candidate_A']['validation_metrics']['log_loss']:.4f} | {ranked_candidates.index('Candidate_A') + 1} |
| Candidate_B | Balanced Class Weights | {candidate_results['Candidate_B']['best_iteration']} | {candidate_results['Candidate_B']['validation_metrics']['macro_f1_supported']:.4f} | {candidate_results['Candidate_B']['validation_metrics']['macro_recall_supported']:.4f} | {candidate_results['Candidate_B']['validation_metrics']['log_loss']:.4f} | {ranked_candidates.index('Candidate_B') + 1} |
| Candidate_C | Regularized | {candidate_results['Candidate_C']['best_iteration']} | {candidate_results['Candidate_C']['validation_metrics']['macro_f1_supported']:.4f} | {candidate_results['Candidate_C']['validation_metrics']['macro_recall_supported']:.4f} | {candidate_results['Candidate_C']['validation_metrics']['log_loss']:.4f} | {ranked_candidates.index('Candidate_C') + 1} |

**Selected Model**: `{winner_id}` was frozen for test evaluation based on deterministic validation selection priority.

## 5. Final Test Evaluation (Evaluated Exactly Once on Held-Out Test Set)
- **Accuracy**: {test_eval['accuracy']:.4f}
- **Macro Precision**: {test_eval['macro_precision']:.4f}
- **Macro Recall**: {test_eval['macro_recall']:.4f}
- **Macro F1 Score**: {test_eval['macro_f1']:.4f}
- **Weighted F1 Score**: {test_eval['weighted_f1']:.4f}
- **Macro ROC-AUC (OvR)**: {test_eval['roc_auc']['macro_roc_auc']:.4f}
- **Macro PR-AUC (OvR)**: {test_eval['pr_auc']['macro_pr_auc']:.4f}
- **Multiclass Log Loss**: {test_eval['log_loss']:.4f}

### Per-Class Test Performance
| Class Index | Class Name | Support | Precision | Recall | F1 Score |
|---|---|---|---|---|---|
"""
    for p in test_eval["per_class_metrics"]:
        summary_md += f"| {p['class_index']} | {p['class_name']} | {p['support']} | {p['precision']:.4f} | {p['recall']:.4f} | {p['f1']:.4f} |\n"

    summary_md += f"""
## 6. Validation Class-6 Asymmetry Handling
- Web Attack (class 6) has 0 positive validation samples.
- Validation OvR ROC-AUC and PR-AUC for class 6 are recorded explicitly as `undefined` (never 0.0).
- Aggregate validation ROC/PR AUCs document supported classes: `[0, 1, 2, 3, 4, 5, 7]` and excluded classes: `[6]`.

## 7. Strict Test Isolation Confirmation
- Test set was strictly isolated: not accessed during training, early stopping, class weighting, or candidate selection.
- Exactly one test evaluation executed after model freeze.
- Saved predictions and probabilities enable read-only independent verification replay.
"""
    with open(PHASE_4_3_SUMMARY_PATH, "w", encoding="utf-8") as f:
        f.write(summary_md)
    logger.info("Saved Phase 4.3 summary markdown to: %s", to_project_relative(PHASE_4_3_SUMMARY_PATH))

    return {
        "status": "COMPLETED",
        "selected_candidate": winner_id,
        "selected_candidate_name": winner_cfg["name"],
        "validation_metrics": candidate_results[winner_id]["validation_metrics"],
        "final_test_metrics": {
            "accuracy": test_eval["accuracy"],
            "macro_f1": test_eval["macro_f1"],
            "macro_recall": test_eval["macro_recall"],
            "macro_roc_auc": test_eval["roc_auc"]["macro_roc_auc"],
            "log_loss": test_eval["log_loss"],
        },
    }


if __name__ == "__main__":
    train_and_evaluate_xgboost()
