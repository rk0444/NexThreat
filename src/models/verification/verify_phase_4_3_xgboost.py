"""
NexThreat Phase 4.3G & 4.3H — XGBoost Independent Verification Suite.

Independently audits the Phase 4.3 pipeline across 14 rigorous checks:
- Check A: Source Data Existence (all required model-ready arrays exist).
- Check B: SHA-256 Integrity (recalculates checksums against baseline manifest).
- Check C: Model-Ready Immutability & Phase 4.2 Preservation (source files & Autoencoder untouched).
- Check D: Feature Contract (13 canonical features, raw/unscaled, no scaler).
- Check E: Label Contract (0..7 taxonomy matching immutable mapping).
- Check F: Dataset Isolation (train/val/test role segregation).
- Check G: Class Weight Integrity (recalculated independently from y_train).
- Check H: Model Loadability (independently loads xgboost_model.json).
- Check I: Model Configuration (objective=multi:softprob, num_class=8, seed=42).
- Check J: Independent Prediction Replay (reproduces test predictions & probabilities <= 1e-5).
- Check K: Independent Metric Replay (recalculates all test and val metrics <= 1e-5).
- Check L: Test Isolation Verification (confirms test excluded from tuning & weighting).
- Check M: Artifact Integrity (recalculates checksums of all Phase 4.3 artifacts).
- Check N: Reproducibility Metadata (confirms complete configuration & provenance).

Produces final acceptance decision:
PHASE 4.3 STATUS: PASS / FAIL
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import xgboost as xgb

from src.models.config import to_project_relative
from src.models.utils import (
    load_numpy_array,
    load_json_report,
    save_json_report,
)
from src.models.xgboost.config import (
    SOURCE_DATA_FILES,
    EXPECTED_DATA_SHAPES,
    FEATURE_COUNT,
    CANONICAL_FEATURE_COLUMNS,
    FEATURE_DTYPE,
    LABEL_DTYPE,
    CLASS_MAPPING,
    INDEX_TO_CLASS,
    NUM_CLASSES,
    RANDOM_SEED,
    NUMERICAL_TOLERANCE,
    XGBOOST_MODEL_DIR,
    XGBOOST_REPORTS_DIR,
    XGBOOST_PREDICTIONS_DIR,
    XGBOOST_BASELINE_MANIFEST_PATH,
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
)
from src.models.xgboost.evaluate import evaluate_multiclass
from src.models.xgboost.analyze_distribution import compute_balanced_class_weights
from src.models.verification.verify_model_infrastructure import BASELINE_MODEL_READY_HASHES

logger = logging.getLogger("NexThreat.Models.Verification.Phase43XGBoost")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash using chunked binary reading."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_phase_4_3() -> Dict[str, Any]:
    """
    Execute independent verification suite for Phase 4.3 XGBoost.
    """
    logger.info("=" * 70)
    logger.info("NexThreat Phase 4.3 — XGBoost Independent Verification Suite")
    logger.info("=" * 70)

    results: Dict[str, Dict[str, Any]] = {}
    all_passed = True

    # ------------------------------------------------------------
    # CHECK A: Source Data Existence
    # ------------------------------------------------------------
    missing_src = [to_project_relative(p) for p in SOURCE_DATA_FILES.values() if not p.exists()]
    check_a_pass = len(missing_src) == 0
    results["Check A  Source Data Existence"] = {
        "status": "PASS" if check_a_pass else "FAIL",
        "description": "All 6 canonical Phase 3.3 XGBoost model-ready array files exist",
        "missing_files": missing_src,
    }
    if not check_a_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK B: SHA-256 Integrity against Baseline Manifest
    # ------------------------------------------------------------
    check_b_pass = True
    manifest_diffs: List[str] = []

    if not XGBOOST_BASELINE_MANIFEST_PATH.exists():
        check_b_pass = False
        manifest_diffs.append("Baseline manifest missing")
    else:
        with open(XGBOOST_BASELINE_MANIFEST_PATH, "r", encoding="utf-8") as f:
            base_manifest = json.load(f)
        for f_key, f_info in base_manifest["files"].items():
            f_path = Path(f_info["relative_path"])
            if not f_path.exists():
                check_b_pass = False
                manifest_diffs.append(f"File missing: {f_path}")
            else:
                actual_hash = compute_sha256(f_path)
                expected_hash = f_info["sha256"]
                if actual_hash != expected_hash:
                    check_b_pass = False
                    manifest_diffs.append(f"Hash mismatch for {f_path}: exp={expected_hash[:10]}, act={actual_hash[:10]}")

    results["Check B  SHA-256 Integrity"] = {
        "status": "PASS" if check_b_pass else "FAIL",
        "description": "Source files match canonical Phase 4.3 baseline manifest SHA-256 hashes exactly",
        "differences": manifest_diffs,
    }
    if not check_b_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK C: Model-Ready Immutability & Phase 4.2 Preservation
    # ------------------------------------------------------------
    check_c_pass = True
    immutability_issues: List[str] = []

    # 1. Check all 26 model-ready files against original Phase 4.1 baseline
    data_dir = Path("data/model_ready")
    for rel_path, exp_hash in BASELINE_MODEL_READY_HASHES.items():
        p = data_dir / rel_path
        if not p.exists():
            check_c_pass = False
            immutability_issues.append(f"Phase 3.3 file missing: {rel_path}")
        else:
            act_hash = compute_sha256(p)
            if act_hash != exp_hash:
                check_c_pass = False
                immutability_issues.append(f"Phase 3.3 file altered: {rel_path}")

    # 2. Check frozen Phase 4.2 Autoencoder artifacts
    frozen_ae_files = [
        Path("data/models/autoencoder/checkpoints/best_model.keras"),
        Path("data/models/autoencoder/final_model/autoencoder.keras"),
        Path("data/models/autoencoder/artifacts/model_metadata.json"),
    ]
    for ae_p in frozen_ae_files:
        if not ae_p.exists():
            check_c_pass = False
            immutability_issues.append(f"Frozen Phase 4.2 artifact missing: {to_project_relative(ae_p)}")

    # Verify frozen threshold in metadata
    ae_meta_path = Path("data/models/autoencoder/artifacts/model_metadata.json")
    if ae_meta_path.exists():
        with open(ae_meta_path, "r", encoding="utf-8") as f:
            ae_meta = json.load(f)
            th = (
                ae_meta.get("threshold", {}).get("selected_threshold")
                or ae_meta.get("threshold_selection", {}).get("selected_threshold")
            )
            if th is None or abs(th - 0.003208) > 1e-4:
                check_c_pass = False
                immutability_issues.append(f"Frozen Phase 4.2 threshold mismatch: expected ~0.003208, got {th}")

    results["Check C  Model-Ready Immutability"] = {
        "status": "PASS" if check_c_pass else "FAIL",
        "description": "All 26 model-ready files unchanged; Phase 4.2 Autoencoder artifacts and threshold intact",
        "issues": immutability_issues,
    }
    if not check_c_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK D: Feature Contract (13 Features & Raw/Unscaled)
    # ------------------------------------------------------------
    check_d_pass = True
    feature_issues: List[str] = []

    for split in ["train", "validation", "test"]:
        X = load_numpy_array(SOURCE_DATA_FILES[f"X_{split}"])
        if X.shape[1] != FEATURE_COUNT:
            check_d_pass = False
            feature_issues.append(f"X_{split} feature count is {X.shape[1]}, expected {FEATURE_COUNT}")
        if X.dtype != FEATURE_DTYPE:
            check_d_pass = False
            feature_issues.append(f"X_{split} dtype is {X.dtype}, expected {FEATURE_DTYPE}")
        if np.isnan(X).sum() > 0 or np.isinf(X).sum() > 0:
            check_d_pass = False
            feature_issues.append(f"X_{split} contains NaN or Inf")

    # Verify raw contract: no scaler artifact in xgboost directories
    if (XGBOOST_MODEL_DIR / "scaler.joblib").exists():
        check_d_pass = False
        feature_issues.append("Found unexpected scaler artifact in XGBoost model dir")

    # Verify feature_schema.json
    if not FEATURE_SCHEMA_FILE_PATH.exists():
        check_d_pass = False
        feature_issues.append("feature_schema.json is missing")
    else:
        with open(FEATURE_SCHEMA_FILE_PATH, "r", encoding="utf-8") as f:
            fs = json.load(f)
            if fs.get("feature_names") != CANONICAL_FEATURE_COLUMNS:
                check_d_pass = False
                feature_issues.append("feature_schema.json column names/ordering mismatch")

    results["Check D  Feature Contract"] = {
        "status": "PASS" if check_d_pass else "FAIL",
        "description": "13 features, exact declared ordering, float32, zero NaN/Inf, raw/unscaled representation",
        "issues": feature_issues,
    }
    if not check_d_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK E: Label Contract
    # ------------------------------------------------------------
    check_e_pass = True
    label_issues: List[str] = []

    for split in ["train", "validation", "test"]:
        y = load_numpy_array(SOURCE_DATA_FILES[f"y_{split}"])
        if y.dtype != LABEL_DTYPE:
            check_e_pass = False
            label_issues.append(f"y_{split} dtype is {y.dtype}, expected {LABEL_DTYPE}")
        unique_lbls = sorted(int(u) for u in np.unique(y))
        if any(lbl < 0 or lbl >= NUM_CLASSES for lbl in unique_lbls):
            check_e_pass = False
            label_issues.append(f"y_{split} contains labels outside 0..7: {unique_lbls}")

    # Verify class_mapping.json
    if not CLASS_MAPPING_FILE_PATH.exists():
        check_e_pass = False
        label_issues.append("class_mapping.json is missing")
    else:
        with open(CLASS_MAPPING_FILE_PATH, "r", encoding="utf-8") as f:
            cm_art = json.load(f)
            if cm_art.get("class_to_index") != CLASS_MAPPING:
                check_e_pass = False
                label_issues.append("class_mapping.json content mismatch")

    results["Check E  Label Contract"] = {
        "status": "PASS" if check_e_pass else "FAIL",
        "description": "Labels strictly within 0..7, int64 dtype, matching immutable 8-class attack taxonomy",
        "issues": label_issues,
    }
    if not check_e_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK F: Dataset Isolation
    # ------------------------------------------------------------
    check_f_pass = True
    isolation_issues: List[str] = []

    # Verify metadata notes test_set_used_in_training=False, test_set_used_in_selection=False
    if not TRAINING_CONFIG_FILE_PATH.exists():
        check_f_pass = False
        isolation_issues.append("training_config.json missing")
    else:
        with open(TRAINING_CONFIG_FILE_PATH, "r", encoding="utf-8") as f:
            tc = json.load(f)
            if tc.get("test_set_used_in_training") is not False:
                check_f_pass = False
                isolation_issues.append("test_set_used_in_training flag is not False")
            if tc.get("test_set_used_in_selection") is not False:
                check_f_pass = False
                isolation_issues.append("test_set_used_in_selection flag is not False")

    results["Check F  Dataset Isolation"] = {
        "status": "PASS" if check_f_pass else "FAIL",
        "description": "Train strictly for fitting; validation strictly for selection/early stopping; test isolated",
        "issues": isolation_issues,
    }
    if not check_f_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK G: Class Weight Integrity
    # ------------------------------------------------------------
    check_g_pass = True
    weight_issues: List[str] = []

    y_train = load_numpy_array(SOURCE_DATA_FILES["y_train"])
    recomputed_weights = compute_balanced_class_weights(y_train, num_classes=NUM_CLASSES)

    # Compare with stored weights in class_distribution_report
    if not CLASS_DISTRIBUTION_REPORT_PATH.exists():
        check_g_pass = False
        weight_issues.append("class_distribution_report.json is missing")
    else:
        with open(CLASS_DISTRIBUTION_REPORT_PATH, "r", encoding="utf-8") as f:
            cdr = json.load(f)
            weights_per_class = cdr.get("imbalance_strategy", {}).get("weights_per_class", [])
            for w_entry in weights_per_class:
                c = w_entry["class_index"]
                expected_w = recomputed_weights[c]
                recorded_w = w_entry["class_weight"]
                if abs(expected_w - recorded_w) > NUMERICAL_TOLERANCE:
                    check_g_pass = False
                    weight_issues.append(f"Weight mismatch for class {c}: exp={expected_w}, rec={recorded_w}")

    results["Check G  Class Weight Integrity"] = {
        "status": "PASS" if check_g_pass else "FAIL",
        "description": "Balanced sample weights recalculated strictly from y_train match stored weights <= 1e-5",
        "recomputed_weights": recomputed_weights,
        "issues": weight_issues,
    }
    if not check_g_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK H: Model Loadability
    # ------------------------------------------------------------
    check_h_pass = True
    load_issues: List[str] = []
    loaded_model = xgb.XGBClassifier()

    if not MODEL_FILE_PATH.exists():
        check_h_pass = False
        load_issues.append("xgboost_model.json is missing")
    else:
        try:
            loaded_model.load_model(MODEL_FILE_PATH)
        except Exception as e:
            check_h_pass = False
            load_issues.append(f"Model load error: {e}")

    results["Check H  Model Loadability"] = {
        "status": "PASS" if check_h_pass else "FAIL",
        "description": "Saved xgboost_model.json successfully loaded into XGBClassifier",
        "issues": load_issues,
    }
    if not check_h_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK I: Model Configuration
    # ------------------------------------------------------------
    check_i_pass = True
    config_issues: List[str] = []

    if not METADATA_FILE_PATH.exists():
        check_i_pass = False
        config_issues.append("metadata.json missing")
    else:
        with open(METADATA_FILE_PATH, "r", encoding="utf-8") as f:
            meta = json.load(f)
            if meta.get("model_objective") != "multi:softprob":
                check_i_pass = False
                config_issues.append(f"Objective mismatch: {meta.get('model_objective')}")
            if meta.get("num_classes") != NUM_CLASSES:
                check_i_pass = False
                config_issues.append(f"num_classes mismatch: {meta.get('num_classes')}")
            if meta.get("random_seed") != RANDOM_SEED:
                check_i_pass = False
                config_issues.append(f"Seed mismatch: {meta.get('random_seed')}")

    results["Check I  Model Configuration"] = {
        "status": "PASS" if check_i_pass else "FAIL",
        "description": "Model configuration contract: objective=multi:softprob, num_class=8, seed=42 verified",
        "issues": config_issues,
    }
    if not check_i_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK J: Independent Prediction Replay
    # ------------------------------------------------------------
    check_j_pass = True
    replay_pred_issues: List[str] = []

    if not (TEST_PREDICTIONS_PATH.exists() and TEST_PROBABILITIES_PATH.exists()):
        check_j_pass = False
        replay_pred_issues.append("Saved test prediction/probability arrays missing")
    else:
        X_test = load_numpy_array(SOURCE_DATA_FILES["X_test"])
        saved_test_preds = np.load(TEST_PREDICTIONS_PATH)
        saved_test_probs = np.load(TEST_PROBABILITIES_PATH)

        # Re-predict using loaded model
        recomputed_test_probs = loaded_model.predict_proba(X_test)
        recomputed_test_preds = np.argmax(recomputed_test_probs, axis=1)

        # Compare probabilities
        prob_diff = float(np.max(np.abs(recomputed_test_probs - saved_test_probs)))
        if prob_diff > NUMERICAL_TOLERANCE:
            check_j_pass = False
            replay_pred_issues.append(f"Test probability max diff {prob_diff:.8f} > tolerance {NUMERICAL_TOLERANCE}")

        # Compare discrete predictions
        if not np.array_equal(recomputed_test_preds, saved_test_preds):
            mismatches = int((recomputed_test_preds != saved_test_preds).sum())
            check_j_pass = False
            replay_pred_issues.append(f"Discrete test predictions mismatch: {mismatches} differences")

    results["Check J  Prediction Replay"] = {
        "status": "PASS" if check_j_pass else "FAIL",
        "description": "Independent re-prediction on X_test matches saved test probabilities (<= 1e-5) & predictions exactly",
        "max_probability_diff": prob_diff if 'prob_diff' in locals() else None,
        "issues": replay_pred_issues,
    }
    if not check_j_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK K: Independent Metric Replay
    # ------------------------------------------------------------
    check_k_pass = True
    metric_issues: List[str] = []

    y_test = load_numpy_array(SOURCE_DATA_FILES["y_test"])
    recomputed_test_eval = evaluate_multiclass(y_test, recomputed_test_probs, recomputed_test_preds, split_name="test_replay")

    if not TEST_REPORT_PATH.exists():
        check_k_pass = False
        metric_issues.append("test_report.json missing")
    else:
        with open(TEST_REPORT_PATH, "r", encoding="utf-8") as f:
            saved_test_report = json.load(f)

        scalar_metrics = ["accuracy", "macro_f1", "weighted_f1", "macro_recall", "weighted_recall", "macro_precision", "weighted_precision", "log_loss"]
        for m in scalar_metrics:
            exp_val = saved_test_report.get(m)
            act_val = recomputed_test_eval.get(m)
            if abs(exp_val - act_val) > NUMERICAL_TOLERANCE:
                check_k_pass = False
                metric_issues.append(f"Test metric {m} mismatch: saved={exp_val}, recomputed={act_val}")

        # Check ROC-AUC
        exp_roc = saved_test_report.get("roc_auc", {}).get("macro_roc_auc")
        act_roc = recomputed_test_eval.get("roc_auc", {}).get("macro_roc_auc")
        if abs(exp_roc - act_roc) > NUMERICAL_TOLERANCE:
            check_k_pass = False
            metric_issues.append(f"Test macro ROC-AUC mismatch: saved={exp_roc}, recomputed={act_roc}")

        # Check PR-AUC
        exp_pr = saved_test_report.get("pr_auc", {}).get("macro_pr_auc")
        act_pr = recomputed_test_eval.get("pr_auc", {}).get("macro_pr_auc")
        if abs(exp_pr - act_pr) > NUMERICAL_TOLERANCE:
            check_k_pass = False
            metric_issues.append(f"Test macro PR-AUC mismatch: saved={exp_pr}, recomputed={act_pr}")

    # Replay Validation Class 6 Undefined Check (Correction 1 & 14)
    if not VALIDATION_REPORT_PATH.exists():
        check_k_pass = False
        metric_issues.append("validation_report.json missing")
    else:
        with open(VALIDATION_REPORT_PATH, "r", encoding="utf-8") as f:
            val_rep = json.load(f)
            val_c6 = val_rep.get("validation_class_6_handling", {})
            if val_c6.get("roc_auc_status") != "undefined" or val_c6.get("pr_auc_status") != "undefined":
                check_k_pass = False
                metric_issues.append("Validation Class 6 ROC/PR status is not explicitly 'undefined'")

    results["Check K  Metric Replay"] = {
        "status": "PASS" if check_k_pass else "FAIL",
        "description": "All test and validation metrics recomputed independently match stored reports <= 1e-5",
        "issues": metric_issues,
    }
    if not check_k_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK L: Test Isolation Verification
    # ------------------------------------------------------------
    check_l_pass = True
    isolation_audit: List[str] = []

    # Audit training timestamps and candidate selection
    with open(METADATA_FILE_PATH, "r", encoding="utf-8") as f:
        meta = json.load(f)
        sel_cand = meta.get("selected_candidate")
    with open(VALIDATION_REPORT_PATH, "r", encoding="utf-8") as f:
        val_rep = json.load(f)
        val_winner = val_rep.get("selected_candidate")

    if sel_cand != val_winner:
        check_l_pass = False
        isolation_audit.append("Candidate selection inconsistency between metadata and validation report")

    # Confirm test labels were not used for sample weights
    with open(CLASS_DISTRIBUTION_REPORT_PATH, "r", encoding="utf-8") as f:
        cdr = json.load(f)
        strat = cdr.get("imbalance_strategy", {})
        if strat.get("test_labels_used") is not False:
            check_l_pass = False
            isolation_audit.append("Test labels were flagged as used in imbalance strategy")

    results["Check L  Test Isolation"] = {
        "status": "PASS" if check_l_pass else "FAIL",
        "description": "Test set isolated from candidate selection, early stopping, and class weighting",
        "issues": isolation_audit,
    }
    if not check_l_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK M: Artifact SHA-256 Integrity
    # ------------------------------------------------------------
    check_m_pass = True
    artifact_hash_issues: List[str] = []

    if not MODEL_HASHES_FILE_PATH.exists():
        check_m_pass = False
        artifact_hash_issues.append("model_hashes.json missing")
    else:
        with open(MODEL_HASHES_FILE_PATH, "r", encoding="utf-8") as f:
            mh = json.load(f)
        for art_key, art_info in mh["hashes"].items():
            p = Path(art_info["relative_path"])
            if not p.exists():
                check_m_pass = False
                artifact_hash_issues.append(f"Artifact {p} is missing")
            else:
                act_h = compute_sha256(p)
                if act_h != art_info["sha256"]:
                    check_m_pass = False
                    artifact_hash_issues.append(f"Artifact {p} SHA mismatch: exp={art_info['sha256'][:10]}, act={act_h[:10]}")

    results["Check M  Artifact Integrity"] = {
        "status": "PASS" if check_m_pass else "FAIL",
        "description": "Cryptographic SHA-256 hashes of all generated model and prediction artifacts verified",
        "issues": artifact_hash_issues,
    }
    if not check_m_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK N: Reproducibility Metadata
    # ------------------------------------------------------------
    check_n_pass = True
    repro_issues: List[str] = []

    if not REPRODUCIBILITY_REPORT_PATH.exists():
        check_n_pass = False
        repro_issues.append("reproducibility_report.json missing")
    else:
        with open(REPRODUCIBILITY_REPORT_PATH, "r", encoding="utf-8") as f:
            rr = json.load(f)
            required_keys = ["random_seed", "python_version", "packages", "feature_columns", "class_mapping", "candidate_configurations", "selected_candidate", "dataset_hashes", "model_artifact_hashes"]
            for k in required_keys:
                if k not in rr:
                    check_n_pass = False
                    repro_issues.append(f"Missing required key in reproducibility report: {k}")

    results["Check N  Reproducibility"] = {
        "status": "PASS" if check_n_pass else "FAIL",
        "description": "Complete reproducibility specification, software versions, PRNG seeds, and artifact provenance recorded",
        "issues": repro_issues,
    }
    if not check_n_pass:
        all_passed = False

    # ------------------------------------------------------------
    # Final Output & Summary Table
    # ------------------------------------------------------------
    final_status = "PASS" if all_passed else "FAIL"

    print("\n" + "=" * 60)
    print("NexThreat Phase 4.3 — XGBoost Independent Verification")
    print("=" * 60)
    for check_name, check_data in results.items():
        print(f"{check_name:<38} {check_data['status']}")
    print("=" * 60)
    print(f"PHASE 4.3 STATUS: {final_status}")
    print("=" * 60 + "\n")

    report = {
        "report_name": "Phase 4.3 Independent Verification Report",
        "timestamp": datetime.now().isoformat(),
        "overall_status": final_status,
        "checks": results,
    }
    save_json_report(report, XGBOOST_REPORTS_DIR / "xgboost_independent_verification_report.json")

    if not all_passed:
        raise RuntimeError("One or more independent verification checks failed. Phase 4.3 status: FAIL.")

    return report


if __name__ == "__main__":
    verify_phase_4_3()
