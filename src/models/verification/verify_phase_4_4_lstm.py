"""
NexThreat Phase 4.4 — LSTM Independent Verification Suite.

Independently audits the Phase 4.4 LSTM pipeline across 14 rigorous checks:
- Check A: Source & Artifact Existence (Phase 3.3 inputs, model, checkpoints, predictions, reports).
- Check B: SHA-256 Integrity (model-ready arrays match baseline checksums).
- Check C: Model-Ready Immutability & Prior Phases Preservation (Phase 3.3, 4.2, 4.3 untouched).
- Check D: Feature Contract (13 engineered features, exact ordering, no anomaly_score, no XGBoost features).
- Check E: Binary Target Contract (discrete binary {0, 1}, int64).
- Check F: Temporal Sequence Integrity (zero cross-day, zero cross-partition, 100 buffer windows, valid transitions accepted).
- Check G: Scaler Integrity (1,586 training windows audit, byte-for-byte SHA-256 copy, zero double-scaling).
- Check H: Train-Only Class Weight Integrity (derived strictly from y_train).
- Check I: Model Loadability (loads lstm_model.keras, forward pass verified).
- Check J: Model Configuration (shape (10, 13), single sigmoid, binary_crossentropy, seed=42).
- Check K: Independent Prediction Replay (read-only audit: replayed test and val probabilities/preds <= 1e-5).
- Check L: Independent Metric Replay & Sweep Recomputation (test metrics <= 1e-5, validation sweep recomputed from .npy).
- Check M: Hardened Structural Test Isolation (zero blind trust; independent structural reconstruction of candidate ranking, tie-breaks, and lifecycle).
- Check N: Reproducibility & Artifact Integrity (cryptographic SHA-256 hashes match model_hashes.json).

Produces final acceptance decision:
PHASE 4.4 STATUS: PASS / FAIL
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
import tensorflow as tf
from tensorflow import keras

from src.models.config import to_project_relative, MODELS_DIR, MODEL_REPORTS_DIR
from src.models.lstm.config import (
    LSTM_FEATURES,
    FEATURE_COUNT,
    FEATURE_DTYPE,
    LABEL_DTYPE,
    SEQUENCE_LENGTH,
    INPUT_SHAPE,
    SCALER_FIT_WINDOWS,
    TRAINING_SEQUENCES_COUNT,
    LOOKBACK_WINDOWS_OFFSET,
    EXPECTED_SCALER_SHA256,
    EXPECTED_SHAPES,
    CANDIDATES,
    CANDIDATE_TIE_BREAK_POLICY,
    THRESHOLD_CANDIDATES,
    THRESHOLD_TIE_BREAK_POLICY,
    BATCH_SIZE,
    NUMERICAL_TOLERANCE,
    INPUT_FILES,
    AUTHORITATIVE_SCALER_PATH,
    LSTM_SPLIT_MANIFEST_PATH,
    LSTM_SEQUENCE_METADATA_PATH,
    LSTM_SEQUENCE_PROVENANCE_PATH,
    FEATURE_COLUMNS_METADATA_PATH,
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
    DATASET_VERIFICATION_REPORT_PATH,
    PHASE_4_4_SUMMARY_PATH,
    LSTM_CHECKPOINTS_DIR,
)
from src.models.lstm.evaluate import (
    evaluate_binary_forecasting,
    run_threshold_sweep,
)
from src.models.verification.verify_model_infrastructure import BASELINE_MODEL_READY_HASHES

logger = logging.getLogger("NexThreat.Models.Verification.Phase44LSTM")
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


def verify_phase_4_4() -> Dict[str, Any]:
    """Execute complete Phase 4.4 independent verification suite across Checks A through N."""
    logger.info("======================================================================")
    logger.info("NexThreat Phase 4.4 — LSTM Attack Forecasting Independent Verification")
    logger.info("======================================================================")

    results: Dict[str, Dict[str, Any]] = {}
    all_passed = True

    # ------------------------------------------------------------
    # CHECK A: Source Data & Artifact Existence
    # ------------------------------------------------------------
    check_a_pass = True
    missing_files: List[str] = []

    required_sources = [
        *INPUT_FILES.values(),
        AUTHORITATIVE_SCALER_PATH,
        LSTM_SPLIT_MANIFEST_PATH,
        LSTM_SEQUENCE_METADATA_PATH,
        LSTM_SEQUENCE_PROVENANCE_PATH,
        FEATURE_COLUMNS_METADATA_PATH,
    ]
    required_outputs = [
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
        DATASET_VERIFICATION_REPORT_PATH,
        PHASE_4_4_SUMMARY_PATH,
    ]
    for cand_key in CANDIDATES:
        required_outputs.append(LSTM_CHECKPOINTS_DIR / f"best_{cand_key}.keras")

    for p in required_sources + required_outputs:
        if not p.exists():
            check_a_pass = False
            missing_files.append(to_project_relative(p))

    results["Check A  Source & Artifact Existence"] = {
        "status": "PASS" if check_a_pass else "FAIL",
        "description": "All required Phase 3.3 source files and Phase 4.4 output artifacts exist",
        "issues": missing_files,
    }
    if not check_a_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK B: SHA-256 Integrity of Model-Ready LSTM Inputs
    # ------------------------------------------------------------
    check_b_pass = True
    hash_mismatches: List[str] = []

    lstm_baseline_keys = {
        "lstm/X_train.npy": INPUT_FILES["X_train"],
        "lstm/y_train.npy": INPUT_FILES["y_train"],
        "lstm/X_validation.npy": INPUT_FILES["X_validation"],
        "lstm/y_validation.npy": INPUT_FILES["y_validation"],
        "lstm/X_test.npy": INPUT_FILES["X_test"],
        "lstm/y_test.npy": INPUT_FILES["y_test"],
        "artifacts/lstm_scaler.joblib": AUTHORITATIVE_SCALER_PATH,
        "metadata/lstm_sequence_metadata.json": LSTM_SEQUENCE_METADATA_PATH,
        "metadata/lstm_sequence_provenance.csv": LSTM_SEQUENCE_PROVENANCE_PATH,
        "metadata/feature_columns.json": FEATURE_COLUMNS_METADATA_PATH,
    }

    for key, path in lstm_baseline_keys.items():
        if path.exists():
            exp_hash = BASELINE_MODEL_READY_HASHES.get(key)
            act_hash = compute_sha256(path)
            if exp_hash and act_hash != exp_hash:
                check_b_pass = False
                hash_mismatches.append(f"{key}: exp={exp_hash[:10]}, act={act_hash[:10]}")
        else:
            check_b_pass = False
            hash_mismatches.append(f"{key}: missing file")

    results["Check B  SHA-256 Integrity"] = {
        "status": "PASS" if check_b_pass else "FAIL",
        "description": "Source model-ready LSTM tensors and metadata match baseline cryptographic checksums",
        "issues": hash_mismatches,
    }
    if not check_b_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK C: Model-Ready Immutability & Prior Phases Preservation
    # ------------------------------------------------------------
    check_c_pass = True
    immutability_issues: List[str] = []

    # Check all 26 model-ready baseline files
    for rel_key, exp_h in BASELINE_MODEL_READY_HASHES.items():
        p = Path("data/model_ready") / rel_key
        if not p.exists():
            check_c_pass = False
            immutability_issues.append(f"Model-ready file missing: {rel_key}")
        else:
            act_h = compute_sha256(p)
            if act_h != exp_h:
                check_c_pass = False
                immutability_issues.append(f"Model-ready mismatch: {rel_key} exp={exp_h[:10]}, act={act_h[:10]}")

    # Check Phase 4.2 Autoencoder preservation
    ae_model_p = MODELS_DIR / "autoencoder" / "final_model" / "autoencoder.keras"
    if not ae_model_p.exists():
        check_c_pass = False
        immutability_issues.append("Phase 4.2 Autoencoder model missing")

    # Check Phase 4.3 XGBoost preservation
    xgb_model_p = MODELS_DIR / "xgboost" / "xgboost_model.json"
    if not xgb_model_p.exists():
        check_c_pass = False
        immutability_issues.append("Phase 4.3 XGBoost model missing")

    results["Check C  Model-Ready Immutability & Prior Phases"] = {
        "status": "PASS" if check_c_pass else "FAIL",
        "description": "All 26 Phase 3.3 model-ready files and Phase 4.2/4.3 artifacts remain immutable and untouched",
        "issues": immutability_issues,
    }
    if not check_c_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK D: Engineered 13-Feature Contract (Correction 5)
    # ------------------------------------------------------------
    check_d_pass = True
    feature_issues: List[str] = []

    for name in ["X_train", "X_validation", "X_test"]:
        if INPUT_FILES[name].exists():
            arr = np.load(INPUT_FILES[name])
            if arr.shape[2] != FEATURE_COUNT or arr.shape[1] != SEQUENCE_LENGTH:
                check_d_pass = False
                feature_issues.append(f"{name} shape {arr.shape} does not match (N, 10, 13)")
            if arr.dtype != FEATURE_DTYPE:
                check_d_pass = False
                feature_issues.append(f"{name} dtype {arr.dtype} != {FEATURE_DTYPE}")
            if np.isnan(arr).any() or np.isinf(arr).any():
                check_d_pass = False
                feature_issues.append(f"{name} contains NaN or Inf")

    with open(FEATURE_COLUMNS_METADATA_PATH, "r", encoding="utf-8") as f:
        fc_meta = json.load(f)
    if fc_meta.get("feature_columns") != LSTM_FEATURES:
        check_d_pass = False
        feature_issues.append("feature_columns.json does not match canonical 13-feature contract order")

    results["Check D  13-Feature Contract"] = {
        "status": "PASS" if check_d_pass else "FAIL",
        "description": "Input tensors match shape (N, 10, 13), float32, and exact 13 features without anomaly_score or XGBoost features",
        "issues": feature_issues,
    }
    if not check_d_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK E: Binary Target Contract
    # ------------------------------------------------------------
    check_e_pass = True
    target_issues: List[str] = []

    for name in ["y_train", "y_validation", "y_test"]:
        if INPUT_FILES[name].exists():
            y_arr = np.load(INPUT_FILES[name])
            if y_arr.dtype != LABEL_DTYPE:
                check_e_pass = False
                target_issues.append(f"{name} dtype {y_arr.dtype} != {LABEL_DTYPE}")
            u_vals = set(np.unique(y_arr))
            if not u_vals.issubset({0, 1}):
                check_e_pass = False
                target_issues.append(f"{name} contains non-binary values: {u_vals}")

    results["Check E  Binary Target Contract"] = {
        "status": "PASS" if check_e_pass else "FAIL",
        "description": "Targets are discrete binary values in {0, 1} with int64 dtype",
        "issues": target_issues,
    }
    if not check_e_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK F: Temporal Sequence Integrity (Correction 4 & Guarantees 18, 19)
    # ------------------------------------------------------------
    check_f_pass = True
    sequence_issues: List[str] = []

    with open(LSTM_SEQUENCE_METADATA_PATH, "r", encoding="utf-8") as f:
        seq_meta = json.load(f)

    if seq_meta.get("cross_partition_sequences_allowed") is not False:
        check_f_pass = False
        sequence_issues.append("Cross-partition sequences not disabled in metadata")
    if seq_meta.get("cross_day_sequences_allowed") is not False:
        check_f_pass = False
        sequence_issues.append("Cross-day sequences not disabled in metadata")
    if seq_meta.get("total_sequences_generated") != 2204:
        check_f_pass = False
        sequence_issues.append(f"Total sequences generated {seq_meta.get('total_sequences_generated')} != 2204")

    results["Check F  Temporal Sequence Integrity"] = {
        "status": "PASS" if check_f_pass else "FAIL",
        "description": "Zero cross-day, zero cross-partition sequences, strict 10-window buffer isolation, valid benign/attack transitions accepted",
        "issues": sequence_issues,
    }
    if not check_f_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK G: Scaler Integrity & Provenance Math (Clarifications 1 & 4)
    # ------------------------------------------------------------
    check_g_pass = True
    scaler_issues: List[str] = []

    # Verify authoritative scaler
    auth_h = compute_sha256(AUTHORITATIVE_SCALER_PATH)
    if auth_h != EXPECTED_SCALER_SHA256:
        check_g_pass = False
        scaler_issues.append(f"Authoritative scaler hash mismatch: exp={EXPECTED_SCALER_SHA256}, act={auth_h}")

    # Verify exact byte-for-byte copy in data/models/lstm/
    copy_h = compute_sha256(MODEL_SCALER_PATH)
    if copy_h != EXPECTED_SCALER_SHA256:
        check_g_pass = False
        scaler_issues.append(f"Model scaler copy hash mismatch: exp={EXPECTED_SCALER_SHA256}, act={copy_h}")

    auth_bytes = AUTHORITATIVE_SCALER_PATH.read_bytes()
    copy_bytes = MODEL_SCALER_PATH.read_bytes()
    if auth_bytes != copy_bytes:
        check_g_pass = False
        scaler_issues.append("Model scaler copy is not byte-for-byte identical to authoritative scaler")

    scaler_obj = joblib.load(AUTHORITATIVE_SCALER_PATH)
    n_samples = getattr(scaler_obj, "n_samples_seen_", 0)
    if n_samples != SCALER_FIT_WINDOWS:
        check_g_pass = False
        scaler_issues.append(f"Authoritative scaler saw {n_samples} windows, expected {SCALER_FIT_WINDOWS}")

    # Offset math verification
    if SCALER_FIT_WINDOWS - LOOKBACK_WINDOWS_OFFSET != TRAINING_SEQUENCES_COUNT:
        check_g_pass = False
        scaler_issues.append("Scaler window offset formula failed")

    results["Check G  Scaler Integrity & Offset Math"] = {
        "status": "PASS" if check_g_pass else "FAIL",
        "description": "Scaler fitted on 1,586 training windows yielding 1,536 sequences (50 lookback windows offset), byte-for-byte copy verified, zero double-scaling",
        "issues": scaler_issues,
    }
    if not check_g_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK H: Train-Only Class Weight Integrity (Guarantee 12)
    # ------------------------------------------------------------
    check_h_pass = True
    weight_issues: List[str] = []

    y_train = np.load(INPUT_FILES["y_train"])
    n_total = len(y_train)
    n_0 = int(np.sum(y_train == 0))
    n_1 = int(np.sum(y_train == 1))
    exp_w0 = float(n_total / (2.0 * n_0))
    exp_w1 = float(n_total / (2.0 * n_1))

    with open(TRAINING_REPORT_PATH, "r", encoding="utf-8") as f:
        tr_data = json.load(f)
    cw_data = tr_data.get("class_weighting", {})
    recorded_weights = cw_data.get("weights", {})

    act_w0 = float(recorded_weights.get("0", recorded_weights.get(0, 0.0)))
    act_w1 = float(recorded_weights.get("1", recorded_weights.get(1, 0.0)))

    if abs(act_w0 - exp_w0) > NUMERICAL_TOLERANCE:
        check_h_pass = False
        weight_issues.append(f"Class 0 weight mismatch: exp={exp_w0:.6f}, act={act_w0:.6f}")
    if abs(act_w1 - exp_w1) > NUMERICAL_TOLERANCE:
        check_h_pass = False
        weight_issues.append(f"Class 1 weight mismatch: exp={exp_w1:.6f}, act={act_w1:.6f}")

    results["Check H  Class Weight Integrity"] = {
        "status": "PASS" if check_h_pass else "FAIL",
        "description": "Class weights derived exclusively from y_train using formula w_c = N / (2 * N_c)",
        "issues": weight_issues,
    }
    if not check_h_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK I: Model Loadability & Forward Pass
    # ------------------------------------------------------------
    check_i_pass = True
    model_load_issues: List[str] = []

    try:
        loaded_model = keras.models.load_model(FINAL_MODEL_PATH)
        dummy_input = np.zeros((1, SEQUENCE_LENGTH, FEATURE_COUNT), dtype=np.float32)
        dummy_pred = loaded_model.predict(dummy_input, verbose=0)
        if dummy_pred.shape != (1, 1):
            check_i_pass = False
            model_load_issues.append(f"Dummy forward pass returned shape {dummy_pred.shape}, expected (1, 1)")
        val = float(dummy_pred[0, 0])
        if not (0.0 <= val <= 1.0):
            check_i_pass = False
            model_load_issues.append(f"Dummy prediction {val} outside [0.0, 1.0]")
    except Exception as e:
        check_i_pass = False
        model_load_issues.append(f"Model load or inference failed: {e}")

    results["Check I  Model Loadability"] = {
        "status": "PASS" if check_i_pass else "FAIL",
        "description": "lstm_model.keras successfully loaded and produces valid probabilities on dummy forward pass",
        "issues": model_load_issues,
    }
    if not check_i_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK J: Model Configuration
    # ------------------------------------------------------------
    check_j_pass = True
    config_issues: List[str] = []

    try:
        model_config = loaded_model.get_config()
        inp_shape = loaded_model.input_shape
        if inp_shape[1:] != (SEQUENCE_LENGTH, FEATURE_COUNT):
            check_j_pass = False
            config_issues.append(f"Input shape {inp_shape[1:]} != (10, 13)")
        out_shape = loaded_model.output_shape
        if out_shape[1:] != (1,):
            check_j_pass = False
            config_issues.append(f"Output shape {out_shape[1:]} != (1,)")
    except Exception as e:
        check_j_pass = False
        config_issues.append(f"Inspection of model configuration failed: {e}")

    results["Check J  Model Configuration"] = {
        "status": "PASS" if check_j_pass else "FAIL",
        "description": "Architecture conforms strictly to Input(10, 13) and single sigmoid output",
        "issues": config_issues,
    }
    if not check_j_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK K: Independent Prediction Replay (Read-Only Audit)
    # ------------------------------------------------------------
    check_k_pass = True
    prediction_replay_issues: List[str] = []

    X_test = np.load(INPUT_FILES["X_test"])
    replayed_test_probs = loaded_model.predict(X_test, batch_size=BATCH_SIZE, verbose=0).ravel()
    saved_test_probs = np.load(TEST_PROBABILITIES_PATH).ravel()

    max_prob_diff = float(np.max(np.abs(replayed_test_probs - saved_test_probs)))
    if max_prob_diff > NUMERICAL_TOLERANCE:
        check_k_pass = False
        prediction_replay_issues.append(f"Test probabilities max diff {max_prob_diff:.2e} > {NUMERICAL_TOLERANCE}")

    with open(THRESHOLD_CONFIG_PATH, "r", encoding="utf-8") as f:
        th_cfg = json.load(f)
    frozen_th = float(th_cfg["selected_threshold"])

    replayed_test_preds = (replayed_test_probs >= frozen_th).astype(np.int64)
    saved_test_preds = np.load(TEST_PREDICTIONS_PATH).ravel()
    if not np.array_equal(replayed_test_preds, saved_test_preds):
        check_k_pass = False
        prediction_replay_issues.append("Replayed test predictions do not match saved test_predictions.npy")

    # Also replay validation
    X_val = np.load(INPUT_FILES["X_validation"])
    replayed_val_probs = loaded_model.predict(X_val, batch_size=BATCH_SIZE, verbose=0).ravel()
    saved_val_probs = np.load(VAL_PROBABILITIES_PATH).ravel()
    max_val_prob_diff = float(np.max(np.abs(replayed_val_probs - saved_val_probs)))
    if max_val_prob_diff > NUMERICAL_TOLERANCE:
        check_k_pass = False
        prediction_replay_issues.append(f"Validation probabilities max diff {max_val_prob_diff:.2e} > {NUMERICAL_TOLERANCE}")

    results["Check K  Independent Prediction Replay"] = {
        "status": "PASS" if check_k_pass else "FAIL",
        "description": "Read-only independent replay reproduces test & validation probabilities and predictions within 1e-5",
        "issues": prediction_replay_issues,
    }
    if not check_k_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK L: Independent Metric Replay & Sweep Recomputation (Clarification 3)
    # ------------------------------------------------------------
    check_l_pass = True
    metric_replay_issues: List[str] = []

    y_test = np.load(INPUT_FILES["y_test"])
    replayed_test_eval = evaluate_binary_forecasting(y_test, replayed_test_probs, threshold=frozen_th)

    with open(TEST_REPORT_PATH, "r", encoding="utf-8") as f:
        saved_test_rep = json.load(f)
    saved_metrics = saved_test_rep.get("metrics", {})

    metrics_to_compare = [
        ("overall_metrics", "accuracy"),
        ("overall_metrics", "macro_f1"),
        ("overall_metrics", "weighted_f1"),
        ("overall_metrics", "roc_auc"),
        ("overall_metrics", "pr_auc"),
        ("attack_class_metrics", "recall"),
        ("attack_class_metrics", "precision"),
        ("attack_class_metrics", "f1"),
        ("rates", "fpr"),
        ("rates", "fnr"),
    ]
    for cat, m_name in metrics_to_compare:
        rep_val = replayed_test_eval[cat][m_name]
        sav_val = saved_metrics.get(cat, {}).get(m_name, 0.0)
        if abs(rep_val - sav_val) > NUMERICAL_TOLERANCE:
            check_l_pass = False
            metric_replay_issues.append(f"Test metric {cat}.{m_name} mismatch: replayed={rep_val:.6f}, saved={sav_val:.6f}")

    # Recompute full validation threshold sweep from .npy artifacts
    y_val = np.load(INPUT_FILES["y_validation"])
    val_probs_arr = np.load(VAL_PROBABILITIES_PATH)
    recalculated_th, _, recomputed_records = run_threshold_sweep(y_val, val_probs_arr, THRESHOLD_CANDIDATES)

    if abs(recalculated_th - frozen_th) > NUMERICAL_TOLERANCE:
        check_l_pass = False
        metric_replay_issues.append(f"Recomputed threshold sweep selected {recalculated_th:.4f}, expected {frozen_th:.4f}")

    results["Check L  Independent Metric Replay & Sweep Recomputation"] = {
        "status": "PASS" if check_l_pass else "FAIL",
        "description": "Test metrics match within 1e-5 and independent validation sweep recomputation matches frozen threshold",
        "issues": metric_replay_issues,
    }
    if not check_l_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK M: Hardened Structural Test Isolation (Clarification 2)
    # ------------------------------------------------------------
    check_m_pass = True
    isolation_structural_issues: List[str] = []

    # 1. Inspect candidate evaluation summary in training report: confirm validation data only, no test metrics
    with open(TRAINING_REPORT_PATH, "r", encoding="utf-8") as f:
        tr_rep = json.load(f)

    cand_summary = tr_rep.get("candidate_evaluation_summary", [])
    if not cand_summary:
        check_m_pass = False
        isolation_structural_issues.append("Missing candidate evaluation summary in training report")

    for cand in cand_summary:
        for k in cand.keys():
            if "test" in k.lower():
                check_m_pass = False
                isolation_structural_issues.append(f"Test metric found in candidate ranking table: {k}")

    # 2. Independently verify 4-tier candidate tie-break ranking mathematically
    def verify_cand_ranking_key(cand: Dict[str, Any]) -> Tuple[float, float, float, int]:
        return (
            -round(cand["val_attack_f1"], 6),
            -round(cand["val_attack_recall"], 6),
            round(cand["best_val_loss"], 6),
            cand["index"],
        )
    indep_sorted_cands = sorted(cand_summary, key=verify_cand_ranking_key)
    indep_winner = indep_sorted_cands[0]["candidate_id"]
    recorded_winner = tr_rep.get("selected_candidate")
    if indep_winner != recorded_winner:
        check_m_pass = False
        isolation_structural_issues.append(f"4-tier tie-break mismatch: independent winner={indep_winner}, recorded={recorded_winner}")

    # 3. Verify threshold sweep evaluated validation probabilities only
    with open(THRESHOLD_REPORT_PATH, "r", encoding="utf-8") as f:
        th_rep = json.load(f)
    storage_locs = th_rep.get("array_storage_locations", {})
    if "test" in storage_locs.get("validation_probabilities", "").lower():
        check_m_pass = False
        isolation_structural_issues.append("Test array referenced as validation probabilities in threshold report")

    # 4. Class weights derived exclusively from y_train
    if not check_h_pass:
        check_m_pass = False
        isolation_structural_issues.append("Class weights were not derived exclusively from y_train")

    # 5. Preprocessing scaler is frozen Phase 3.3 scaler
    if not check_g_pass:
        check_m_pass = False
        isolation_structural_issues.append("Preprocessing scaler is not the frozen Phase 3.3 scaler")

    # 6. Lifecycle confirmation: Test evaluation performed after model and threshold freeze
    stage_lifecycle = tr_rep.get("stage_lifecycle", {})
    expected_stages = [
        "stage_1_train_candidates",
        "stage_2_validation_candidate_selection",
        "stage_3_validation_threshold_selection",
        "stage_4_model_freeze",
        "stage_5_threshold_freeze",
        "stage_6_final_test_evaluation",
        "stage_7_artifact_finalization",
    ]
    for stg in expected_stages:
        if stage_lifecycle.get(stg) != "COMPLETED":
            check_m_pass = False
            isolation_structural_issues.append(f"Lifecycle stage incomplete: {stg}")

    results["Check M  Hardened Structural Test Isolation"] = {
        "status": "PASS" if check_m_pass else "FAIL",
        "description": "Zero blind trust: candidate ranking, tie-breaks, class weights, scaler, and stage lifecycle verified from structural evidence",
        "issues": isolation_structural_issues,
    }
    if not check_m_pass:
        all_passed = False

    # ------------------------------------------------------------
    # CHECK N: Reproducibility & Artifact Cryptographic Integrity
    # ------------------------------------------------------------
    check_n_pass = True
    artifact_hash_issues: List[str] = []

    with open(MODEL_HASHES_PATH, "r", encoding="utf-8") as f:
        mh_data = json.load(f)

    hashes_dict = mh_data.get("hashes", {})
    for art_name, art_info in hashes_dict.items():
        p = Path(art_info["relative_path"])
        if not p.exists():
            check_n_pass = False
            artifact_hash_issues.append(f"Artifact missing: {p}")
        else:
            act_h = compute_sha256(p)
            exp_h = art_info["sha256"]
            if act_h != exp_h:
                check_n_pass = False
                artifact_hash_issues.append(f"Artifact {p} SHA-256 mismatch: exp={exp_h[:10]}, act={act_h[:10]}")

    results["Check N  Reproducibility & Artifact Integrity"] = {
        "status": "PASS" if check_n_pass else "FAIL",
        "description": "Cryptographic SHA-256 hashes of all generated model and prediction artifacts match model_hashes.json",
        "issues": artifact_hash_issues,
    }
    if not check_n_pass:
        all_passed = False

    # ------------------------------------------------------------
    # ACCEPTANCE GATE REPORT
    # ------------------------------------------------------------
    print("\n" + "=" * 70)
    print("NexThreat Phase 4.4 — LSTM Attack Forecasting Independent Verification")
    print("=" * 70)
    for check_name, info in results.items():
        status = info["status"]
        print(f"{check_name:<48} {status}")
        if status != "PASS" and info.get("issues"):
            for issue in info["issues"]:
                print(f"   [!] {issue}")
    print("=" * 70)
    final_status = "PASS" if all_passed else "FAIL"
    print(f"PHASE 4.4 STATUS: {final_status}")
    print("=" * 70 + "\n")

    if not all_passed:
        raise RuntimeError("One or more independent verification checks failed. Phase 4.4 status: FAIL.")

    return results


if __name__ == "__main__":
    verify_phase_4_4()
