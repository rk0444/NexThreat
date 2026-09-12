"""
NexThreat Phase 4.4 — LSTM Dataset & Provenance Verification Engine.

Audits model-ready sequence tensors, feature contract, scaler provenance math
(1,586 scaler windows vs. 1,536 sequences), sequence boundary integrity
(zero cross-day, zero cross-partition, zero buffer inclusion), and permits
valid within-partition BENIGN <-> ATTACK transitions.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd

from src.models.config import to_project_relative
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
    INPUT_FILES,
    AUTHORITATIVE_SCALER_PATH,
    LSTM_SPLIT_MANIFEST_PATH,
    LSTM_SEQUENCE_METADATA_PATH,
    LSTM_SEQUENCE_PROVENANCE_PATH,
    FEATURE_COLUMNS_METADATA_PATH,
    DATASET_VERIFICATION_REPORT_PATH,
)

logger = logging.getLogger("NexThreat.Models.LSTM.VerifyDataset")
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


def verify_tensors() -> Dict[str, Any]:
    """Verify shapes, dtypes, and numerical finiteness of all 6 LSTM arrays."""
    tensor_results: Dict[str, Any] = {}
    all_valid = True

    for name, path in INPUT_FILES.items():
        if not path.exists():
            tensor_results[name] = {"status": "FAIL", "error": f"File missing: {path}"}
            all_valid = False
            continue

        arr = np.load(path)
        expected_shape = EXPECTED_SHAPES[name]
        expected_dtype = FEATURE_DTYPE if name.startswith("X") else LABEL_DTYPE

        has_nan = bool(np.isnan(arr).any()) if np.issubdtype(arr.dtype, np.floating) else False
        has_inf = bool(np.isinf(arr).any()) if np.issubdtype(arr.dtype, np.floating) else False
        shape_match = (arr.shape == expected_shape)
        dtype_match = (arr.dtype == expected_dtype)

        unique_vals = [int(x) for x in np.unique(arr)] if name.startswith("y") else None
        valid_binary = True if unique_vals is None else set(unique_vals).issubset({0, 1})

        valid = shape_match and dtype_match and not has_nan and not has_inf and valid_binary
        if not valid:
            all_valid = False

        tensor_results[name] = {
            "status": "PASS" if valid else "FAIL",
            "shape": list(arr.shape),
            "expected_shape": list(expected_shape),
            "dtype": str(arr.dtype),
            "expected_dtype": str(np.dtype(expected_dtype)),
            "has_nan": has_nan,
            "has_inf": has_inf,
            "unique_values": unique_vals,
        }

    return {"status": "PASS" if all_valid else "FAIL", "arrays": tensor_results}


def verify_feature_contract() -> Dict[str, Any]:
    """Verify the exact engineered 13-feature contract (Correction 5)."""
    if not FEATURE_COLUMNS_METADATA_PATH.exists():
        return {"status": "FAIL", "error": "feature_columns.json missing"}

    with open(FEATURE_COLUMNS_METADATA_PATH, "r", encoding="utf-8") as f:
        meta = json.load(f)

    cols = meta.get("feature_columns", [])
    count = meta.get("feature_count", 0)

    count_match = (count == FEATURE_COUNT == 13)
    order_match = (cols == LSTM_FEATURES)
    no_anomaly_score = ("anomaly_score" not in cols)
    no_xgboost_features = not any(c.startswith("xgb_") for c in cols)

    valid = count_match and order_match and no_anomaly_score and no_xgboost_features
    return {
        "status": "PASS" if valid else "FAIL",
        "feature_count": count,
        "expected_count": FEATURE_COUNT,
        "features_match": order_match,
        "no_anomaly_score": no_anomaly_score,
        "no_xgboost_features": no_xgboost_features,
        "feature_list": cols,
    }


def verify_scaler_provenance() -> Dict[str, Any]:
    """
    Verify authoritative Phase 3.3 StandardScaler provenance (Clarification 1 & 4).
    Documents that the scaler was fitted on 1,586 training windows to yield
    1,536 training sequences with 5 days * 10 lookback = 50 offset windows.
    """
    if not AUTHORITATIVE_SCALER_PATH.exists():
        return {"status": "FAIL", "error": "Authoritative scaler missing"}

    actual_hash = compute_sha256(AUTHORITATIVE_SCALER_PATH)
    hash_match = (actual_hash == EXPECTED_SCALER_SHA256)

    scaler = joblib.load(AUTHORITATIVE_SCALER_PATH)
    n_samples_seen = int(getattr(scaler, "n_samples_seen_", 0))
    n_features_in = int(getattr(scaler, "n_features_in_", 0))

    # Math check: 1586 scaler windows - (5 dataset days * 10 lookback windows) = 1536 sequences
    math_match = (SCALER_FIT_WINDOWS - LOOKBACK_WINDOWS_OFFSET == TRAINING_SEQUENCES_COUNT)
    samples_match = (n_samples_seen == SCALER_FIT_WINDOWS)
    features_match = (n_features_in == FEATURE_COUNT)

    valid = hash_match and math_match and samples_match and features_match
    return {
        "status": "PASS" if valid else "FAIL",
        "sha256": actual_hash,
        "expected_sha256": EXPECTED_SCALER_SHA256,
        "hash_match": hash_match,
        "n_samples_seen": n_samples_seen,
        "expected_samples_seen": SCALER_FIT_WINDOWS,
        "n_features_in": n_features_in,
        "expected_features_in": FEATURE_COUNT,
        "mathematical_offset_formula": "1586 scaler windows - (5 days * 10 lookback windows) = 1536 training sequences",
        "math_verified": math_match,
        "pre_scaled_policy": "Model-ready arrays are pre-scaled and must not be transformed again (Zero Double-Scaling)",
    }


def verify_sequence_boundaries() -> Dict[str, Any]:
    """
    Verify sequence boundary integrity (Correction 4 & Guarantee 18, 19).
    Audits sequence provenance: zero cross-day, zero cross-partition, zero buffer
    inclusion, and validates that normal within-partition BENIGN <-> ATTACK
    transitions are recognized and accepted.
    """
    if not LSTM_SEQUENCE_PROVENANCE_PATH.exists():
        return {"status": "FAIL", "error": "lstm_sequence_provenance.csv missing"}
    if not LSTM_SPLIT_MANIFEST_PATH.exists():
        return {"status": "FAIL", "error": "lstm_split_manifest.csv missing"}

    prov_df = pd.read_csv(LSTM_SEQUENCE_PROVENANCE_PATH)
    manifest_df = pd.read_csv(LSTM_SPLIT_MANIFEST_PATH)

    manifest_map = manifest_df.set_index("global_position").to_dict(orient="index")

    cross_day_violations = 0
    cross_partition_violations = 0
    buffer_inclusion_violations = 0
    valid_transitions_observed = 0

    total_sequences = len(prov_df)

    for idx, row in prov_df.iterrows():
        split = row["split"]
        day = row["day"]
        start_pos = int(row["sequence_start_global_position"])
        end_pos = int(row["sequence_end_global_position"])
        target_pos = int(row["target_global_position"])

        # Check all window positions involved in this sequence and target
        window_positions = list(range(start_pos, end_pos + 1)) + [target_pos]

        window_days = set()
        window_splits = set()
        has_buffer = False
        target_statuses = []

        for p in window_positions:
            win_info = manifest_map.get(p)
            if win_info is not None:
                window_days.add(win_info.get("dataset_day"))
                window_splits.add(win_info.get("split"))
                if win_info.get("is_buffer") is True:
                    has_buffer = True
                target_statuses.append(win_info.get("is_attack"))

        if len(window_days) > 1 or list(window_days)[0] != day:
            cross_day_violations += 1
        if len(window_splits) > 1 or list(window_splits)[0] != split:
            cross_partition_violations += 1
        if has_buffer:
            buffer_inclusion_violations += 1

        # Check temporal transition within sequence (e.g. benign -> attack or attack -> benign)
        if len(set(target_statuses)) > 1:
            valid_transitions_observed += 1

    valid = (
        cross_day_violations == 0
        and cross_partition_violations == 0
        and buffer_inclusion_violations == 0
        and total_sequences == 2204
    )

    return {
        "status": "PASS" if valid else "FAIL",
        "total_sequences_audited": total_sequences,
        "cross_day_violations": cross_day_violations,
        "cross_partition_violations": cross_partition_violations,
        "buffer_inclusion_violations": buffer_inclusion_violations,
        "within_partition_temporal_transitions_observed": valid_transitions_observed,
        "boundary_isolation_verified": valid,
        "permitted_transitions_policy": (
            "Valid chronological transitions between BENIGN and ATTACK within the same "
            "partition/day are legitimate temporal patterns and accepted."
        ),
    }


def run_dataset_verification() -> Dict[str, Any]:
    """Execute complete dataset and provenance verification suite."""
    logger.info("============================================================")
    logger.info("NexThreat Phase 4.4 — LSTM Dataset & Provenance Verification")
    logger.info("============================================================")

    DATASET_VERIFICATION_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    tensors_res = verify_tensors()
    feature_res = verify_feature_contract()
    scaler_res = verify_scaler_provenance()
    boundary_res = verify_sequence_boundaries()

    all_passed = (
        tensors_res["status"] == "PASS"
        and feature_res["status"] == "PASS"
        and scaler_res["status"] == "PASS"
        and boundary_res["status"] == "PASS"
    )

    report = {
        "report_name": "Phase 4.4 LSTM Dataset Verification Report",
        "timestamp": datetime.now().isoformat(),
        "overall_status": "PASS" if all_passed else "FAIL",
        "checks": {
            "tensor_specifications": tensors_res,
            "feature_contract": feature_res,
            "scaler_provenance": scaler_res,
            "sequence_boundaries": boundary_res,
        },
    }

    with open(DATASET_VERIFICATION_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
        f.write("\n")

    logger.info("Saved dataset verification report to: %s", to_project_relative(DATASET_VERIFICATION_REPORT_PATH))
    logger.info("DATASET VERIFICATION STATUS: %s", "PASS" if all_passed else "FAIL")

    if not all_passed:
        raise RuntimeError("Phase 4.4 LSTM dataset verification failed!")

    return report


if __name__ == "__main__":
    run_dataset_verification()
