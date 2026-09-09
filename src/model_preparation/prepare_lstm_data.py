"""
NexThreat Phase 3.3C — LSTM Dataset & Sequence Preparation.

Prepares scaled 3D temporal sequence tensors (N, 10, 13) and binary forecasting targets
for the LSTM attack forecasting model. Sequences are generated independently per
partition (train/validation/test) and per day (using the canonical day column)
to strictly prevent cross-split or cross-day boundary bleeding. Also records comprehensive
sequence provenance metadata for independent chronological verification.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from src.model_preparation.config import (
    LSTM_INPUTS_DIR,
    LSTM_READY_DIR,
    LSTM_OUTPUT_FILES,
    LSTM_SEQUENCE_LENGTH,
    LSTM_FEATURE_COUNT,
    LSTM_MIN_WINDOWS_REQUIRED,
    LSTM_SCALER_PATH,
    LSTM_SCALER_TYPE,
    LSTM_PROVENANCE_PATH,
    LSTM_SEQUENCE_METADATA_PATH,
    PREPARATION_METADATA_PATH,
    DAY_COLUMN,
    GLOBAL_POSITION_COLUMN,
    IS_ATTACK_COLUMN,
    FEATURE_COLUMNS,
    FEATURE_COUNT,
    FEATURE_DTYPE,
    LABEL_DTYPE,
    METADATA_DIR,
    ARTIFACTS_DIR,
    LSTM_TRAIN_WINDOWS_CSV,
    LSTM_VALIDATION_WINDOWS_CSV,
    LSTM_TEST_WINDOWS_CSV,
    AUTOENCODER_SCALER_TYPE,
    XGBOOST_NUM_CLASSES,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def generate_partition_sequences(
    df: pd.DataFrame,
    scaled_features: np.ndarray,
    split_name: str,
) -> tuple[np.ndarray, np.ndarray, list[dict[str, Any]], dict[str, Any]]:
    """
    Generate rolling sequence tensors and binary targets for a single partition.
    Ensures zero cross-day boundary bleeding by grouping strictly by canonical DAY_COLUMN.
    """
    # Detect day column from dataframe if canonical name differs
    day_col = DAY_COLUMN if DAY_COLUMN in df.columns else ("day_name" if "day_name" in df.columns else "day")
    if day_col not in df.columns:
        raise KeyError(f"Neither '{DAY_COLUMN}', 'day_name', nor 'day' found in dataframe columns: {df.columns.tolist()}")

    sequences_list: list[np.ndarray] = []
    targets_list: list[int] = []
    provenance_list: list[dict[str, Any]] = []

    days_processed: list[str] = []
    days_skipped: list[dict[str, Any]] = []

    # Map dataframe rows to scaled feature array rows
    df = df.copy().reset_index(drop=True)
    df["_array_idx"] = np.arange(len(df))

    # Group strictly by day
    for day_value, day_group in df.groupby(day_col, sort=False):
        # Sort chronologically by global_position (or index)
        if GLOBAL_POSITION_COLUMN in day_group.columns:
            sorted_day_df = day_group.sort_values(by=GLOBAL_POSITION_COLUMN).reset_index(drop=True)
        else:
            sorted_day_df = day_group.reset_index(drop=True)

        num_day_windows = len(sorted_day_df)

        # Handle short partition days gracefully
        if num_day_windows < LSTM_MIN_WINDOWS_REQUIRED:
            logger.warning(
                "Skipping split=%s day=%s: contains %d windows (< %d required for seq_len=%d + target)",
                split_name,
                day_value,
                num_day_windows,
                LSTM_MIN_WINDOWS_REQUIRED,
                LSTM_SEQUENCE_LENGTH,
            )
            days_skipped.append({
                "day": str(day_value),
                "window_count": int(num_day_windows),
                "reason": f"Fewer than {LSTM_MIN_WINDOWS_REQUIRED} windows",
            })
            continue

        days_processed.append(str(day_value))
        day_indices = sorted_day_df["_array_idx"].to_numpy()
        day_scaled_feats = scaled_features[day_indices]
        day_targets = (sorted_day_df[IS_ATTACK_COLUMN] != 0).astype(int).to_numpy()
        day_global_positions = sorted_day_df[GLOBAL_POSITION_COLUMN].to_numpy() if GLOBAL_POSITION_COLUMN in sorted_day_df.columns else day_indices

        # Construct sequences: observe previous 10 windows -> predict next window t
        for target_idx in range(LSTM_SEQUENCE_LENGTH, num_day_windows):
            seq_feats = day_scaled_feats[target_idx - LSTM_SEQUENCE_LENGTH : target_idx]
            target_val = int(day_targets[target_idx])

            sequences_list.append(seq_feats)
            targets_list.append(target_val)

            # Record detailed provenance record
            seq_start_pos = int(day_global_positions[target_idx - LSTM_SEQUENCE_LENGTH])
            seq_end_pos = int(day_global_positions[target_idx - 1])
            target_pos = int(day_global_positions[target_idx])

            provenance_list.append({
                "split": split_name,
                "day": str(day_value),
                "sequence_start_global_position": seq_start_pos,
                "sequence_end_global_position": seq_end_pos,
                "target_global_position": target_pos,
                "target_attack_status": target_val,
            })

    if not sequences_list:
        X_split = np.empty((0, LSTM_SEQUENCE_LENGTH, LSTM_FEATURE_COUNT), dtype=FEATURE_DTYPE)
        y_split = np.empty((0,), dtype=LABEL_DTYPE)
    else:
        X_split = np.array(sequences_list, dtype=FEATURE_DTYPE)
        y_split = np.array(targets_list, dtype=LABEL_DTYPE)

    split_stats = {
        "sequence_count": int(len(X_split)),
        "days_processed": days_processed,
        "days_skipped": days_skipped,
        "attack_target_count": int(np.sum(y_split)) if len(y_split) > 0 else 0,
        "benign_target_count": int(len(y_split) - np.sum(y_split)) if len(y_split) > 0 else 0,
    }

    return X_split, y_split, provenance_list, split_stats


def save_preparation_metadata() -> None:
    """
    Save the complete Phase 3.3 preparation architecture metadata.
    """
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    prep_metadata = {
        "phase": "3.3",
        "feature_configuration": {
            "feature_count": FEATURE_COUNT,
            "feature_dtype": "float32",
            "feature_columns": FEATURE_COLUMNS,
        },
        "autoencoder": {
            "scaler": AUTOENCODER_SCALER_TYPE,
            "scaler_fit_partition": "train",
            "training_policy": "BENIGN_ONLY",
            "evaluation_labels": "binary",
        },
        "xgboost": {
            "scaling_applied": False,
            "feature_dtype": "float32",
            "label_dtype": "int64",
            "class_count": XGBOOST_NUM_CLASSES,
        },
        "lstm": {
            "scaler": LSTM_SCALER_TYPE,
            "scaler_fit_partition": "train",
            "sequence_length": LSTM_SEQUENCE_LENGTH,
            "feature_count": LSTM_FEATURE_COUNT,
            "target_type": "binary_attack_forecast",
            "generation_policy": "partition_and_day_isolated",
            "cross_partition_sequences_allowed": False,
            "cross_day_sequences_allowed": False,
        },
    }
    with open(PREPARATION_METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(prep_metadata, f, indent=4)
    logger.info("Saved preparation architecture metadata to %s", PREPARATION_METADATA_PATH)


def prepare_lstm_datasets() -> dict[str, Any]:
    """
    Main execution pipeline for Phase 3.3C LSTM dataset and sequence preparation.
    """
    logger.info("=" * 60)
    logger.info("STARTING PHASE 3.3C — LSTM DATASET & SEQUENCE PREPARATION")
    logger.info("=" * 60)

    # Ensure output directories exist
    LSTM_READY_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)

    # Load Phase 3.2 immutable input CSVs
    train_path = LSTM_INPUTS_DIR / LSTM_TRAIN_WINDOWS_CSV
    val_path = LSTM_INPUTS_DIR / LSTM_VALIDATION_WINDOWS_CSV
    test_path = LSTM_INPUTS_DIR / LSTM_TEST_WINDOWS_CSV

    logger.info("Loading LSTM train windows from %s", train_path)
    train_df = pd.read_csv(train_path)

    logger.info("Loading LSTM validation windows from %s", val_path)
    val_df = pd.read_csv(val_path)

    logger.info("Loading LSTM test windows from %s", test_path)
    test_df = pd.read_csv(test_path)

    # Fit StandardScaler STRICTLY on LSTM train windows
    X_train_raw = train_df[FEATURE_COLUMNS].to_numpy()
    X_val_raw = val_df[FEATURE_COLUMNS].to_numpy()
    X_test_raw = test_df[FEATURE_COLUMNS].to_numpy()

    logger.info("Fitting %s strictly on LSTM train windows (shape: %s)", LSTM_SCALER_TYPE, X_train_raw.shape)
    scaler = StandardScaler()
    scaler.fit(X_train_raw)

    # Transform window features
    train_scaled = scaler.transform(X_train_raw).astype(FEATURE_DTYPE)
    val_scaled = scaler.transform(X_val_raw).astype(FEATURE_DTYPE)
    test_scaled = scaler.transform(X_test_raw).astype(FEATURE_DTYPE)

    # Generate 3D sequences independently per split
    logger.info("Generating Train sequences...")
    X_train, y_train, train_prov, train_stats = generate_partition_sequences(
        train_df, train_scaled, "train"
    )

    logger.info("Generating Validation sequences...")
    X_val, y_val, val_prov, val_stats = generate_partition_sequences(
        val_df, val_scaled, "validation"
    )

    logger.info("Generating Test sequences...")
    X_test, y_test, test_prov, test_stats = generate_partition_sequences(
        test_df, test_scaled, "test"
    )

    # Combine provenance records
    all_provenance = train_prov + val_prov + test_prov
    prov_df = pd.DataFrame(all_provenance)

    # Save provenance CSV
    logger.info("Saving LSTM sequence provenance to %s (%d records)", LSTM_PROVENANCE_PATH, len(prov_df))
    prov_df.to_csv(LSTM_PROVENANCE_PATH, index=False)

    # Save sequence metadata JSON
    sequence_metadata = {
        "sequence_length": LSTM_SEQUENCE_LENGTH,
        "feature_count": LSTM_FEATURE_COUNT,
        "generation_policy": "partition_and_day_isolated",
        "cross_partition_sequences_allowed": False,
        "cross_day_sequences_allowed": False,
        "total_sequences_generated": int(len(prov_df)),
        "train": train_stats,
        "validation": val_stats,
        "test": test_stats,
    }
    with open(LSTM_SEQUENCE_METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(sequence_metadata, f, indent=4)
    logger.info("Saved LSTM sequence metadata to %s", LSTM_SEQUENCE_METADATA_PATH)

    # Save master preparation metadata
    save_preparation_metadata()

    # Sanity checks
    assert X_train.ndim == 3, f"Expected 3D tensor for X_train, got {X_train.ndim}D"
    assert X_train.shape[1] == LSTM_SEQUENCE_LENGTH, f"Expected seq_len {LSTM_SEQUENCE_LENGTH}, got {X_train.shape[1]}"
    assert X_train.shape[2] == LSTM_FEATURE_COUNT, f"Expected features {LSTM_FEATURE_COUNT}, got {X_train.shape[2]}"
    assert X_val.ndim == 3 and X_val.shape[1] == LSTM_SEQUENCE_LENGTH and X_val.shape[2] == LSTM_FEATURE_COUNT
    assert X_test.ndim == 3 and X_test.shape[1] == LSTM_SEQUENCE_LENGTH and X_test.shape[2] == LSTM_FEATURE_COUNT
    assert len(X_train) == len(y_train), f"Train shape mismatch: {len(X_train)} vs {len(y_train)}"
    assert len(X_val) == len(y_val), f"Validation shape mismatch: {len(X_val)} vs {len(y_val)}"
    assert len(X_test) == len(y_test), f"Test shape mismatch: {len(X_test)} vs {len(y_test)}"
    assert len(prov_df) == len(X_train) + len(X_val) + len(X_test), "Provenance row count mismatch"
    assert not np.isnan(X_train).any(), "NaN in X_train"
    assert not np.isnan(X_val).any(), "NaN in X_val"
    assert not np.isnan(X_test).any(), "NaN in X_test"

    # Save output numpy arrays
    logger.info("Saving LSTM ready arrays to %s", LSTM_READY_DIR)
    np.save(LSTM_OUTPUT_FILES["X_train"], X_train)
    np.save(LSTM_OUTPUT_FILES["X_validation"], X_val)
    np.save(LSTM_OUTPUT_FILES["X_test"], X_test)
    np.save(LSTM_OUTPUT_FILES["y_train"], y_train)
    np.save(LSTM_OUTPUT_FILES["y_validation"], y_val)
    np.save(LSTM_OUTPUT_FILES["y_test"], y_test)

    # Save Scaler artifact
    logger.info("Saving LSTM scaler artifact to %s", LSTM_SCALER_PATH)
    joblib.dump(scaler, LSTM_SCALER_PATH)

    results = {
        "status": "PASS",
        "train_shape": list(X_train.shape),
        "validation_shape": list(X_val.shape),
        "test_shape": list(X_test.shape),
        "total_sequences": int(len(prov_df)),
        "train_stats": train_stats,
        "validation_stats": val_stats,
        "test_stats": test_stats,
    }

    logger.info("Phase 3.3C LSTM preparation completed successfully.")
    logger.info("X_train shape: %s, y_train shape: %s", X_train.shape, y_train.shape)
    logger.info("X_val shape: %s, y_val shape: %s", X_val.shape, y_val.shape)
    logger.info("X_test shape: %s, y_test shape: %s", X_test.shape, y_test.shape)

    return results


if __name__ == "__main__":
    prepare_lstm_datasets()
