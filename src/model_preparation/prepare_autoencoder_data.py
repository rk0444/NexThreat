"""
NexThreat Phase 3.3A — Autoencoder Dataset Preparation.

Prepares scaled numerical feature arrays and binary evaluation labels for the
Autoencoder anomaly detection model. Fits StandardScaler strictly on Pure-BENIGN
training data to prevent any data leakage from validation or test splits.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from src.model_preparation.config import (
    AUTOENCODER_INPUTS_DIR,
    AUTOENCODER_OUTPUT_FILES,
    AUTOENCODER_READY_DIR,
    AUTOENCODER_SCALER_PATH,
    AUTOENCODER_SCALER_TYPE,
    FEATURE_COLUMNS,
    FEATURE_COUNT,
    FEATURE_DTYPE,
    FEATURE_COLUMNS_METADATA_PATH,
    IS_ATTACK_COLUMN,
    ATTACK_CATEGORY_COLUMN,
    LABEL_DTYPE,
    METADATA_DIR,
    ARTIFACTS_DIR,
    TRAIN_CSV,
    VALIDATION_CSV,
    TEST_CSV,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def save_canonical_feature_metadata() -> None:
    """
    Save the canonical 13-feature metadata artifact to data/model_ready/metadata/.
    """
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    metadata = {
        "feature_count": FEATURE_COUNT,
        "feature_columns": FEATURE_COLUMNS,
    }
    with open(FEATURE_COLUMNS_METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
    logger.info("Saved canonical feature metadata to %s", FEATURE_COLUMNS_METADATA_PATH)


def prepare_autoencoder_datasets() -> dict[str, Any]:
    """
    Main execution pipeline for Phase 3.3A Autoencoder dataset preparation.
    """
    logger.info("=" * 60)
    logger.info("STARTING PHASE 3.3A — AUTOENCODER DATASET PREPARATION")
    logger.info("=" * 60)

    # Ensure directories exist
    AUTOENCODER_READY_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)

    # Save feature metadata
    save_canonical_feature_metadata()

    # Load Phase 3.2 immutable input CSVs
    train_path = AUTOENCODER_INPUTS_DIR / TRAIN_CSV
    val_path = AUTOENCODER_INPUTS_DIR / VALIDATION_CSV
    test_path = AUTOENCODER_INPUTS_DIR / TEST_CSV

    logger.info("Loading Autoencoder training data from %s", train_path)
    train_df = pd.read_csv(train_path)

    logger.info("Loading Autoencoder validation data from %s", val_path)
    val_df = pd.read_csv(val_path)

    logger.info("Loading Autoencoder test data from %s", test_path)
    test_df = pd.read_csv(test_path)

    # Verify Autoencoder training source is strictly Pure-BENIGN
    non_benign_count = (train_df[IS_ATTACK_COLUMN] != 0).sum()
    if non_benign_count > 0:
        raise ValueError(
            f"CRITICAL ERROR: Autoencoder training source contains {non_benign_count} non-benign windows!"
        )
    logger.info("Verified Autoencoder train source: 100%% Pure BENIGN (%d windows)", len(train_df))

    # Extract 13 canonical features
    missing_features = [f for f in FEATURE_COLUMNS if f not in train_df.columns]
    if missing_features:
        raise ValueError(f"Missing canonical features in dataset: {missing_features}")

    X_train_raw = train_df[FEATURE_COLUMNS].to_numpy()
    X_val_raw = val_df[FEATURE_COLUMNS].to_numpy()
    X_test_raw = test_df[FEATURE_COLUMNS].to_numpy()

    # Fit StandardScaler STRICTLY on Autoencoder training features
    logger.info("Fitting %s strictly on Autoencoder X_train (shape: %s)", AUTOENCODER_SCALER_TYPE, X_train_raw.shape)
    scaler = StandardScaler()
    scaler.fit(X_train_raw)

    # Transform splits
    X_train = scaler.transform(X_train_raw).astype(FEATURE_DTYPE)
    X_val = scaler.transform(X_val_raw).astype(FEATURE_DTYPE)
    X_test = scaler.transform(X_test_raw).astype(FEATURE_DTYPE)

    # Generate Binary Evaluation Labels (0 = BENIGN, 1 = Attack)
    y_val = (val_df[IS_ATTACK_COLUMN] != 0).astype(LABEL_DTYPE).to_numpy()
    y_test = (test_df[IS_ATTACK_COLUMN] != 0).astype(LABEL_DTYPE).to_numpy()

    # Sanity checks
    assert X_train.shape[1] == FEATURE_COUNT, f"Expected {FEATURE_COUNT} features, got {X_train.shape[1]}"
    assert X_val.shape[1] == FEATURE_COUNT, f"Expected {FEATURE_COUNT} features, got {X_val.shape[1]}"
    assert X_test.shape[1] == FEATURE_COUNT, f"Expected {FEATURE_COUNT} features, got {X_test.shape[1]}"
    assert len(y_val) == len(X_val), f"Validation label length mismatch: {len(y_val)} vs {len(X_val)}"
    assert len(y_test) == len(X_test), f"Test label length mismatch: {len(y_test)} vs {len(X_test)}"
    assert not np.isnan(X_train).any(), "NaN detected in X_train"
    assert not np.isnan(X_val).any(), "NaN detected in X_val"
    assert not np.isnan(X_test).any(), "NaN detected in X_test"
    assert not np.isinf(X_train).any(), "Inf detected in X_train"
    assert not np.isinf(X_val).any(), "Inf detected in X_val"
    assert not np.isinf(X_test).any(), "Inf detected in X_test"

    # Save output numpy arrays
    logger.info("Saving Autoencoder ready arrays to %s", AUTOENCODER_READY_DIR)
    np.save(AUTOENCODER_OUTPUT_FILES["X_train"], X_train)
    np.save(AUTOENCODER_OUTPUT_FILES["X_validation"], X_val)
    np.save(AUTOENCODER_OUTPUT_FILES["X_test"], X_test)
    np.save(AUTOENCODER_OUTPUT_FILES["y_validation"], y_val)
    np.save(AUTOENCODER_OUTPUT_FILES["y_test"], y_test)

    # Save Scaler artifact
    logger.info("Saving Autoencoder scaler artifact to %s", AUTOENCODER_SCALER_PATH)
    joblib.dump(scaler, AUTOENCODER_SCALER_PATH)

    val_attacks = int(np.sum(y_val))
    val_benign = int(len(y_val) - val_attacks)
    test_attacks = int(np.sum(y_test))
    test_benign = int(len(y_test) - test_attacks)

    results = {
        "status": "PASS",
        "train_shape": list(X_train.shape),
        "validation_shape": list(X_val.shape),
        "test_shape": list(X_test.shape),
        "scaler_type": AUTOENCODER_SCALER_TYPE,
        "scaler_feature_count": int(scaler.n_features_in_),
        "validation_attack_distribution": {
            "total": int(len(y_val)),
            "benign": val_benign,
            "attack": val_attacks,
            "attack_ratio": float(val_attacks / len(y_val)) if len(y_val) > 0 else 0.0,
        },
        "test_attack_distribution": {
            "total": int(len(y_test)),
            "benign": test_benign,
            "attack": test_attacks,
            "attack_ratio": float(test_attacks / len(y_test)) if len(y_test) > 0 else 0.0,
        },
    }

    logger.info("Phase 3.3A Autoencoder preparation completed successfully.")
    logger.info("Train shape: %s (Pure BENIGN)", X_train.shape)
    logger.info("Validation shape: %s (Benign: %d, Attack: %d)", X_val.shape, val_benign, val_attacks)
    logger.info("Test shape: %s (Benign: %d, Attack: %d)", X_test.shape, test_benign, test_attacks)

    return results


if __name__ == "__main__":
    prepare_autoencoder_datasets()
