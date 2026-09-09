"""
NexThreat Phase 3.3B — XGBoost Dataset Preparation.

Prepares unscaled raw numerical feature arrays and multiclass encoded integer labels
for the XGBoost multiclass attack classification model. Preserves exact engineered
feature distributions and applies a fixed, deterministic 8-class label mapping.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd

from src.model_preparation.config import (
    XGBOOST_INPUTS_DIR,
    XGBOOST_READY_DIR,
    XGBOOST_OUTPUT_FILES,
    XGBOOST_CLASS_MAPPING,
    XGBOOST_REQUIRED_CLASSES,
    XGBOOST_NUM_CLASSES,
    XGBOOST_LABEL_ENCODER_PATH,
    XGBOOST_LABEL_MAPPING_PATH,
    FEATURE_COLUMNS,
    FEATURE_COUNT,
    FEATURE_DTYPE,
    LABEL_DTYPE,
    ATTACK_CATEGORY_COLUMN,
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


def save_xgboost_label_mapping() -> None:
    """
    Save the deterministic 8-class mapping metadata to data/model_ready/metadata/.
    """
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(XGBOOST_LABEL_MAPPING_PATH, "w", encoding="utf-8") as f:
        json.dump(XGBOOST_CLASS_MAPPING, f, indent=4)
    logger.info("Saved XGBoost class mapping metadata to %s", XGBOOST_LABEL_MAPPING_PATH)


def prepare_xgboost_datasets() -> dict[str, Any]:
    """
    Main execution pipeline for Phase 3.3B XGBoost dataset preparation.
    """
    logger.info("=" * 60)
    logger.info("STARTING PHASE 3.3B — XGBOOST DATASET PREPARATION")
    logger.info("=" * 60)

    # Ensure output directories exist
    XGBOOST_READY_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)

    # Save class mapping metadata
    save_xgboost_label_mapping()

    # Load Phase 3.2 input CSVs
    train_path = XGBOOST_INPUTS_DIR / TRAIN_CSV
    val_path = XGBOOST_INPUTS_DIR / VALIDATION_CSV
    test_path = XGBOOST_INPUTS_DIR / TEST_CSV

    logger.info("Loading XGBoost training data from %s", train_path)
    train_df = pd.read_csv(train_path)

    logger.info("Loading XGBoost validation data from %s", val_path)
    val_df = pd.read_csv(val_path)

    logger.info("Loading XGBoost test data from %s", test_path)
    test_df = pd.read_csv(test_path)

    # Extract 13 canonical features WITHOUT scaling (preserving raw values)
    missing_features = [f for f in FEATURE_COLUMNS if f not in train_df.columns]
    if missing_features:
        raise ValueError(f"Missing canonical features in XGBoost dataset: {missing_features}")

    logger.info("Extracting %d unscaled canonical features (dtype: %s)", FEATURE_COUNT, FEATURE_DTYPE)
    X_train = train_df[FEATURE_COLUMNS].to_numpy().astype(FEATURE_DTYPE)
    X_val = val_df[FEATURE_COLUMNS].to_numpy().astype(FEATURE_DTYPE)
    X_test = test_df[FEATURE_COLUMNS].to_numpy().astype(FEATURE_DTYPE)

    # Check for unmapped classes
    for name, df in [("Train", train_df), ("Validation", val_df), ("Test", test_df)]:
        unmapped = set(df[ATTACK_CATEGORY_COLUMN].unique()) - set(XGBOOST_CLASS_MAPPING.keys())
        if unmapped:
            raise ValueError(f"Unexpected attack categories in {name} split: {unmapped}")

    # Encode labels
    y_train = train_df[ATTACK_CATEGORY_COLUMN].map(XGBOOST_CLASS_MAPPING).to_numpy().astype(LABEL_DTYPE)
    y_val = val_df[ATTACK_CATEGORY_COLUMN].map(XGBOOST_CLASS_MAPPING).to_numpy().astype(LABEL_DTYPE)
    y_test = test_df[ATTACK_CATEGORY_COLUMN].map(XGBOOST_CLASS_MAPPING).to_numpy().astype(LABEL_DTYPE)

    # Class validation
    train_classes = set(np.unique(y_train))
    expected_classes = set(range(XGBOOST_NUM_CLASSES))
    if train_classes != expected_classes:
        missing = expected_classes - train_classes
        raise ValueError(f"XGBoost train labels missing required classes: {missing}")

    logger.info("Verified all %d required attack classes present in XGBoost Train split.", XGBOOST_NUM_CLASSES)

    # Sanity checks
    assert X_train.shape[1] == FEATURE_COUNT, f"Expected {FEATURE_COUNT} features, got {X_train.shape[1]}"
    assert X_val.shape[1] == FEATURE_COUNT, f"Expected {FEATURE_COUNT} features, got {X_val.shape[1]}"
    assert X_test.shape[1] == FEATURE_COUNT, f"Expected {FEATURE_COUNT} features, got {X_test.shape[1]}"
    assert len(y_train) == len(X_train), f"Train label length mismatch: {len(y_train)} vs {len(X_train)}"
    assert len(y_val) == len(X_val), f"Validation label length mismatch: {len(y_val)} vs {len(X_val)}"
    assert len(y_test) == len(X_test), f"Test label length mismatch: {len(y_test)} vs {len(X_test)}"
    assert not np.isnan(X_train).any(), "NaN detected in X_train"
    assert not np.isnan(X_val).any(), "NaN detected in X_val"
    assert not np.isnan(X_test).any(), "NaN detected in X_test"
    assert not np.isinf(X_train).any(), "Inf detected in X_train"
    assert not np.isinf(X_val).any(), "Inf detected in X_val"
    assert not np.isinf(X_test).any(), "Inf detected in X_test"

    # Save output numpy arrays
    logger.info("Saving XGBoost ready arrays to %s", XGBOOST_READY_DIR)
    np.save(XGBOOST_OUTPUT_FILES["X_train"], X_train)
    np.save(XGBOOST_OUTPUT_FILES["X_validation"], X_val)
    np.save(XGBOOST_OUTPUT_FILES["X_test"], X_test)
    np.save(XGBOOST_OUTPUT_FILES["y_train"], y_train)
    np.save(XGBOOST_OUTPUT_FILES["y_validation"], y_val)
    np.save(XGBOOST_OUTPUT_FILES["y_test"], y_test)

    # Save Label Encoder Artifact
    logger.info("Saving XGBoost label encoder artifact to %s", XGBOOST_LABEL_ENCODER_PATH)
    encoder_artifact = {
        "class_mapping": XGBOOST_CLASS_MAPPING,
        "inverse_mapping": {v: k for k, v in XGBOOST_CLASS_MAPPING.items()},
        "classes": XGBOOST_REQUIRED_CLASSES,
        "num_classes": XGBOOST_NUM_CLASSES,
    }
    joblib.dump(encoder_artifact, XGBOOST_LABEL_ENCODER_PATH)

    # Class distribution calculations
    train_dist = {cat: int((y_train == code).sum()) for cat, code in XGBOOST_CLASS_MAPPING.items()}
    val_dist = {cat: int((y_val == code).sum()) for cat, code in XGBOOST_CLASS_MAPPING.items()}
    test_dist = {cat: int((y_test == code).sum()) for cat, code in XGBOOST_CLASS_MAPPING.items()}

    results = {
        "status": "PASS",
        "train_shape": list(X_train.shape),
        "validation_shape": list(X_val.shape),
        "test_shape": list(X_test.shape),
        "scaling_applied": False,
        "num_classes": XGBOOST_NUM_CLASSES,
        "class_mapping": XGBOOST_CLASS_MAPPING,
        "train_class_distribution": train_dist,
        "validation_class_distribution": val_dist,
        "test_class_distribution": test_dist,
    }

    logger.info("Phase 3.3B XGBoost preparation completed successfully.")
    logger.info("Train shape: %s (Classes present: %d/8)", X_train.shape, len(train_classes))
    logger.info("Validation shape: %s", X_val.shape)
    logger.info("Test shape: %s", X_test.shape)

    return results


if __name__ == "__main__":
    prepare_xgboost_datasets()
