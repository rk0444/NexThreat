from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List, Any, Union
import numpy as np

# Canonical feature list from Phase 2.3
from src.feature_engineering.config import (
    FEATURE_COLUMNS as CANONICAL_FEATURE_COLUMNS,
    OUTPUT_SCHEMA_COLUMNS as CANONICAL_OUTPUT_SCHEMA_COLUMNS,
)

# Canonical dataset columns & split constants from Phase 3.2
from src.dataset_preparation.config import (
    DATASET_DAY_COLUMN as CANONICAL_DATASET_DAY_COLUMN,
    IS_ATTACK_COLUMN as CANONICAL_IS_ATTACK_COLUMN,
    ATTACK_CATEGORY_COLUMN as CANONICAL_ATTACK_CATEGORY_COLUMN,
    WINDOW_ID_COLUMN as CANONICAL_WINDOW_ID_COLUMN,
    TRAIN_CSV,
    VALIDATION_CSV,
    TEST_CSV,
    LSTM_TRAIN_WINDOWS_CSV,
    LSTM_VALIDATION_WINDOWS_CSV,
    LSTM_TEST_WINDOWS_CSV,
    AUTOENCODER_MODEL_NAME,
    XGBOOST_MODEL_NAME,
    LSTM_MODEL_NAME,
    TRAIN_SPLIT,
    VALIDATION_SPLIT,
    TEST_SPLIT,
)


# ============================================================
# PROJECT & DIRECTORY PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"

# Immutable Phase 3.2 Input Directories
MODEL_INPUTS_DIR = DATA_DIR / "model_inputs"
AUTOENCODER_INPUTS_DIR = MODEL_INPUTS_DIR / AUTOENCODER_MODEL_NAME
XGBOOST_INPUTS_DIR = MODEL_INPUTS_DIR / XGBOOST_MODEL_NAME
LSTM_INPUTS_DIR = MODEL_INPUTS_DIR / LSTM_MODEL_NAME

# Phase 3.3 Model-Ready Directories
MODEL_READY_DIR = DATA_DIR / "model_ready"
METADATA_DIR = MODEL_READY_DIR / "metadata"
ARTIFACTS_DIR = MODEL_READY_DIR / "artifacts"
REPORTS_DIR = MODEL_READY_DIR / "reports"

AUTOENCODER_READY_DIR = MODEL_READY_DIR / AUTOENCODER_MODEL_NAME
XGBOOST_READY_DIR = MODEL_READY_DIR / XGBOOST_MODEL_NAME
LSTM_READY_DIR = MODEL_READY_DIR / LSTM_MODEL_NAME


# ============================================================
# CANONICAL FEATURE & COLUMN DEFINITIONS
# ============================================================

FEATURE_COLUMNS = list(CANONICAL_FEATURE_COLUMNS)
FEATURE_COUNT = len(FEATURE_COLUMNS)  # Exactly 13

# Canonical Column Names derived from existing project configuration
DAY_COLUMN = CANONICAL_DATASET_DAY_COLUMN
IS_ATTACK_COLUMN = CANONICAL_IS_ATTACK_COLUMN
ATTACK_CATEGORY_COLUMN = CANONICAL_ATTACK_CATEGORY_COLUMN
WINDOW_ID_COLUMN = CANONICAL_WINDOW_ID_COLUMN
GLOBAL_POSITION_COLUMN = "global_position"

# Metadata columns explicitly excluded from model input tensors
METADATA_EXCLUDED_COLUMNS = [
    "global_position",
    "day",
    "day_name",
    "date",
    "timestamp",
    "Timestamp",
    "window_id",
    "window_start",
    "window_end",
    "window_index",
    "dataset_day",
    "attack_category",
    "attack_categories_present",
    "is_attack_window",
    "is_attack",
    "segment_id",
    "split",
    "model",
    "allocation_reason",
    "is_exception",
    "is_buffer",
    "notes",
]


# ============================================================
# DATA TYPES
# ============================================================

FEATURE_DTYPE = np.float32
LABEL_DTYPE = np.int64


# ============================================================
# AUTOENCODER CONFIGURATION
# ============================================================

AUTOENCODER_SCALER_TYPE = "StandardScaler"
AUTOENCODER_SCALER_FILENAME = "autoencoder_scaler.joblib"
AUTOENCODER_SCALER_PATH = ARTIFACTS_DIR / AUTOENCODER_SCALER_FILENAME

AUTOENCODER_OUTPUT_FILES = {
    "X_train": AUTOENCODER_READY_DIR / "X_train.npy",
    "X_validation": AUTOENCODER_READY_DIR / "X_validation.npy",
    "X_test": AUTOENCODER_READY_DIR / "X_test.npy",
    "y_validation": AUTOENCODER_READY_DIR / "y_validation.npy",
    "y_test": AUTOENCODER_READY_DIR / "y_test.npy",
}


# ============================================================
# XGBOOST CONFIGURATION
# ============================================================

XGBOOST_CLASS_MAPPING = {
    "BENIGN": 0,
    "Brute Force": 1,
    "Bot": 2,
    "DoS": 3,
    "Infiltration": 4,
    "PortScan": 5,
    "Web Attack": 6,
    "DDoS": 7,
}

XGBOOST_REQUIRED_CLASSES = list(XGBOOST_CLASS_MAPPING.keys())
XGBOOST_NUM_CLASSES = len(XGBOOST_CLASS_MAPPING)  # Exactly 8

XGBOOST_LABEL_ENCODER_FILENAME = "xgboost_label_encoder.joblib"
XGBOOST_LABEL_ENCODER_PATH = ARTIFACTS_DIR / XGBOOST_LABEL_ENCODER_FILENAME
XGBOOST_LABEL_MAPPING_FILENAME = "xgboost_label_mapping.json"
XGBOOST_LABEL_MAPPING_PATH = METADATA_DIR / XGBOOST_LABEL_MAPPING_FILENAME

XGBOOST_OUTPUT_FILES = {
    "X_train": XGBOOST_READY_DIR / "X_train.npy",
    "X_validation": XGBOOST_READY_DIR / "X_validation.npy",
    "X_test": XGBOOST_READY_DIR / "X_test.npy",
    "y_train": XGBOOST_READY_DIR / "y_train.npy",
    "y_validation": XGBOOST_READY_DIR / "y_validation.npy",
    "y_test": XGBOOST_READY_DIR / "y_test.npy",
}


# ============================================================
# LSTM CONFIGURATION
# ============================================================

LSTM_SEQUENCE_LENGTH = 10
LSTM_FEATURE_COUNT = 13
LSTM_MIN_WINDOWS_REQUIRED = LSTM_SEQUENCE_LENGTH + 1  # 11 windows

LSTM_SCALER_TYPE = "StandardScaler"
LSTM_SCALER_FILENAME = "lstm_scaler.joblib"
LSTM_SCALER_PATH = ARTIFACTS_DIR / LSTM_SCALER_FILENAME

LSTM_SEQUENCE_METADATA_FILENAME = "lstm_sequence_metadata.json"
LSTM_SEQUENCE_METADATA_PATH = METADATA_DIR / LSTM_SEQUENCE_METADATA_FILENAME

LSTM_PROVENANCE_FILENAME = "lstm_sequence_provenance.csv"
LSTM_PROVENANCE_PATH = METADATA_DIR / LSTM_PROVENANCE_FILENAME

LSTM_OUTPUT_FILES = {
    "X_train": LSTM_READY_DIR / "X_train.npy",
    "X_validation": LSTM_READY_DIR / "X_validation.npy",
    "X_test": LSTM_READY_DIR / "X_test.npy",
    "y_train": LSTM_READY_DIR / "y_train.npy",
    "y_validation": LSTM_READY_DIR / "y_validation.npy",
    "y_test": LSTM_READY_DIR / "y_test.npy",
}


# ============================================================
# SHARED METADATA & REPORT PATHS
# ============================================================

FEATURE_COLUMNS_METADATA_FILENAME = "feature_columns.json"
FEATURE_COLUMNS_METADATA_PATH = METADATA_DIR / FEATURE_COLUMNS_METADATA_FILENAME

PREPARATION_METADATA_FILENAME = "preparation_metadata.json"
PREPARATION_METADATA_PATH = METADATA_DIR / PREPARATION_METADATA_FILENAME

MODEL_PREPARATION_REPORT_FILENAME = "model_preparation_report.json"
MODEL_PREPARATION_REPORT_PATH = REPORTS_DIR / MODEL_PREPARATION_REPORT_FILENAME


# ============================================================
# PHASE 3.2 IMMUTABILITY VERIFICATION FILES
# ============================================================

PHASE_3_2_INPUT_FILES = {
    "autoencoder/train.csv": AUTOENCODER_INPUTS_DIR / TRAIN_CSV,
    "autoencoder/validation.csv": AUTOENCODER_INPUTS_DIR / VALIDATION_CSV,
    "autoencoder/test.csv": AUTOENCODER_INPUTS_DIR / TEST_CSV,
    "xgboost/train.csv": XGBOOST_INPUTS_DIR / TRAIN_CSV,
    "xgboost/validation.csv": XGBOOST_INPUTS_DIR / VALIDATION_CSV,
    "xgboost/test.csv": XGBOOST_INPUTS_DIR / TEST_CSV,
    "lstm/train_windows.csv": LSTM_INPUTS_DIR / LSTM_TRAIN_WINDOWS_CSV,
    "lstm/validation_windows.csv": LSTM_INPUTS_DIR / LSTM_VALIDATION_WINDOWS_CSV,
    "lstm/test_windows.csv": LSTM_INPUTS_DIR / LSTM_TEST_WINDOWS_CSV,
}


# ============================================================
# SHA-256 CRYPTOGRAPHIC HASH HELPER
# ============================================================

def calculate_file_sha256(file_path: Path | str) -> str:
    """
    Calculate the SHA-256 cryptographic hash of a file by reading in binary chunks.
    Avoids loading large files entirely into memory.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Target file for SHA-256 calculation does not exist: {path}")

    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_phase_3_2_input_hashes() -> dict[str, str]:
    """
    Compute SHA-256 hashes for all Phase 3.2 input CSV files.
    """
    hashes = {}
    for rel_name, file_path in PHASE_3_2_INPUT_FILES.items():
        hashes[rel_name] = calculate_file_sha256(file_path)
    return hashes
