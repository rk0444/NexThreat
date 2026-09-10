"""
NexThreat Phase 4.1 — Centralized Model Training Infrastructure Configuration.

Defines canonical directory hierarchies, reproducibility seeds, input dataset
specifications, and serialization paths for all modeling phases (Autoencoder,
XGBoost, LSTM).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Union
import numpy as np

# Canonical feature list from Phase 2.3 / Phase 3.3
from src.feature_engineering.config import (
    FEATURE_COLUMNS as CANONICAL_FEATURE_COLUMNS,
)

# Canonical dataset split names and model identifiers from Phase 3.2 / 3.3
from src.dataset_preparation.config import (
    AUTOENCODER_MODEL_NAME,
    XGBOOST_MODEL_NAME,
    LSTM_MODEL_NAME,
    TRAIN_SPLIT,
    VALIDATION_SPLIT,
    TEST_SPLIT,
)


# ============================================================
# PROJECT & DIRECTORY ROOTS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"

# Phase 4 Directories
MODELS_DIR = DATA_DIR / "models"
MODEL_REPORTS_DIR = DATA_DIR / "model_reports"

# Previous Phase Data Directories (Treated as Strictly Read-Only)
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
WINDOWS_DATA_DIR = DATA_DIR / "windows"
FEATURES_DATA_DIR = DATA_DIR / "features"
MODEL_INPUTS_DIR = DATA_DIR / "model_inputs"
MODEL_READY_DIR = DATA_DIR / "model_ready"

READ_ONLY_DIRECTORIES: List[Path] = [
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    WINDOWS_DATA_DIR,
    FEATURES_DATA_DIR,
    MODEL_INPUTS_DIR,
    MODEL_READY_DIR,
]


# ============================================================
# REPRODUCIBILITY CONFIGURATION
# ============================================================

RANDOM_SEED: int = 42
ENABLE_DETERMINISTIC_OPERATIONS: bool = True


# ============================================================
# CANONICAL DIRECTORY COLLECTIONS (Refinements 1 & 6)
# ============================================================

MODEL_DIRECTORIES: List[Path] = [
    MODELS_DIR,
    MODELS_DIR / "autoencoder",
    MODELS_DIR / "autoencoder" / "checkpoints",
    MODELS_DIR / "xgboost",
    MODELS_DIR / "xgboost" / "checkpoints",
    MODELS_DIR / "lstm",
    MODELS_DIR / "lstm" / "checkpoints",
    MODELS_DIR / "baseline",
    MODELS_DIR / "baseline" / "checkpoints",
]

REPORT_DIRECTORIES: List[Path] = [
    MODEL_REPORTS_DIR,
    MODEL_REPORTS_DIR / "infrastructure",
    MODEL_REPORTS_DIR / "autoencoder",
    MODEL_REPORTS_DIR / "xgboost",
    MODEL_REPORTS_DIR / "lstm",
    MODEL_REPORTS_DIR / "baseline",
    MODEL_REPORTS_DIR / "comparison",
    MODEL_REPORTS_DIR / "figures",
]

REQUIRED_DIRECTORIES: List[Path] = [
    *MODEL_DIRECTORIES,
    *REPORT_DIRECTORIES,
]


# ============================================================
# PHASE 4.1 INFRASTRUCTURE REPORT PATHS
# ============================================================

INFRASTRUCTURE_REPORT_DIR = MODEL_REPORTS_DIR / "infrastructure"
INFRASTRUCTURE_METADATA_PATH = INFRASTRUCTURE_REPORT_DIR / "infrastructure_metadata.json"
MODEL_INFRASTRUCTURE_VERIFICATION_REPORT_PATH = (
    INFRASTRUCTURE_REPORT_DIR / "model_infrastructure_verification_report.json"
)


# ============================================================
# IMMUTABLE PHASE 3.3 MODEL-READY INPUT PATHS
# ============================================================

AUTOENCODER_READY_DIR = MODEL_READY_DIR / AUTOENCODER_MODEL_NAME
XGBOOST_READY_DIR = MODEL_READY_DIR / XGBOOST_MODEL_NAME
LSTM_READY_DIR = MODEL_READY_DIR / LSTM_MODEL_NAME

METADATA_DIR = MODEL_READY_DIR / "metadata"
ARTIFACTS_DIR = MODEL_READY_DIR / "artifacts"
REPORTS_DIR = MODEL_READY_DIR / "reports"

# Autoencoder Input Arrays & Scaler
AUTOENCODER_INPUT_FILES: Dict[str, Path] = {
    "X_train": AUTOENCODER_READY_DIR / "X_train.npy",
    "X_validation": AUTOENCODER_READY_DIR / "X_validation.npy",
    "X_test": AUTOENCODER_READY_DIR / "X_test.npy",
    "y_validation": AUTOENCODER_READY_DIR / "y_validation.npy",
    "y_test": AUTOENCODER_READY_DIR / "y_test.npy",
}
AUTOENCODER_SCALER_PATH = ARTIFACTS_DIR / "autoencoder_scaler.joblib"

# XGBoost Input Arrays & Encoder
XGBOOST_INPUT_FILES: Dict[str, Path] = {
    "X_train": XGBOOST_READY_DIR / "X_train.npy",
    "X_validation": XGBOOST_READY_DIR / "X_validation.npy",
    "X_test": XGBOOST_READY_DIR / "X_test.npy",
    "y_train": XGBOOST_READY_DIR / "y_train.npy",
    "y_validation": XGBOOST_READY_DIR / "y_validation.npy",
    "y_test": XGBOOST_READY_DIR / "y_test.npy",
}
XGBOOST_LABEL_ENCODER_PATH = ARTIFACTS_DIR / "xgboost_label_encoder.joblib"
XGBOOST_LABEL_MAPPING_PATH = METADATA_DIR / "xgboost_label_mapping.json"

# LSTM Input Arrays & Scaler
LSTM_INPUT_FILES: Dict[str, Path] = {
    "X_train": LSTM_READY_DIR / "X_train.npy",
    "X_validation": LSTM_READY_DIR / "X_validation.npy",
    "X_test": LSTM_READY_DIR / "X_test.npy",
    "y_train": LSTM_READY_DIR / "y_train.npy",
    "y_validation": LSTM_READY_DIR / "y_validation.npy",
    "y_test": LSTM_READY_DIR / "y_test.npy",
}
LSTM_SCALER_PATH = ARTIFACTS_DIR / "lstm_scaler.joblib"
LSTM_SEQUENCE_METADATA_PATH = METADATA_DIR / "lstm_sequence_metadata.json"
LSTM_PROVENANCE_PATH = METADATA_DIR / "lstm_sequence_provenance.csv"

# Shared Phase 3.3 Metadata & Report
FEATURE_COLUMNS_METADATA_PATH = METADATA_DIR / "feature_columns.json"
PREPARATION_METADATA_PATH = METADATA_DIR / "preparation_metadata.json"
MODEL_PREPARATION_REPORT_PATH = REPORTS_DIR / "model_preparation_report.json"

# All 16 Input Arrays Combined for Auditing
ALL_MODEL_READY_ARRAYS: Dict[str, Path] = {
    **{f"autoencoder/{k}": p for k, p in AUTOENCODER_INPUT_FILES.items()},
    **{f"xgboost/{k}": p for k, p in XGBOOST_INPUT_FILES.items()},
    **{f"lstm/{k}": p for k, p in LSTM_INPUT_FILES.items()},
}

ALL_MODEL_READY_ARTIFACTS: Dict[str, Path] = {
    "autoencoder_scaler": AUTOENCODER_SCALER_PATH,
    "xgboost_label_encoder": XGBOOST_LABEL_ENCODER_PATH,
    "lstm_scaler": LSTM_SCALER_PATH,
}

ALL_MODEL_READY_METADATA: Dict[str, Path] = {
    "feature_columns": FEATURE_COLUMNS_METADATA_PATH,
    "preparation_metadata": PREPARATION_METADATA_PATH,
    "xgboost_label_mapping": XGBOOST_LABEL_MAPPING_PATH,
    "lstm_sequence_metadata": LSTM_SEQUENCE_METADATA_PATH,
    "lstm_sequence_provenance": LSTM_PROVENANCE_PATH,
    "model_preparation_report": MODEL_PREPARATION_REPORT_PATH,
}


# ============================================================
# CANONICAL MODEL SPECIFICATIONS & TENSOR SCHEMAS
# ============================================================

FEATURE_COLUMNS = list(CANONICAL_FEATURE_COLUMNS)
FEATURE_COUNT = len(FEATURE_COLUMNS)  # 13
FEATURE_DTYPE = np.float32
LABEL_DTYPE = np.int64

LSTM_SEQUENCE_LENGTH = 10
LSTM_FEATURE_COUNT = 13

XGBOOST_NUM_CLASSES = 8
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

# Expected Array Specifications (ndim, dtype, feature_dim)
EXPECTED_TENSOR_SPECS: Dict[str, Dict[str, Any]] = {
    # Autoencoder
    "autoencoder/X_train": {"ndim": 2, "dtype": np.float32, "feature_dim": 13, "expected_shape": (1511, 13)},
    "autoencoder/X_validation": {"ndim": 2, "dtype": np.float32, "feature_dim": 13, "expected_shape": (535, 13)},
    "autoencoder/X_test": {"ndim": 2, "dtype": np.float32, "feature_dim": 13, "expected_shape": (408, 13)},
    "autoencoder/y_validation": {"ndim": 1, "dtype": np.int64, "feature_dim": None, "expected_shape": (535,)},
    "autoencoder/y_test": {"ndim": 1, "dtype": np.int64, "feature_dim": None, "expected_shape": (408,)},
    # XGBoost
    "xgboost/X_train": {"ndim": 2, "dtype": np.float32, "feature_dim": 13, "expected_shape": (1799, 13)},
    "xgboost/X_validation": {"ndim": 2, "dtype": np.float32, "feature_dim": 13, "expected_shape": (325, 13)},
    "xgboost/X_test": {"ndim": 2, "dtype": np.float32, "feature_dim": 13, "expected_shape": (319, 13)},
    "xgboost/y_train": {"ndim": 1, "dtype": np.int64, "feature_dim": None, "expected_shape": (1799,)},
    "xgboost/y_validation": {"ndim": 1, "dtype": np.int64, "feature_dim": None, "expected_shape": (325,)},
    "xgboost/y_test": {"ndim": 1, "dtype": np.int64, "feature_dim": None, "expected_shape": (319,)},
    # LSTM
    "lstm/X_train": {"ndim": 3, "dtype": np.float32, "feature_dim": 13, "expected_shape": (1536, 10, 13)},
    "lstm/X_validation": {"ndim": 3, "dtype": np.float32, "feature_dim": 13, "expected_shape": (382, 10, 13)},
    "lstm/X_test": {"ndim": 3, "dtype": np.float32, "feature_dim": 13, "expected_shape": (286, 10, 13)},
    "lstm/y_train": {"ndim": 1, "dtype": np.int64, "feature_dim": None, "expected_shape": (1536,)},
    "lstm/y_validation": {"ndim": 1, "dtype": np.int64, "feature_dim": None, "expected_shape": (382,)},
    "lstm/y_test": {"ndim": 1, "dtype": np.int64, "feature_dim": None, "expected_shape": (286,)},
}


# ============================================================
# RELATIVE PATH HELPER (Refinement 7)
# ============================================================

def to_project_relative(path: Union[Path, str]) -> str:
    """
    Convert an absolute or local path to a project-root relative POSIX path.
    Ensures metadata files are machine-independent and portable across
    operating systems (Windows, Linux, macOS).
    """
    p = Path(path).resolve()
    try:
        rel = p.relative_to(PROJECT_ROOT.resolve())
        return rel.as_posix()
    except ValueError:
        return p.as_posix()
