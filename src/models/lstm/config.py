"""
NexThreat Phase 4.4 — LSTM Future Attack Forecasting Configuration.

Defines the exact engineered 13-feature contract, sequence dimensions,
deterministic candidate model architectures, 4-tier selection tie-break,
threshold sweep parameters, and serialization paths for all artifacts and reports.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Union
import numpy as np

from src.models.config import (
    PROJECT_ROOT,
    DATA_DIR,
    MODELS_DIR,
    MODEL_REPORTS_DIR,
    MODEL_READY_DIR,
    MODEL_INPUTS_DIR,
    RANDOM_SEED,
    to_project_relative,
)

# ============================================================
# EXACT ENGINEERED 13-FEATURE CONTRACT (Correction 5)
# ============================================================

LSTM_FEATURES: List[str] = [
    "flow_count",
    "packet_rate",
    "byte_rate",
    "mean_flow_duration",
    "std_flow_duration",
    "short_flow_ratio",
    "mean_packet_size",
    "packet_length_variability",
    "fwd_bwd_packet_ratio",
    "unique_dst_ports",
    "unique_dst_ips",
    "tcp_flow_ratio",
    "syn_packet_ratio",
]

FEATURE_COUNT: int = len(LSTM_FEATURES)  # 13
FEATURE_DTYPE = np.float32
LABEL_DTYPE = np.int64

# Sequence & Forecasting Dimensions
SEQUENCE_LENGTH: int = 10
FORECAST_HORIZON: int = 1  # Next window (t + 1)
INPUT_SHAPE: tuple[int, int] = (SEQUENCE_LENGTH, FEATURE_COUNT)  # (10, 13)

# Target Contract: Discrete Binary
TARGET_CLASSES: Dict[str, int] = {
    "BENIGN": 0,
    "ATTACK": 1,
}
INDEX_TO_TARGET: Dict[int, str] = {0: "BENIGN", 1: "ATTACK"}

# Scaler Fitting Dimensions (Clarification 1 & 4)
SCALER_FIT_WINDOWS: int = 1586
TRAINING_SEQUENCES_COUNT: int = 1536
LOOKBACK_WINDOWS_OFFSET: int = 50  # 5 days * 10 lookback windows = 50
EXPECTED_SCALER_SHA256: str = "0f1ee25a878ebc60c9169d4fd826a66d41565aec4e1c8e7eb5d2d5e72867cbe7"

# Expected Tensor Shapes
EXPECTED_SHAPES: Dict[str, tuple[int, ...]] = {
    "X_train": (1536, 10, 13),
    "y_train": (1536,),
    "X_validation": (382, 10, 13),
    "y_validation": (382,),
    "X_test": (286, 10, 13),
    "y_test": (286,),
}

# ============================================================
# DETERMINISTIC CANDIDATE ARCHITECTURES (Correction 6)
# ============================================================

CANDIDATES: Dict[str, Dict[str, Any]] = {
    "Candidate_A": {
        "index": 0,
        "name": "Candidate A (Standard LSTM-64)",
        "lstm_units": 64,
        "lstm_dropout": 0.20,
        "dense_units": 32,
        "dense_activation": "relu",
        "dense_dropout": 0.20,
        "output_units": 1,
        "output_activation": "sigmoid",
        "learning_rate": 0.001,
    },
    "Candidate_B": {
        "index": 1,
        "name": "Candidate B (Higher Dropout LSTM-64)",
        "lstm_units": 64,
        "lstm_dropout": 0.30,
        "dense_units": 32,
        "dense_activation": "relu",
        "dense_dropout": 0.30,
        "output_units": 1,
        "output_activation": "sigmoid",
        "learning_rate": 0.001,
    },
    "Candidate_C": {
        "index": 2,
        "name": "Candidate C (Compact LSTM-32)",
        "lstm_units": 32,
        "lstm_dropout": 0.20,
        "dense_units": 16,
        "dense_activation": "relu",
        "dense_dropout": 0.20,
        "output_units": 1,
        "output_activation": "sigmoid",
        "learning_rate": 0.001,
    },
}

# Candidate Selection Tie-Break Priority (Correction 6):
# 1. Higher Validation Attack F1
# 2. Higher Validation Attack Recall
# 3. Lower Validation Loss
# 4. Lower Candidate Index (0, 1, 2)
CANDIDATE_TIE_BREAK_POLICY: str = "val_attack_f1_desc_val_attack_recall_desc_val_loss_asc_candidate_index_asc"

# Training Hyperparameters
MAX_EPOCHS: int = 100
BATCH_SIZE: int = 32
EARLY_STOPPING_PATIENCE: int = 10
EARLY_STOPPING_MONITOR: str = "val_loss"
EARLY_STOPPING_MODE: str = "min"
RESTORE_BEST_WEIGHTS: bool = True
LOSS_FUNCTION: str = "binary_crossentropy"
OPTIMIZER_NAME: str = "adam"

# Threshold Tuning Configuration (Clarification 3)
THRESHOLD_CANDIDATES: List[float] = [
    0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70
]
# Threshold Selection Priority:
# 1. Maximize Attack Recall
# 2. Maximize Attack F1
# 3. Minimize False Positive Rate (FPR)
# 4. Minimize Threshold value
THRESHOLD_TIE_BREAK_POLICY: str = "attack_recall_desc_attack_f1_desc_fpr_asc_threshold_asc"

# Numerical Replay Tolerance
NUMERICAL_TOLERANCE: float = 1e-5

# ============================================================
# DIRECTORY & FILE PATHS
# ============================================================

# Model-Ready Inputs (Phase 3.3, Strictly Read-Only)
LSTM_READY_DIR: Path = MODEL_READY_DIR / "lstm"
LSTM_ARTIFACTS_DIR: Path = MODEL_READY_DIR / "artifacts"
LSTM_METADATA_DIR: Path = MODEL_READY_DIR / "metadata"
LSTM_MANIFESTS_DIR: Path = MODEL_INPUTS_DIR / "manifests"

INPUT_FILES: Dict[str, Path] = {
    "X_train": LSTM_READY_DIR / "X_train.npy",
    "y_train": LSTM_READY_DIR / "y_train.npy",
    "X_validation": LSTM_READY_DIR / "X_validation.npy",
    "y_validation": LSTM_READY_DIR / "y_validation.npy",
    "X_test": LSTM_READY_DIR / "X_test.npy",
    "y_test": LSTM_READY_DIR / "y_test.npy",
}

AUTHORITATIVE_SCALER_PATH: Path = LSTM_ARTIFACTS_DIR / "lstm_scaler.joblib"
LSTM_SPLIT_MANIFEST_PATH: Path = LSTM_MANIFESTS_DIR / "lstm_split_manifest.csv"
LSTM_SEQUENCE_METADATA_PATH: Path = LSTM_METADATA_DIR / "lstm_sequence_metadata.json"
LSTM_SEQUENCE_PROVENANCE_PATH: Path = LSTM_METADATA_DIR / "lstm_sequence_provenance.csv"
FEATURE_COLUMNS_METADATA_PATH: Path = LSTM_METADATA_DIR / "feature_columns.json"

# Output Model Directories (Phase 4.4)
LSTM_MODEL_DIR: Path = MODELS_DIR / "lstm"
LSTM_CHECKPOINTS_DIR: Path = LSTM_MODEL_DIR / "checkpoints"
LSTM_PREDICTIONS_DIR: Path = LSTM_MODEL_DIR / "predictions"
LSTM_REPORTS_DIR: Path = MODEL_REPORTS_DIR / "lstm"

REQUIRED_LSTM_DIRS: List[Path] = [
    LSTM_MODEL_DIR,
    LSTM_CHECKPOINTS_DIR,
    LSTM_PREDICTIONS_DIR,
    LSTM_REPORTS_DIR,
]

# Output Artifact Paths
FINAL_MODEL_PATH: Path = LSTM_MODEL_DIR / "lstm_model.keras"
MODEL_SCALER_PATH: Path = LSTM_MODEL_DIR / "lstm_scaler.joblib"  # Exact byte-for-byte copy

# Output Predictions (Clarification 3)
VAL_PREDICTIONS_PATH: Path = LSTM_PREDICTIONS_DIR / "validation_predictions.npy"
VAL_PROBABILITIES_PATH: Path = LSTM_PREDICTIONS_DIR / "validation_probabilities.npy"
TEST_PREDICTIONS_PATH: Path = LSTM_PREDICTIONS_DIR / "test_predictions.npy"
TEST_PROBABILITIES_PATH: Path = LSTM_PREDICTIONS_DIR / "test_probabilities.npy"

# Output Reports
DATASET_VERIFICATION_REPORT_PATH: Path = LSTM_REPORTS_DIR / "dataset_verification_report.json"
TRAINING_REPORT_PATH: Path = LSTM_REPORTS_DIR / "training_report.json"
THRESHOLD_REPORT_PATH: Path = LSTM_REPORTS_DIR / "threshold_report.json"
THRESHOLD_CONFIG_PATH: Path = LSTM_REPORTS_DIR / "threshold_config.json"
TEST_REPORT_PATH: Path = LSTM_REPORTS_DIR / "test_report.json"
MODEL_HASHES_PATH: Path = LSTM_REPORTS_DIR / "model_hashes.json"
PHASE_4_4_SUMMARY_PATH: Path = LSTM_REPORTS_DIR / "phase_4_4_summary.md"
