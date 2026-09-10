"""
NexThreat Phase 4.2 — Autoencoder Centralized Configuration.

Defines model architecture dimensions, training hyperparameters, threshold selection
policy, and serialization paths for all Autoencoder artifacts and reports.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from src.models.config import (
    FEATURE_COUNT,
    FEATURE_DTYPE,
    LABEL_DTYPE,
    RANDOM_SEED,
    MODELS_DIR,
    MODEL_REPORTS_DIR,
    AUTOENCODER_INPUT_FILES,
    AUTOENCODER_SCALER_PATH,
    to_project_relative,
)

# ============================================================
# ARCHITECTURE CONFIGURATION
# ============================================================

INPUT_DIM: int = FEATURE_COUNT  # Canonical 13 features
LATENT_DIM: int = 8             # Bottleneck compression dimension

# Layer sizes: 13 -> 32 -> 16 -> 8 -> 16 -> 32 -> 13
ENCODER_DIMS: List[int] = [32, 16, 8]
DECODER_DIMS: List[int] = [16, 32, INPUT_DIM]
LAYER_DIMS: List[int] = [INPUT_DIM, 32, 16, 8, 16, 32, INPUT_DIM]

HIDDEN_ACTIVATION: str = "relu"
OUTPUT_ACTIVATION: str = "linear"  # Reconstructing standardized continuous features
LOSS_FUNCTION: str = "mean_squared_error"
OPTIMIZER_NAME: str = "adam"


# ============================================================
# TRAINING HYPERPARAMETERS
# ============================================================

BATCH_SIZE: int = 32
MAX_EPOCHS: int = 100
LEARNING_RATE: float = 0.001

EARLY_STOPPING_MONITOR: str = "val_loss"
EARLY_STOPPING_MODE: str = "min"
EARLY_STOPPING_PATIENCE: int = 10
RESTORE_BEST_WEIGHTS: bool = True


# ============================================================
# THRESHOLD SELECTION CONFIGURATION
# ============================================================

PRIMARY_THRESHOLD_METRIC: str = "f1"
THRESHOLD_SELECTION_SPLIT: str = "validation"

# Deterministic tie-breaking rules:
# 1. Highest F1 score
# 2. Highest Recall
# 3. Lowest Threshold value
TIE_BREAK_POLICY: str = "highest_f1_highest_recall_lowest_threshold"


# ============================================================
# DIRECTORY & FILE PATHS
# ============================================================

AUTOENCODER_MODEL_DIR: Path = MODELS_DIR / "autoencoder"
AUTOENCODER_CHECKPOINTS_DIR: Path = AUTOENCODER_MODEL_DIR / "checkpoints"
AUTOENCODER_FINAL_DIR: Path = AUTOENCODER_MODEL_DIR / "final_model"
AUTOENCODER_ARTIFACTS_DIR: Path = AUTOENCODER_MODEL_DIR / "artifacts"
AUTOENCODER_REPORTS_DIR: Path = MODEL_REPORTS_DIR / "autoencoder"

# Model artifacts
BEST_MODEL_PATH: Path = AUTOENCODER_CHECKPOINTS_DIR / "best_model.keras"
FINAL_MODEL_PATH: Path = AUTOENCODER_FINAL_DIR / "autoencoder.keras"
MODEL_METADATA_PATH: Path = AUTOENCODER_ARTIFACTS_DIR / "model_metadata.json"

# Reports
TRAINING_REPORT_PATH: Path = AUTOENCODER_REPORTS_DIR / "training_report.json"
TRAINING_HISTORY_PATH: Path = AUTOENCODER_REPORTS_DIR / "training_history.json"
RECONSTRUCTION_STATS_PATH: Path = AUTOENCODER_REPORTS_DIR / "reconstruction_error_statistics.json"
AUTOENCODER_EVALUATION_REPORT_PATH: Path = AUTOENCODER_REPORTS_DIR / "autoencoder_evaluation_report.json"
AUTOENCODER_VERIFICATION_REPORT_PATH: Path = AUTOENCODER_REPORTS_DIR / "autoencoder_verification_report.json"

REQUIRED_AUTOENCODER_DIRS: List[Path] = [
    AUTOENCODER_MODEL_DIR,
    AUTOENCODER_CHECKPOINTS_DIR,
    AUTOENCODER_FINAL_DIR,
    AUTOENCODER_ARTIFACTS_DIR,
    AUTOENCODER_REPORTS_DIR,
]
