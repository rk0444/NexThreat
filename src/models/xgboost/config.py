"""
NexThreat Phase 4.3 — XGBoost Centralized Configuration.

Defines canonical immutable configuration for:
- 8-class label taxonomy and mappings
- 13 canonical features and ordering
- Data types, expected shapes, and directories
- Baseline manifest and artifact paths
- Predefined candidate model specifications
- Deterministic model selection policies and numerical tolerances
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple
import numpy as np

from src.models.config import (
    PROJECT_ROOT,
    DATA_DIR,
    MODELS_DIR,
    MODEL_REPORTS_DIR,
    MODEL_READY_DIR,
    RANDOM_SEED as GLOBAL_RANDOM_SEED,
    to_project_relative,
)

# ============================================================
# IDENTIFIERS & TAXONOMY
# ============================================================

PROJECT_NAME: str = "NexThreat"
PHASE_NAME: str = "Phase 4.3 — XGBoost Multiclass Development"
XGBOOST_MODEL_NAME: str = "xgboost"
RANDOM_SEED: int = GLOBAL_RANDOM_SEED  # Strictly 42
NUM_CLASSES: int = 8
NUMERICAL_TOLERANCE: float = 1e-5

# Canonical 8-Class Mapping (Immutable Contract)
CLASS_MAPPING: Dict[str, int] = {
    "BENIGN": 0,
    "Brute Force": 1,
    "Bot": 2,
    "DoS": 3,
    "Infiltration": 4,
    "PortScan": 5,
    "Web Attack": 6,
    "DDoS": 7,
}

INDEX_TO_CLASS: Dict[int, str] = {v: k for k, v in CLASS_MAPPING.items()}
CLASS_NAMES: List[str] = [INDEX_TO_CLASS[i] for i in range(NUM_CLASSES)]

# Canonical 13 Features and Ordering (Phase 2.3 / 3.3 Contract)
CANONICAL_FEATURE_COLUMNS: List[str] = [
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

FEATURE_COUNT: int = len(CANONICAL_FEATURE_COLUMNS)  # Strictly 13
FEATURE_DTYPE = np.float32
LABEL_DTYPE = np.int64


# ============================================================
# CANONICAL DIRECTORIES & PATHS
# ============================================================

XGBOOST_MODEL_DIR: Path = MODELS_DIR / XGBOOST_MODEL_NAME
XGBOOST_CHECKPOINTS_DIR: Path = XGBOOST_MODEL_DIR / "checkpoints"
XGBOOST_PREDICTIONS_DIR: Path = XGBOOST_MODEL_DIR / "predictions"
XGBOOST_REPORTS_DIR: Path = MODEL_REPORTS_DIR / XGBOOST_MODEL_NAME

REQUIRED_XGBOOST_DIRS: List[Path] = [
    XGBOOST_MODEL_DIR,
    XGBOOST_CHECKPOINTS_DIR,
    XGBOOST_PREDICTIONS_DIR,
    XGBOOST_REPORTS_DIR,
]

# Source Data Paths (Phase 3.3 Model-Ready XGBoost Files)
XGBOOST_READY_DIR: Path = MODEL_READY_DIR / XGBOOST_MODEL_NAME
SOURCE_DATA_FILES: Dict[str, Path] = {
    "X_train": XGBOOST_READY_DIR / "X_train.npy",
    "X_validation": XGBOOST_READY_DIR / "X_validation.npy",
    "X_test": XGBOOST_READY_DIR / "X_test.npy",
    "y_train": XGBOOST_READY_DIR / "y_train.npy",
    "y_validation": XGBOOST_READY_DIR / "y_validation.npy",
    "y_test": XGBOOST_READY_DIR / "y_test.npy",
}

# Expected Dataset Shapes
EXPECTED_DATA_SHAPES: Dict[str, Tuple[int, ...]] = {
    "X_train": (1799, 13),
    "X_validation": (325, 13),
    "X_test": (319, 13),
    "y_train": (1799,),
    "y_validation": (325,),
    "y_test": (319,),
}

# Canonical Phase 4.3 XGBoost Baseline Manifest
XGBOOST_BASELINE_MANIFEST_PATH: Path = (
    XGBOOST_MODEL_DIR / "xgboost_dataset_baseline_manifest.json"
)

# Canonical Model Artifacts (under data/models/xgboost/)
MODEL_FILE_PATH: Path = XGBOOST_MODEL_DIR / "xgboost_model.json"
METADATA_FILE_PATH: Path = XGBOOST_MODEL_DIR / "metadata.json"
FEATURE_SCHEMA_FILE_PATH: Path = XGBOOST_MODEL_DIR / "feature_schema.json"
CLASS_MAPPING_FILE_PATH: Path = XGBOOST_MODEL_DIR / "class_mapping.json"
TRAINING_CONFIG_FILE_PATH: Path = XGBOOST_MODEL_DIR / "training_config.json"
DATASET_MANIFEST_FILE_PATH: Path = XGBOOST_MODEL_DIR / "dataset_manifest.json"
MODEL_HASHES_FILE_PATH: Path = XGBOOST_MODEL_DIR / "model_hashes.json"

# Canonical Prediction Arrays (under data/models/xgboost/predictions/)
VAL_PREDICTIONS_PATH: Path = XGBOOST_PREDICTIONS_DIR / "validation_predictions.npy"
VAL_PROBABILITIES_PATH: Path = XGBOOST_PREDICTIONS_DIR / "validation_probabilities.npy"
TEST_PREDICTIONS_PATH: Path = XGBOOST_PREDICTIONS_DIR / "test_predictions.npy"
TEST_PROBABILITIES_PATH: Path = XGBOOST_PREDICTIONS_DIR / "test_probabilities.npy"

# Canonical Reports (under data/model_reports/xgboost/)
DATASET_VERIFICATION_REPORT_PATH: Path = (
    XGBOOST_REPORTS_DIR / "dataset_verification_report.json"
)
CLASS_DISTRIBUTION_REPORT_PATH: Path = (
    XGBOOST_REPORTS_DIR / "class_distribution_report.json"
)
TRAINING_REPORT_PATH: Path = XGBOOST_REPORTS_DIR / "training_report.json"
VALIDATION_REPORT_PATH: Path = XGBOOST_REPORTS_DIR / "validation_report.json"
TEST_REPORT_PATH: Path = XGBOOST_REPORTS_DIR / "test_report.json"
CLASSIFICATION_REPORT_PATH: Path = XGBOOST_REPORTS_DIR / "classification_report.json"
CONFUSION_MATRIX_REPORT_PATH: Path = XGBOOST_REPORTS_DIR / "confusion_matrix.json"
ROC_AUC_REPORT_PATH: Path = XGBOOST_REPORTS_DIR / "roc_auc_report.json"
PR_AUC_REPORT_PATH: Path = XGBOOST_REPORTS_DIR / "pr_auc_report.json"
LOG_LOSS_REPORT_PATH: Path = XGBOOST_REPORTS_DIR / "log_loss_report.json"
REPRODUCIBILITY_REPORT_PATH: Path = XGBOOST_REPORTS_DIR / "reproducibility_report.json"
PHASE_4_3_SUMMARY_PATH: Path = XGBOOST_REPORTS_DIR / "phase_4_3_summary.md"


# ============================================================
# PREDEFINED CANDIDATE SPECIFICATIONS
# ============================================================

COMMON_XGB_PARAMS: Dict[str, Any] = {
    "objective": "multi:softprob",
    "num_class": NUM_CLASSES,
    "eval_metric": "mlogloss",
    "tree_method": "hist",
    "random_state": RANDOM_SEED,
    "early_stopping_rounds": 15,
}

CANDIDATE_CONFIGURATIONS: Dict[str, Dict[str, Any]] = {
    "Candidate_A": {
        "candidate_id": "Candidate_A",
        "name": "Unweighted Baseline",
        "description": "Baseline multiclass XGBoost with default sampling and uniform sample weights",
        "use_class_weights": False,
        "params": {
            **COMMON_XGB_PARAMS,
            "n_estimators": 200,
            "max_depth": 5,
            "learning_rate": 0.1,
            "subsample": 1.0,
            "colsample_bytree": 1.0,
            "min_child_weight": 1,
        },
    },
    "Candidate_B": {
        "candidate_id": "Candidate_B",
        "name": "Balanced Class Weights",
        "description": "Multiclass XGBoost with balanced sample weights derived strictly from y_train: w_c = N / (K * N_c)",
        "use_class_weights": True,
        "params": {
            **COMMON_XGB_PARAMS,
            "n_estimators": 200,
            "max_depth": 5,
            "learning_rate": 0.1,
            "subsample": 1.0,
            "colsample_bytree": 1.0,
            "min_child_weight": 1,
        },
    },
    "Candidate_C": {
        "candidate_id": "Candidate_C",
        "name": "Regularized",
        "description": "Regularized multiclass XGBoost with feature/row subsampling and shallower tree depth to prevent overfitting",
        "use_class_weights": False,
        "params": {
            **COMMON_XGB_PARAMS,
            "n_estimators": 200,
            "max_depth": 4,
            "learning_rate": 0.08,
            "subsample": 0.85,
            "colsample_bytree": 0.85,
            "min_child_weight": 2,
        },
    },
}

# Validation Selection Criteria Priority:
# 1. Higher Macro F1 (over supported validation classes)
# 2. Higher Macro Recall (over supported validation classes)
# 3. Lower Validation Log Loss
# 4. Lower candidate index (deterministic tie-breaker)
SELECTION_PRIORITY: List[str] = [
    "macro_f1_supported",
    "macro_recall_supported",
    "log_loss",
    "candidate_index",
]
