from pathlib import Path

# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"

FEATURES_DIR = DATA_DIR / "features"
MODEL_INPUTS_DIR = DATA_DIR / "model_inputs"
METADATA_DIR = MODEL_INPUTS_DIR / "metadata"

# ============================================================
# FEATURE FILE MAPPING
# ============================================================

FEATURE_FILES = {
    "Monday": "Monday_features.csv",
    "Tuesday": "Tuesday_features.csv",
    "Wednesday": "Wednesday_features.csv",
    "Thursday": "Thursday_features.csv",
    "Friday": "Friday_features.csv",
}

# ============================================================
# DATASET VALIDATION CONSTANTS
# ============================================================

EXPECTED_TOTAL_WINDOWS = 2454

EXPECTED_DAILY_COUNTS = {
    "Monday": 487,
    "Tuesday": 488,
    "Wednesday": 509,
    "Thursday": 486,
    "Friday": 484,
}

# ============================================================
# COLUMN NAMES
# ============================================================

WINDOW_ID_COLUMN = "window_id"
ATTACK_CATEGORY_COLUMN = "attack_category"
IS_ATTACK_COLUMN = "is_attack"
SOURCE_IS_ATTACK_COLUMN = "is_attack_window"
DATASET_DAY_COLUMN = "dataset_day"

REQUIRED_COLUMNS = [
    WINDOW_ID_COLUMN,
    ATTACK_CATEGORY_COLUMN,
    IS_ATTACK_COLUMN,
    DATASET_DAY_COLUMN,
]

# ============================================================
# ANALYSIS THRESHOLDS AND SPLIT PARAMETERS
# ============================================================

RARE_CLASS_THRESHOLD = 20

SPLIT_RATIOS = {
    "train": 0.70,
    "validation": 0.15,
    "test": 0.15,
}

# Criteria for mathematical split feasibility (at least 1 sample per split)
MIN_SPLIT_FEASIBLE = {
    "train": 1,
    "validation": 1,
    "test": 1,
}

# Criteria for realistic supervised learning evaluation
MIN_SUPERVISED_RECOMMENDED = {
    "train": 10,
    "validation": 2,
    "test": 2,
}

# ============================================================
# OUTPUT FILENAMES
# ============================================================

# Phase 3.1A Output Filenames
BINARY_DISTRIBUTION_CSV = "binary_distribution.csv"
ATTACK_CATEGORY_DISTRIBUTION_CSV = "attack_category_distribution.csv"
DAILY_CATEGORY_DISTRIBUTION_CSV = "daily_category_distribution.csv"
RARE_CATEGORY_ANALYSIS_CSV = "rare_category_analysis.csv"
CATEGORY_TIMELINE_CSV = "category_timeline.csv"
SPLIT_FEASIBILITY_CSV = "split_feasibility_analysis.csv"
DISTRIBUTION_SUMMARY_JSON = "distribution_summary.json"

# Phase 3.1B Output Filenames
ATTACK_SEGMENTS_CSV = "attack_segments.csv"
BENIGN_GAPS_CSV = "benign_gaps.csv"
ATTACK_CATEGORY_SEGMENT_SUMMARY_CSV = "attack_category_segment_summary.csv"
PER_DAY_SPLIT_BOUNDARIES_CSV = "per_day_split_boundaries.csv"
PER_DAY_SPLIT_CATEGORY_COVERAGE_CSV = "per_day_split_category_coverage.csv"
PER_DAY_SPLIT_CATEGORY_SUMMARY_CSV = "per_day_split_category_summary.csv"
GLOBAL_SPLIT_CATEGORY_COVERAGE_CSV = "global_split_category_coverage.csv"
SPLIT_STRATEGY_RISK_ANALYSIS_CSV = "split_strategy_risk_analysis.csv"
ATTACK_SEGMENT_SUMMARY_JSON = "attack_segment_summary.json"

# ============================================================
# PHASE 3.1C MODEL ARCHITECTURE CONSTANTS & METADATA FILENAMES
# ============================================================

AUTOENCODER_TARGET_CLASS = "BENIGN"

XGBOOST_SUPERVISED_CLASSES = [
    "BENIGN",
    "Brute Force",
    "Bot",
    "DoS",
    "Infiltration",
    "PortScan",
    "Web Attack",
    "DDoS",
]

EXCLUDED_SUPERVISED_CLASS = "ATTACK"  # Heartbleed (11 windows - evaluated in binary anomaly detection only)

LSTM_SEQUENCE_LENGTH = 10
LSTM_FEATURE_DIM = 13
LSTM_TARGET_COLUMN = "is_attack"

# Phase 3.1C Output Filenames
CANDIDATE_SPLIT_STRATEGIES_CSV = "candidate_split_strategies.csv"
SEGMENT_ALLOCATION_FEASIBILITY_CSV = "segment_allocation_feasibility.csv"
MODEL_SPECIFIC_SPLIT_REQUIREMENTS_CSV = "model_specific_split_requirements.csv"
LSTM_SEQUENCE_FEASIBILITY_CSV = "lstm_sequence_feasibility.csv"
SPLIT_STRATEGY_ANALYSIS_SUMMARY_JSON = "split_strategy_analysis_summary.json"

# ============================================================
# PHASE 3.2 MODEL DIRECTORIES, MANIFESTS & DATASET CONSTANTS
# ============================================================

# Directory Paths
MANIFESTS_DIR = MODEL_INPUTS_DIR / "manifests"
AUTOENCODER_DIR = MODEL_INPUTS_DIR / "autoencoder"
XGBOOST_DIR = MODEL_INPUTS_DIR / "xgboost"
LSTM_DIR = MODEL_INPUTS_DIR / "lstm"

# Model Identifiers
AUTOENCODER_MODEL_NAME = "autoencoder"
XGBOOST_MODEL_NAME = "xgboost"
LSTM_MODEL_NAME = "lstm"

# Split Labels
TRAIN_SPLIT = "train"
VALIDATION_SPLIT = "validation"
TEST_SPLIT = "test"
BUFFER_SPLIT = "buffer"
EXCLUDED_SPLIT = "excluded"

# Manifest Filenames
AUTOENCODER_MANIFEST_CSV = "autoencoder_split_manifest.csv"
XGBOOST_MANIFEST_CSV = "xgboost_split_manifest.csv"
LSTM_MANIFEST_CSV = "lstm_split_manifest.csv"
SPLIT_INTEGRITY_REPORT_JSON = "split_integrity_report.json"

# Dataset Output Filenames
TRAIN_CSV = "train.csv"
VALIDATION_CSV = "validation.csv"
TEST_CSV = "test.csv"
LSTM_TRAIN_WINDOWS_CSV = "train_windows.csv"
LSTM_VALIDATION_WINDOWS_CSV = "validation_windows.csv"
LSTM_TEST_WINDOWS_CSV = "test_windows.csv"

# LSTM Sequence & Buffer Parameters
LSTM_BOUNDARY_BUFFER = 10

# XGBoost Parameters
XGBOOST_REQUIRED_CLASSES = XGBOOST_SUPERVISED_CLASSES
XGBOOST_EXCLUDED_CLASSES = [EXCLUDED_SUPERVISED_CLASS]

# Reproducibility
RANDOM_SEED = 42



