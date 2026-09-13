"""
NexThreat Phase 4.5 — Configuration and Canonical Taxonomy.

Centralizes:
- Project paths and deliverable target paths
- Canonical 13-feature contract
- Exactly 8 neutral canonical threat states (S0-S7)
- Dynamic threshold loading references
- Verification expectations (explicitly marked as expectations, NOT hardcoded production authority)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "data"

FEATURES_DIR = DATA_DIR / "features"
MODEL_INPUTS_DIR = DATA_DIR / "model_inputs"
MODEL_INPUTS_MANIFESTS_DIR = MODEL_INPUTS_DIR / "manifests"
MODEL_INPUTS_METADATA_DIR = MODEL_INPUTS_DIR / "metadata"

MODEL_READY_DIR = DATA_DIR / "model_ready"
MODEL_READY_ARTIFACTS_DIR = MODEL_READY_DIR / "artifacts"
MODEL_READY_METADATA_DIR = MODEL_READY_DIR / "metadata"
MODEL_READY_REPORTS_DIR = MODEL_READY_DIR / "reports"

MODELS_DIR = DATA_DIR / "models"
AUTOENCODER_MODELS_DIR = MODELS_DIR / "autoencoder"
XGBOOST_MODELS_DIR = MODELS_DIR / "xgboost"
LSTM_MODELS_DIR = MODELS_DIR / "lstm"

MODEL_REPORTS_DIR = DATA_DIR / "model_reports"
AUTOENCODER_REPORTS_DIR = MODEL_REPORTS_DIR / "autoencoder"
XGBOOST_REPORTS_DIR = MODEL_REPORTS_DIR / "xgboost"
LSTM_REPORTS_DIR = MODEL_REPORTS_DIR / "lstm"
COMPARISON_REPORT_DIR = MODEL_REPORTS_DIR / "comparison"

# ============================================================
# CANONICAL FEATURE CONTRACT (Phase 2.3 -> Phase 4.5)
# ============================================================

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
FEATURE_COUNT = 13

# ============================================================
# DAILY FEATURE FILES
# ============================================================

FEATURE_FILES: Dict[str, str] = {
    "Monday": "Monday_features.csv",
    "Tuesday": "Tuesday_features.csv",
    "Wednesday": "Wednesday_features.csv",
    "Thursday": "Thursday_features.csv",
    "Friday": "Friday_features.csv",
}

# ============================================================
# PRIOR-PHASE ARTIFACT PATHS
# ============================================================

# Phase 3.2 Manifests and Metadata
AUTOENCODER_SPLIT_MANIFEST_PATH = MODEL_INPUTS_MANIFESTS_DIR / "autoencoder_split_manifest.csv"
XGBOOST_SPLIT_MANIFEST_PATH = MODEL_INPUTS_MANIFESTS_DIR / "xgboost_split_manifest.csv"
LSTM_SPLIT_MANIFEST_PATH = MODEL_INPUTS_MANIFESTS_DIR / "lstm_split_manifest.csv"
SPLIT_INTEGRITY_REPORT_PATH = MODEL_INPUTS_MANIFESTS_DIR / "split_integrity_report.json"
ATTACK_SEGMENTS_PATH = MODEL_INPUTS_METADATA_DIR / "attack_segments.csv"

# Phase 3.3 Scalers and Encoders
AUTOENCODER_SCALER_PATH = MODEL_READY_ARTIFACTS_DIR / "autoencoder_scaler.joblib"
LSTM_SCALER_PATH = MODEL_READY_ARTIFACTS_DIR / "lstm_scaler.joblib"
XGBOOST_LABEL_ENCODER_PATH = MODEL_READY_ARTIFACTS_DIR / "xgboost_label_encoder.joblib"

# Phase 3.3 Metadata
FEATURE_COLUMNS_METADATA_PATH = MODEL_READY_METADATA_DIR / "feature_columns.json"
PREPARATION_METADATA_PATH = MODEL_READY_METADATA_DIR / "preparation_metadata.json"
XGBOOST_LABEL_MAPPING_PATH = MODEL_READY_METADATA_DIR / "xgboost_label_mapping.json"
LSTM_SEQUENCE_METADATA_PATH = MODEL_READY_METADATA_DIR / "lstm_sequence_metadata.json"
LSTM_SEQUENCE_PROVENANCE_PATH = MODEL_READY_METADATA_DIR / "lstm_sequence_provenance.csv"
MODEL_PREPARATION_REPORT_PATH = MODEL_READY_REPORTS_DIR / "model_preparation_report.json"

# Phase 4.2 Autoencoder Models & Metadata
AUTOENCODER_FINAL_MODEL_PATH = AUTOENCODER_MODELS_DIR / "final_model" / "autoencoder.keras"
AUTOENCODER_BEST_MODEL_PATH = AUTOENCODER_MODELS_DIR / "checkpoints" / "best_model.keras"
AUTOENCODER_METADATA_PATH = AUTOENCODER_MODELS_DIR / "artifacts" / "model_metadata.json"
AUTOENCODER_EVALUATION_REPORT_PATH = AUTOENCODER_REPORTS_DIR / "autoencoder_evaluation_report.json"
AUTOENCODER_RECONSTRUCTION_STATS_PATH = AUTOENCODER_REPORTS_DIR / "reconstruction_error_statistics.json"

# Phase 4.3 XGBoost Models & Metadata
XGBOOST_MODEL_PATH = XGBOOST_MODELS_DIR / "xgboost_model.json"
XGBOOST_METADATA_PATH = XGBOOST_MODELS_DIR / "metadata.json"
XGBOOST_FEATURE_SCHEMA_PATH = XGBOOST_MODELS_DIR / "feature_schema.json"
XGBOOST_CLASS_MAPPING_PATH = XGBOOST_MODELS_DIR / "class_mapping.json"
XGBOOST_MODEL_HASHES_PATH = XGBOOST_MODELS_DIR / "model_hashes.json"
XGBOOST_TEST_REPORT_PATH = XGBOOST_REPORTS_DIR / "test_report.json"

# Phase 4.4 LSTM Models & Metadata
LSTM_FINAL_MODEL_PATH = LSTM_MODELS_DIR / "lstm_model.keras"
LSTM_CANDIDATE_C_PATH = LSTM_MODELS_DIR / "checkpoints" / "best_Candidate_C.keras"
LSTM_RUNTIME_SCALER_PATH = LSTM_MODELS_DIR / "lstm_scaler.joblib"
LSTM_MODEL_HASHES_PATH = LSTM_REPORTS_DIR / "model_hashes.json"
LSTM_THRESHOLD_CONFIG_PATH = LSTM_REPORTS_DIR / "threshold_config.json"
LSTM_TEST_REPORT_PATH = LSTM_REPORTS_DIR / "test_report.json"

# ============================================================
# PHASE 4.5 DELIVERABLE OUTPUT PATHS (Exactly 7 Files)
# ============================================================

CROSS_MODEL_EVALUATION_REPORT_PATH = COMPARISON_REPORT_DIR / "cross_model_evaluation_report.json"
MODEL_CONSISTENCY_REPORT_PATH = COMPARISON_REPORT_DIR / "model_consistency_report.json"
TRI_MODEL_THREAT_MATRIX_PATH = COMPARISON_REPORT_DIR / "tri_model_threat_matrix.json"
TEMPORAL_LEAD_TIME_REPORT_PATH = COMPARISON_REPORT_DIR / "temporal_lead_time_report.json"
UNIFIED_INFERENCE_SPEC_PATH = COMPARISON_REPORT_DIR / "unified_inference_spec.json"
PHASE_4_5_VERIFICATION_REPORT_PATH = COMPARISON_REPORT_DIR / "phase_4_5_verification_report.json"
PHASE_4_5_SUMMARY_MD_PATH = COMPARISON_REPORT_DIR / "phase_4_5_summary.md"

ALL_PHASE_4_5_DELIVERABLES: List[Path] = [
    CROSS_MODEL_EVALUATION_REPORT_PATH,
    MODEL_CONSISTENCY_REPORT_PATH,
    TRI_MODEL_THREAT_MATRIX_PATH,
    TEMPORAL_LEAD_TIME_REPORT_PATH,
    UNIFIED_INFERENCE_SPEC_PATH,
    PHASE_4_5_VERIFICATION_REPORT_PATH,
    PHASE_4_5_SUMMARY_MD_PATH,
]

# ============================================================
# CANONICAL 8-STATE TAXONOMY (Strictly S0 to S7)
# ============================================================

CANONICAL_THREAT_STATES: Dict[str, Dict[str, Any]] = {
    "S0": {
        "code": "S0",
        "name": "BENIGN_CONCORDANCE",
        "priority": "PRIORITY_4",
        "triage_tier": "Priority 4 (Baseline Operations)",
        "inputs": (0, 0, 0),
        "meaning": "Normal baseline; all models concordant benign.",
    },
    "S1": {
        "code": "S1",
        "name": "LSTM_FORECAST_ONLY",
        "priority": "PRIORITY_3",
        "triage_tier": "Priority 3 (Monitored Anomalies & Warnings)",
        "inputs": (0, 0, 1),
        "meaning": "Forward-looking warning; current window clean.",
    },
    "S2": {
        "code": "S2",
        "name": "XGB_ATTACK_ONLY",
        "priority": "PRIORITY_3",
        "triage_tier": "Priority 3 (Monitored Anomalies & Warnings)",
        "inputs": (0, 1, 0),
        "meaning": "Known signature matched without AE anomaly.",
    },
    "S3": {
        "code": "S3",
        "name": "XGB_LSTM_CONSISTENCY",
        "priority": "PRIORITY_2",
        "triage_tier": "Priority 2 (Priority Investigation)",
        "inputs": (0, 1, 1),
        "meaning": "Forecasted signature attack active; low AE error.",
    },
    "S4": {
        "code": "S4",
        "name": "AE_ANOMALY_ONLY",
        "priority": "PRIORITY_3",
        "triage_tier": "Priority 3 (Monitored Anomalies & Warnings)",
        "inputs": (1, 0, 0),
        "meaning": "Statistical deviation without signature match.",
    },
    "S5": {
        "code": "S5",
        "name": "AE_LSTM_CONSISTENCY",
        "priority": "PRIORITY_2",
        "triage_tier": "Priority 2 (Priority Investigation)",
        "inputs": (1, 0, 1),
        "meaning": "Forecasted novel anomaly active.",
    },
    "S6": {
        "code": "S6",
        "name": "AE_XGB_CONSENSUS",
        "priority": "PRIORITY_2",
        "triage_tier": "Priority 2 (Priority Investigation)",
        "inputs": (1, 1, 0),
        "meaning": "Unpredicted sudden attack confirmed by AE + XGB.",
    },
    "S7": {
        "code": "S7",
        "name": "TRI_MODEL_CONSENSUS",
        "priority": "PRIORITY_1",
        "triage_tier": "Priority 1 (Immediate SOC Triage)",
        "inputs": (1, 1, 1),
        "meaning": "Full agreement: forecasted, anomalous, classified.",
    },
}

INPUT_TUPLE_TO_STATE: Dict[Tuple[int, int, int], str] = {
    v["inputs"]: v["name"] for v in CANONICAL_THREAT_STATES.values()
}
INPUT_TUPLE_TO_NAME = INPUT_TUPLE_TO_STATE

INPUT_TUPLE_TO_CODE: Dict[Tuple[int, int, int], str] = {
    v["inputs"]: v["code"] for v in CANONICAL_THREAT_STATES.values()
}

ALL_CANONICAL_STATE_NAMES: List[str] = [
    v["name"] for v in CANONICAL_THREAT_STATES.values()
]

ALL_CANONICAL_STATE_CODES: List[str] = [
    v["code"] for v in CANONICAL_THREAT_STATES.values()
]

# Forbidden legacy / non-neutral labels for Check J inspection
FORBIDDEN_SEMANTIC_LABELS: List[str] = [
    "confirmed_attack",
    "zero_day_detection",
    "novel_attack_confirmation",
    "guaranteed_prevention",
    "autonomous_response",
    "CRITICAL_ATTACK",
    "PROBABLE_ATTACK",
    "SUSPICIOUS_ACTIVITY",
    "S8",
    "LSTM_UNAVAILABLE",
]

# ============================================================
# REPOSITORY VERIFICATION EXPECTATIONS
# (Used solely for audit assertions, NEVER as hardcoded production authorities)
# ============================================================

EXPECTED_VERIFICATION_COUNTS = {
    "campaign_count": 81,
    "master_timeline_windows": 2454,
    "eligible_windows": 2404,
    "ineligible_windows": 50,
    "scope_a_autoencoder_samples": 408,
    "scope_a_xgboost_samples": 319,
    "scope_a_lstm_samples": 286,
    "scope_a_manifest_overlap": 51,
    "scope_a_synchronized_samples": 45,
    "scope_a_excluded_positions": [918, 2383, 2384, 2385, 2386, 2387],
}

RANDOM_SEED = 42


def to_project_relative(p: Union[Path, str]) -> str:
    """Convert an absolute or relative path to a POSIX path relative to PROJECT_ROOT."""
    try:
        resolved = Path(p).resolve()
        rel = resolved.relative_to(PROJECT_ROOT.resolve())
        return rel.as_posix()
    except Exception:
        return Path(p).as_posix()


def load_dynamic_thresholds() -> Tuple[float, float]:
    """
    Dynamically retrieve authoritative decision thresholds from frozen model artifacts.
    Returns: (ae_threshold, lstm_threshold)
    """
    with open(AUTOENCODER_METADATA_PATH, "r", encoding="utf-8") as f:
        ae_meta = json.load(f)
    ae_threshold = float(ae_meta["threshold"]["selected_threshold"])

    with open(LSTM_THRESHOLD_CONFIG_PATH, "r", encoding="utf-8") as f:
        lstm_cfg = json.load(f)
    lstm_threshold = float(lstm_cfg.get("selected_threshold", lstm_cfg.get("threshold", 0.3)))

    return ae_threshold, lstm_threshold
