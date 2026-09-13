"""
NexThreat Phase 5.2 — Application Configuration and Authoritative Invariants.

Centralizes paths, canonical 13-feature contract, frozen thresholds,
authoritative XGBoost class mapping, and verified canonical S0-S7 threat taxonomy.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from src.models.comparison.config import (
    PROJECT_ROOT,
    DATA_DIR,
    CANONICAL_FEATURE_COLUMNS,
    FEATURE_COUNT,
    CANONICAL_THREAT_STATES,
    INPUT_TUPLE_TO_STATE,
    INPUT_TUPLE_TO_CODE,
    ALL_CANONICAL_STATE_NAMES,
    ALL_CANONICAL_STATE_CODES,
    FORBIDDEN_SEMANTIC_LABELS,
    AUTOENCODER_FINAL_MODEL_PATH,
    AUTOENCODER_SCALER_PATH,
    AUTOENCODER_METADATA_PATH,
    XGBOOST_MODEL_PATH,
    XGBOOST_CLASS_MAPPING_PATH,
    XGBOOST_FEATURE_SCHEMA_PATH,
    LSTM_FINAL_MODEL_PATH,
    LSTM_RUNTIME_SCALER_PATH,
    LSTM_THRESHOLD_CONFIG_PATH,
)

# ============================================================
# FROZEN THRESHOLDS & INVARIANTS
# ============================================================

AUTOENCODER_THRESHOLD: float = 0.003207791231673312
LSTM_THRESHOLD: float = 0.3
LSTM_SEQUENCE_LENGTH: int = 10
WINDOW_DURATION_SECONDS: int = 60

# ============================================================
# AUTHORITATIVE XGBOOST CLASS MAPPING (Loaded & Verified)
# ============================================================

def load_authoritative_xgboost_class_mapping() -> Tuple[Dict[str, int], Dict[int, str]]:
    """
    Load and structurally verify the authoritative XGBoost 8-class mapping from disk.
    Guarantees no hardcoding or invention of class names/indices.
    """
    if not XGBOOST_CLASS_MAPPING_PATH.exists():
        raise FileNotFoundError(f"Missing authoritative XGBoost class mapping: {XGBOOST_CLASS_MAPPING_PATH}")

    with open(XGBOOST_CLASS_MAPPING_PATH, "r", encoding="utf-8") as f:
        mapping_data = json.load(f)

    if mapping_data.get("num_classes") != 8:
        raise ValueError(f"Expected num_classes=8, got {mapping_data.get('num_classes')}")

    class_to_index: Dict[str, int] = mapping_data["class_to_index"]
    index_to_class: Dict[int, str] = {int(k): v for k, v in mapping_data["index_to_class"].items()}

    # Assert exact 8 classes present
    expected_classes = {"BENIGN", "Brute Force", "Bot", "DoS", "Infiltration", "PortScan", "Web Attack", "DDoS"}
    if set(class_to_index.keys()) != expected_classes:
        raise ValueError(f"Class mapping keys do not match authoritative set: {class_to_index.keys()}")

    if index_to_class[0] != "BENIGN":
        raise ValueError(f"Class index 0 must be 'BENIGN', got '{index_to_class.get(0)}'")

    return class_to_index, index_to_class


XGBOOST_CLASS_TO_INDEX, XGBOOST_INDEX_TO_CLASS = load_authoritative_xgboost_class_mapping()

# ============================================================
# CANONICAL THREAT TAXONOMY RE-EXPORT & STRUCTURAL VERIFICATION
# ============================================================

# Verify that Phase 4 canonical taxonomy is 100% compliant with Phase 5.1
assert len(CANONICAL_THREAT_STATES) == 8, f"Expected exactly 8 threat states, got {len(CANONICAL_THREAT_STATES)}"
assert "S8" not in CANONICAL_THREAT_STATES, "State S8 is strictly prohibited!"
assert "LSTM_UNAVAILABLE" not in CANONICAL_THREAT_STATES, "LSTM_UNAVAILABLE as state is prohibited!"
assert len(INPUT_TUPLE_TO_STATE) == 8, "Expected 8 input tuple mappings"
