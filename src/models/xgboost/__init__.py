"""
NexThreat Phase 4.3 — XGBoost Multiclass Pipeline Package.

Provides dataset verification, class distribution and imbalance analysis,
deterministic multiclass XGBoost training with validation-based model selection,
support-aware multiclass evaluation, and model artifact persistence.
"""
from __future__ import annotations

from src.models.xgboost.config import (
    XGBOOST_MODEL_NAME,
    CANONICAL_FEATURE_COLUMNS,
    FEATURE_COUNT,
    CLASS_MAPPING,
    NUM_CLASSES,
    RANDOM_SEED,
)

__all__ = [
    "XGBOOST_MODEL_NAME",
    "CANONICAL_FEATURE_COLUMNS",
    "FEATURE_COUNT",
    "CLASS_MAPPING",
    "NUM_CLASSES",
    "RANDOM_SEED",
]
