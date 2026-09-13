"""
NexThreat Phase 5.2 — Input Validator.

Validates the external canonical input contract and enforces physical bounds
derived strictly from Phase 5.1 Section 9 and Section 18.
"""
from __future__ import annotations

import datetime
import math
import re
from typing import Any, Dict, List, Tuple, Union

import numpy as np

from src.application.exceptions import InputValidationError
from src.application.schemas import CanonicalInputRecord

# Regex pattern for window_id (YYYYMMDD_HHMM)
WINDOW_ID_PATTERN = re.compile(r"^[0-9]{8}_[0-9]{4}$")

VALID_DAYS = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}


def parse_timestamp(ts_str: str) -> datetime.datetime:
    """Parse ISO-8601 or standard datetime string."""
    if not isinstance(ts_str, str) or not ts_str.strip():
        raise InputValidationError(f"Invalid timestamp format: {ts_str}. Expected non-empty string.")
    
    clean_ts = ts_str.strip()
    formats_to_try = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f",
    ]
    for fmt in formats_to_try:
        try:
            return datetime.datetime.strptime(clean_ts, fmt)
        except ValueError:
            pass
    try:
        return datetime.datetime.fromisoformat(clean_ts)
    except Exception as e:
        raise InputValidationError(f"Failed to parse timestamp '{clean_ts}': {e}") from e


def derive_dataset_day(dt: datetime.datetime) -> str:
    """
    Derive dataset_day partition strictly according to Phase 5.1 contract.
    Enum: ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Unknown"]
    """
    day_name = dt.strftime("%A")
    if day_name in VALID_DAYS:
        return day_name
    return "Unknown"


def validate_canonical_input(
    raw_input: Union[Dict[str, Any], CanonicalInputRecord]
) -> Tuple[str, str, datetime.datetime, str, np.ndarray]:
    """
    Validate an external input record against the Phase 5.1 Canonical Input Contract.
    
    Returns:
        (window_id, timestamp_str, timestamp_dt, dataset_day, features_float32_array)
    """
    if isinstance(raw_input, CanonicalInputRecord):
        window_id = raw_input.window_id
        timestamp_str = raw_input.timestamp
        features_list = raw_input.features
    elif isinstance(raw_input, dict):
        if "window_id" not in raw_input:
            raise InputValidationError("Missing required field 'window_id'.")
        if "timestamp" not in raw_input:
            raise InputValidationError("Missing required field 'timestamp'.")
        if "features" not in raw_input:
            raise InputValidationError("Missing required field 'features'.")
        window_id = raw_input["window_id"]
        timestamp_str = raw_input["timestamp"]
        features_list = raw_input["features"]
    else:
        raise InputValidationError(f"Expected dict or CanonicalInputRecord, got {type(raw_input)}")

    # 1. Validate window_id
    if not isinstance(window_id, str) or not WINDOW_ID_PATTERN.match(window_id):
        raise InputValidationError(
            f"Invalid window_id '{window_id}'. Expected pattern 'YYYYMMDD_HHMM' (e.g. '20170703_1355')."
        )

    # 2. Validate and parse timestamp
    timestamp_dt = parse_timestamp(timestamp_str)
    dataset_day = derive_dataset_day(timestamp_dt)

    # 3. Validate features
    if not isinstance(features_list, (list, tuple, np.ndarray)):
        raise InputValidationError(f"Field 'features' must be a sequence, got {type(features_list)}.")
    
    if len(features_list) != 13:
        raise InputValidationError(
            f"Expected exactly 13 canonical features, got {len(features_list)}."
        )

    features_array = np.empty(13, dtype=np.float32)
    for idx, val in enumerate(features_list):
        if not isinstance(val, (int, float, np.number)):
            raise InputValidationError(
                f"Feature at index {idx} must be numeric, got {type(val)}: {val}"
            )
        f_val = float(val)
        if math.isnan(f_val) or math.isinf(f_val):
            raise InputValidationError(
                f"Feature at index {idx} is non-finite ({f_val}). NaN and Inf are forbidden."
            )
        
        # 4. Physical bounds validation (Phase 5.1 Section 9)
        # Indices 0..4, 6..10: rates, counts, sizes >= 0
        if idx in (0, 1, 2, 3, 4, 6, 7, 8, 9, 10):
            if f_val < 0.0:
                raise InputValidationError(
                    f"Feature at index {idx} has invalid negative value {f_val}. Must be >= 0.0."
                )
        # Indices 5, 11, 12: ratios in [0.0, 1.0]
        elif idx in (5, 11, 12):
            if f_val < 0.0 or f_val > 1.0:
                raise InputValidationError(
                    f"Ratio feature at index {idx} has value {f_val} outside [0.0, 1.0]."
                )

        features_array[idx] = np.float32(f_val)

    return window_id, timestamp_str, timestamp_dt, dataset_day, features_array
