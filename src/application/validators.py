"""
NexThreat Phase 5.5 — Input/Output Validator & Defensive Assertion Boundary.

Validates the external canonical input contract and enforces physical bounds
derived strictly from Phase 5.1 Section 9 and Section 18.
Provides defensive assert-only output validation across all model predictions,
threat-state mappings, and assembled application records.
Provides string sanitization to protect against information leakage in client error responses.
"""
from __future__ import annotations

import datetime
import math
import re
from typing import Any, Dict, List, Tuple, Union

import numpy as np

from src.application.config import (
    AUTOENCODER_THRESHOLD,
    LSTM_THRESHOLD,
    XGBOOST_INDEX_TO_CLASS,
    INPUT_TUPLE_TO_CODE,
    INPUT_TUPLE_TO_STATE,
    CANONICAL_THREAT_STATES,
)
from src.application.exceptions import (
    InputValidationError,
    IntegrationContractError,
)
from src.application.schemas import (
    CanonicalInputRecord,
    AutoencoderOutputRecord,
    XGBoostOutputRecord,
    LSTMOutputRecord,
    ThreatInferenceRecord,
    ApplicationOutputRecord,
)

# Regex pattern for window_id (YYYYMMDD_HHMM)
WINDOW_ID_PATTERN = re.compile(r"^[0-9]{8}_[0-9]{4}$")

VALID_DAYS = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}


def parse_timestamp(ts_str: str) -> datetime.datetime:
    """Parse ISO-8601 or standard datetime string with strict type and content checking."""
    if isinstance(ts_str, bool) or not isinstance(ts_str, str) or not ts_str.strip():
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
    
    Enforces:
    - Root dictionary keys strictly limited to {"window_id", "timestamp", "features"}
    - window_id matching regex YYYYMMDD_HHMM (rejects booleans, integers, empty/malformed)
    - timestamp valid ISO-8601 or standard format
    - features sequence of length exactly 13
    - features numeric and finite (strictly rejects booleans, NaN, Inf, null, objects)
    - physical domain bounds (indices 0..4, 6..10 >= 0.0; ratio indices 5, 11, 12 in [0.0, 1.0])

    Returns:
        (window_id, timestamp_str, timestamp_dt, dataset_day, features_float32_array)
    """
    if isinstance(raw_input, CanonicalInputRecord):
        window_id = raw_input.window_id
        timestamp_str = raw_input.timestamp
        features_list = raw_input.features
    elif isinstance(raw_input, dict):
        # Enforce strict top-level keys for single-window request
        allowed_keys = {"window_id", "timestamp", "features"}
        raw_keys = set(raw_input.keys())
        extraneous = raw_keys - allowed_keys
        if extraneous:
            raise InputValidationError(
                f"Extraneous top-level key(s) detected: {sorted(list(extraneous))}. "
                f"Allowed keys: {sorted(list(allowed_keys))}."
            )
        missing = allowed_keys - raw_keys
        if missing:
            raise InputValidationError(
                f"Missing required key(s): {sorted(list(missing))}."
            )
        window_id = raw_input["window_id"]
        timestamp_str = raw_input["timestamp"]
        features_list = raw_input["features"]
    else:
        raise InputValidationError(f"Expected dict or CanonicalInputRecord, got {type(raw_input)}")

    # 1. Validate window_id
    if isinstance(window_id, bool) or not isinstance(window_id, str):
        raise InputValidationError(
            f"Invalid window_id type '{type(window_id)}'. Expected non-empty string."
        )
    if not WINDOW_ID_PATTERN.match(window_id):
        raise InputValidationError(
            f"Invalid window_id '{window_id}'. Expected pattern 'YYYYMMDD_HHMM' (e.g. '20170703_1355')."
        )

    # 2. Validate and parse timestamp
    if isinstance(timestamp_str, bool) or not isinstance(timestamp_str, str):
        raise InputValidationError(
            f"Invalid timestamp type '{type(timestamp_str)}'. Expected non-empty string."
        )
    timestamp_dt = parse_timestamp(timestamp_str)
    dataset_day = derive_dataset_day(timestamp_dt)

    # 3. Validate features
    if isinstance(features_list, (str, bytes, dict)) or not isinstance(features_list, (list, tuple, np.ndarray)):
        raise InputValidationError(f"Field 'features' must be a sequence, got {type(features_list)}.")
    
    if len(features_list) != 13:
        raise InputValidationError(
            f"Expected exactly 13 canonical features, got {len(features_list)}."
        )

    features_array = np.empty(13, dtype=np.float32)
    for idx, val in enumerate(features_list):
        if isinstance(val, bool):
            raise InputValidationError(
                f"Feature at index {idx} must be numeric, got bool: {val}. Booleans are strictly forbidden."
            )
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


# =============================================================================
# DEFENSIVE ASSERT-ONLY OUTPUT VALIDATORS
# =============================================================================

def validate_autoencoder_output(ae_record: AutoencoderOutputRecord) -> None:
    """
    Assert-only defensive validation for Autoencoder prediction record.
    Never mutates state; raises IntegrationContractError on contract violation.
    """
    if not isinstance(ae_record.reconstruction_mse, (int, float, np.number)):
        raise IntegrationContractError(
            f"Autoencoder reconstruction_mse must be numeric, got {type(ae_record.reconstruction_mse)}"
        )
    mse = float(ae_record.reconstruction_mse)
    if math.isnan(mse) or math.isinf(mse) or mse < 0.0:
        raise IntegrationContractError(
            f"Autoencoder reconstruction_mse must be a finite non-negative float, got {mse}"
        )
    if abs(float(ae_record.threshold) - AUTOENCODER_THRESHOLD) > 1e-12:
        raise IntegrationContractError(
            f"Autoencoder threshold mutated: expected {AUTOENCODER_THRESHOLD}, got {ae_record.threshold}"
        )
    expected_anomaly = 1 if mse > float(ae_record.threshold) else 0
    if ae_record.is_anomaly not in (0, 1) or ae_record.is_anomaly != expected_anomaly:
        raise IntegrationContractError(
            f"Autoencoder decision inconsistent: mse={mse}, threshold={ae_record.threshold}, "
            f"expected is_anomaly={expected_anomaly}, got {ae_record.is_anomaly}"
        )


def validate_xgboost_output(xgb_record: XGBoostOutputRecord) -> None:
    """
    Assert-only defensive validation for XGBoost prediction record.
    Never mutates state; raises IntegrationContractError on contract violation.
    """
    if not isinstance(xgb_record.predicted_class_index, (int, np.integer)):
        raise IntegrationContractError(
            f"XGBoost predicted_class_index must be integer, got {type(xgb_record.predicted_class_index)}"
        )
    c_idx = int(xgb_record.predicted_class_index)
    if c_idx not in range(8):
        raise IntegrationContractError(
            f"XGBoost predicted_class_index out of range 0..7: {c_idx}"
        )
    expected_class_name = XGBOOST_INDEX_TO_CLASS.get(c_idx)
    if xgb_record.predicted_class_name != expected_class_name:
        raise IntegrationContractError(
            f"XGBoost class name mismatch for index {c_idx}: expected '{expected_class_name}', "
            f"got '{xgb_record.predicted_class_name}'"
        )
    expected_attack = 1 if c_idx != 0 else 0
    if xgb_record.is_attack not in (0, 1) or xgb_record.is_attack != expected_attack:
        raise IntegrationContractError(
            f"XGBoost is_attack decision inconsistent for index {c_idx}: "
            f"expected {expected_attack}, got {xgb_record.is_attack}"
        )
    if xgb_record.class_probabilities is not None:
        if len(xgb_record.class_probabilities) != 8:
            raise IntegrationContractError(
                f"XGBoost class_probabilities vector must have length 8, got {len(xgb_record.class_probabilities)}"
            )
        for idx, p in enumerate(xgb_record.class_probabilities):
            if not isinstance(p, (int, float, np.number)):
                raise IntegrationContractError(f"Probability at index {idx} not numeric: {type(p)}")
            p_val = float(p)
            if math.isnan(p_val) or math.isinf(p_val) or p_val < 0.0 or p_val > 1.0:
                raise IntegrationContractError(
                    f"XGBoost class probability at index {idx} out of domain [0.0, 1.0]: {p_val}"
                )
        prob_sum = sum(float(p) for p in xgb_record.class_probabilities)
        if abs(prob_sum - 1.0) > 1e-4:
            raise IntegrationContractError(
                f"XGBoost class_probabilities sum != 1.0 (sum={prob_sum:.6f})"
            )


def validate_lstm_output(lstm_record: LSTMOutputRecord) -> None:
    """
    Assert-only defensive validation for LSTM forecast record.
    Never mutates state; raises IntegrationContractError on contract violation.
    """
    if lstm_record.is_eligible:
        if lstm_record.forecast_probability is None or not isinstance(lstm_record.forecast_probability, (int, float, np.number)):
            raise IntegrationContractError(
                f"Eligible LSTM record must have numeric forecast_probability, got {type(lstm_record.forecast_probability)}"
            )
        p_val = float(lstm_record.forecast_probability)
        if math.isnan(p_val) or math.isinf(p_val) or p_val < 0.0 or p_val > 1.0:
            raise IntegrationContractError(
                f"LSTM forecast_probability out of domain [0.0, 1.0]: {p_val}"
            )
        if abs(float(lstm_record.threshold) - LSTM_THRESHOLD) > 1e-6:
            raise IntegrationContractError(
                f"LSTM threshold mutated: expected {LSTM_THRESHOLD}, got {lstm_record.threshold}"
            )
        expected_decision = 1 if p_val >= float(lstm_record.threshold) else 0
        if lstm_record.forecast_decision not in (0, 1) or lstm_record.forecast_decision != expected_decision:
            raise IntegrationContractError(
                f"LSTM forecast_decision inconsistent: prob={p_val}, threshold={lstm_record.threshold}, "
                f"expected decision={expected_decision}, got {lstm_record.forecast_decision}"
            )
        if lstm_record.ineligibility_reason is not None:
            raise IntegrationContractError(
                f"Eligible LSTM record must not have ineligibility_reason, got '{lstm_record.ineligibility_reason}'"
            )
    else:
        if lstm_record.forecast_probability is not None:
            raise IntegrationContractError(
                f"Ineligible LSTM record must have null forecast_probability, got {lstm_record.forecast_probability}"
            )
        if lstm_record.forecast_decision != "unavailable":
            raise IntegrationContractError(
                f"Ineligible LSTM record must have forecast_decision='unavailable', got '{lstm_record.forecast_decision}'"
            )
        if not lstm_record.ineligibility_reason:
            raise IntegrationContractError("Ineligible LSTM record must specify ineligibility_reason")


def validate_threat_inference_output(
    threat_record: ThreatInferenceRecord,
    b_ae: int,
    b_xgb: int,
    b_lstm: Union[int, str],
) -> None:
    """
    Assert-only defensive validation of threat inference against authoritative truth table.
    Never mutates state; raises IntegrationContractError on contract violation.
    """
    if b_lstm == "unavailable":
        if (
            threat_record.is_eligible is not False
            or threat_record.threat_state_code is not None
            or threat_record.threat_state_name is not None
            or threat_record.priority_tier is not None
            or threat_record.decision_tuple is not None
        ):
            raise IntegrationContractError(
                f"Ineligible threat inference record must have null state values: {threat_record}"
            )
    else:
        if threat_record.is_eligible is not True:
            raise IntegrationContractError(
                f"Threat inference record expected eligible, got {threat_record.is_eligible}"
            )
        key = (int(b_ae), int(b_xgb), int(b_lstm))
        if key not in INPUT_TUPLE_TO_CODE:
            raise IntegrationContractError(
                f"Decision tuple {key} is not in canonical {{0, 1}}^3 taxonomy"
            )
        expected_code = INPUT_TUPLE_TO_CODE[key]
        expected_name = INPUT_TUPLE_TO_STATE[key]
        if (
            threat_record.threat_state_code != expected_code
            or threat_record.threat_state_name != expected_name
        ):
            raise IntegrationContractError(
                f"Threat-state mismatch for inputs {key}: expected code='{expected_code}', "
                f"name='{expected_name}', got code='{threat_record.threat_state_code}', "
                f"name='{threat_record.threat_state_name}'"
            )
        expected_tier = CANONICAL_THREAT_STATES[expected_code]["triage_tier"]
        if threat_record.priority_tier != expected_tier:
            raise IntegrationContractError(
                f"Priority tier mismatch for {expected_code}: expected '{expected_tier}', "
                f"got '{threat_record.priority_tier}'"
            )
        if threat_record.decision_tuple != list(key):
            raise IntegrationContractError(
                f"Decision tuple mismatch: expected {list(key)}, got {threat_record.decision_tuple}"
            )


def validate_application_output_record(app_record: ApplicationOutputRecord) -> None:
    """
    Assert-only defensive validation for the assembled ApplicationOutputRecord.
    Never mutates state; raises IntegrationContractError on contract violation.
    """
    if not isinstance(app_record.window_id, str) or not WINDOW_ID_PATTERN.match(app_record.window_id):
        raise IntegrationContractError(f"Invalid window_id in application output: '{app_record.window_id}'")
    if not isinstance(app_record.global_position, int) or app_record.global_position < 1:
        raise IntegrationContractError(f"Invalid global_position in application output: {app_record.global_position}")
    if app_record.dataset_day not in VALID_DAYS and app_record.dataset_day != "Unknown":
        raise IntegrationContractError(f"Invalid dataset_day in application output: '{app_record.dataset_day}'")

    validate_autoencoder_output(app_record.autoencoder)
    validate_xgboost_output(app_record.xgboost)
    validate_lstm_output(app_record.lstm)
    validate_threat_inference_output(
        app_record.threat_inference,
        app_record.autoencoder.is_anomaly,
        app_record.xgboost.is_attack,
        app_record.lstm.forecast_decision,
    )
    if (
        not isinstance(app_record.execution_metadata.inference_latency_ms, (int, float, np.number))
        or app_record.execution_metadata.inference_latency_ms < 0.0
    ):
        raise IntegrationContractError(
            f"Invalid inference_latency_ms in metadata: {app_record.execution_metadata.inference_latency_ms}"
        )


# =============================================================================
# INFORMATION LEAKAGE PREVENTION & ERROR MESSAGE SANITIZER
# =============================================================================

def sanitize_error_message(msg: str) -> str:
    """
    Sanitize client-facing error message strings to prevent technical information leakage.
    Redacts:
    - Windows filesystem drive paths (e.g. C:\\, E:\\)
    - Unix absolute directory paths (/home/, /usr/, /var/, /tmp/, /etc/, /opt/, /project/)
    - Python source code filenames (*.py)
    - Python stack trace line numbers (line 123)
    - Memory addresses (0x...)
    """
    if not isinstance(msg, str):
        return "An error occurred."

    clean = msg
    # 1. Redact Windows drive paths
    clean = re.sub(r"[A-Za-z]:\\[^ \"'\n\r\t]+", "[REDACTED_PATH]", clean)
    # 2. Redact Unix paths
    clean = re.sub(r"/(?:home|usr|var|tmp|etc|opt|project)/[^ \"'\n\r\t]+", "[REDACTED_PATH]", clean)
    # 3. Redact Python source references
    clean = re.sub(r"\b[\w\-]+\.py\b", "[REDACTED_SRC]", clean)
    # 4. Redact line references
    clean = re.sub(r"\bline \d+\b", "line [REDACTED]", clean, flags=re.IGNORECASE)
    # 5. Redact memory addresses
    clean = re.sub(r"\b0x[0-9a-fA-F]+\b", "[REDACTED_ADDR]", clean)

    return clean
