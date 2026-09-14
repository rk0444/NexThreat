"""
NexThreat Phase 6.2 — API Request and Response Validators.

Implements pure request validation and Format B dictionary mapping to
CanonicalInputRecord without executing model inference, threshold logic, or
state-machine transitions.
Implements assert-only response integrity validation across the complete
24-field Authority Matrix strictly corresponding to Phase 5.1 Section 17.
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from src.api.exceptions import (
    APIValidationError,
    StreamTooLargeError,
)
from src.api.schemas import (
    CANONICAL_FEATURE_KEYS,
    SingleWindowCanonicalRequest,
    SingleWindowNamedRequest,
    StandardInferenceResponse,
    StreamBatchRequest,
)
from src.application.config import (
    AUTOENCODER_THRESHOLD,
    CANONICAL_THREAT_STATES,
    INPUT_TUPLE_TO_STATE,
    LSTM_THRESHOLD,
    XGBOOST_INDEX_TO_CLASS,
)
from src.application.exceptions import InputValidationError
from src.application.schemas import (
    ApplicationOutputRecord,
    CanonicalInputRecord,
)
from src.application.validators import (
    VALID_DAYS,
    WINDOW_ID_PATTERN,
    parse_timestamp,
)

MAX_STREAM_RECORDS: int = 5000
ALLOWED_REQUEST_KEYS: Set[str] = {"window_id", "timestamp", "features"}
ALLOWED_STREAM_KEYS: Set[str] = {"stream"}
CANONICAL_STATE_CODES: Set[str] = {"S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7"}
VALID_PRIORITY_TIERS: Set[str] = {"P1", "P2", "P3", "P4"}
VALID_DATASET_DAYS: Set[str] = VALID_DAYS | {"Unknown"}


# =============================================================================
# REQUEST VALIDATORS (ADAPTER TO CANONICALINPUTRECORD)
# =============================================================================

def validate_single_window_request(raw_payload: Any) -> CanonicalInputRecord:
    """
    Validate an external single-window request payload and return a CanonicalInputRecord.

    Supports:
    - Format A: features provided as canonical 13-element float list.
    - Format B: features provided as dictionary with 13 named canonical keys,
      mapped in-order into the canonical list without scaling or normalization.

    Strictly rejects:
    - Missing required fields, extra keys, non-dict payloads.
    - Invalid window_id (non-string, bool, non-matching regex).
    - Invalid timestamp (non-string, bool, unparseable under Phase 5 semantics).
    - Non-numeric, boolean, null, NaN, or infinite feature values.
    """
    if raw_payload is None:
        raise APIValidationError("Request payload cannot be null.")

    if isinstance(raw_payload, SingleWindowCanonicalRequest):
        window_id = raw_payload.window_id
        timestamp_str = raw_payload.timestamp
        raw_features = raw_payload.features
    elif isinstance(raw_payload, SingleWindowNamedRequest):
        window_id = raw_payload.window_id
        timestamp_str = raw_payload.timestamp
        raw_features = raw_payload.features
    elif isinstance(raw_payload, dict):
        raw_keys = set(raw_payload.keys())
        missing = ALLOWED_REQUEST_KEYS - raw_keys
        if missing:
            raise APIValidationError(f"Missing required field(s): {sorted(list(missing))}.")
        extra = raw_keys - ALLOWED_REQUEST_KEYS
        if extra:
            raise APIValidationError(
                f"Extraneous field(s) detected: {sorted(list(extra))}. "
                f"Allowed fields: {sorted(list(ALLOWED_REQUEST_KEYS))}."
            )
        window_id = raw_payload["window_id"]
        timestamp_str = raw_payload["timestamp"]
        raw_features = raw_payload["features"]
    else:
        raise APIValidationError(f"Expected JSON object, got {type(raw_payload).__name__}.")

    # 1. Validate window_id
    if isinstance(window_id, bool) or not isinstance(window_id, str):
        raise APIValidationError(
            f"Field 'window_id' must be a string, got {type(window_id).__name__}."
        )
    if not WINDOW_ID_PATTERN.match(window_id):
        raise APIValidationError(
            f"Invalid window_id '{window_id}'. Expected format 'YYYYMMDD_HHMM' (e.g. '20170703_1355')."
        )

    # 2. Validate timestamp
    if isinstance(timestamp_str, bool) or not isinstance(timestamp_str, str):
        raise APIValidationError(
            f"Field 'timestamp' must be a string, got {type(timestamp_str).__name__}."
        )
    try:
        parse_timestamp(timestamp_str)
    except InputValidationError as e:
        raise APIValidationError(f"Invalid timestamp format '{timestamp_str}': {e}") from e
    except Exception as e:
        raise APIValidationError(f"Failed to parse timestamp '{timestamp_str}': {e}") from e

    # 3. Validate features
    if raw_features is None:
        raise APIValidationError("Field 'features' cannot be null.")

    canonical_features: List[float] = []

    if isinstance(raw_features, list):
        # Format A: Canonical array of 13 numbers
        if len(raw_features) != 13:
            raise APIValidationError(
                f"Expected exactly 13 canonical features, got {len(raw_features)}."
            )
        for idx, val in enumerate(raw_features):
            if isinstance(val, bool):
                raise APIValidationError(
                    f"Feature at index {idx} must be numeric, got boolean: {val}."
                )
            if not isinstance(val, (int, float)):
                raise APIValidationError(
                    f"Feature at index {idx} must be numeric, got {type(val).__name__}."
                )
            f_val = float(val)
            if math.isnan(f_val) or math.isinf(f_val):
                raise APIValidationError(
                    f"Feature at index {idx} has non-finite value ({f_val}). NaN and Infinity are forbidden."
                )
            canonical_features.append(f_val)

    elif isinstance(raw_features, dict):
        # Format B: Named object with 13 canonical keys
        dict_keys = set(raw_features.keys())
        expected_keys = set(CANONICAL_FEATURE_KEYS)
        missing_keys = expected_keys - dict_keys
        if missing_keys:
            raise APIValidationError(
                f"Missing required feature key(s) in Format B: {sorted(list(missing_keys))}."
            )
        extra_keys = dict_keys - expected_keys
        if extra_keys:
            raise APIValidationError(
                f"Extraneous feature key(s) in Format B: {sorted(list(extra_keys))}."
            )

        # Map sequentially according to CANONICAL_FEATURE_KEYS
        for key in CANONICAL_FEATURE_KEYS:
            val = raw_features[key]
            if isinstance(val, bool):
                raise APIValidationError(
                    f"Feature '{key}' must be numeric, got boolean: {val}."
                )
            if not isinstance(val, (int, float)):
                raise APIValidationError(
                    f"Feature '{key}' must be numeric, got {type(val).__name__}."
                )
            f_val = float(val)
            if math.isnan(f_val) or math.isinf(f_val):
                raise APIValidationError(
                    f"Feature '{key}' has non-finite value ({f_val}). NaN and Infinity are forbidden."
                )
            canonical_features.append(f_val)

    else:
        raise APIValidationError(
            f"Field 'features' must be an array of 13 numbers (Format A) "
            f"or an object with 13 named features (Format B), got {type(raw_features).__name__}."
        )

    return CanonicalInputRecord(
        window_id=str(window_id),
        timestamp=str(timestamp_str),
        features=canonical_features,
    )


def validate_stream_batch_request(raw_payload: Any) -> List[CanonicalInputRecord]:
    """
    Validate a stream container payload and return a list of CanonicalInputRecords.

    Enforces:
    - Root object has key 'stream' with 0 extra keys.
    - 'stream' is a non-empty list of window records.
    - Max stream size <= 5,000 records (StreamTooLargeError if exceeded).
    - Every individual record conforms to validate_single_window_request.
    """
    if raw_payload is None:
        raise APIValidationError("Stream payload cannot be null.")

    if isinstance(raw_payload, StreamBatchRequest):
        raw_stream = raw_payload.stream
    elif isinstance(raw_payload, dict):
        raw_keys = set(raw_payload.keys())
        if "stream" not in raw_keys:
            raise APIValidationError("Missing required field 'stream' in batch payload.")
        extra = raw_keys - ALLOWED_STREAM_KEYS
        if extra:
            raise APIValidationError(
                f"Extraneous field(s) in stream container: {sorted(list(extra))}."
            )
        raw_stream = raw_payload["stream"]
    else:
        raise APIValidationError(f"Expected JSON object with 'stream' key, got {type(raw_payload).__name__}.")

    if not isinstance(raw_stream, list):
        raise APIValidationError(f"Field 'stream' must be a list, got {type(raw_stream).__name__}.")

    if len(raw_stream) == 0:
        raise APIValidationError("Field 'stream' cannot be empty.")

    if len(raw_stream) > MAX_STREAM_RECORDS:
        raise StreamTooLargeError(
            f"Stream batch exceeds maximum limit of {MAX_STREAM_RECORDS} records (got {len(raw_stream)})."
        )

    records: List[CanonicalInputRecord] = []
    for idx, item in enumerate(raw_stream):
        try:
            record = validate_single_window_request(item)
            records.append(record)
        except APIValidationError as e:
            raise APIValidationError(f"Stream record at index {idx} invalid: {e.message}") from e

    return records


# =============================================================================
# RESPONSE INTEGRITY VALIDATION (24 AUTHORITATIVE FIELDS)
# =============================================================================

def validate_application_response(
    response_data: Union[Dict[str, Any], StandardInferenceResponse, ApplicationOutputRecord]
) -> Dict[str, Any]:
    """
    Validate that an outgoing API response adheres strictly to the 24-field Authority Matrix.

    Performs structural and representation integrity checks only.
    Strictly does NOT evaluate model inference, threshold calculations, or threat state logic.
    """
    if isinstance(response_data, StandardInferenceResponse):
        d = response_data.to_dict()
    elif isinstance(response_data, ApplicationOutputRecord):
        d = response_data.to_dict()
    elif isinstance(response_data, dict):
        d = response_data
    else:
        raise APIValidationError(f"Expected response object or dict, got {type(response_data).__name__}.")

    # --- Top-Level Root Fields ---
    # Field 1: window_id
    if "window_id" not in d or d["window_id"] is None:
        raise APIValidationError("Missing or null required field 'window_id' in response.")
    w_id = d["window_id"]
    if isinstance(w_id, bool) or not isinstance(w_id, str) or not WINDOW_ID_PATTERN.match(w_id):
        raise APIValidationError(f"Invalid 'window_id' in response: {w_id}")

    # Field 2: timestamp
    if "timestamp" not in d or d["timestamp"] is None:
        raise APIValidationError("Missing or null required field 'timestamp' in response.")
    ts = d["timestamp"]
    if isinstance(ts, bool) or not isinstance(ts, str):
        raise APIValidationError(f"Invalid 'timestamp' in response: {ts}")
    try:
        parse_timestamp(ts)
    except Exception as e:
        raise APIValidationError(f"Unparseable response timestamp '{ts}': {e}") from e

    # Field 3: global_position (Optional, Nullable, int >= 1)
    if "global_position" in d and d["global_position"] is not None:
        gp = d["global_position"]
        if isinstance(gp, bool) or not isinstance(gp, int) or gp < 1:
            raise APIValidationError(f"Invalid 'global_position' in response: {gp}. Must be integer >= 1.")

    # Field 4: dataset_day (Optional, Nullable, enum)
    if "dataset_day" in d and d["dataset_day"] is not None:
        day = d["dataset_day"]
        if isinstance(day, bool) or not isinstance(day, str) or day not in VALID_DATASET_DAYS:
            raise APIValidationError(f"Invalid 'dataset_day' in response: {day}. Allowed: {sorted(list(VALID_DATASET_DAYS))}.")

    # --- Autoencoder Block (Fields 5..7) ---
    if "autoencoder" not in d or not isinstance(d["autoencoder"], dict):
        raise APIValidationError("Missing or invalid 'autoencoder' section in response.")
    ae = d["autoencoder"]

    # Field 5: reconstruction_mse (finite float >= 0.0)
    if "reconstruction_mse" not in ae or ae["reconstruction_mse"] is None or isinstance(ae["reconstruction_mse"], bool):
        raise APIValidationError("Missing or invalid 'autoencoder.reconstruction_mse'.")
    mse = float(ae["reconstruction_mse"])
    if math.isnan(mse) or math.isinf(mse) or mse < 0.0:
        raise APIValidationError(f"Invalid 'autoencoder.reconstruction_mse': {mse}. Must be finite >= 0.0.")

    # Field 6: threshold (exact constant 0.003207791231673312)
    if "threshold" not in ae or ae["threshold"] is None or isinstance(ae["threshold"], bool):
        raise APIValidationError("Missing or invalid 'autoencoder.threshold'.")
    ae_thresh = float(ae["threshold"])
    if abs(ae_thresh - AUTOENCODER_THRESHOLD) > 1e-12:
        raise APIValidationError(
            f"Mutated 'autoencoder.threshold': expected {AUTOENCODER_THRESHOLD}, got {ae_thresh}."
        )

    # Field 7: is_anomaly (int in [0, 1], not bool)
    if "is_anomaly" not in ae or isinstance(ae["is_anomaly"], bool) or ae["is_anomaly"] not in (0, 1):
        raise APIValidationError(f"Invalid 'autoencoder.is_anomaly': {ae.get('is_anomaly')}. Must be 0 or 1.")

    # --- XGBoost Block (Fields 8..11) ---
    if "xgboost" not in d or not isinstance(d["xgboost"], dict):
        raise APIValidationError("Missing or invalid 'xgboost' section in response.")
    xgb = d["xgboost"]

    # Field 8: predicted_class_index (int in 0..7, not bool)
    if "predicted_class_index" not in xgb or isinstance(xgb["predicted_class_index"], bool) or xgb["predicted_class_index"] not in range(8):
        raise APIValidationError(f"Invalid 'xgboost.predicted_class_index': {xgb.get('predicted_class_index')}.")

    # Field 9: predicted_class_name (str in authoritative mapping)
    expected_class_name = XGBOOST_INDEX_TO_CLASS.get(xgb["predicted_class_index"])
    if "predicted_class_name" not in xgb or xgb["predicted_class_name"] != expected_class_name:
        raise APIValidationError(
            f"Inconsistent 'xgboost.predicted_class_name': expected '{expected_class_name}', got '{xgb.get('predicted_class_name')}'."
        )

    # Field 10: is_attack (int in [0, 1], not bool)
    if "is_attack" not in xgb or isinstance(xgb["is_attack"], bool) or xgb["is_attack"] not in (0, 1):
        raise APIValidationError(f"Invalid 'xgboost.is_attack': {xgb.get('is_attack')}. Must be 0 or 1.")

    # Field 11: class_probabilities (Optional, Nullable, List[float] length 8)
    if "class_probabilities" in xgb and xgb["class_probabilities"] is not None:
        c_probs = xgb["class_probabilities"]
        if not isinstance(c_probs, list) or len(c_probs) != 8:
            raise APIValidationError("Field 'xgboost.class_probabilities' must be a list of 8 floats or null.")
        for p_idx, p_val in enumerate(c_probs):
            if isinstance(p_val, bool) or not isinstance(p_val, (int, float)):
                raise APIValidationError(f"Probability at index {p_idx} must be numeric float.")
            fp = float(p_val)
            if math.isnan(fp) or math.isinf(fp) or fp < 0.0 or fp > 1.0:
                raise APIValidationError(f"Probability at index {p_idx} out of range [0.0, 1.0]: {fp}.")

    # --- LSTM Block (Fields 12..16) ---
    if "lstm" not in d or not isinstance(d["lstm"], dict):
        raise APIValidationError("Missing or invalid 'lstm' section in response.")
    lstm = d["lstm"]

    # Field 12: is_eligible (strictly bool)
    if "is_eligible" not in lstm or not isinstance(lstm["is_eligible"], bool):
        raise APIValidationError(f"Field 'lstm.is_eligible' must be boolean, got {type(lstm.get('is_eligible')).__name__}.")
    is_lstm_eligible = lstm["is_eligible"]

    # Field 13: ineligibility_reason (str if not eligible, null if eligible)
    if is_lstm_eligible:
        if lstm.get("ineligibility_reason") is not None:
            raise APIValidationError("Field 'lstm.ineligibility_reason' must be null when is_eligible is True.")
    else:
        if not isinstance(lstm.get("ineligibility_reason"), str) or not lstm["ineligibility_reason"].strip():
            raise APIValidationError("Field 'lstm.ineligibility_reason' must be non-empty string when is_eligible is False.")

    # Field 14: forecast_probability (float in [0, 1] if eligible, null if not)
    if is_lstm_eligible:
        if "forecast_probability" not in lstm or lstm["forecast_probability"] is None or isinstance(lstm["forecast_probability"], bool):
            raise APIValidationError("Field 'lstm.forecast_probability' must be a float when is_eligible is True.")
        fp = float(lstm["forecast_probability"])
        if math.isnan(fp) or math.isinf(fp) or fp < 0.0 or fp > 1.0:
            raise APIValidationError(f"Invalid 'lstm.forecast_probability': {fp}. Must be finite in [0.0, 1.0].")
    else:
        if lstm.get("forecast_probability") is not None:
            raise APIValidationError("Field 'lstm.forecast_probability' must be null when is_eligible is False.")

    # Field 15: threshold (exact constant 0.3)
    if "threshold" not in lstm or lstm["threshold"] is None or isinstance(lstm["threshold"], bool):
        raise APIValidationError("Missing or invalid 'lstm.threshold'.")
    lstm_thresh = float(lstm["threshold"])
    if abs(lstm_thresh - LSTM_THRESHOLD) > 1e-12:
        raise APIValidationError(f"Mutated 'lstm.threshold': expected {LSTM_THRESHOLD}, got {lstm_thresh}.")

    # Field 16: forecast_decision (int in (0, 1) if eligible, "unavailable" if not)
    if is_lstm_eligible:
        if isinstance(lstm.get("forecast_decision"), bool) or lstm.get("forecast_decision") not in (0, 1):
            raise APIValidationError(
                f"Field 'lstm.forecast_decision' must be 0 or 1 when eligible, got {lstm.get('forecast_decision')}."
            )
    else:
        if lstm.get("forecast_decision") != "unavailable":
            raise APIValidationError(
                f"Field 'lstm.forecast_decision' must be 'unavailable' when ineligible, got '{lstm.get('forecast_decision')}'."
            )

    # --- Threat Inference Block (Fields 17..21) ---
    if "threat_inference" not in d or not isinstance(d["threat_inference"], dict):
        raise APIValidationError("Missing or invalid 'threat_inference' section in response.")
    ti = d["threat_inference"]

    # Field 17: is_eligible (strictly bool)
    if "is_eligible" not in ti or not isinstance(ti["is_eligible"], bool):
        raise APIValidationError(f"Field 'threat_inference.is_eligible' must be boolean, got {type(ti.get('is_eligible')).__name__}.")
    is_ti_eligible = ti["is_eligible"]

    if is_ti_eligible != is_lstm_eligible:
        raise APIValidationError(
            f"Eligibility mismatch: 'threat_inference.is_eligible' ({is_ti_eligible}) "
            f"must match 'lstm.is_eligible' ({is_lstm_eligible})."
        )

    # Field 18: threat_state_code
    # Field 19: threat_state_name
    # Field 20: priority_tier
    # Field 21: decision_tuple
    if is_ti_eligible:
        # Field 18: threat_state_code (enum S0..S7; S8, UNKNOWN, LSTM_UNAVAILABLE forbidden)
        code = ti.get("threat_state_code")
        if code not in CANONICAL_STATE_CODES:
            raise APIValidationError(
                f"Invalid 'threat_inference.threat_state_code': '{code}'. Must be in {sorted(list(CANONICAL_STATE_CODES))}."
            )

        # Field 19: threat_state_name
        name = ti.get("threat_state_name")
        if not isinstance(name, str) or not name.strip():
            raise APIValidationError("Field 'threat_inference.threat_state_name' must be non-empty string when eligible.")

        # Field 20: priority_tier
        tier = ti.get("priority_tier")
        if tier not in VALID_PRIORITY_TIERS:
            raise APIValidationError(
                f"Invalid 'threat_inference.priority_tier': '{tier}'. Must be in {sorted(list(VALID_PRIORITY_TIERS))}."
            )

        # Field 21: decision_tuple
        dt = ti.get("decision_tuple")
        if not isinstance(dt, list) or len(dt) != 3:
            raise APIValidationError("Field 'threat_inference.decision_tuple' must be a list of 3 integers.")
        for elem in dt:
            if isinstance(elem, bool) or elem not in (0, 1):
                raise APIValidationError(f"Elements of 'decision_tuple' must be 0 or 1, got {elem}.")
    else:
        # When ineligible, threat fields must be null
        if ti.get("threat_state_code") is not None:
            raise APIValidationError("Field 'threat_inference.threat_state_code' must be null when ineligible.")
        if ti.get("threat_state_name") is not None:
            raise APIValidationError("Field 'threat_inference.threat_state_name' must be null when ineligible.")
        if ti.get("priority_tier") is not None:
            raise APIValidationError("Field 'threat_inference.priority_tier' must be null when ineligible.")
        if ti.get("decision_tuple") is not None:
            raise APIValidationError("Field 'threat_inference.decision_tuple' must be null when ineligible.")

    # --- Execution Metadata Block (Fields 22..24) ---
    if "execution_metadata" in d and d["execution_metadata"] is not None:
        meta = d["execution_metadata"]
        if not isinstance(meta, dict):
            raise APIValidationError("Field 'execution_metadata' must be a dictionary.")

        # Field 22: inference_latency_ms
        if "inference_latency_ms" not in meta or meta["inference_latency_ms"] is None or isinstance(meta["inference_latency_ms"], bool):
            raise APIValidationError("Missing or invalid 'execution_metadata.inference_latency_ms'.")
        lat = float(meta["inference_latency_ms"])
        if math.isnan(lat) or math.isinf(lat) or lat < 0.0:
            raise APIValidationError(f"Invalid 'execution_metadata.inference_latency_ms': {lat}. Must be finite >= 0.0.")

        # Field 23: schema_version (Constant "1.0.0")
        if meta.get("schema_version") != "1.0.0":
            raise APIValidationError(
                f"Invalid 'execution_metadata.schema_version': expected '1.0.0', got '{meta.get('schema_version')}'."
            )

        # Field 24: engine (Constant "NexThreat-Phase5.2")
        if meta.get("engine") != "NexThreat-Phase5.2":
            raise APIValidationError(
                f"Invalid 'execution_metadata.engine': expected 'NexThreat-Phase5.2', got '{meta.get('engine')}'."
            )

    return d
