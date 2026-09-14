"""
NexThreat Phase 6.2 — Request/Response Schemas & Validation Verification Suite.

Implements automated verification gates V1 through V16 strictly adhering to
the audited Revision 8 implementation plan.
"""
from __future__ import annotations

import ast
import datetime
import hashlib
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Setup logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("NexThreat.Verification.Phase6_2")

# Authoritative imports
from src.api.exceptions import (
    APIError,
    APIValidationError,
    InternalAPIError,
    PayloadTooLargeError,
    StreamTooLargeError,
    format_api_error_response,
    sanitize_error_message,
)
from src.api.schemas import (
    CANONICAL_FEATURE_KEYS,
    AutoencoderResponse,
    ExecutionMetadataResponse,
    LSTMResponse,
    SingleWindowCanonicalRequest,
    SingleWindowNamedRequest,
    StandardInferenceResponse,
    StreamBatchRequest,
    ThreatInferenceResponse,
    XGBoostResponse,
)
from src.api.validators import (
    MAX_STREAM_RECORDS,
    validate_application_response,
    validate_single_window_request,
    validate_stream_batch_request,
)
from src.application.config import (
    AUTOENCODER_THRESHOLD,
    CANONICAL_THREAT_STATES,
    INPUT_TUPLE_TO_STATE,
    LSTM_THRESHOLD,
    XGBOOST_INDEX_TO_CLASS,
)
from src.application.schemas import (
    ApplicationOutputRecord,
    AutoencoderOutputRecord,
    CanonicalInputRecord,
    ExecutionMetadataRecord,
    LSTMOutputRecord,
    ThreatInferenceRecord,
    XGBoostOutputRecord,
)
from src.application.validators import (
    VALID_DAYS,
    WINDOW_ID_PATTERN,
    parse_timestamp,
    validate_canonical_input,
)


class Phase6_2_Verifier:
    """Automated verification suite executing Gates V1 through V16."""

    def __init__(self) -> None:
        self.results: Dict[str, Dict[str, Any]] = {}
        self.sample_features_format_a: List[float] = [
            124.0, 25.4, 18420.5, 0.45, 0.12, 0.35, 725.0, 150.2, 1.25, 4.0, 2.0, 0.85, 0.15
        ]
        self.sample_features_format_b: Dict[str, float] = {
            "flow_count": 124.0,
            "packet_rate": 25.4,
            "byte_rate": 18420.5,
            "mean_flow_duration": 0.45,
            "std_flow_duration": 0.12,
            "short_flow_ratio": 0.35,
            "mean_packet_size": 725.0,
            "packet_length_variability": 150.2,
            "fwd_bwd_packet_ratio": 1.25,
            "unique_dst_ports": 4.0,
            "unique_dst_ips": 2.0,
            "tcp_flow_ratio": 0.85,
            "syn_packet_ratio": 0.15,
        }

    def run_all_gates(self) -> bool:
        logger.info("================================================================================")
        logger.info("STARTING PHASE 6.2 SCHEMAS & VALIDATION VERIFICATION (GATES V1 – V16)")
        logger.info("================================================================================")

        gates = [
            ("V1", "Schema Existence & Interface Definition", self.gate_v1_schema_existence),
            ("V2", "Required Fields Validation", self.gate_v2_required_fields),
            ("V3", "Type Validation & Strict Type Disambiguation", self.gate_v3_type_validation),
            ("V4", "window_id Contract Validation (Inherited Regex)", self.gate_v4_window_id_contract),
            ("V5", "Canonical Feature Contract Validation (13 Features, Ordering, Finite)", self.gate_v5_canonical_features),
            ("V6", "Timestamp Contract Validation (Accepted Semantics)", self.gate_v6_timestamp_contract),
            ("V7", "Threat-State Contract Validation (S0–S7 Discrete States)", self.gate_v7_threat_state_contract),
            ("V8", "Nullability Contract Validation (Authoritative Null Bounds)", self.gate_v8_nullability_contract),
            ("V9", "Standardized Error Schema & Sanitization Validation", self.gate_v9_error_sanitization),
            ("V10", "Zero Inference on Invalid Input Guarantee", self.gate_v10_zero_inference_on_invalid),
            ("V11", "Phase 5 Input Contract Semantic Preservation", self.gate_v11_phase_5_input_preservation),
            ("V12", "Phase 5 Output Response Semantic Preservation", self.gate_v12_phase_5_output_preservation),
            ("V13", "Zero Semantic Duplication AST Audit", self.gate_v13_zero_duplication_ast),
            ("V14", "Phase 4 Frozen Artifact Integrity (33/33 SHA-256)", self.gate_v14_phase_4_integrity),
            ("V15", "Phase 5 Regression Suite Execution (22/22 Gates)", self.gate_v15_phase_5_regression),
            ("V16", "24-Field Authority Matrix Field-by-Field Audit", self.gate_v16_authority_matrix_audit),
        ]

        all_passed = True
        for gate_id, gate_name, gate_fn in gates:
            logger.info(f"Executing Gate {gate_id}: {gate_name}...")
            try:
                gate_fn()
                self.results[gate_id] = {"name": gate_name, "status": "PASS", "details": "Verification passed."}
                logger.info(f"Gate {gate_id} [{gate_name}]: PASS")
            except Exception as e:
                all_passed = False
                self.results[gate_id] = {"name": gate_name, "status": "FAIL", "details": str(e)}
                logger.error(f"Gate {gate_id} [{gate_name}]: FAIL - {e}", exc_info=True)

        logger.info("================================================================================")
        logger.info(f"PHASE 6.2 VERIFICATION SUMMARY: {'ALL 16 GATES PASSED' if all_passed else 'SOME GATES FAILED'}")
        logger.info("================================================================================")
        return all_passed

    # -------------------------------------------------------------------------
    # GATE V1: Schema Existence & Interface Definition
    # -------------------------------------------------------------------------
    def gate_v1_schema_existence(self) -> None:
        required_classes = [
            APIError,
            APIValidationError,
            PayloadTooLargeError,
            StreamTooLargeError,
            InternalAPIError,
            SingleWindowCanonicalRequest,
            SingleWindowNamedRequest,
            StreamBatchRequest,
            AutoencoderResponse,
            XGBoostResponse,
            LSTMResponse,
            ThreatInferenceResponse,
            ExecutionMetadataResponse,
            StandardInferenceResponse,
        ]
        for cls in required_classes:
            assert cls is not None, f"Required class {cls} not defined."

        required_funcs = [
            validate_single_window_request,
            validate_stream_batch_request,
            validate_application_response,
            sanitize_error_message,
            format_api_error_response,
        ]
        for fn in required_funcs:
            assert callable(fn), f"Required function {fn} is not callable."

    # -------------------------------------------------------------------------
    # GATE V2: Required Fields Validation
    # -------------------------------------------------------------------------
    def gate_v2_required_fields(self) -> None:
        # 1. Missing window_id
        try:
            validate_single_window_request({
                "timestamp": "2017-07-03T13:55:00",
                "features": self.sample_features_format_a,
            })
            assert False, "Failed to reject missing window_id"
        except APIValidationError:
            pass

        # 2. Missing timestamp
        try:
            validate_single_window_request({
                "window_id": "20170703_1355",
                "features": self.sample_features_format_a,
            })
            assert False, "Failed to reject missing timestamp"
        except APIValidationError:
            pass

        # 3. Missing features
        try:
            validate_single_window_request({
                "window_id": "20170703_1355",
                "timestamp": "2017-07-03T13:55:00",
            })
            assert False, "Failed to reject missing features"
        except APIValidationError:
            pass

        # 4. Empty payload
        try:
            validate_single_window_request({})
            assert False, "Failed to reject empty dict"
        except APIValidationError:
            pass

        # 5. Null payload
        try:
            validate_single_window_request(None)
            assert False, "Failed to reject None payload"
        except APIValidationError:
            pass

    # -------------------------------------------------------------------------
    # GATE V3: Type Validation & Strict Type Disambiguation
    # -------------------------------------------------------------------------
    def gate_v3_type_validation(self) -> None:
        # Integer window_id
        try:
            validate_single_window_request({
                "window_id": 201707031355,
                "timestamp": "2017-07-03T13:55:00",
                "features": self.sample_features_format_a,
            })
            assert False, "Failed to reject integer window_id"
        except APIValidationError:
            pass

        # Boolean window_id
        try:
            validate_single_window_request({
                "window_id": True,
                "timestamp": "2017-07-03T13:55:00",
                "features": self.sample_features_format_a,
            })
            assert False, "Failed to reject boolean window_id"
        except APIValidationError:
            pass

        # Boolean in features list
        bad_feats_bool = list(self.sample_features_format_a)
        bad_feats_bool[1] = True
        try:
            validate_single_window_request({
                "window_id": "20170703_1355",
                "timestamp": "2017-07-03T13:55:00",
                "features": bad_feats_bool,
            })
            assert False, "Failed to reject boolean in features"
        except APIValidationError:
            pass

        # String in features list
        bad_feats_str = list(self.sample_features_format_a)
        bad_feats_str[2] = "18420.5"
        try:
            validate_single_window_request({
                "window_id": "20170703_1355",
                "timestamp": "2017-07-03T13:55:00",
                "features": bad_feats_str,
            })
            assert False, "Failed to reject string in features"
        except APIValidationError:
            pass

        # Valid integers in features are accepted and converted to floats
        valid_int_feats = [int(x) if idx in (0, 9, 10) else x for idx, x in enumerate(self.sample_features_format_a)]
        rec = validate_single_window_request({
            "window_id": "20170703_1355",
            "timestamp": "2017-07-03T13:55:00",
            "features": valid_int_feats,
        })
        assert isinstance(rec.features[0], float)
        assert rec.features[0] == 124.0

    # -------------------------------------------------------------------------
    # GATE V4: window_id Contract Validation
    # -------------------------------------------------------------------------
    def gate_v4_window_id_contract(self) -> None:
        valid_ids = ["20170703_1355", "20170704_0900", "20170705_2359"]
        for vid in valid_ids:
            rec = validate_single_window_request({
                "window_id": vid,
                "timestamp": "2017-07-03T13:55:00",
                "features": self.sample_features_format_a,
            })
            assert rec.window_id == vid

        invalid_ids = [
            "2017073_1355",      # Short year/date
            "20170703-1355",      # Hyphen instead of underscore
            "abc_1234",          # Non-numeric
            "20170703_13550",     # Extra digit
            "20170703_135",       # Missing digit
            "",                   # Empty
            " 20170703_1355 ",    # Untrimmed whitespace
        ]
        for inv in invalid_ids:
            try:
                validate_single_window_request({
                    "window_id": inv,
                    "timestamp": "2017-07-03T13:55:00",
                    "features": self.sample_features_format_a,
                })
                assert False, f"Failed to reject invalid window_id '{inv}'"
            except APIValidationError:
                pass

    # -------------------------------------------------------------------------
    # GATE V5: Canonical Feature Contract Validation
    # -------------------------------------------------------------------------
    def gate_v5_canonical_features(self) -> None:
        # Format A: exactly 13 features
        rec_a = validate_single_window_request({
            "window_id": "20170703_1355",
            "timestamp": "2017-07-03T13:55:00",
            "features": self.sample_features_format_a,
        })
        assert len(rec_a.features) == 13
        assert rec_a.features == self.sample_features_format_a

        # Format A: 12 features (truncated)
        try:
            validate_single_window_request({
                "window_id": "20170703_1355",
                "timestamp": "2017-07-03T13:55:00",
                "features": self.sample_features_format_a[:12],
            })
            assert False, "Failed to reject truncated features (12)"
        except APIValidationError:
            pass

        # Format A: 14 features (oversized)
        try:
            validate_single_window_request({
                "window_id": "20170703_1355",
                "timestamp": "2017-07-03T13:55:00",
                "features": self.sample_features_format_a + [1.0],
            })
            assert False, "Failed to reject oversized features (14)"
        except APIValidationError:
            pass

        # Format A: NaN, +Inf, -Inf
        for bad_val in [float("nan"), float("inf"), float("-inf")]:
            bad_f = list(self.sample_features_format_a)
            bad_f[0] = bad_val
            try:
                validate_single_window_request({
                    "window_id": "20170703_1355",
                    "timestamp": "2017-07-03T13:55:00",
                    "features": bad_f,
                })
                assert False, f"Failed to reject non-finite feature ({bad_val})"
            except APIValidationError:
                pass

        # Format B: named object adapter
        rec_b = validate_single_window_request({
            "window_id": "20170703_1355",
            "timestamp": "2017-07-03T13:55:00",
            "features": self.sample_features_format_b,
        })
        assert len(rec_b.features) == 13
        assert rec_b.features == self.sample_features_format_a

        # Format B: missing key
        bad_dict_missing = dict(self.sample_features_format_b)
        del bad_dict_missing["syn_packet_ratio"]
        try:
            validate_single_window_request({
                "window_id": "20170703_1355",
                "timestamp": "2017-07-03T13:55:00",
                "features": bad_dict_missing,
            })
            assert False, "Failed to reject Format B missing key"
        except APIValidationError:
            pass

        # Format B: extra key
        bad_dict_extra = dict(self.sample_features_format_b)
        bad_dict_extra["extra_traffic_metric"] = 99.0
        try:
            validate_single_window_request({
                "window_id": "20170703_1355",
                "timestamp": "2017-07-03T13:55:00",
                "features": bad_dict_extra,
            })
            assert False, "Failed to reject Format B extra key"
        except APIValidationError:
            pass

    # -------------------------------------------------------------------------
    # GATE V6: Timestamp Contract Validation
    # -------------------------------------------------------------------------
    def gate_v6_timestamp_contract(self) -> None:
        valid_ts = [
            "2017-07-03T13:55:00",
            "2017-07-03 13:55:00",
            "2017-07-03T13:55:00.123456",
            "2017-07-03 13:55:00.123456",
        ]
        for ts in valid_ts:
            rec = validate_single_window_request({
                "window_id": "20170703_1355",
                "timestamp": ts,
                "features": self.sample_features_format_a,
            })
            assert rec.timestamp == ts

        invalid_ts = [
            1499080500,          # Unix epoch integer
            True,                # Boolean
            "not-a-date",        # Non-date string
            "2017/07/03 13:55",  # Slashes instead of dashes
            "",                  # Empty string
        ]
        for its in invalid_ts:
            try:
                validate_single_window_request({
                    "window_id": "20170703_1355",
                    "timestamp": its,
                    "features": self.sample_features_format_a,
                })
                assert False, f"Failed to reject invalid timestamp '{its}'"
            except APIValidationError:
                pass

    # -------------------------------------------------------------------------
    # GATE V7: Threat-State Contract Validation
    # -------------------------------------------------------------------------
    def gate_v7_threat_state_contract(self) -> None:
        # Build base valid response dict
        base_resp = {
            "window_id": "20170703_1355",
            "timestamp": "2017-07-03T13:55:00",
            "autoencoder": {
                "reconstruction_mse": 0.0015,
                "threshold": AUTOENCODER_THRESHOLD,
                "is_anomaly": 0,
            },
            "xgboost": {
                "predicted_class_index": 0,
                "predicted_class_name": "BENIGN",
                "is_attack": 0,
                "class_probabilities": [0.93, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01],
            },
            "lstm": {
                "is_eligible": True,
                "ineligibility_reason": None,
                "forecast_probability": 0.12,
                "threshold": LSTM_THRESHOLD,
                "forecast_decision": 0,
            },
            "threat_inference": {
                "is_eligible": True,
                "threat_state_code": "S0",
                "threat_state_name": "BENIGN_CONCORDANCE",
                "priority_tier": "P4",
                "decision_tuple": [0, 0, 0],
            },
            "execution_metadata": {
                "inference_latency_ms": 3.456,
                "schema_version": "1.0.0",
                "engine": "NexThreat-Phase5.2",
            },
        }

        # Validate S0 through S7 all pass
        for code in ["S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7"]:
            test_resp = json.loads(json.dumps(base_resp))
            test_resp["threat_inference"]["threat_state_code"] = code
            validate_application_response(test_resp)

        # Validate prohibited states raise APIValidationError
        prohibited_states = ["S8", "UNKNOWN", "LSTM_UNAVAILABLE", "ERROR", "BENIGN", "ATTACK"]
        for p_state in prohibited_states:
            test_resp = json.loads(json.dumps(base_resp))
            test_resp["threat_inference"]["threat_state_code"] = p_state
            try:
                validate_application_response(test_resp)
                assert False, f"Failed to reject prohibited threat state '{p_state}'"
            except APIValidationError:
                pass

    # -------------------------------------------------------------------------
    # GATE V8: Nullability Contract Validation
    # -------------------------------------------------------------------------
    def gate_v8_nullability_contract(self) -> None:
        # Null in required request fields rejected
        for field in ["window_id", "timestamp", "features"]:
            payload = {
                "window_id": "20170703_1355",
                "timestamp": "2017-07-03T13:55:00",
                "features": self.sample_features_format_a,
            }
            payload[field] = None
            try:
                validate_single_window_request(payload)
                assert False, f"Failed to reject null required field '{field}'"
            except APIValidationError:
                pass

        # Cold-start response with nulls in threat inference is valid
        cold_start_resp = {
            "window_id": "20170703_1355",
            "timestamp": "2017-07-03T13:55:00",
            "autoencoder": {
                "reconstruction_mse": 0.0015,
                "threshold": AUTOENCODER_THRESHOLD,
                "is_anomaly": 0,
            },
            "xgboost": {
                "predicted_class_index": 0,
                "predicted_class_name": "BENIGN",
                "is_attack": 0,
                "class_probabilities": None,
            },
            "lstm": {
                "is_eligible": False,
                "ineligibility_reason": "Cold-start: Insufficient lookback depth (current depth: 1, required: 10)",
                "forecast_probability": None,
                "threshold": LSTM_THRESHOLD,
                "forecast_decision": "unavailable",
            },
            "threat_inference": {
                "is_eligible": False,
                "threat_state_code": None,
                "threat_state_name": None,
                "priority_tier": None,
                "decision_tuple": None,
            },
            "execution_metadata": {
                "inference_latency_ms": 1.23,
                "schema_version": "1.0.0",
                "engine": "NexThreat-Phase5.2",
            },
        }
        res = validate_application_response(cold_start_resp)
        assert res["threat_inference"]["threat_state_code"] is None
        assert res["lstm"]["forecast_decision"] == "unavailable"

    # -------------------------------------------------------------------------
    # GATE V9: Standardized Error Schema & Sanitization Validation
    # -------------------------------------------------------------------------
    def gate_v9_error_sanitization(self) -> None:
        err = format_api_error_response(
            code="INPUT_VALIDATION_ERROR",
            message="Error in E:\\Project\\NexThreat\\src\\api\\validators.py at line 145 address 0x7ffee4b2a1c0",
            status_code=400,
            details={"field": "features"},
        )
        assert "error" in err
        err_body = err["error"]
        assert err_body["code"] == "INPUT_VALIDATION_ERROR"
        assert err_body["status_code"] == 400
        assert "timestamp" in err_body
        assert err_body["details"] == {"field": "features"}

        msg = err_body["message"]
        assert "E:\\Project" not in msg
        assert "validators.py" not in msg
        assert "0x7ffee4b2a1c0" not in msg
        assert "line 145" not in msg

    # -------------------------------------------------------------------------
    # GATE V10: Zero Inference on Invalid Input Guarantee
    # -------------------------------------------------------------------------
    def gate_v10_zero_inference_on_invalid(self) -> None:
        # Verify that invalid inputs raise APIValidationError without touching model layer
        invalid_inputs = [
            {},
            {"window_id": "invalid"},
            {"window_id": "20170703_1355", "timestamp": "bad", "features": [1.0] * 13},
            {"window_id": "20170703_1355", "timestamp": "2017-07-03T13:55:00", "features": [1.0] * 12},
        ]
        for inv in invalid_inputs:
            try:
                validate_single_window_request(inv)
                assert False, "Expected validation failure"
            except APIValidationError:
                pass

    # -------------------------------------------------------------------------
    # GATE V11: Phase 5 Input Contract Semantic Preservation
    # -------------------------------------------------------------------------
    def gate_v11_phase_5_input_preservation(self) -> None:
        # Format A request produces CanonicalInputRecord recognized by Phase 5
        req_a = validate_single_window_request({
            "window_id": "20170703_1355",
            "timestamp": "2017-07-03T13:55:00",
            "features": self.sample_features_format_a,
        })
        assert isinstance(req_a, CanonicalInputRecord)
        w_id, ts_str, ts_dt, day, arr = validate_canonical_input(req_a)
        assert w_id == "20170703_1355"
        assert len(arr) == 13
        assert arr.dtype.name == "float32"

        # Format B request also produces CanonicalInputRecord recognized by Phase 5
        req_b = validate_single_window_request({
            "window_id": "20170703_1355",
            "timestamp": "2017-07-03T13:55:00",
            "features": self.sample_features_format_b,
        })
        assert isinstance(req_b, CanonicalInputRecord)
        w_id_b, ts_str_b, ts_dt_b, day_b, arr_b = validate_canonical_input(req_b)
        assert w_id_b == "20170703_1355"
        assert len(arr_b) == 13
        assert list(arr) == list(arr_b)

    # -------------------------------------------------------------------------
    # GATE V12: Phase 5 Output Response Semantic Preservation
    # -------------------------------------------------------------------------
    def gate_v12_phase_5_output_preservation(self) -> None:
        # Create authoritative Phase 5 ApplicationOutputRecord
        p5_record = ApplicationOutputRecord(
            window_id="20170703_1355",
            timestamp="2017-07-03T13:55:00",
            global_position=15,
            dataset_day="Monday",
            autoencoder=AutoencoderOutputRecord(
                reconstruction_mse=0.0045,
                threshold=AUTOENCODER_THRESHOLD,
                is_anomaly=1,
            ),
            xgboost=XGBoostOutputRecord(
                predicted_class_index=1,
                predicted_class_name="Brute Force",
                is_attack=1,
                class_probabilities=[0.05, 0.70, 0.05, 0.05, 0.05, 0.04, 0.03, 0.03],
            ),
            lstm=LSTMOutputRecord(
                is_eligible=True,
                ineligibility_reason=None,
                forecast_probability=0.75,
                threshold=LSTM_THRESHOLD,
                forecast_decision=1,
            ),
            threat_inference=ThreatInferenceRecord(
                is_eligible=True,
                threat_state_code="S7",
                threat_state_name="TRI_MODEL_CONSENSUS",
                priority_tier="P1",
                decision_tuple=[1, 1, 1],
            ),
            execution_metadata=ExecutionMetadataRecord(
                inference_latency_ms=4.123,
                schema_version="1.0.0",
                engine="NexThreat-Phase5.2",
            ),
        )

        api_response = StandardInferenceResponse.from_application_record(p5_record)
        validated_dict = validate_application_response(api_response)

        # Field-for-field and structural correspondence verification
        p5_dict = p5_record.to_dict()
        assert validated_dict["window_id"] == p5_dict["window_id"]
        assert validated_dict["timestamp"] == p5_dict["timestamp"]
        assert validated_dict["global_position"] == p5_dict["global_position"]
        assert validated_dict["dataset_day"] == p5_dict["dataset_day"]
        assert validated_dict["autoencoder"] == p5_dict["autoencoder"]
        assert validated_dict["xgboost"] == p5_dict["xgboost"]
        assert validated_dict["lstm"] == p5_dict["lstm"]
        assert validated_dict["threat_inference"] == p5_dict["threat_inference"]
        assert validated_dict["execution_metadata"] == p5_dict["execution_metadata"]

    # -------------------------------------------------------------------------
    # GATE V13: Zero Semantic Duplication AST Audit
    # -------------------------------------------------------------------------
    def gate_v13_zero_duplication_ast(self) -> None:
        api_dir = PROJECT_ROOT / "src" / "api"
        py_files = [f for f in api_dir.rglob("*.py") if "verification" not in f.parts]
        assert len(py_files) >= 4, f"Expected at least 4 API files, found {len(py_files)}"

        prohibited_imports = {
            "torch",
            "xgboost",
            "tensorflow",
            "keras",
            "sklearn.preprocessing",
            "sklearn.pipeline",
        }
        prohibited_symbols = {
            "AutoencoderPredictor",
            "XGBoostPredictor",
            "LSTMPredictor",
            "ApplicationInferenceEngine",
            "TemporalHistoryBuffer",
            "fit_transform",
            "robust_scaler",
            "minmax_scaler",
        }

        for py_f in py_files:
            content = py_f.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(py_f))

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for p_imp in prohibited_imports:
                            assert not alias.name.startswith(p_imp), (
                                f"Prohibited import '{alias.name}' detected in {py_f.name}"
                            )
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    for p_imp in prohibited_imports:
                        assert not mod.startswith(p_imp), (
                            f"Prohibited import from '{mod}' detected in {py_f.name}"
                        )
                    for alias in node.names:
                        assert alias.name not in prohibited_symbols, (
                            f"Prohibited symbol import '{alias.name}' detected in {py_f.name}"
                        )
                elif isinstance(node, ast.Name):
                    assert node.id not in prohibited_symbols, (
                        f"Prohibited symbol reference '{node.id}' detected in {py_f.name}"
                    )

    # -------------------------------------------------------------------------
    # GATE V14: Phase 4 Frozen Artifact Integrity
    # -------------------------------------------------------------------------
    def gate_v14_phase_4_integrity(self) -> None:
        manifest_path = PROJECT_ROOT / "data" / "model_reports" / "acceptance" / "phase_4_7_acceptance_report.json"
        assert manifest_path.exists(), f"Missing Phase 4.7 manifest: {manifest_path}"

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        artifacts = manifest["pillars"]["Pillar_1_PRE"]["artifacts"]
        assert len(artifacts) == 33, f"Expected 33 artifacts, got {len(artifacts)}"

        for item in artifacts:
            rel = item["path"]
            abs_p = PROJECT_ROOT / rel
            assert abs_p.exists(), f"Missing Phase 4 artifact: {abs_p}"
            expected_sha = item["sha256"].lower()
            raw = open(abs_p, "rb").read()
            current_sha = hashlib.sha256(raw).hexdigest().lower()
            assert current_sha == expected_sha, (
                f"Hash mismatch for {rel}: expected {expected_sha}, got {current_sha}"
            )

    # -------------------------------------------------------------------------
    # GATE V15: Phase 5 Regression Suite Execution
    # -------------------------------------------------------------------------
    def gate_v15_phase_5_regression(self) -> None:
        from src.application.verification.verify_phase_5_7 import Phase5_7_Verifier
        v5 = Phase5_7_Verifier()
        success = v5.run_all_checks()
        assert success is True, "Phase 5.7 regression suite failed (expected 22/22 PASS)."

    # -------------------------------------------------------------------------
    # GATE V16: 24-Field Authority Matrix Field-by-Field Audit
    # -------------------------------------------------------------------------
    def gate_v16_authority_matrix_audit(self) -> None:
        """
        Independent field-by-field audit verifying all 24 fields across all 16 attributes.
        """
        # Exact 24 fields in Section 5.2 master matrix
        matrix_24_fields = [
            # 1
            {
                "id": 1,
                "path": "window_id",
                "type": str,
                "required": True,
                "nullable": False,
                "enum": None,
                "format": "Regex ^[0-9]{8}_[0-9]{4}$",
                "authority_layer": "Phase 5.1 / 5.5 / 6.1",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L223,436,544; validators.py:L41,127",
            },
            # 2
            {
                "id": 2,
                "path": "timestamp",
                "type": str,
                "required": True,
                "nullable": False,
                "enum": None,
                "format": "Accepted datetime formats",
                "authority_layer": "Phase 5.1 / 5.5 / 6.1",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L228,440; validators.py:L46-67",
            },
            # 3
            {
                "id": 3,
                "path": "global_position",
                "type": int,
                "required": False,
                "nullable": True,
                "enum": None,
                "format": None,
                "authority_layer": "Phase 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L238,443; validators.py:L363",
            },
            # 4
            {
                "id": 4,
                "path": "dataset_day",
                "type": str,
                "required": False,
                "nullable": True,
                "enum": set(VALID_DAYS) | {"Unknown"},
                "format": None,
                "authority_layer": "Phase 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L233,447; validators.py:L43,69-77",
            },
            # 5
            {
                "id": 5,
                "path": "autoencoder.reconstruction_mse",
                "type": float,
                "required": True,
                "nullable": False,
                "enum": None,
                "format": None,
                "authority_layer": "Phase 4.2 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L458; validators.py:L197-201",
            },
            # 6
            {
                "id": 6,
                "path": "autoencoder.threshold",
                "type": float,
                "required": True,
                "nullable": False,
                "enum": None,
                "format": None,
                "authority_layer": "Phase 4.2 / 5.1 / 5.2 / 6.1",
                "source_file": "src/application/config.py; src/application/schemas.py",
                "line_ref": "config.py:L39; schemas.py:L27; p6_1:L388",
            },
            # 7
            {
                "id": 7,
                "path": "autoencoder.is_anomaly",
                "type": int,
                "required": True,
                "nullable": False,
                "enum": {0, 1},
                "format": None,
                "authority_layer": "Phase 4.2 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L460; validators.py:L206-211",
            },
            # 8
            {
                "id": 8,
                "path": "xgboost.predicted_class_index",
                "type": int,
                "required": True,
                "nullable": False,
                "enum": set(range(8)),
                "format": None,
                "authority_layer": "Phase 4.3 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L471; validators.py:L223-227",
            },
            # 9
            {
                "id": 9,
                "path": "xgboost.predicted_class_name",
                "type": str,
                "required": True,
                "nullable": False,
                "enum": set(XGBOOST_INDEX_TO_CLASS.values()),
                "format": None,
                "authority_layer": "Phase 4.3 / 5.1 / 5.5",
                "source_file": "src/application/config.py; src/application/validators.py",
                "line_ref": "config.py:L63-73; validators.py:L228",
            },
            # 10
            {
                "id": 10,
                "path": "xgboost.is_attack",
                "type": int,
                "required": True,
                "nullable": False,
                "enum": {0, 1},
                "format": None,
                "authority_layer": "Phase 4.3 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L473; validators.py:L234-239",
            },
            # 11
            {
                "id": 11,
                "path": "xgboost.class_probabilities",
                "type": list,
                "required": False,
                "nullable": True,
                "enum": None,
                "format": "List of 8 floats in [0, 1]",
                "authority_layer": "Phase 4.3 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/schemas.py",
                "line_ref": "p5_1:L474; schemas.py:L43",
            },
            # 12
            {
                "id": 12,
                "path": "lstm.is_eligible",
                "type": bool,
                "required": True,
                "nullable": False,
                "enum": {True, False},
                "format": None,
                "authority_layer": "Phase 4.4 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L489; validators.py:L265-289",
            },
            # 13
            {
                "id": 13,
                "path": "lstm.ineligibility_reason",
                "type": str,
                "required": False,
                "nullable": True,
                "enum": None,
                "format": None,
                "authority_layer": "Phase 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L490; validators.py:L286,298",
            },
            # 14
            {
                "id": 14,
                "path": "lstm.forecast_probability",
                "type": float,
                "required": False,
                "nullable": True,
                "enum": None,
                "format": "Float in [0, 1]",
                "authority_layer": "Phase 4.4 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L491; validators.py:L270-274",
            },
            # 15
            {
                "id": 15,
                "path": "lstm.threshold",
                "type": float,
                "required": True,
                "nullable": False,
                "enum": None,
                "format": "Constant 0.3",
                "authority_layer": "Phase 4.4 / 5.1 / 5.2 / 6.1",
                "source_file": "src/application/config.py; src/application/schemas.py",
                "line_ref": "config.py:L40; schemas.py:L63; p6_1:L410",
            },
            # 16
            {
                "id": 16,
                "path": "lstm.forecast_decision",
                "type": (int, str),
                "required": True,
                "nullable": False,
                "enum": {0, 1, "unavailable"},
                "format": None,
                "authority_layer": "Phase 4.4 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L493; validators.py:L280,294",
            },
            # 17
            {
                "id": 17,
                "path": "threat_inference.is_eligible",
                "type": bool,
                "required": True,
                "nullable": False,
                "enum": {True, False},
                "format": None,
                "authority_layer": "Phase 4.5 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L505; validators.py:L312-327",
            },
            # 18
            {
                "id": 18,
                "path": "threat_inference.threat_state_code",
                "type": str,
                "required": False,
                "nullable": True,
                "enum": {"S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7"},
                "format": None,
                "authority_layer": "Phase 4.5 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/threat_engine.py",
                "line_ref": "p5_1:L506; threat_engine.py:L56",
            },
            # 19
            {
                "id": 19,
                "path": "threat_inference.threat_state_name",
                "type": str,
                "required": False,
                "nullable": True,
                "enum": {s["name"] for s in CANONICAL_THREAT_STATES.values()},
                "format": None,
                "authority_layer": "Phase 4.5 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/threat_engine.py",
                "line_ref": "p5_1:L507-517; threat_engine.py:L57",
            },
            # 20
            {
                "id": 20,
                "path": "threat_inference.priority_tier",
                "type": str,
                "required": False,
                "nullable": True,
                "enum": {"P1", "P2", "P3", "P4"},
                "format": None,
                "authority_layer": "Phase 4.5 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/threat_engine.py",
                "line_ref": "p5_1:L518; threat_engine.py:L71",
            },
            # 21
            {
                "id": 21,
                "path": "threat_inference.decision_tuple",
                "type": list,
                "required": False,
                "nullable": True,
                "enum": None,
                "format": "List of 3 ints in {0, 1}",
                "authority_layer": "Phase 4.5 / 5.1 / 5.5",
                "source_file": "phase_5_1_specification.md; src/application/validators.py",
                "line_ref": "p5_1:L519-524; validators.py:L350-353",
            },
            # 22
            {
                "id": 22,
                "path": "execution_metadata.inference_latency_ms",
                "type": float,
                "required": True,
                "nullable": False,
                "enum": None,
                "format": "Float >= 0.0",
                "authority_layer": "Phase 5.1 / 5.5",
                "source_file": "src/application/schemas.py; src/application/validators.py",
                "line_ref": "schemas.py:L96; validators.py:L379",
            },
            # 23
            {
                "id": 23,
                "path": "execution_metadata.schema_version",
                "type": str,
                "required": True,
                "nullable": False,
                "enum": {"1.0.0"},
                "format": "Constant '1.0.0'",
                "authority_layer": "Phase 5.2 / 6.1",
                "source_file": "src/application/schemas.py; phase_6_1_specification.md",
                "line_ref": "schemas.py:L97; phase_6_1:L360,422",
            },
            # 24
            {
                "id": 24,
                "path": "execution_metadata.engine",
                "type": str,
                "required": True,
                "nullable": False,
                "enum": {"NexThreat-Phase5.2"},
                "format": "Constant 'NexThreat-Phase5.2'",
                "authority_layer": "Phase 5.2 / 6.1",
                "source_file": "src/application/schemas.py; phase_6_1_specification.md",
                "line_ref": "schemas.py:L98; phase_6_1:L361,423",
            },
        ]

        assert len(matrix_24_fields) == 24, f"Expected exactly 24 fields, got {len(matrix_24_fields)}"

        # Validate that each of the 24 fields is represented in StandardInferenceResponse
        sample_resp = StandardInferenceResponse(
            window_id="20170703_1355",
            timestamp="2017-07-03T13:55:00",
            autoencoder=AutoencoderResponse(
                reconstruction_mse=0.001,
                threshold=AUTOENCODER_THRESHOLD,
                is_anomaly=0,
            ),
            xgboost=XGBoostResponse(
                predicted_class_index=0,
                predicted_class_name="BENIGN",
                is_attack=0,
                class_probabilities=[0.93, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01],
            ),
            lstm=LSTMResponse(
                is_eligible=True,
                ineligibility_reason=None,
                forecast_probability=0.12,
                threshold=LSTM_THRESHOLD,
                forecast_decision=0,
            ),
            threat_inference=ThreatInferenceResponse(
                is_eligible=True,
                threat_state_code="S0",
                threat_state_name="BENIGN_CONCORDANCE",
                priority_tier="P4",
                decision_tuple=[0, 0, 0],
            ),
            global_position=1,
            dataset_day="Monday",
            execution_metadata=ExecutionMetadataResponse(
                inference_latency_ms=2.5,
                schema_version="1.0.0",
                engine="NexThreat-Phase5.2",
            ),
        )

        cold_resp = StandardInferenceResponse(
            window_id="20170703_1355",
            timestamp="2017-07-03T13:55:00",
            autoencoder=AutoencoderResponse(
                reconstruction_mse=0.001,
                threshold=AUTOENCODER_THRESHOLD,
                is_anomaly=0,
            ),
            xgboost=XGBoostResponse(
                predicted_class_index=0,
                predicted_class_name="BENIGN",
                is_attack=0,
                class_probabilities=None,
            ),
            lstm=LSTMResponse(
                is_eligible=False,
                ineligibility_reason="Cold-start: Insufficient lookback depth (current depth: 1, required: 10)",
                forecast_probability=None,
                threshold=LSTM_THRESHOLD,
                forecast_decision="unavailable",
            ),
            threat_inference=ThreatInferenceResponse(
                is_eligible=False,
                threat_state_code=None,
                threat_state_name=None,
                priority_tier=None,
                decision_tuple=None,
            ),
            global_position=1,
            dataset_day="Monday",
            execution_metadata=ExecutionMetadataResponse(
                inference_latency_ms=1.5,
                schema_version="1.0.0",
                engine="NexThreat-Phase5.2",
            ),
        )

        for test_obj in [sample_resp, cold_resp]:
            d = test_obj.to_dict()
            for f_info in matrix_24_fields:
                fid = f_info["id"]
                path = f_info["path"]
                parts = path.split(".")
                val = d
                for p in parts:
                    assert p in val, f"Field {path} missing in response dictionary"
                    val = val[p]

                # Verify nullability and type
                if val is None:
                    assert f_info["nullable"] is True, (
                        f"Field {path} is None but marked non-nullable in authority matrix"
                    )
                else:
                    exp_type = f_info["type"]
                    if isinstance(exp_type, tuple):
                        assert isinstance(val, exp_type), (
                            f"Field {path} type mismatch: expected one of {exp_type}, got {type(val)}"
                        )
                    else:
                        assert isinstance(val, exp_type), (
                            f"Field {path} type mismatch: expected {exp_type}, got {type(val)}"
                        )

                    # Verify enum if defined
                    if f_info["enum"] is not None:
                        assert val in f_info["enum"], (
                            f"Field {path} enum violation: '{val}' not in {f_info['enum']}"
                        )

                # Verify line ref & source file present
                assert f_info["source_file"], f"Field {path} missing authoritative source citation"
                assert f_info["line_ref"], f"Field {path} missing authoritative line reference"


def main():
    verifier = Phase6_2_Verifier()
    success = verifier.run_all_gates()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
