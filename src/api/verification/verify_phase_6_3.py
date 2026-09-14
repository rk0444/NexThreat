"""
NexThreat Phase 6.3 — API Transport Handlers & Endpoints Verification Suite.

Executes all 20 mandatory acceptance gates (T1–T20) strictly conforming to
data/model_reports/application/phase_6_3_api_endpoint_integration_and_transport_handlers_implementation_plan.md.
"""
from __future__ import annotations

import ast
import concurrent.futures
import datetime
import hashlib
import http.client
import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.api.handlers import NexThreatAPIHandler
from src.api.schemas import CANONICAL_FEATURE_KEYS
from src.api.server import NexThreatAPIServer
from src.api.validators import validate_application_response
from src.application.orchestrator import ApplicationInferenceEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Phase6_3_Verifier")

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Phase6_3_Verifier:
    """Comprehensive verifier executing all 20 Phase 6.3 acceptance gates (T1–T20)."""

    def __init__(self) -> None:
        self.results: Dict[str, Tuple[bool, str]] = {}
        self.server: Optional[NexThreatAPIServer] = None
        self.port: int = 0

    def _start_test_server(self, engine: Optional[ApplicationInferenceEngine] = None) -> None:
        """Start an ephemeral test server on an OS-allocated port."""
        if self.server is not None:
            self._stop_test_server()
        test_engine = engine or ApplicationInferenceEngine()
        self.server = NexThreatAPIServer(host="127.0.0.1", port=0, engine=test_engine)
        self.server.start()
        self.port = self.server.actual_port
        time.sleep(0.1)  # allow socket initialization

    def _stop_test_server(self) -> None:
        """Stop the test server."""
        if self.server is not None:
            self.server.stop()
            self.server = None
            self.port = 0

    def _http_request(
        self,
        method: str,
        path: str,
        body: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        raw_body: Optional[bytes] = None,
    ) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        """Perform a synchronous HTTP request and return status, parsed JSON (or empty), and headers."""
        req_headers = headers.copy() if headers else {}
        body_bytes: Optional[bytes] = None

        if raw_body is not None:
            body_bytes = raw_body
        elif body is not None:
            body_bytes = json.dumps(body).encode("utf-8")
            if "Content-Type" not in req_headers:
                req_headers["Content-Type"] = "application/json"

        if body_bytes is not None and "Content-Length" not in req_headers:
            req_headers["Content-Length"] = str(len(body_bytes))

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.request(method, path, body=body_bytes, headers=req_headers)
            resp = conn.getresponse()
            resp_bytes = resp.read()
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            data: Dict[str, Any] = {}
            if resp_bytes:
                try:
                    data = json.loads(resp_bytes.decode("utf-8"))
                except Exception:
                    data = {"_raw": resp_bytes.decode("utf-8", errors="replace")}
            return resp.status, data, resp_headers
        finally:
            conn.close()

    # =========================================================================
    # GATE T1: Authority Compliance & Scope Verification
    # =========================================================================
    def gate_t1_authority_compliance(self) -> None:
        """Verify zero modifications to Phase 4, Phase 5, and Phase 6.2 frozen source files."""
        # Check git status
        res = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, cwd=PROJECT_ROOT)
        lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]

        forbidden_prefixes = (
            "src/application/",
            "src/models/",
            "data/models/",
            "src/api/schemas.py",
            "src/api/validators.py",
            "src/api/exceptions.py",
        )

        for line in lines:
            status = line[:2].strip()
            path = line[3:].strip()
            if status != "??" and any(path.startswith(p) for p in forbidden_prefixes):
                raise AssertionError(f"Forbidden modification to frozen upstream file: {path} (status {status})")

    # =========================================================================
    # GATE T2: Endpoint Existence & Route Reachability
    # =========================================================================
    def gate_t2_endpoint_existence(self) -> None:
        """Probe all 4 required routes on the test server."""
        self._start_test_server()
        try:
            # 1. /health
            status, _, _ = self._http_request("GET", "/health")
            assert status in (200, 503), f"Expected 200/503 for /health, got {status}"

            # 2. /status
            status, _, _ = self._http_request("GET", "/status")
            assert status == 200, f"Expected 200 for /status, got {status}"

            # 3. /api/v1/infer/window (probe with GET -> 405 Method Not Allowed)
            status, _, _ = self._http_request("GET", "/api/v1/infer/window")
            assert status == 405, f"Expected 405 for GET /infer/window, got {status}"

            # 4. /api/v1/infer/stream (probe with GET -> 405 Method Not Allowed)
            status, _, _ = self._http_request("GET", "/api/v1/infer/stream")
            assert status == 405, f"Expected 405 for GET /infer/stream, got {status}"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T3: Health Endpoint Evaluation
    # =========================================================================
    def gate_t3_health_endpoint(self) -> None:
        """Verify GET /health evaluates model integrity and returns standard JSON."""
        self._start_test_server()
        try:
            status, body, _ = self._http_request("GET", "/health")
            assert status == 200, f"Expected 200 for healthy system, got {status}"
            assert body.get("status") == "HEALTHY", f"Expected 'HEALTHY', got {body.get('status')}"
            assert body.get("integrity") == "VERIFIED", f"Expected 'VERIFIED', got {body.get('integrity')}"
            assert "timestamp" in body, "Missing timestamp in health response"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T4: Status Endpoint Runtime Telemetry
    # =========================================================================
    def gate_t4_status_endpoint(self) -> None:
        """Verify GET /status returns telemetry without secret or path leakage."""
        self._start_test_server()
        try:
            status, body, _ = self._http_request("GET", "/status")
            assert status == 200, f"Expected 200 for status endpoint, got {status}"
            assert body.get("status") == "READY", f"Expected 'READY', got {body.get('status')}"
            assert "processed_windows" in body, "Missing processed_windows"
            assert "lookback_depth" in body, "Missing lookback_depth"
            assert body.get("engine_version") == "1.0.0", "Expected engine_version 1.0.0"
            assert "timestamp" in body, "Missing timestamp"

            # Check that no internal file paths or secrets are leaked in string representations
            body_str = json.dumps(body)
            assert "E:\\" not in body_str and "C:\\" not in body_str, "Windows path leaked in /status"
            assert "/Users/" not in body_str and "/home/" not in body_str, "Unix path leaked in /status"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T5: Single-Window Format A Ingestion
    # =========================================================================
    def gate_t5_format_a_ingestion(self) -> None:
        """Verify single-window inference endpoint accepts canonical 13-element feature array."""
        self._start_test_server()
        try:
            payload = {
                "window_id": "20260914_1200",
                "timestamp": "2026-09-14 12:00:00",
                "features": [1.0, 0.5, 120.0, 0.05, 0.01, 0.0, 64.0, 0.1, 1.0, 5.0, 2.0, 0.8, 0.2],
            }
            status, body, _ = self._http_request("POST", "/api/v1/infer/window", body=payload)
            assert status == 200, f"Expected 200 for valid Format A, got {status}: {body}"
            assert body.get("window_id") == "20260914_1200", f"Unexpected window_id: {body.get('window_id')}"
            assert "threat_inference" in body, "Missing threat_inference in response"
            assert "autoencoder" in body, "Missing autoencoder in response"
            assert "xgboost" in body, "Missing xgboost in response"
            assert "lstm" in body, "Missing lstm in response"
            assert "execution_metadata" in body, "Missing execution_metadata in response"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T6: Single-Window Format B Ingestion
    # =========================================================================
    def gate_t6_format_b_ingestion(self) -> None:
        """Verify single-window endpoint accepts 13 named key dictionary with identical result structure."""
        self._start_test_server()
        try:
            features_dict = {
                "flow_count": 1.0,
                "packet_rate": 0.5,
                "byte_rate": 120.0,
                "mean_flow_duration": 0.05,
                "std_flow_duration": 0.01,
                "short_flow_ratio": 0.0,
                "mean_packet_size": 64.0,
                "packet_length_variability": 0.1,
                "fwd_bwd_packet_ratio": 1.0,
                "unique_dst_ports": 5.0,
                "unique_dst_ips": 2.0,
                "tcp_flow_ratio": 0.8,
                "syn_packet_ratio": 0.2,
            }
            payload = {
                "window_id": "20260914_1201",
                "timestamp": "2026-09-14 12:01:00",
                "features": features_dict,
            }
            status, body, _ = self._http_request("POST", "/api/v1/infer/window", body=payload)
            assert status == 200, f"Expected 200 for valid Format B, got {status}: {body}"
            assert body.get("window_id") == "20260914_1201"
            assert "threat_inference" in body
            assert "autoencoder" in body
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T7: 24-Field Response Authority Compliance
    # =========================================================================
    def gate_t7_24_field_response(self) -> None:
        """Verify response field-for-field matches Phase 5.1 Section 17 schema."""
        self._start_test_server()
        try:
            payload = {
                "window_id": "20260914_1202",
                "timestamp": "2026-09-14 12:02:00",
                "features": [1.0] * 13,
            }
            status, body, _ = self._http_request("POST", "/api/v1/infer/window", body=payload)
            assert status == 200, f"Expected 200, got {status}"

            # Validate structural integrity via validate_application_response
            val_d = validate_application_response(body)
            assert isinstance(val_d, dict)

            # Check 24 fields:
            # Top-level (4 fields)
            for k in ("window_id", "timestamp", "global_position", "dataset_day"):
                assert k in body, f"Missing top-level field {k}"

            # Autoencoder sub-record (3 fields)
            for k in ("reconstruction_mse", "threshold", "is_anomaly"):
                assert k in body["autoencoder"], f"Missing autoencoder field {k}"

            # XGBoost sub-record (4 fields)
            for k in ("predicted_class_index", "predicted_class_name", "is_attack", "class_probabilities"):
                assert k in body["xgboost"], f"Missing xgboost field {k}"

            # LSTM sub-record (5 fields)
            for k in ("is_eligible", "ineligibility_reason", "forecast_probability", "threshold", "forecast_decision"):
                assert k in body["lstm"], f"Missing lstm field {k}"

            # Threat inference sub-record (5 fields)
            for k in ("is_eligible", "threat_state_code", "threat_state_name", "priority_tier", "decision_tuple"):
                assert k in body["threat_inference"], f"Missing threat_inference field {k}"

            # Execution metadata sub-record (3 fields)
            for k in ("inference_latency_ms", "schema_version", "engine"):
                assert k in body["execution_metadata"], f"Missing execution_metadata field {k}"

            # 4 + 3 + 4 + 5 + 5 + 3 = 24 authoritative fields verified!
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T8: Standardized Nested Error Envelope
    # =========================================================================
    def gate_t8_error_envelope(self) -> None:
        """Verify that all errors conform to the nested Phase 6.2 standard error structure."""
        self._start_test_server()
        try:
            # 1. 404 error
            status, body, _ = self._http_request("GET", "/unknown_route")
            assert status == 404
            assert "error" in body
            err = body["error"]
            for f in ("code", "message", "status_code", "timestamp", "details"):
                assert f in err, f"Missing '{f}' in 404 error envelope"
            assert err["status_code"] == 404

            # 2. 405 error
            status, body, _ = self._http_request("POST", "/health")
            assert status == 405
            assert body["error"]["code"] == "METHOD_NOT_ALLOWED"
            assert body["error"]["status_code"] == 405

            # 3. 415 error
            status, body, _ = self._http_request("POST", "/api/v1/infer/window", raw_body=b"{}", headers={"Content-Type": "text/plain"})
            assert status == 415
            assert body["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"
            assert body["error"]["status_code"] == 415
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T9: Input Validation Rejection
    # =========================================================================
    def gate_t9_input_validation(self) -> None:
        """Verify invalid requests fail at the transport boundary before inference."""
        self._start_test_server()
        try:
            # 1. Missing window_id
            payload_no_id = {"timestamp": "2026-09-14 12:00:00", "features": [1.0] * 13}
            status, body, _ = self._http_request("POST", "/api/v1/infer/window", body=payload_no_id)
            assert status == 400, f"Expected 400 for missing window_id, got {status}"
            assert body["error"]["code"] == "INPUT_VALIDATION_ERROR"

            # 2. Extraneous keys
            payload_extra = {"window_id": "20260914_1200", "timestamp": "2026-09-14 12:00:00", "features": [1.0] * 13, "extra": 123}
            status, body, _ = self._http_request("POST", "/api/v1/infer/window", body=payload_extra)
            assert status == 400, f"Expected 400 for extra keys, got {status}"

            # 3. Malformed JSON
            status, body, _ = self._http_request("POST", "/api/v1/infer/window", raw_body=b"{invalid_json", headers={"Content-Type": "application/json"})
            assert status == 400, f"Expected 400 for malformed JSON, got {status}"
            assert body["error"]["code"] == "INVALID_JSON"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T10: Zero Model Inference Negative Proof
    # =========================================================================
    def gate_t10_zero_inference(self) -> None:
        """Verify invalid requests execute exactly ZERO model inferences."""
        engine = ApplicationInferenceEngine()
        self._start_test_server(engine=engine)
        try:
            initial_count = engine._internal_position_counter

            # Send 5 invalid payloads
            bad_payloads = [
                {"window_id": "bad", "timestamp": "2026-09-14 12:00:00", "features": [1.0] * 13},
                {"window_id": "20260914_1200", "timestamp": "not_a_time", "features": [1.0] * 13},
                {"window_id": "20260914_1200", "timestamp": "2026-09-14 12:00:00", "features": [1.0] * 12},  # 12 features
                {"window_id": "20260914_1200", "timestamp": "2026-09-14 12:00:00", "features": None},
                {},
            ]

            for bp in bad_payloads:
                status, _, _ = self._http_request("POST", "/api/v1/infer/window", body=bp)
                assert status == 400, f"Expected 400, got {status}"

            assert engine._internal_position_counter == initial_count, (
                f"Position counter increased from {initial_count} to {engine._internal_position_counter}! "
                f"Model inference was executed on invalid inputs!"
            )
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T11: Non-Finite Numbers Rejection
    # =========================================================================
    def gate_t11_non_finite_numbers(self) -> None:
        """Verify payload containing NaN, Inf, or -Inf is rejected at boundary."""
        self._start_test_server()
        try:
            # Send raw JSON string with NaN
            raw_nan = b'{"window_id": "20260914_1200", "timestamp": "2026-09-14 12:00:00", "features": [NaN, 0.5, 120.0, 0.05, 0.01, 0.0, 64.0, 0.1, 1.0, 5.0, 2.0, 0.8, 0.2]}'
            status, body, _ = self._http_request("POST", "/api/v1/infer/window", raw_body=raw_nan, headers={"Content-Type": "application/json"})
            assert status == 400, f"Expected 400 for NaN, got {status}"

            raw_inf = b'{"window_id": "20260914_1200", "timestamp": "2026-09-14 12:00:00", "features": [Infinity, 0.5, 120.0, 0.05, 0.01, 0.0, 64.0, 0.1, 1.0, 5.0, 2.0, 0.8, 0.2]}'
            status, body, _ = self._http_request("POST", "/api/v1/infer/window", raw_body=raw_inf, headers={"Content-Type": "application/json"})
            assert status == 400, f"Expected 400 for Infinity, got {status}"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T12: Method Enforcement (HTTP 405)
    # =========================================================================
    def gate_t12_method_enforcement(self) -> None:
        """Verify disallowed HTTP verbs on endpoints return HTTP 405 with Allow header."""
        self._start_test_server()
        try:
            # GET on /api/v1/infer/window
            status, body, headers = self._http_request("GET", "/api/v1/infer/window")
            assert status == 405
            assert body["error"]["code"] == "METHOD_NOT_ALLOWED"
            assert "allow" in headers
            assert headers["allow"] == "POST"

            # POST on /health
            status, body, headers = self._http_request("POST", "/health", body={})
            assert status == 405
            assert body["error"]["code"] == "METHOD_NOT_ALLOWED"
            assert "allow" in headers
            assert headers["allow"] == "GET"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T13: Media-Type Enforcement (HTTP 415)
    # =========================================================================
    def gate_t13_media_enforcement(self) -> None:
        """Verify non-JSON Content-Type returns HTTP 415."""
        self._start_test_server()
        try:
            status, body, _ = self._http_request(
                "POST",
                "/api/v1/infer/window",
                raw_body=b"dummy",
                headers={"Content-Type": "text/xml"},
            )
            assert status == 415, f"Expected 415 for text/xml, got {status}"
            assert body["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T14: Payload Ceiling Enforcement (HTTP 413)
    # =========================================================================
    def gate_t14_payload_ceiling(self) -> None:
        """Verify request exceeding 10 MB limit is rejected with HTTP 413."""
        self._start_test_server()
        try:
            oversized_len = 10 * 1024 * 1024 + 1024  # 10 MB + 1 KB
            status, body, _ = self._http_request(
                "POST",
                "/api/v1/infer/window",
                raw_body=b"{}",
                headers={"Content-Type": "application/json", "Content-Length": str(oversized_len)},
            )
            assert status == 413, f"Expected 413 for oversized body, got {status}"
            assert body["error"]["code"] == "PAYLOAD_TOO_LARGE"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T15: Public Reset Prohibition (HTTP 404)
    # =========================================================================
    def gate_t15_reset_prohibition(self) -> None:
        """Verify /api/v1/reset strictly returns HTTP 404 for ALL verbs."""
        self._start_test_server()
        try:
            for verb in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
                status, body, _ = self._http_request(verb, "/api/v1/reset")
                assert status == 404, f"Expected 404 for {verb} /api/v1/reset, got {status}"
                assert body["error"]["code"] == "NOT_FOUND"
                assert "prohibited" in body["error"]["message"].lower(), "Reset prohibition reason missing"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T16: Stream Transport Processing
    # =========================================================================
    def gate_t16_stream_transport(self) -> None:
        """Verify stream batch processing up to 5,000 records returns ordered results."""
        self._start_test_server()
        try:
            stream_batch = []
            for i in range(10):
                stream_batch.append({
                    "window_id": f"20260914_{1200 + i:04d}",
                    "timestamp": f"2026-09-14 12:{i:02d}:00",
                    "features": [1.0, 0.5, 120.0 + i, 0.05, 0.01, 0.0, 64.0, 0.1, 0.5, 5.0, 2.0, 0.8, 0.2],
                })
            payload = {"stream": stream_batch}

            status, body, _ = self._http_request("POST", "/api/v1/infer/stream", body=payload)
            assert status == 200, f"Expected 200 for stream, got {status}: {body}"
            assert body.get("processed_count") == 10
            assert len(body.get("results", [])) == 10

            # Verify order
            for i in range(10):
                assert body["results"][i]["window_id"] == f"20260914_{1200 + i:04d}"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T17: Stream Size Limit Enforcement (HTTP 400)
    # =========================================================================
    def gate_t17_stream_size_limit(self) -> None:
        """Verify stream batch exceeding 5,000 records is rejected upfront."""
        self._start_test_server()
        try:
            valid_feat = [1.0, 0.5, 120.0, 0.05, 0.01, 0.0, 64.0, 0.1, 0.5, 5.0, 2.0, 0.8, 0.2]
            oversized_stream = [{"window_id": f"20260914_{i % 1000:04d}", "timestamp": "2026-09-14 12:00:00", "features": valid_feat} for i in range(5001)]
            payload = {"stream": oversized_stream}
            status, body, _ = self._http_request("POST", "/api/v1/infer/stream", body=payload)
            assert status == 400, f"Expected 400 for stream > 5000, got {status}"
            assert body["error"]["code"] == "STREAM_TOO_LARGE"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T18: Concurrency & State Thread-Safety
    # =========================================================================
    def gate_t18_concurrency_safety(self) -> None:
        """Verify multi-threaded client requests and sequential state determinism."""
        self._start_test_server()
        try:
            # 1. Concurrent telemetry probes (/health and /status across 10 threads)
            def probe_status(idx: int) -> int:
                endpoint = "/health" if idx % 2 == 0 else "/status"
                status, _, _ = self._http_request("GET", endpoint)
                return status

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                probe_futures = [executor.submit(probe_status, i) for i in range(20)]
                probe_statuses = [f.result() for f in concurrent.futures.as_completed(probe_futures)]

            assert all(s == 200 for s in probe_statuses), f"Concurrent telemetry probes failed: {probe_statuses}"

            # 2. Concurrent inference probes (verify lock safety; statuses must be 200 or 400, 0 unhandled 500s)
            def infer_probe(idx: int) -> int:
                payload = {
                    "window_id": f"20260914_{1400 + idx:04d}",
                    "timestamp": f"2026-09-14 14:{idx % 60:02d}:00",
                    "features": [1.0, 0.5, 120.0, 0.05, 0.01, 0.0, 64.0, 0.1, 0.5, 5.0, 2.0, 0.8, 0.2],
                }
                status, _, _ = self._http_request("POST", "/api/v1/infer/window", body=payload)
                return status

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                infer_futures = [executor.submit(infer_probe, i) for i in range(16)]
                infer_statuses = [f.result() for f in concurrent.futures.as_completed(infer_futures)]

            assert all(s in (200, 400) for s in infer_statuses), f"Unexpected status in concurrent inference: {infer_statuses}"
            assert 500 not in infer_statuses, f"Internal server error occurred during concurrent inference: {infer_statuses}"

            # 3. Deterministic sequential processing on fresh engine
            fresh_engine = ApplicationInferenceEngine()
            self._start_test_server(engine=fresh_engine)

            seq_positions: List[int] = []
            for i in range(10):
                payload = {
                    "window_id": f"20260914_{1500 + i:04d}",
                    "timestamp": f"2026-09-14 15:{i:02d}:00",
                    "features": [1.0, 0.5, 120.0, 0.05, 0.01, 0.0, 64.0, 0.1, 0.5, 5.0, 2.0, 0.8, 0.2],
                }
                status, body, _ = self._http_request("POST", "/api/v1/infer/window", body=payload)
                assert status == 200, f"Sequential request {i} failed: {body}"
                seq_positions.append(body.get("global_position"))

            assert seq_positions == list(range(1, 11)), f"Positions not strictly contiguous 1..10: {seq_positions}"
        finally:
            self._stop_test_server()

    # =========================================================================
    # GATE T19: Static / AST Audit
    # =========================================================================
    def gate_t19_static_ast_audit(self) -> None:
        """Verify handlers.py and server.py contain 0 model imports and 0 threshold constants."""
        target_files = [
            PROJECT_ROOT / "src" / "api" / "handlers.py",
            PROJECT_ROOT / "src" / "api" / "server.py",
        ]

        forbidden_import_modules = {"src.models", "xgboost", "tensorflow", "keras", "torch", "sklearn"}
        forbidden_constants = {0.003207791231673312, 0.3000}

        for tf in target_files:
            assert tf.exists(), f"Target file missing: {tf}"
            tree = ast.parse(tf.read_text(encoding="utf-8"))

            for node in ast.walk(tree):
                # 1. Imports check
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for mod in forbidden_import_modules:
                            assert not alias.name.startswith(mod), f"Forbidden import '{alias.name}' in {tf}"
                elif isinstance(node, ast.ImportFrom):
                    mod_name = node.module or ""
                    for mod in forbidden_import_modules:
                        assert not mod_name.startswith(mod), f"Forbidden import from '{mod_name}' in {tf}"

                # 2. Threshold constant literal check
                if isinstance(node, ast.Constant):
                    if isinstance(node.value, float):
                        for c in forbidden_constants:
                            assert abs(node.value - c) > 1e-6, f"Forbidden threshold constant {node.value} in {tf}"

    # =========================================================================
    # GATE T20: Full Regression Across Phase 4, Phase 5, Phase 6.2
    # =========================================================================
    def gate_t20_full_regression(self) -> None:
        """Run Phase 4 SHA-256 check (33/33), Phase 5 regression (22/22), and Phase 6.2 verification (16/16)."""
        # 1. Phase 4 Hash check
        manifest_p = PROJECT_ROOT / "data" / "model_reports" / "acceptance" / "phase_4_7_acceptance_report.json"
        assert manifest_p.exists()
        manifest = json.loads(manifest_p.read_text(encoding="utf-8"))
        artifacts = manifest["pillars"]["Pillar_1_PRE"]["artifacts"]
        assert len(artifacts) == 33
        for item in artifacts:
            abs_p = PROJECT_ROOT / item["path"]
            assert abs_p.exists(), f"Missing Phase 4 file: {abs_p}"
            sha = hashlib.sha256(abs_p.read_bytes()).hexdigest().lower()
            assert sha == item["sha256"].lower(), f"Phase 4 hash mismatch: {item['path']}"

        # 2. Phase 5 regression (22/22)
        from src.application.verification.verify_phase_5_7 import Phase5_7_Verifier
        v5 = Phase5_7_Verifier()
        res_p5 = v5.run_all_checks()
        assert res_p5 is True, "Phase 5.7 regression suite failed (22/22 expected)"

        # 3. Phase 6.2 verification (16/16)
        from src.api.verification.verify_phase_6_2 import Phase6_2_Verifier
        v6_2 = Phase6_2_Verifier()
        res_p6_2 = v6_2.run_all_gates()
        assert res_p6_2 is True, "Phase 6.2 verification suite failed (16/16 expected)"

    # =========================================================================
    # RUNNER
    # =========================================================================
    def run_all_gates(self) -> bool:
        """Execute all 20 gates sequentially and report findings."""
        logger.info("================================================================================")
        logger.info("STARTING PHASE 6.3 VERIFICATION SUITE — 20 MANDATORY ACCEPTANCE GATES (T1–T20)")
        logger.info("================================================================================")

        gates = [
            ("T1", "Authority Compliance & Scope", self.gate_t1_authority_compliance),
            ("T2", "Endpoint Existence & Reachability", self.gate_t2_endpoint_existence),
            ("T3", "Health Endpoint Evaluation", self.gate_t3_health_endpoint),
            ("T4", "Status Endpoint Runtime Telemetry", self.gate_t4_status_endpoint),
            ("T5", "Single-Window Format A Ingestion", self.gate_t5_format_a_ingestion),
            ("T6", "Single-Window Format B Ingestion", self.gate_t6_format_b_ingestion),
            ("T7", "24-Field Response Authority Compliance", self.gate_t7_24_field_response),
            ("T8", "Standardized Error Envelope", self.gate_t8_error_envelope),
            ("T9", "Input Validation Rejection", self.gate_t9_input_validation),
            ("T10", "Zero Model Inference Negative Proof", self.gate_t10_zero_inference),
            ("T11", "Non-Finite Numbers Rejection", self.gate_t11_non_finite_numbers),
            ("T12", "Method Enforcement (HTTP 405)", self.gate_t12_method_enforcement),
            ("T13", "Media-Type Enforcement (HTTP 415)", self.gate_t13_media_enforcement),
            ("T14", "Payload Ceiling Enforcement (HTTP 413)", self.gate_t14_payload_ceiling),
            ("T15", "Public Reset Prohibition (HTTP 404)", self.gate_t15_reset_prohibition),
            ("T16", "Stream Transport Processing", self.gate_t16_stream_transport),
            ("T17", "Stream Size Limit Enforcement (HTTP 400)", self.gate_t17_stream_size_limit),
            ("T18", "Concurrency & State Thread-Safety", self.gate_t18_concurrency_safety),
            ("T19", "Static / AST Architectural Audit", self.gate_t19_static_ast_audit),
            ("T20", "Full Multi-Phase Regression", self.gate_t20_full_regression),
        ]

        passed_count = 0
        total_count = len(gates)

        for gid, desc, func in gates:
            logger.info("Executing Gate [%s]: %s...", gid, desc)
            try:
                func()
                logger.info("Gate [%s] -> PASS", gid)
                self.results[gid] = (True, "PASS")
                passed_count += 1
            except Exception as e:
                logger.error("Gate [%s] -> FAILED: %s", gid, e, exc_info=True)
                self.results[gid] = (False, f"FAILED: {e}")
                self._stop_test_server()
                break

        logger.info("================================================================================")
        logger.info("PHASE 6.3 VERIFICATION SUMMARY: %d / %d GATES PASSED", passed_count, total_count)
        logger.info("================================================================================")

        return passed_count == total_count


if __name__ == "__main__":
    verifier = Phase6_3_Verifier()
    success = verifier.run_all_gates()
    sys.exit(0 if success else 1)
