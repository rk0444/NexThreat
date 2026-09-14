"""
NexThreat Phase 6.3 — API Transport Handlers.

Implements the external HTTP request handler conforming to Phase 6.1, Phase 6.2,
and Phase 5.3 specifications. Exposes /health, /status, /api/v1/infer/window,
and /api/v1/infer/stream while strictly prohibiting /api/v1/reset (HTTP 404).
Delegates schema validation to src.api.validators and inference to
src.application.orchestrator.ApplicationInferenceEngine.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional

from src.api.exceptions import (
    APIError,
    APIValidationError,
    PayloadTooLargeError,
    StreamTooLargeError,
    format_api_error_response,
)
from src.api.validators import (
    MAX_STREAM_RECORDS,
    validate_application_response,
    validate_single_window_request,
    validate_stream_batch_request,
)
from src.application.exceptions import (
    InputValidationError,
    IntegrationContractError,
    ModelExecutionError,
    NexThreatApplicationError,
)
from src.application.service import (
    MAX_REQUEST_BYTES,
    verify_authoritative_33_files_integrity,
)

logger = logging.getLogger(__name__)


class NexThreatAPIHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler exposing Phase 6.2 API endpoints with strict transport
    hardening, information sanitization, and Phase 5 engine delegation.
    """

    engine: ClassVar[Optional[Any]] = None
    engine_lock: ClassVar[Optional[threading.Lock]] = None

    def log_message(self, format: str, *args: Any) -> None:
        """Override to route HTTP access logs to standard logging instead of stderr."""
        logger.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)

    def _send_json_response(
        self,
        status_code: int,
        data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Serialize and send a JSON response with UTF-8 encoding."""
        body_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body_bytes)

    def _send_error_response(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Serialize and send a standardized Phase 6.2 error envelope."""
        error_dict = format_api_error_response(
            code=code,
            message=message,
            status_code=status_code,
            details=details or {},
        )
        body_bytes = json.dumps(error_dict, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body_bytes)

    def _handle_reset_prohibition(self) -> None:
        """Enforce strict HTTP 404 on any attempt to access /api/v1/reset."""
        self._send_error_response(
            status_code=404,
            code="NOT_FOUND",
            message="Endpoint '/api/v1/reset' does not exist. Public client resets are prohibited.",
        )

    def _handle_method_not_allowed(self, allowed_methods: str) -> None:
        """Send HTTP 405 Method Not Allowed with Allow header."""
        self._send_error_response(
            status_code=405,
            code="METHOD_NOT_ALLOWED",
            message=f"HTTP method {self.command} is not allowed for this endpoint. Allowed: {allowed_methods}.",
            headers={"Allow": allowed_methods},
        )

    def do_GET(self) -> None:
        """Handle HTTP GET requests."""
        path = self.path.split("?")[0]

        # Reset prohibition check
        if path == "/api/v1/reset":
            self._handle_reset_prohibition()
            return

        if path == "/health":
            self._handle_health()
            return

        if path == "/status":
            self._handle_status()
            return

        if path in ("/api/v1/infer/window", "/api/v1/infer/stream"):
            self._handle_method_not_allowed("POST")
            return

        self._send_error_response(
            status_code=404,
            code="NOT_FOUND",
            message=f"Unknown endpoint '{path}'.",
        )

    def do_POST(self) -> None:
        """Handle HTTP POST requests."""
        path = self.path.split("?")[0]

        # Reset prohibition check
        if path == "/api/v1/reset":
            self._handle_reset_prohibition()
            return

        if path in ("/health", "/status"):
            self._handle_method_not_allowed("GET")
            return

        if path not in ("/api/v1/infer/window", "/api/v1/infer/stream"):
            self._send_error_response(
                status_code=404,
                code="NOT_FOUND",
                message=f"Unknown endpoint '{path}'.",
            )
            return

        # 1. Content-Type check (must contain application/json)
        content_type = self.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            self._send_error_response(
                status_code=415,
                code="UNSUPPORTED_MEDIA_TYPE",
                message="Content-Type must be 'application/json'.",
            )
            return

        # 2. Content-Length check
        content_length_header = self.headers.get("Content-Length")
        if not content_length_header:
            self._send_error_response(
                status_code=411,
                code="LENGTH_REQUIRED",
                message="Missing Content-Length header.",
            )
            return

        try:
            content_length = int(content_length_header)
        except ValueError:
            self._send_error_response(
                status_code=400,
                code="BAD_REQUEST",
                message="Invalid Content-Length header.",
            )
            return

        # 3. Payload size ceiling check (10 MB)
        if content_length > MAX_REQUEST_BYTES:
            self._send_error_response(
                status_code=413,
                code="PAYLOAD_TOO_LARGE",
                message=f"Payload size {content_length} bytes exceeds maximum limit of {MAX_REQUEST_BYTES} bytes (10 MB).",
            )
            return

        # 4. Read body & safe JSON decode
        try:
            body_bytes = self.rfile.read(content_length)
            body_json = json.loads(body_bytes.decode("utf-8"))
        except UnicodeDecodeError as e:
            self._send_error_response(
                status_code=400,
                code="INVALID_JSON",
                message=f"Request body is not valid UTF-8: {e}",
            )
            return
        except json.JSONDecodeError as e:
            self._send_error_response(
                status_code=400,
                code="INVALID_JSON",
                message=f"Malformed JSON request body: {e}",
            )
            return
        except Exception as e:
            self._send_error_response(
                status_code=400,
                code="BAD_REQUEST",
                message=f"Failed to read request body: {e}",
            )
            return

        # 5. Route to endpoint processor
        if path == "/api/v1/infer/window":
            self._process_single_window(body_json)
            return

        if path == "/api/v1/infer/stream":
            self._process_stream(body_json)
            return

    def do_PUT(self) -> None:
        self._handle_unsupported_verb()

    def do_DELETE(self) -> None:
        self._handle_unsupported_verb()

    def do_PATCH(self) -> None:
        self._handle_unsupported_verb()

    def do_OPTIONS(self) -> None:
        self._handle_unsupported_verb()

    def do_HEAD(self) -> None:
        self._handle_unsupported_verb()

    def _handle_unsupported_verb(self) -> None:
        path = self.path.split("?")[0]
        if path == "/api/v1/reset":
            self._handle_reset_prohibition()
            return
        if path in ("/health", "/status"):
            self._handle_method_not_allowed("GET")
            return
        if path in ("/api/v1/infer/window", "/api/v1/infer/stream"):
            self._handle_method_not_allowed("POST")
            return
        self._send_error_response(
            status_code=404,
            code="NOT_FOUND",
            message=f"Unknown endpoint '{path}'.",
        )

    # =========================================================================
    # ENDPOINT IMPLEMENTATIONS
    # =========================================================================

    def _handle_health(self) -> None:
        """Evaluate Phase 4 model assets integrity and engine operational readiness."""
        is_healthy, count, mutations = verify_authoritative_33_files_integrity()
        if self.engine is None:
            is_healthy = False

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if is_healthy:
            self._send_json_response(200, {
                "status": "HEALTHY",
                "integrity": "VERIFIED",
                "timestamp": now_utc,
            })
        else:
            self._send_json_response(503, {
                "status": "UNHEALTHY",
                "integrity": "FAILED",
                "timestamp": now_utc,
            })

    def _handle_status(self) -> None:
        """Return engine runtime telemetry without leaking internal paths or secrets."""
        pos = 0
        depth = 0
        if self.engine is not None and self.engine_lock is not None:
            with self.engine_lock:
                pos = getattr(self.engine, "_internal_position_counter", 0)
                if hasattr(self.engine, "history_buffer") and hasattr(self.engine.history_buffer, "current_depth"):
                    depth = self.engine.history_buffer.current_depth

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._send_json_response(200, {
            "status": "READY",
            "processed_windows": pos,
            "lookback_depth": depth,
            "engine_version": "1.0.0",
            "timestamp": now_utc,
        })

    def _process_single_window(self, body_json: Any) -> None:
        """
        Process single-window inference request.
        1. Validate schema via validate_single_window_request.
           Failure terminates here with ZERO inference.
        2. Execute inference via engine.process_window under engine_lock.
        3. Validate response via validate_application_response.
        4. Send 200 OK.
        """
        # Step 1: Schema validation
        try:
            canonical_input = validate_single_window_request(body_json)
        except APIValidationError as e:
            self._send_error_response(
                status_code=e.status_code,
                code=e.code,
                message=e.message,
                details=e.details,
            )
            return
        except Exception as e:
            self._send_error_response(
                status_code=400,
                code="INPUT_VALIDATION_ERROR",
                message=str(e),
            )
            return

        # Step 2: Engine inference delegation under lock
        if self.engine is None or self.engine_lock is None:
            self._send_error_response(
                status_code=500,
                code="INTERNAL_ERROR",
                message="Inference engine is not initialized.",
            )
            return

        try:
            with self.engine_lock:
                output_record = self.engine.process_window(canonical_input)
        except InputValidationError as e:
            self._send_error_response(
                status_code=400,
                code="INPUT_VALIDATION_ERROR",
                message=str(e),
            )
            return
        except ModelExecutionError as e:
            self._send_error_response(
                status_code=500,
                code="MODEL_EXECUTION_ERROR",
                message=str(e),
            )
            return
        except (IntegrationContractError, NexThreatApplicationError) as e:
            self._send_error_response(
                status_code=500,
                code="INTERNAL_ERROR",
                message=str(e),
            )
            return
        except Exception as e:
            self._send_error_response(
                status_code=500,
                code="INTERNAL_ERROR",
                message=f"Inference processing failed: {e}",
            )
            return

        # Step 3: Validate response integrity against 24-field Authority Matrix
        try:
            validated_response = validate_application_response(output_record)
        except Exception as e:
            self._send_error_response(
                status_code=500,
                code="INTERNAL_ERROR",
                message=f"Response serialization integrity check failed: {e}",
            )
            return

        # Step 4: Send HTTP 200 OK
        self._send_json_response(200, validated_response)

    def _process_stream(self, body_json: Any) -> None:
        """
        Process stream batch inference request up to 5,000 records.
        1. Validate entire batch upfront via validate_stream_batch_request.
           Failure terminates here with ZERO inference.
        2. Execute sequential window inference under engine_lock.
        3. Validate each output record via validate_application_response.
        4. Send 200 OK with processed_count and results array.
        """
        # Step 1: Upfront batch validation
        try:
            canonical_records = validate_stream_batch_request(body_json)
        except StreamTooLargeError as e:
            self._send_error_response(
                status_code=e.status_code,
                code=e.code,
                message=e.message,
                details=e.details,
            )
            return
        except APIValidationError as e:
            self._send_error_response(
                status_code=e.status_code,
                code=e.code,
                message=e.message,
                details=e.details,
            )
            return
        except Exception as e:
            self._send_error_response(
                status_code=400,
                code="INPUT_VALIDATION_ERROR",
                message=str(e),
            )
            return

        # Step 2: Sequential inference under engine lock
        if self.engine is None or self.engine_lock is None:
            self._send_error_response(
                status_code=500,
                code="INTERNAL_ERROR",
                message="Inference engine is not initialized.",
            )
            return

        results: List[Dict[str, Any]] = []
        try:
            with self.engine_lock:
                for idx, rec in enumerate(canonical_records):
                    output_rec = self.engine.process_window(rec)
                    val_resp = validate_application_response(output_rec)
                    results.append(val_resp)
        except InputValidationError as e:
            self._send_error_response(
                status_code=400,
                code="INPUT_VALIDATION_ERROR",
                message=f"Stream item {len(results)} failed validation: {e}",
            )
            return
        except ModelExecutionError as e:
            self._send_error_response(
                status_code=500,
                code="MODEL_EXECUTION_ERROR",
                message=f"Stream item {len(results)} execution failed: {e}",
            )
            return
        except Exception as e:
            self._send_error_response(
                status_code=500,
                code="INTERNAL_ERROR",
                message=f"Stream processing error at item {len(results)}: {e}",
            )
            return

        # Step 3: Send 200 OK
        self._send_json_response(200, {
            "processed_count": len(results),
            "results": results,
        })
