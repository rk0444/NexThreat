"""
NexThreat Phase 5.3 — Application Service HTTP/REST API.

Provides an accessible, standard-library HTTP service for single-window and stream inference.
Built exclusively using http.server to avoid external unpinned package dependencies.
Enforces thread-safe mutual exclusion on the shared ApplicationInferenceEngine instance.
Strictly excludes any public client-facing reset endpoint to preserve temporal integrity.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer

from src.application.exceptions import (
    InputValidationError,
    ModelExecutionError,
    IntegrationContractError,
)
from src.application.orchestrator import ApplicationInferenceEngine
from src.application.schemas import ApplicationOutputRecord
from src.application.validators import sanitize_error_message
from src.models.comparison.config import PROJECT_ROOT

logger = logging.getLogger("NexThreat.Service")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

MAX_REQUEST_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
MAX_STREAM_RECORDS: int = 5000

PHASE_4_7_ACCEPTANCE_REPORT_PATH = (
    PROJECT_ROOT / "data" / "model_reports" / "acceptance" / "phase_4_7_acceptance_report.json"
)


def verify_authoritative_33_files_integrity() -> Tuple[bool, int, List[Dict[str, str]]]:
    """
    Dynamically verify the 33 frozen Phase 4 artifacts against expected hashes
    stored in the authoritative Phase 4.7 acceptance report.
    Returns: (is_healthy, verified_count, mutations_or_missing_list)
    """
    if not PHASE_4_7_ACCEPTANCE_REPORT_PATH.exists():
        return False, 0, [{"error": "Missing authoritative Phase 4.7 acceptance report"}]

    try:
        with open(PHASE_4_7_ACCEPTANCE_REPORT_PATH, "r", encoding="utf-8") as f:
            report_data = json.load(f)

        artifacts = report_data["pillars"]["Pillar_1_PRE"]["artifacts"]
        if len(artifacts) != 33:
            return False, len(artifacts), [{"error": f"Expected 33 artifacts, found {len(artifacts)}"}]

        mutations: List[Dict[str, str]] = []
        verified_count = 0

        for item in artifacts:
            rel_path = item["path"]
            expected_sha = item["sha256"].lower()
            abs_path = PROJECT_ROOT / rel_path

            if not abs_path.exists():
                mutations.append({"file": rel_path, "issue": "MISSING_FILE"})
                continue

            h = hashlib.sha256()
            with open(abs_path, "rb") as af:
                while chunk := af.read(65536):
                    h.update(chunk)
            actual_sha = h.hexdigest().lower()

            if actual_sha != expected_sha:
                mutations.append({
                    "file": rel_path,
                    "issue": "HASH_MISMATCH",
                    "expected": expected_sha,
                    "actual": actual_sha,
                })
            else:
                verified_count += 1

        is_healthy = (len(mutations) == 0 and verified_count == 33)
        return is_healthy, verified_count, mutations

    except Exception as e:
        return False, 0, [{"error": f"Integrity check execution failed: {e}"}]


class NexThreatHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler exposing /health, /status, and /api/v1/infer/* endpoints.
    """
    # Injected by NexThreatService
    engine: ApplicationInferenceEngine
    engine_lock: threading.Lock

    def log_message(self, format: str, *args: Any) -> None:
        # Standardize HTTP request logging through logger
        logger.info(f"{self.address_string()} - {format % args}")

    def _send_json_response(self, status_code: int, data: Dict[str, Any]) -> None:
        response_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def _send_error_response(self, status_code: int, error_type: str, message: str) -> None:
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if status_code >= 500:
            client_message = "An internal server error occurred."
            logger.error(f"Internal server error [{error_type}]: {message}")
        else:
            client_message = sanitize_error_message(message)
        payload = {
            "error": error_type,
            "message": client_message,
            "status_code": status_code,
            "timestamp": now_utc,
        }
        self._send_json_response(status_code, payload)

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path == "/health":
            is_healthy, count, mutations = verify_authoritative_33_files_integrity()
            now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if is_healthy:
                self._send_json_response(200, {
                    "status": "HEALTHY",
                    "engine": "ready",
                    "immutability_33_files": "PASS",
                    "verified_count": count,
                    "timestamp": now_utc,
                })
            else:
                self._send_json_response(503, {
                    "status": "UNHEALTHY",
                    "engine": "compromised",
                    "immutability_33_files": "FAIL",
                    "verified_count": count,
                    "mutations": mutations,
                    "timestamp": now_utc,
                })
            return

        elif path == "/status":
            with self.engine_lock:
                pos = self.engine._internal_position_counter
                depth = self.engine.history_buffer.current_depth
            now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self._send_json_response(200, {
                "status": "READY",
                "processed_windows": pos,
                "lookback_depth": depth,
                "engine_version": "1.0.0",
                "timestamp": now_utc,
            })
            return

        elif path in ("/api/v1/infer/window", "/api/v1/infer/stream"):
            self._send_error_response(405, "METHOD_NOT_ALLOWED", "Inference endpoints require HTTP POST.")
            return

        else:
            self._send_error_response(404, "NOT_FOUND", f"Unknown endpoint '{path}'.")
            return

    def do_POST(self) -> None:
        path = self.path.split("?")[0]

        # Explicitly enforce removal of public reset endpoint
        if path == "/api/v1/reset":
            self._send_error_response(
                404,
                "NOT_FOUND",
                "Endpoint '/api/v1/reset' does not exist. Public client resets are prohibited."
            )
            return

        if path not in ("/api/v1/infer/window", "/api/v1/infer/stream"):
            self._send_error_response(404, "NOT_FOUND", f"Unknown endpoint '{path}'.")
            return

        # Check content-length
        content_length_header = self.headers.get("Content-Length")
        if not content_length_header:
            self._send_error_response(411, "LENGTH_REQUIRED", "Missing Content-Length header.")
            return

        try:
            content_length = int(content_length_header)
        except ValueError:
            self._send_error_response(400, "BAD_REQUEST", "Invalid Content-Length header.")
            return

        if content_length > MAX_REQUEST_BYTES:
            self._send_error_response(
                413,
                "PAYLOAD_TOO_LARGE",
                f"Payload size {content_length} bytes exceeds maximum limit of {MAX_REQUEST_BYTES} bytes (10 MB)."
            )
            return

        try:
            body_bytes = self.rfile.read(content_length)
            body_json = json.loads(body_bytes.decode("utf-8"))
        except json.JSONDecodeError as e:
            self._send_error_response(400, "INVALID_JSON", f"Malformed JSON request body: {e}")
            return
        except Exception as e:
            self._send_error_response(400, "BAD_REQUEST", f"Failed to read request body: {e}")
            return

        # Handle single window inference
        if path == "/api/v1/infer/window":
            try:
                with self.engine_lock:
                    result = self.engine.process_window(body_json)
                self._send_json_response(200, result.to_dict())
            except InputValidationError as e:
                self._send_error_response(400, "INPUT_VALIDATION_ERROR", str(e))
            except ModelExecutionError as e:
                self._send_error_response(500, "MODEL_EXECUTION_ERROR", str(e))
            except Exception as e:
                self._send_error_response(500, "INTERNAL_ERROR", f"Inference processing failed: {e}")
            return

        # Handle sequential stream inference
        if path == "/api/v1/infer/stream":
            stream_records = body_json.get("stream") if isinstance(body_json, dict) else body_json
            if not isinstance(stream_records, list):
                self._send_error_response(
                    400,
                    "BAD_REQUEST",
                    "Expected JSON object with 'stream' array or top-level array of window records."
                )
                return

            if len(stream_records) > MAX_STREAM_RECORDS:
                self._send_error_response(
                    400,
                    "STREAM_TOO_LARGE",
                    f"Stream contains {len(stream_records)} items, exceeding maximum of {MAX_STREAM_RECORDS} records."
                )
                return

            results: List[Dict[str, Any]] = []
            try:
                with self.engine_lock:
                    for idx, rec in enumerate(stream_records):
                        res = self.engine.process_window(rec)
                        results.append(res.to_dict())

                self._send_json_response(200, {
                    "processed_count": len(results),
                    "results": results,
                })
            except InputValidationError as e:
                self._send_error_response(
                    400,
                    "INPUT_VALIDATION_ERROR",
                    f"Stream item {len(results)} failed validation: {e}"
                )
            except ModelExecutionError as e:
                self._send_error_response(
                    500,
                    "MODEL_EXECUTION_ERROR",
                    f"Stream item {len(results)} execution failed: {e}"
                )
            except Exception as e:
                self._send_error_response(
                    500,
                    "INTERNAL_ERROR",
                    f"Stream processing error at item {len(results)}: {e}"
                )
            return


class NexThreatService:
    """
    Server lifecycle wrapper managing the HTTP service.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8000,
        engine: Optional[ApplicationInferenceEngine] = None,
    ):
        self.host = host
        self.port = port
        self.engine = engine or ApplicationInferenceEngine()
        self.engine_lock = threading.Lock()
        self.server: Optional[ThreadingHTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None

    def start(self, daemon: bool = True) -> None:
        """Start the HTTP server in a background thread."""
        handler_cls = NexThreatHTTPRequestHandler
        handler_cls.engine = self.engine
        handler_cls.engine_lock = self.engine_lock

        self.server = ThreadingHTTPServer((self.host, self.port), handler_cls)
        logger.info(f"NexThreat Service started at http://{self.host}:{self.port}")

        self._server_thread = threading.Thread(target=self.server.serve_forever, daemon=daemon)
        self._server_thread.start()

    def stop(self) -> None:
        """Stop the HTTP server."""
        if self.server:
            logger.info("Stopping NexThreat Service...")
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=2.0)
            self._server_thread = None
        logger.info("NexThreat Service stopped.")
