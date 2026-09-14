"""
NexThreat Phase 6.2 — Request/Response Schemas & Validation Package.

Provides strongly typed schemas, input adapters, output integrity validators,
and error handling interfaces strictly conforming to Phase 6.1 Section 7, 8, 15
and Phase 5.1 Section 17.
"""
from __future__ import annotations

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
from src.api.handlers import NexThreatAPIHandler
from src.api.server import NexThreatAPIServer
from src.api.validators import (
    MAX_STREAM_RECORDS,
    validate_application_response,
    validate_single_window_request,
    validate_stream_batch_request,
)

__all__ = [
    # Exceptions
    "APIError",
    "APIValidationError",
    "PayloadTooLargeError",
    "StreamTooLargeError",
    "InternalAPIError",
    "sanitize_error_message",
    "format_api_error_response",
    # Constants & Schemas
    "CANONICAL_FEATURE_KEYS",
    "MAX_STREAM_RECORDS",
    "SingleWindowCanonicalRequest",
    "SingleWindowNamedRequest",
    "StreamBatchRequest",
    "AutoencoderResponse",
    "XGBoostResponse",
    "LSTMResponse",
    "ThreatInferenceResponse",
    "ExecutionMetadataResponse",
    "StandardInferenceResponse",
    # Validators
    "validate_single_window_request",
    "validate_stream_batch_request",
    "validate_application_response",
    # Transport Handlers & Server
    "NexThreatAPIHandler",
    "NexThreatAPIServer",
]
