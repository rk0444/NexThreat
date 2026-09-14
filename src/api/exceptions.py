"""
NexThreat Phase 6.2 — API Exception Hierarchy and Error Formatting.

Provides standardized error definitions and technical information leakage
sanitization for the external API layer strictly conforming to Phase 6.1 Section 15.
"""
from __future__ import annotations

import datetime
import re
from typing import Any, Dict, Optional


class APIError(Exception):
    """Base API exception for all NexThreat API errors."""

    def __init__(
        self,
        message: str,
        code: str = "API_ERROR",
        status_code: int = 400,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return format_api_error_response(
            code=self.code,
            message=self.message,
            status_code=self.status_code,
            details=self.details,
        )


class APIValidationError(APIError):
    """Raised when request payload fails schema or structural validation."""

    def __init__(
        self,
        message: str,
        code: str = "INPUT_VALIDATION_ERROR",
        status_code: int = 400,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code, details=details)


class PayloadTooLargeError(APIError):
    """Raised when request payload exceeds maximum permitted byte size (10 MB)."""

    def __init__(
        self,
        message: str = "Payload exceeds maximum allowed size of 10 MB.",
        code: str = "PAYLOAD_TOO_LARGE",
        status_code: int = 413,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code, details=details)


class StreamTooLargeError(APIError):
    """Raised when stream batch exceeds maximum allowed record count (5,000 records)."""

    def __init__(
        self,
        message: str = "Stream batch exceeds maximum limit of 5000 records.",
        code: str = "STREAM_TOO_LARGE",
        status_code: int = 400,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code, details=details)


class InternalAPIError(APIError):
    """Raised when an unexpected internal error occurs at the API layer."""

    def __init__(
        self,
        message: str = "An internal API error occurred.",
        code: str = "INTERNAL_ERROR",
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, code=code, status_code=status_code, details=details)


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


def format_api_error_response(
    code: str,
    message: str,
    status_code: int = 400,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Format standardized error response dictionary strictly adhering to Phase 6.1 Section 15.1.
    """
    if timestamp is None:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return {
        "error": {
            "code": str(code),
            "message": sanitize_error_message(str(message)),
            "status_code": int(status_code),
            "timestamp": str(timestamp),
            "details": details if isinstance(details, dict) else {},
        }
    }
