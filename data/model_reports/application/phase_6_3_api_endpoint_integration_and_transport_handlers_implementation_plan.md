# NexThreat Phase 6.3 — API Endpoint Integration & Transport Handlers Implementation Plan

```text
================================================================================
NEXTHREAT SECURE NETWORK TELEMETRY THREAT-DETECTION PLATFORM
PHASE 6.3 — API ENDPOINT INTEGRATION & TRANSPORT HANDLERS IMPLEMENTATION PLAN
================================================================================
Document Version  : 1.0.0
Status            : PLAN ONLY — IMPLEMENTATION NOT AUTHORIZED
Phase Target      : Phase 6.3 (API Endpoint Integration & Transport Handlers)
Upstream Baseline : Phase 4 (Accepted), Phase 5 (Accepted), Phase 6.2 (Accepted)
Downstream Target : Phase 6.4 (Production Packaging & Deployment Hardening)
Date Generated    : 2026-09-14
================================================================================
```

---

## 1. Document Control

| Metadata Field | Value / Specification |
| :--- | :--- |
| **Document ID** | `NT-PLAN-PHASE-6.3-001` |
| **Document Title** | Phase 6.3 API Endpoint Integration & Transport Handlers Implementation Plan |
| **Version** | `1.0.0` |
| **Author** | NexThreat Core Engineering & Architecture Team |
| **Lifecycle State** | `PLAN ONLY` |
| **Implementation Authorization** | `NOT GRANTED` |
| **Upstream Dependencies** | Phase 4.7 (Model Freeze), Phase 5.1–5.7 (Application Engine), Phase 6.1 (API Audit), Phase 6.2 (Schemas & Validation) |
| **Target Code Directory** | `src/api/` |
| **Target Report Path** | `data/model_reports/application/phase_6_3_api_endpoint_integration_and_transport_handlers_implementation_plan.md` |

---

## 2. Phase 6.3 Objective

The primary objective of **Phase 6.3 (API Endpoint Integration & Transport Handlers)** is to design and specify the HTTP transport layer that exposes the accepted NexThreat application capabilities to external consumers over standard HTTP/1.1 protocols.

Phase 6.3 bridges the external network transport boundary to the internal application engine by:
1. Receiving HTTP requests across defined routes (`/health`, `/status`, `/api/v1/infer/window`, `/api/v1/infer/stream`).
2. Enforcing transport-level constraints (HTTP method, Content-Type, Content-Length limits, UTF-8 encoding).
3. Invoking the accepted Phase 6.2 schema validators (`validate_single_window_request`, `validate_stream_batch_request`) to produce validated `CanonicalInputRecord` instances.
4. Delegating inference execution exclusively to the authoritative Phase 5 `ApplicationInferenceEngine` under strict thread-safe concurrency controls.
5. Validating outgoing application records against the accepted Phase 6.2 response schema (`validate_application_response`) to guarantee 24-field structural compliance.
6. Serializing standardized JSON responses and error envelopes (`format_api_error_response`) with technical information sanitization (`sanitize_error_message`).
7. Strictly enforcing the permanent prohibition of public state resets (`/api/v1/reset` -> HTTP 404).

---

## 3. Governing Principle

> **"Phase 6 exposes NexThreat; Phase 6 does not redefine NexThreat."**

For Phase 6.3 specifically:

> **"Phase 6.3 exposes the accepted Phase 6.2 API contracts through transport handlers; it does not redefine the underlying contracts."**

The transport layer is strictly a communication adapter. Under no circumstances shall transport code:
- Import or invoke ML models (`Autoencoder`, `XGBoost`, `LSTM`) directly.
- Calculate or transform raw feature vectors beyond the accepted Format B dictionary mapping.
- Compute anomaly errors, reconstruction MSEs, or classification probabilities.
- Evaluate decision thresholds or assign threat states.
- Re-architect the internal sequential window pipeline or cross-day state isolation.

---

## 4. Authoritative Upstream Contracts

Phase 6.3 strictly inherits and adheres to the following frozen upstream authorities:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       UPSTREAM CONTRACT HIERARCHY                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Phase 4.7 Model Freeze Baseline                                          │
│    - 33/33 SHA-256 Verified Artifacts (Models, Scalers, Datasets)           │
│ 2. Phase 5.1 Application Integration Architecture & Contract               │
│    - Section 17 Authoritative 24-Field Response Matrix                      │
│    - CanonicalInputRecord & ApplicationOutputRecord Schemas                 │
│ 3. Phase 5.2 Application Inference Engine & Orchestration                   │
│    - ApplicationInferenceEngine (Thread-safe, Sequential, History Buffer)   │
│ 4. Phase 5.3 Application Service API / Stream Ingestion / Alert Dispatcher  │
│    - 10 MB Payload Limit, 5,000 Records Stream Limit, /health & /status     │
│ 5. Phase 5.4 Unified Threat-State Integration                               │
│    - Canonical Threat Taxonomy S0–S7 (S8, UNKNOWN, FALLBACK prohibited)     │
│ 6. Phase 5.5 Validation & Error Handling Contract                          │
│    - InputValidationError, ModelExecutionError, StateManagerError           │
│ 7. Phase 5.7 Final Acceptance & Hardening Baseline                          │
│    - 22 / 22 Mandatory Acceptance Gates PASS                                │
│ 8. Phase 6.1 API Contract Audit & Architecture Specification                │
│    - Sections 7, 8, 14, 15: Dual Request Formats, Error Envelope, Resets    │
│ 9. Phase 6.2 Request/Response Schemas & Validation                          │
│    - 16 / 16 Verification Gates PASS, 18 / 18 Acceptance Gates PASS         │
│    - src/api/schemas.py, src/api/validators.py, src/api/exceptions.py       │
└─────────────────────────────────────────────────────────────────────────────┘
```

Any contradiction between proposed transport code and any upstream contract constitutes a critical blocker.

---

## 5. Current Repository / Transport Baseline

### 5.1 Existing Phase 5 Transport Baseline (`src/application/service.py`)

Phase 5 established an initial HTTP service using Python's standard library `http.server`:
- **Server Component**: `NexThreatService` wrapping `http.server.ThreadingHTTPServer`.
- **Handler Component**: `NexThreatHTTPRequestHandler` inheriting from `http.server.BaseHTTPRequestHandler`.
- **Concurrency**: Process-level thread synchronization using `threading.Lock()` (`engine_lock`) protecting `ApplicationInferenceEngine`.
- **Established Endpoints**:
  - `GET /health`: Evaluates 33-file SHA-256 hash manifest. Returns 200 (`"HEALTHY"`) or 503 (`"UNHEALTHY"`).
  - `GET /status`: Returns service status (`"READY"`), processed window count, lookback depth, engine version, timestamp.
  - `POST /api/v1/infer/window`: Processes single window payload. Enforces 10 MB limit.
  - `POST /api/v1/infer/stream`: Processes sequential batch stream. Enforces 5,000 records limit.
  - `GET/POST /api/v1/reset`: Explicitly returns HTTP 404 (`"Not Found"`) to prohibit external state destruction.

### 5.2 Identified Architectural Gaps Between Phase 5 Service and Phase 6.2 API

While the Phase 5 transport baseline proved server viability, the following structural gaps exist between `src/application/service.py` and the accepted Phase 6.2 API contracts:

1. **Error Envelope Structure**: Phase 5 emits a flat dictionary `{"error": code, "message": msg, "status_code": c, "timestamp": ts}`. Phase 6.1 Section 15 and Phase 6.2 require the nested standard envelope `{"error": {"code": ..., "message": ..., "status_code": ..., "timestamp": ..., "details": ...}}`.
2. **Format B Ingestion**: Phase 5 handlers parse only Format A (canonical 13-feature array). External clients providing Format B (dictionary of 13 named keys) fail validation in Phase 5 handlers.
3. **Response Schema Enforcement**: Phase 5 handlers directly serialize `ApplicationOutputRecord.to_dict()` without running the Phase 6.2 assert-only `validate_application_response()` verification.
4. **Architectural Separation**: `src/application/` is the core domain application package. External API transport handlers must reside within `src/api/` to maintain clean boundary separation between domain logic and transport protocols.

### 5.3 Phase 6.3 Transport Strategy: Clean Adapter Layer

Phase 6.3 will implement `src/api/handlers.py` and `src/api/server.py` as a dedicated transport layer that:
- Uses standard library `http.server.ThreadingHTTPServer` to avoid unapproved web framework dependencies.
- Consumes `validate_single_window_request()` and `validate_stream_batch_request()` from `src.api.validators`.
- Consumes `validate_application_response()` from `src.api.validators`.
- Consumes `format_api_error_response()` and `sanitize_error_message()` from `src.api.exceptions`.
- Delegates core inference directly to `src.application.orchestrator.ApplicationInferenceEngine`.
- Leaves `src/application/service.py` intact as an accepted upstream Phase 5 component.

---

## 6. Scope

The scope of Phase 6.3 is strictly bounded to:
1. **Endpoint Implementation**:
   - `GET /health`
   - `GET /status`
   - `POST /api/v1/infer/window`
   - `POST /api/v1/infer/stream`
   - `/api/v1/reset` (Prohibited / HTTP 404 enforcement)
2. **Transport Handlers**:
   - HTTP request parsing, header inspection, Content-Type negotiation.
   - Content-Length validation and payload size bounding (10 MB ceiling).
   - Safe JSON decoding and malformed payload rejection.
   - HTTP status code mapping (200, 400, 404, 405, 411, 413, 415, 500, 503).
3. **Phase 6.2 Schema & Validation Integration**:
   - Ingestion of Format A and Format B requests via `validate_single_window_request()`.
   - Ingestion of stream requests via `validate_stream_batch_request()`.
   - Validation of output records via `validate_application_response()`.
4. **Error Formatting & Technical Information Leakage Sanitization**:
   - Standardized nested error envelope serialization.
   - Path, line number, source code, and memory address sanitization.
5. **Server Lifecycle Management**:
   - Graceful startup, background thread execution, and clean shutdown.
6. **Verification & Testing Suite**:
   - Comprehensive verification suite in `src/api/verification/verify_phase_6_3.py`.
   - Full regression across Phase 4, Phase 5, and Phase 6.2.

---

## 7. Out-of-Scope

The following items are explicitly **EXCLUDED** from Phase 6.3:
- Modification of Phase 4 model binaries, scalers, thresholds, or datasets.
- Modification of Phase 5 orchestration, feature processing, threat logic, or schemas.
- Modification of accepted Phase 6.2 schemas, validators, or exceptions.
- Introduction of new ML models, ensemble algorithms, or score blending.
- Introduction of third-party web frameworks (FastAPI, Flask, Starlette, Tornado).
- Public state reset capabilities (`/api/v1/reset`).
- Reverse proxy configurations (Nginx, Envoy, Caddy).
- Authentication, authorization, API key validation, or rate limiting (reserved for Phase 6.4).
- Containerization and Docker packaging (reserved for Phase 6.4).
- Production monitoring dashboards or alerting webhooks (reserved for Phase 6.4).

---

## 8. Architecture & Request/Response Flow

### 8.1 End-to-End Single-Window Request Flow

```
[ External HTTP Client ]
          │  HTTP POST /api/v1/infer/window
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHASE 6.3 TRANSPORT LAYER                            │
│  src/api/handlers.py: NexThreatAPIHandler                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Check HTTP Method: POST required (Else 405 Method Not Allowed)          │
│  2. Check Route: Route matching (Else 404 Not Found)                        │
│  3. Check Content-Type: application/json required (Else 415)                │
│  4. Check Content-Length: Required & <= 10 MB (Else 411 / 413)              │
│  5. Safe JSON Decode: UTF-8 decoding & parse (Else 400 Invalid JSON)        │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │ raw payload (dict)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     PHASE 6.2 VALIDATION BOUNDARY                           │
│  src.api.validators: validate_single_window_request()                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Disallow null / non-dict / extraneous keys                               │
│  • Validate window_id format (W\d{4}_\d{6})                                 │
│  • Validate ISO-8601 timestamp string                                       │
│  • Parse Format A (list of 13 floats) OR Format B (13 named keys dict)      │
│  • Reject non-finite numbers (NaN, Inf, -Inf) and booleans                  │
│  • Construct authoritative CanonicalInputRecord                             │
│  [IF INVALID] -> Raise APIValidationError -> Return HTTP 400 Error Envelope │
│                  *** ZERO MODEL INFERENCE EXECUTED ***                      │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │ Valid CanonicalInputRecord
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                  PHASE 5 APPLICATION INFERENCE ENGINE                       │
│  src.application.orchestrator: ApplicationInferenceEngine.process_window()  │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Acquire engine_lock (Thread-safe concurrency guarantee)                  │
│  • Preprocessing & scaling (StandardScaler & RobustScaler)                  │
│  • Authoritative Tri-Model Inference (Autoencoder, XGBoost, LSTM)           │
│  • Cold-start tracking & 60-second continuity buffer update                 │
│  • Deterministic S0–S7 Threat State assignment                              │
│  • Produce authoritative ApplicationOutputRecord                            │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │ ApplicationOutputRecord
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 PHASE 6.2 RESPONSE INTEGRITY VERIFIER                       │
│  src.api.validators: validate_application_response()                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Verify exact 24-field Authority Matrix                                   │
│  • Verify mathematical and logical constraints across sub-records           │
│  • Return strongly-typed StandardInferenceResponse                          │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │ StandardInferenceResponse.to_dict()
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHASE 6.3 HTTP SERIALIZER                            │
│  src/api/handlers.py                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Send HTTP 200 OK                                                         │
│  • Set Content-Type: application/json; charset=utf-8                        │
│  • Stream JSON response body to client                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Endpoint Contract Matrix

| Endpoint Route | HTTP Method | Content-Type In | Content-Type Out | Expected Status | Error Statuses | Authority Traced |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `/health` | `GET` | None | `application/json` | `200 OK` | `405, 503` | Phase 5.3 Section 14; Phase 6.1 Section 14.1 |
| `/status` | `GET` | None | `application/json` | `200 OK` | `405, 500` | Phase 5.3 Section 14; Phase 6.1 Section 14.2 |
| `/api/v1/infer/window` | `POST` | `application/json` | `application/json` | `200 OK` | `400, 405, 411, 413, 415, 500` | Phase 5.1 Section 17; Phase 6.1 Section 7 |
| `/api/v1/infer/stream` | `POST` | `application/json` | `application/json` | `200 OK` | `400, 405, 411, 413, 415, 500` | Phase 5.3 Section 12; Phase 6.1 Section 8 |
| `/api/v1/reset` | `ANY` | Any | `application/json` | `None` (Prohibited) | `404 Not Found` | Phase 5.3 Section 14.4; Phase 6.1 Section 14.4 |
| `/*` (Unknown) | `ANY` | Any | `application/json` | `None` | `404 Not Found` | Standard HTTP/1.1 Protocol |

---

## 10. Phase 6.2 Integration Boundary

The transport layer in `src/api/` integrates with Phase 6.2 purely through public, audited interfaces:

```python
# Permitted Phase 6.2 Imports in Transport Handlers:
from src.api.exceptions import (
    APIError,
    APIValidationError,
    PayloadTooLargeError,
    StreamTooLargeError,
    InternalAPIError,
    format_api_error_response,
    sanitize_error_message,
)
from src.api.schemas import (
    StandardInferenceResponse,
    SingleWindowCanonicalRequest,
    SingleWindowNamedRequest,
    StreamBatchRequest,
)
from src.api.validators import (
    validate_single_window_request,
    validate_stream_batch_request,
    validate_application_response,
    MAX_STREAM_RECORDS,
)
```

### Invariants:
1. **No Validation Re-Implementation**: `NexThreatAPIHandler` shall not validate field types, regex patterns, or feature bounds. It must delegate entirely to `validate_single_window_request()` and `validate_stream_batch_request()`.
2. **No Error Formatting Duplication**: All error responses must be constructed via `format_api_error_response()`.
3. **No Schema Alteration**: The returned response must be the direct result of `validate_application_response(result).to_dict()`.

---

## 11. Phase 5 Integration Boundary

The transport layer interacts with the core application exclusively through the accepted Phase 5 application interface:

```python
# Permitted Phase 5 Imports in Transport Handlers & Server:
from src.application.orchestrator import ApplicationInferenceEngine
from src.application.schemas import CanonicalInputRecord, ApplicationOutputRecord
from src.application.exceptions import (
    InputValidationError,
    ModelExecutionError,
    StateManagerError,
)
from src.application.service import MAX_REQUEST_BYTES  # 10 * 1024 * 1024 (10 MB)
```

### Invariants:
1. **Thread-Safe Mutual Exclusion**: All calls to `ApplicationInferenceEngine.process_window()` must be guarded by a process-level `threading.Lock` (`engine_lock`).
2. **Zero Model Bypassing**: Inference is never performed by calling underlying model classes directly.
3. **Exception Translation**: Phase 5 application exceptions are caught and cleanly mapped into Phase 6.2 `APIError` structures:
   - `InputValidationError` -> `APIValidationError` (HTTP 400)
   - `ModelExecutionError` -> `InternalAPIError` (HTTP 500)
   - `StateManagerError` -> `InternalAPIError` (HTTP 500)

---

## 12. HTTP Transport Contract

### 12.1 Content-Type Negotiation
- For `POST /api/v1/infer/window` and `POST /api/v1/infer/stream`, the `Content-Type` request header must contain `application/json`.
- Requests with missing or non-JSON `Content-Type` headers must be rejected immediately with HTTP 415 (`UNSUPPORTED_MEDIA_TYPE`):
  ```json
  {
    "error": {
      "code": "UNSUPPORTED_MEDIA_TYPE",
      "message": "Content-Type must be 'application/json'.",
      "status_code": 415,
      "timestamp": "2026-09-14T12:00:00.000000+00:00",
      "details": {}
    }
  }
  ```
- All responses from all endpoints (success and error) must include:
  `Content-Type: application/json; charset=utf-8`

### 12.2 Content-Length Enforcement & Payload Ceiling
- `POST` requests without a `Content-Length` header must be rejected with HTTP 411 (`LENGTH_REQUIRED`).
- `POST` requests with a non-integer `Content-Length` header must be rejected with HTTP 400 (`BAD_REQUEST`).
- Payloads exceeding `MAX_REQUEST_BYTES` (10,485,760 bytes / 10 MB) must be rejected with HTTP 413 (`PAYLOAD_TOO_LARGE`) before attempting JSON parsing.

### 12.3 Method Restrictions
- `/health` and `/status` strictly accept `GET`. `POST`, `PUT`, `DELETE`, etc. return HTTP 405 (`METHOD_NOT_ALLOWED`).
- `/api/v1/infer/window` and `/api/v1/infer/stream` strictly accept `POST`. `GET`, `PUT`, `DELETE`, etc. return HTTP 405 (`METHOD_NOT_ALLOWED`).
- All 405 responses must include an `Allow` header specifying the allowed HTTP method(s).

### 12.4 Malformed JSON Handling
- Payloads that cannot be decoded as UTF-8 or fail JSON parsing must return HTTP 400 (`INVALID_JSON`) with technical error strings sanitized.

---

## 13. Error Handling Contract

### 13.1 Standardized Error Envelope
All error responses emitted by the transport layer must strictly conform to the Phase 6.1 Section 15.1 specification:

```json
{
  "error": {
    "code": "ERROR_CODE_STRING",
    "message": "Sanitized, human-readable error description.",
    "status_code": 400,
    "timestamp": "2026-09-14T12:00:00.000000+00:00",
    "details": {}
  }
}
```

### 13.2 Status Code Mapping Table

| HTTP Status | Error Code | Trigger Condition |
| :--- | :--- | :--- |
| **400** | `BAD_REQUEST` | Missing body, invalid Content-Length format, non-object JSON root |
| **400** | `INVALID_JSON` | JSON parsing syntax error, non-UTF-8 payload |
| **400** | `INPUT_VALIDATION_ERROR` | Schema failure, missing keys, invalid types, NaN/Inf, bad window_id |
| **400** | `STREAM_TOO_LARGE` | Stream batch contains > 5,000 records |
| **404** | `NOT_FOUND` | Unknown route requested, OR any request to `/api/v1/reset` |
| **405** | `METHOD_NOT_ALLOWED` | Disallowed HTTP verb for a valid endpoint path |
| **411** | `LENGTH_REQUIRED` | Missing Content-Length header on POST requests |
| **413** | `PAYLOAD_TOO_LARGE` | Content-Length exceeds 10 MB limit |
| **415** | `UNSUPPORTED_MEDIA_TYPE` | Content-Type header does not contain `application/json` |
| **500** | `INTERNAL_ERROR` | Unhandled exception or application execution failure |
| **500** | `MODEL_EXECUTION_ERROR` | Internal model inference failure caught from application engine |
| **503** | `SERVICE_UNAVAILABLE` | Health check failed (hash verification failure or engine not ready) |

### 13.3 Information Leakage Prevention
All error messages must pass through `sanitize_error_message()`:
- Redacting Windows drive paths (`C:\...`, `E:\...` -> `[REDACTED_PATH]`).
- Redacting Unix system paths (`/home/...`, `/tmp/...` -> `[REDACTED_PATH]`).
- Redacting Python source filenames (`*.py` -> `[REDACTED_SRC]`).
- Redacting stack trace line numbers (`line 123` -> `line [REDACTED]`).
- Redacting memory pointers (`0x7fff5fbff...` -> `[REDACTED_ADDR]`).
- Never returning raw traceback strings or model internals to external clients.

---

## 14. Stream Transport Contract

### 14.1 Stream Ingestion Format
`POST /api/v1/infer/stream` accepts a JSON object containing a `"stream"` array, or a top-level JSON array of window records:
```json
{
  "stream": [
    {
      "window_id": "W0001_000001",
      "timestamp": "2026-09-14T12:00:00.000000+00:00",
      "features": [1.0, 0.5, 120.0, 0.05, 0.01, 0.0, 64.0, 0.1, 1.0, 5.0, 2.0, 0.8, 0.2]
    }
  ]
}
```

### 14.2 Stream Processing Semantics
1. **Pre-Execution Validation**: The entire stream payload is validated upfront by `validate_stream_batch_request()`. If any item in the batch fails validation or if batch size exceeds 5,000 records, the request fails immediately with HTTP 400. **Zero windows are submitted to the engine.**
2. **Ordered Execution**: Validated records are processed in strict sequential chronological order under `engine_lock`.
3. **Temporal Continuity**: The 60-second continuity rules, history buffer updates, and cold-start logic (minimum 10 windows for LSTM) are managed deterministically by the underlying `ApplicationInferenceEngine`.
4. **Output Structure**:
   ```json
   {
     "processed_count": 1,
     "results": [
       {
         "window_id": "W0001_000001",
         "timestamp": "2026-09-14T12:00:00.000000+00:00",
         "threat_state": "S0",
         "threat_state_name": "BENIGN_CONCORDANCE",
         "autoencoder": { ... },
         "xgboost": { ... },
         "lstm": { ... },
         "inference": { ... },
         "metadata": { ... }
       }
     ]
   }
   ```

---

## 15. Health & Status Contract

### 15.1 Health Check (`GET /health`)
- Evaluates system operational readiness:
  - Validates that Phase 4 model assets and hash manifest are intact.
  - Verifies that `ApplicationInferenceEngine` is initialized and operational.
- Response on Success (`200 OK`):
  ```json
  {
    "status": "HEALTHY",
    "integrity": "VERIFIED",
    "timestamp": "2026-09-14T12:00:00.000000+00:00"
  }
  ```
- Response on Failure (`503 Service Unavailable`):
  ```json
  {
    "status": "UNHEALTHY",
    "integrity": "FAILED",
    "timestamp": "2026-09-14T12:00:00.000000+00:00"
  }
  ```

### 15.2 Status Endpoint (`GET /status`)
- Exposes high-level runtime telemetry without exposing internal memory addresses or environment variables.
- Response (`200 OK`):
  ```json
  {
    "status": "READY",
    "processed_windows": 1420,
    "lookback_depth": 10,
    "engine_version": "1.0.0",
    "timestamp": "2026-09-14T12:00:00.000000+00:00"
  }
  ```

---

## 16. Reset Prohibition

### 16.1 Public Reset Prohibition Contract
In accordance with Phase 5.3 Section 14.4 and Phase 6.1 Section 14.4:
- The route `/api/v1/reset` is strictly non-existent to external clients.
- Any request (GET, POST, PUT, DELETE, OPTIONS, HEAD) targeting `/api/v1/reset` must return HTTP 404 (`NOT_FOUND`).
- The response must use the standard error envelope:
  ```json
  {
    "error": {
      "code": "NOT_FOUND",
      "message": "Endpoint '/api/v1/reset' does not exist. Public client resets are prohibited.",
      "status_code": 404,
      "timestamp": "2026-09-14T12:00:00.000000+00:00",
      "details": {}
    }
  }
  ```
- No query parameters (`?reset=true`), HTTP headers (`X-Reset-State`), or payload flags may trigger state reset over the transport layer.

---

## 17. Security Hardening

| Security Vector | Implementation Mechanism in Phase 6.3 Transport |
| :--- | :--- |
| **Denial of Service (Oversized Body)** | Immediate rejection of requests where `Content-Length > 10 MB` (HTTP 413) before buffering. |
| **Denial of Service (Unbounded Stream)** | Hard limit of 5,000 records per stream batch (`MAX_STREAM_RECORDS`). Rejection with HTTP 400. |
| **Content Sniffing / Ambiguity** | Mandatory `Content-Type: application/json` enforcement (HTTP 415). Response fixed to `application/json; charset=utf-8`. |
| **JSON Injection / Malformed Bytes** | Strict UTF-8 decoding and safe `json.loads` within try-except blocks. Malformed JSON returns HTTP 400. |
| **Information Leakage** | All error strings pass through `sanitize_error_message()`. Absolute paths, source files, and stack traces redacted. |
| **Path Traversal / Arbitrary Execution** | Strict explicit route matching (`if path == ...`). No reflection, dynamic imports, or file lookups based on request paths. |
| **State Tampering** | Rejection of public reset mechanisms. Concurrency safety ensured via `threading.Lock`. |

---

## 18. Dependency Constraints

Phase 6.3 adheres to a **Zero New External Dependencies** constraint:
- Built exclusively using the Python Standard Library:
  - `http.server` (`ThreadingHTTPServer`, `BaseHTTPRequestHandler`)
  - `threading` (`Lock`, `Thread`)
  - `json`
  - `datetime`
  - `re`
  - `typing`
- Prohibited dependencies for Phase 6.3:
  - `fastapi`, `uvicorn`, `starlette`
  - `flask`, `werkzeug`
  - `aiohttp`, `tornado`, `twisted`
  - `requests`, `httpx` in runtime source code (testing may use standard library `urllib.request`)

---

## 19. Exact Implementation File Matrix

```
================================================================================
EXACT IMPLEMENTATION FILE MATRIX — PHASE 6.3
================================================================================
```

| File Path | Action | Role & Purpose | Authority Traced | Upstream Dependencies |
| :--- | :--- | :--- | :--- | :--- |
| `src/api/handlers.py` | **NEW** | Primary HTTP request handler class (`NexThreatAPIHandler`). Parses HTTP requests, enforces method/type/length rules, dispatches to Phase 6.2 validators, coordinates inference delegation, serializes responses and sanitized error envelopes. | Phase 6.1 Sec 7, 8, 14, 15; Phase 5.3 Sec 14 | `src.api.validators`, `src.api.exceptions`, `src.application.orchestrator` |
| `src/api/server.py` | **NEW** | HTTP service lifecycle manager (`NexThreatAPIServer`). Manages `ThreadingHTTPServer` instantiation, port binding, background worker thread, engine association, and clean shutdown. | Phase 5.3 Sec 14.5; Phase 6.1 Sec 14 | `src.api.handlers`, `src.application.orchestrator` |
| `src/api/__init__.py` | **MODIFY** | Expose public transport symbols: `NexThreatAPIHandler`, `NexThreatAPIServer`. Maintain full backward compatibility with Phase 6.2 exports. | Phase 6.1 Section 4 | `src/api/handlers.py`, `src/api/server.py` |
| `src/api/verification/__init__.py` | **MAINTAIN** | Verification package marker. | Phase 6.2 Baseline | None |
| `src/api/verification/verify_phase_6_3.py` | **NEW** | Comprehensive Phase 6.3 verification script executing all 20 mandatory acceptance gates (T1–T20). | Phase 6.3 Implementation Plan | All Phase 6.2 & 6.3 modules, Phase 5 engine |

### Frozen Upstream Artifacts (MODIFICATION STRICTLY PROHIBITED):
- `src/application/*` (All Phase 5 modules remain frozen)
- `src/models/*` (All Phase 4 models remain frozen)
- `src/api/schemas.py` (Phase 6.2 frozen)
- `src/api/validators.py` (Phase 6.2 frozen)
- `src/api/exceptions.py` (Phase 6.2 frozen)
- `data/models/*` (All model binaries and scalers remain frozen)
- `data/model_reports/*` (All accepted reports remain frozen)

---

## 20. Testing Strategy

The verification strategy encompasses 25 rigorous test scenarios executed via standard library HTTP client tooling:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       PHASE 6.3 TEST SCENARIOS                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1.  Health Check Success (GET /health -> 200 OK {"status": "HEALTHY"})       │
│ 2.  Health Check Method Enforcement (POST /health -> 405 Method Not Allowed)│
│ 3.  Status Endpoint Telemetry (GET /status -> 200 OK {"status": "READY"})   │
│ 4.  Status Endpoint Method Enforcement (POST /status -> 405)                │
│ 5.  Single-Window Format A Ingestion (POST /api/v1/infer/window -> 200 OK)  │
│ 6.  Single-Window Format B Ingestion (POST /api/v1/infer/window -> 200 OK)  │
│ 7.  Single-Window Response 24-Field Structural Verification                 │
│ 8.  Single-Window Method Enforcement (GET /api/v1/infer/window -> 405)      │
│ 9.  Single-Window Content-Type Enforcement (text/plain -> 415)              │
│ 10. Single-Window Content-Length Missing (POST without length -> 411)       │
│ 11. Single-Window Payload Ceiling (> 10 MB -> 413 Payload Too Large)        │
│ 12. Single-Window Malformed JSON (corrupt syntax -> 400 Invalid JSON)       │
│ 13. Single-Window Invalid Schema (missing keys -> 400 Validation Error)     │
│ 14. Single-Window NaN/Inf Rejection (NaN feature -> 400 Validation Error)   │
│ 15. Zero-Inference Negative Proof (Engine count unmodified on invalid req)  │
│ 16. Stream Batch Ingestion Success (POST /api/v1/infer/stream -> 200 OK)    │
│ 17. Stream Batch Response Ordering & Continuity Proof                       │
│ 18. Stream Batch Size Limit Rejection (> 5,000 records -> 400 Stream Large) │
│ 19. Stream Batch Atomic Validation (1 bad record in batch -> 400, 0 infer)  │
│ 20. Reset Endpoint Prohibition (GET /api/v1/reset -> 404 Not Found)         │
│ 21. Reset Endpoint Prohibition (POST /api/v1/reset -> 404 Not Found)        │
│ 22. Unknown Route Rejection (GET /api/v1/unknown -> 404 Not Found)          │
│ 23. Error Envelope & Information Leakage Sanitization Verification          │
│ 24. Concurrency & Thread-Safety Stress Test (Concurrent requests)           │
│ 25. Clean Server Lifecycle & Graceful Shutdown                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 21. Static / AST Verification

To guarantee architectural purity, `verify_phase_6_3.py` must execute static Abstract Syntax Tree (AST) analysis on `src/api/handlers.py` and `src/api/server.py`.

### Required Static Checks:
1. **Forbidden Model Imports**:
   - MUST NOT import from `src.models` (`AutoencoderModel`, `XGBoostModel`, `LSTMModel`).
   - MUST NOT import `xgboost`, `tensorflow`, `keras`, `torch`, `sklearn`.
2. **Forbidden Calculation Patterns**:
   - MUST NOT contain threshold literals (`0.00320779...`, `0.3000`).
   - MUST NOT contain threat state transition mappings (`S0`, `S1`, etc. truth table logic).
   - MUST NOT perform score blending, feature scaling, or mathematical transformations.
3. **Forbidden System Calls**:
   - MUST NOT call `os.system`, `subprocess.Popen`, `eval`, `exec`, or `pickle.loads`.
   - MUST NOT perform direct disk reads based on request payload parameters.

---

## 22. Regression Strategy

Phase 6.3 verification must validate that the entire platform remains robust and regression-free across all historic phases:

```
[Phase 4 Hash Verification: 33/33 PASS]
                 │
                 ▼
[Phase 5 Acceptance Regression: 22/22 PASS]
                 │
                 ▼
[Phase 6.2 Verification & Acceptance: 16/16 & 18/18 PASS]
                 │
                 ▼
[Phase 6.3 Verification: 20/20 PASS]
```

---

## 23. Phase 4 Integrity Strategy

- **Baseline Requirement**: All 33 model weights, scalers, and model-ready test datasets frozen in Phase 4.7 must maintain absolute SHA-256 integrity.
- **Verification Tool**: Re-execute the Phase 4 hash manifest check against `data/model_reports/application/phase_4_hash_manifest.json`.
- **Pass Criterion**: 33 / 33 files match identical cryptographic hashes. 0 modified, 0 missing.

---

## 24. Phase 5 Regression Strategy

- **Baseline Requirement**: The accepted Phase 5 application integration layer must remain 100% compliant with its 22 acceptance gates.
- **Verification Tool**: Execute `verify_phase_5_acceptance()` suite.
- **Pass Criterion**: 22 / 22 Phase 5 acceptance gates PASS. 0 failures, 0 regressions.

---

## 25. Phase 6.2 Regression Strategy

- **Baseline Requirement**: The accepted Phase 6.2 schema and validation layer must maintain 100% compliance.
- **Verification Tool**:
  1. Execute `src/api/verification/verify_phase_6_2.py` (16 / 16 verification gates PASS).
  2. Execute the Phase 6.2 final acceptance suite (18 / 18 acceptance gates PASS).
- **Pass Criterion**: 34 / 34 cumulative Phase 6.2 gates PASS.

---

## 26. Contract-Drift Audit

An automated contract-drift audit will compare runtime transport behavior against Phase 5, Phase 6.1, and Phase 6.2 specifications:

| Contract Dimension | Phase 5 Baseline | Phase 6.1 / 6.2 Spec | Phase 6.3 Planned Implementation | Drift Status |
| :--- | :--- | :--- | :--- | :--- |
| **Response Fields** | 24 Fields | 24 Fields | 24 Fields (`validate_application_response`) | **NO DRIFT** |
| **Feature Ordering** | 13 Canonical Keys | 13 Canonical Keys | 13 Canonical Keys (`CANONICAL_FEATURE_KEYS`) | **NO DRIFT** |
| **Request Formats** | Format A Only | Format A + Format B | Format A + Format B supported | **NO DRIFT** |
| **Error Structure** | Flat Dict | Nested Standard Envelope | Standard Envelope (`format_api_error_response`) | **NO DRIFT** |
| **Reset Route** | HTTP 404 | HTTP 404 | HTTP 404 strictly enforced | **NO DRIFT** |
| **Max Payload** | 10 MB | 10 MB | 10 MB (`MAX_REQUEST_BYTES`) | **NO DRIFT** |
| **Max Stream** | 5,000 Records | 5,000 Records | 5,000 Records (`MAX_STREAM_RECORDS`) | **NO DRIFT** |
| **Model Invocations** | Via Orchestrator | Via Orchestrator | Delegated to `ApplicationInferenceEngine` | **NO DRIFT** |

---

## 27. Acceptance Gate Matrix

Phase 6.3 defines **20 Mandatory Acceptance Gates (T1–T20)**. Every gate is mandatory; 100% must pass for Phase 6.3 acceptance.

| Gate ID | Category | Requirement Description | Verification Method | Expected Result | Failure Condition |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **T1** | Authority Compliance | Zero modifications to Phase 4, Phase 5, or Phase 6.2 frozen source files. | Git diff check & SHA-256 manifest check | 0 modified upstream files | Any modified upstream file |
| **T2** | Endpoint Existence | All 4 required routes exist and accept authorized HTTP methods. | HTTP client probing against test server | 200 OK on valid requests to `/health`, `/status`, `/window`, `/stream` | Route missing or connection refused |
| **T3** | Health Endpoint | `GET /health` evaluates model integrity and returns standard JSON. | HTTP GET `/health` | HTTP 200, `{"status": "HEALTHY", "integrity": "VERIFIED"}` | Non-200 or malformed body |
| **T4** | Status Endpoint | `GET /status` returns engine runtime telemetry without secret leakage. | HTTP GET `/status` | HTTP 200, telemetry fields present, no paths/secrets | Non-200 or secret leakage |
| **T5** | Format A Ingestion | Single-window endpoint accepts canonical 13-element feature array. | POST valid Format A payload | HTTP 200 OK, full 24-field response | Non-200 or invalid response |
| **T6** | Format B Ingestion | Single-window endpoint accepts 13 named key dictionary. | POST valid Format B payload | HTTP 200 OK, identical inference results as Format A | Non-200 or mapping failure |
| **T7** | 24-Field Response | Response field-for-field matches Phase 5.1 Section 17 schema. | Output verification via `validate_application_response` | Exact 24 fields present and typed | Missing/extra field or type mismatch |
| **T8** | Error Envelope | All errors return standardized nested error envelope. | Trigger 400, 404, 405, 413, 415 | Response matches `{"error": {"code", "message", "status_code", "timestamp", "details"}}` | Flat error or non-standard envelope |
| **T9** | Input Validation | Invalid requests fail at transport boundary before inference. | POST missing fields, bad types, nulls | HTTP 400 `INPUT_VALIDATION_ERROR` | Non-400 or unhandled crash |
| **T10** | Zero Inference | Invalid requests execute exactly ZERO model inferences. | Inspect `engine._internal_position_counter` before/after invalid request | Position counter completely unchanged | Counter incremented on invalid input |
| **T11** | Non-Finite Numbers | Request with NaN, Inf, or -Inf rejected at boundary. | POST payload with `float('nan')` or `float('inf')` | HTTP 400 `INPUT_VALIDATION_ERROR`, 0 inference | Non-400 or inference execution |
| **T12** | Method Enforcement | Invalid HTTP verbs on endpoints return HTTP 405. | GET `/infer/window`, POST `/health` | HTTP 405 `METHOD_NOT_ALLOWED` with `Allow` header | Non-405 status code |
| **T13** | Media-Type Enforcement| Non-JSON Content-Type returns HTTP 415. | POST with `Content-Type: text/plain` | HTTP 415 `UNSUPPORTED_MEDIA_TYPE` | Non-415 status code |
| **T14** | Payload Ceiling | Request exceeding 10 MB rejected with HTTP 413. | POST with Content-Length > 10 MB | HTTP 413 `PAYLOAD_TOO_LARGE` | Non-413 status code |
| **T15** | Reset Prohibition | `/api/v1/reset` strictly returns HTTP 404 for all verbs. | GET, POST, PUT, DELETE `/api/v1/reset` | HTTP 404 `NOT_FOUND`, public reset prohibited | Non-404 status code |
| **T16** | Stream Transport | Sequential batch processing up to 5,000 records. | POST 20 sequential records | HTTP 200, `processed_count: 20`, continuity maintained | Non-200 or continuity failure |
| **T17** | Stream Size Limit | Stream batch > 5,000 records rejected with HTTP 400. | POST stream with 5,001 items | HTTP 400 `STREAM_TOO_LARGE`, 0 inference | Non-400 status code |
| **T18** | Concurrency Safety | Multi-threaded client requests cannot corrupt engine state. | Concurrent requests across 10 threads | All requests succeed, sequential positions intact | Race condition or engine corruption |
| **T19** | Static / AST Audit | Transport source contains zero model imports or threshold logic. | AST parse of `src/api/handlers.py` and `server.py` | 0 model imports, 0 threshold constants | AST violation detected |
| **T20** | Full Regression | Phase 4, Phase 5, and Phase 6.2 regression suites pass 100%. | Re-run hash check, Phase 5 suite, Phase 6.2 suite | Phase 4 (33/33), Phase 5 (22/22), Phase 6.2 (16/16) | Any upstream gate regression |

---

## 28. Evidence Requirements

Upon future authorization and execution of Phase 6.3 implementation, the following evidence artifacts must be generated:
1. **Verification Test Log**: Console output and execution logs showing all 20 gates passing.
2. **Phase 6.3 Verification Report**:
   - `data/model_reports/application/phase_6_3_verification_report.json`
   - `data/model_reports/application/phase_6_3_verification_report.md`
3. **AST Static Analysis Output**: Documenting zero forbidden imports or calculations in `src/api/handlers.py` and `src/api/server.py`.
4. **Upstream Regression Certificates**: Evidence of 33/33 Phase 4 SHA-256 pass, 22/22 Phase 5 acceptance pass, and 34/34 Phase 6.2 verification/acceptance pass.

---

## 29. Failure / Blocker Rules

The occurrence of any of the following conditions constitutes an immediate **HARD BLOCKER** that terminates Phase 6.3 implementation:
1. Any mutation or modification to Phase 4 frozen model binaries, scalers, or test datasets.
2. Any mutation to Phase 5 core application files in `src/application/`.
3. Any mutation to accepted Phase 6.2 schema, validator, or exception files (`src/api/schemas.py`, `src/api/validators.py`, `src/api/exceptions.py`).
4. Re-implementing validation logic in transport handlers rather than delegating to Phase 6.2 validators.
5. Direct model imports or inference execution inside `src/api/handlers.py` or `src/api/server.py`.
6. Exposing a working state-reset mechanism on `/api/v1/reset` or any other route.
7. Any failure of the 20 mandatory acceptance gates (T1–T20).
8. Introduction of unapproved third-party dependencies (FastAPI, Flask, Starlette, etc.).

---

## 30. Implementation Authorization Boundary

```text
================================================================================
CRITICAL GOVERNANCE DIRECTIVE:
THIS DOCUMENT IS AN IMPLEMENTATION PLAN ONLY.
IMPLEMENTATION AUTHORIZATION = NOT GRANTED.

DO NOT:
- Implement src/api/handlers.py
- Implement src/api/server.py
- Modify src/api/__init__.py
- Implement src/api/verification/verify_phase_6_3.py
- Execute Git commit, push, or stash operations
- Begin Phase 6.4

PROCEED ONLY TO INDEPENDENT AUDIT OF THIS PLAN.
================================================================================
```

---

## 31. Phase 6.3 Acceptance Criteria

Phase 6.3 will be formally accepted when:
1. This implementation plan is independently audited and approved.
2. Implementation is explicitly authorized by user directive.
3. `src/api/handlers.py` and `src/api/server.py` are implemented strictly according to this plan.
4. All 20 mandatory acceptance gates (T1–T20) achieve 100% PASS.
5. Zero regressions are observed across Phase 4, Phase 5, and Phase 6.2.
6. The Phase 6.3 verification report is signed off and archived.

---

## 32. Phase 6.4 Entry Criteria

Phase 6.4 (Production Packaging & Deployment Hardening) may commence ONLY after:
1. Phase 6.3 achieves full formal acceptance and is declared closed.
2. All Phase 6.3 transport handlers are verified operational and stable.
3. Phase 4 integrity (33/33 SHA-256) remains unbroken.
4. User explicitly issues the directive to begin Phase 6.4 planning.

```text
================================================================================
END OF IMPLEMENTATION PLAN: PHASE 6.3
================================================================================
```
