# NexThreat Phase 6.4 — API Documentation, Integration Contracts & Operational Interface Specification Implementation Plan

```text
================================================================================
NEXTHREAT SECURE NETWORK TELEMETRY THREAT-DETECTION PLATFORM
PHASE 6.4 — API DOCUMENTATION, INTEGRATION CONTRACTS & OPERATIONAL SPECIFICATION
DOCUMENT VERSION : 1.5.0
DATE             : 2026-09-15
GOVERNANCE STAGE : PLAN ONLY — IMPLEMENTATION NOT AUTHORIZED
STATUS           : READY FOR FINAL AUDIT
================================================================================
```

---

## 1. Governance Principle & Status

### 1.1 Governing Principle
> **"Phase 6 exposes NexThreat; Phase 6 does not redefine NexThreat."**

All documentation, interface contracts, OpenAPI schemas, and operational runbooks formulated under Phase 6.4 are strictly descriptive, contractually binding, and verified against the accepted repository implementation. Phase 6.4 does not alter, extend, mutate, or redefine upstream contracts, model architectures, thresholds, or execution semantics established and frozen in Phase 4, Phase 5, Phase 6.2, or Phase 6.3.

### 1.2 Governance Workflow Stage
The engineering governance lifecycle mandates:
```text
Plan → Audit → Corrections → Approval → Implementation → Verification → Acceptance
```
**Current Status**: **Corrections Complete — READY FOR FINAL AUDIT**.
**Implementation Authorization**: **NOT GRANTED**.
No runtime code, documentation files, verification suites, or report artifacts shall be created or modified until this corrected implementation plan receives formal final approval.

---

## 2. Objective & Scope Boundaries

### 2.1 Objective
Phase 6.4 formalizes the complete technical specification, developer documentation, enterprise integration guide, operational runbook, and machine-readable API contracts for the NexThreat HTTP API.

The primary objectives are:
1. Deliver a fully valid, machine-readable **OpenAPI 3.1.0 specification** reflecting the exact accepted HTTP routes, request/response contracts, and error structures.
2. Author an **API Integration Guide** detailing payload formats (Format A and Format B), stream batch processing, cold-start sequence handling, and error response interpretations.
3. Author an **Operational Runbook** detailing server instantiation, host/port binding, `/health` evaluation, `/status` runtime telemetry inspection, graceful shutdown procedures, concurrency safety, and environmental operational considerations.
4. Compile a **Canonical Integration Examples Catalogue** providing schema-validated JSON examples for requests, cold-start responses, eligible responses, and error envelopes.
5. Define an automated, deterministic verification suite (`src/api/verification/verify_phase_6_4.py`) executing Gates **D1 through D16** alongside full multi-phase regression checks across Phases 4, 5, 6.2, and 6.3.
6. Formalize Phase 6.4 verification reporting standards (`data/model_reports/application/phase_6_4_verification_report.md` and `.json`).

### 2.2 Exact Phase 6.4 Deliverables Scope (Authorized Outputs)
The authorized scope of Phase 6.4 outputs is defined unambiguously:

```text
Total Phase 6.4 authorized artifacts = 7

4 documentation/specification artifacts + 1 verifier + 2 verification report artifacts = 7 authorized Phase 6.4 deliverables.

The four documentation/specification artifacts are:
1. docs/api/openapi.json
2. docs/api/api_integration_guide.md
3. docs/api/operational_runbook.md
4. docs/api/integration_examples.json

The single verification artifact is:
5. src/api/verification/verify_phase_6_4.py

The two verification report artifacts are:
6. data/model_reports/application/phase_6_4_verification_report.md
7. data/model_reports/application/phase_6_4_verification_report.json
```

| Artifact Path | Category | Purpose |
| :--- | :--- | :--- |
| `docs/api/openapi.json` | Documentation / Specification | Machine-readable OpenAPI 3.1.0 document specifying routes, schemas, headers, status codes, and security limits. |
| `docs/api/api_integration_guide.md` | Documentation / Specification | Comprehensive integration manual for SOC dashboard and pipeline developers detailing Format A, Format B, stream ingestion, cold start, and errors. |
| `docs/api/operational_runbook.md` | Documentation / Specification | Runbook for SREs covering server lifecycle, port binding, `/health` and `/status` monitoring, graceful shutdown, and concurrency safety. |
| `docs/api/integration_examples.json` | Documentation / Specification | Concrete, schema-valid JSON payloads for all requests, responses, and error states. |
| `src/api/verification/verify_phase_6_4.py` | Verification Tooling (Verifier) | Automated test harness executing Gates D1 through D16 and upstream regression gates. |
| `data/model_reports/application/phase_6_4_verification_report.md` | Verification Report | Human-readable verification report detailing gate outcomes, SHA-256 checksums, and regression status. |
| `data/model_reports/application/phase_6_4_verification_report.json` | Verification Report | Machine-readable JSON execution summary of the verification suite. |

No additional source files, documentation files, configuration files, test scripts, models, or runtime artifacts may be added.

### 2.3 Frozen Pre-Existing Runtime Boundary (Zero-Modification Boundary)
Phase 6.4 may create **only** the single verifier (`src/api/verification/verify_phase_6_4.py`), the four documentation/specification artifacts, and the two verification report artifacts explicitly listed above. **No pre-existing runtime or API file may be modified, deleted, or renamed.**

The following pre-existing files are strictly frozen and immutable:
```text
src/api/__init__.py
src/api/exceptions.py
src/api/handlers.py
src/api/schemas.py
src/api/server.py
src/api/validators.py
src/api/verification/verify_phase_6_2.py
src/api/verification/verify_phase_6_3.py
all src/application/* (all files)
all src/models/* (all files)
all data/models/* (all model binaries, scalers, mappings, metadata)
```

### 2.4 Non-Scope
The following areas remain strictly outside Phase 6.4 scope:
1. **Runtime Implementation Changes**: Zero edits to any pre-existing file in `src/api/*`, `src/application/*`, or `src/models/*`.
2. **Phase 6.5 Production Packaging & Containerization**: Dockerfiles, multi-stage builds, container registries, Kubernetes manifests, and systemd units belong exclusively to Phase 6.5 and must not appear in Phase 6.4. Phase 6.5 remains blocked until Phase 6.4 achieves formal acceptance.
3. **Machine Learning Model Modifications**: No fourth model, ensemble, stacking, meta-model, score fusion, weighted probability blending, retraining, or threshold modification.
4. **Transport or Route Expansion**: No new HTTP endpoints, WebSocket endpoints, gRPC interfaces, or GraphQL schemas.
5. **Public Reset Endpoint**: `/api/v1/reset` remains strictly prohibited and returns HTTP 404. It must never be documented as an available API operation in OpenAPI.
6. **Authentication & Authorization Logic**: Phase 6.1 explicitly designated authentication (JWT, mTLS, API keys) as an external API gateway / reverse-proxy concern. No transport authentication logic shall be introduced into the Python process.

---

## 3. Authoritative Baselines & Upstream Contracts

Phase 6.4 inherits immutable contracts from prior accepted phases:

### 3.1 Phase 4 Baseline (Phase 4.7 Accepted & Frozen)
- **Status**: FROZEN & IMMUTABLE.
- **Inventory**: 33 files with verified SHA-256 hashes registered in `data/model_reports/acceptance/phase_4_7_acceptance_report.json`.
- **Three-Model Inventory**:
  1. Autoencoder (`data/models/autoencoder/autoencoder_final.h5`): Unsupervised anomaly detector. Threshold MSE $> 0.003207791231673312$.
  2. XGBoost (`data/models/xgboost/xgboost_multiclass_final.json`): 8-class supervised multiclass classifier operating on the raw, unscaled canonical 13-feature vector. Prediction uses argmax over the 8 classes (0..7: `0: BENIGN`, `1: Brute Force`, `2: Bot`, `3: DoS`, `4: Infiltration`, `5: PortScan`, `6: Web Attack`, `7: DDoS`). Attack condition: `predicted_class_index != 0` (class 0 is BENIGN; classes 1..7 indicate attack). No probability threshold (no 0.5000 threshold). Do not describe XGBoost as a binary classifier. Do not introduce probability-threshold logic. Zero score fusion.
  3. LSTM (`data/models/lstm/lstm_final.h5`): Temporal future attack forecaster. Threshold probability $\ge 0.3000$ over 10-window lookback ($10 \times 13$).
- **Threat States**: Exactly 8 discrete states ($S_0$ through $S_7$). Zero score fusion.

### 3.2 Phase 5 Baseline (Phase 5.7 Accepted)
- **Status**: FROZEN & ACCEPTED (22 / 22 Gates PASS).
- **Core Engine**: `src/application/orchestrator.py` (`ApplicationInferenceEngine`).
- **10-Step Execution Invariant**: Transactional state commit occurs strictly at Step 9.
- **Temporal Authority**: `TemporalHistoryBuffer` in `src/application/state_manager.py` enforces strict 60-second continuity ($\Delta t = 60\,\text{s}$), chronological monotonicity ($t_n > t_{n-1}$), calendar day boundary isolation (`current_dt.date() != last_dt.date()`), and 10-window cold-start quarantine.

### 3.3 Phase 6.1 Baseline (Accepted Architecture Specification)
- **Status**: ACCEPTED (`data/model_reports/application/phase_6_1_api_backend_architecture_and_contract.md`).
- **Architecture**: Defines HTTP transport adapter boundaries, route taxonomy, payload ceilings (10 MB, 5,000 stream items), error envelope schema, and technical information leakage sanitization.

### 3.4 Phase 6.2 Baseline (Accepted Schemas & Validators)
- **Status**: FROZEN & ACCEPTED (16 / 16 Gates PASS).
- **Verification Tool**: `src/api/verification/verify_phase_6_2.py`.
- **Artifact Report**: `data/model_reports/application/phase_6_2_final_acceptance_report.md`.

### 3.5 Phase 6.3 Baseline (Accepted Transport Handlers & Server)
- **Status**: FROZEN & ACCEPTED (20 / 20 Gates PASS).
- **Verification Tool**: `src/api/verification/verify_phase_6_3.py`.
- **Artifact Report**: `data/model_reports/application/phase_6_3_verification_report.md`.

---

## 4. Repository Discovery: Authoritative Symbol & Validator Registry

A comprehensive inspection of `src/api/` confirms the exact authoritative names, schemas, exceptions, and validators established in Phase 6.2 and Phase 6.3.

### 4.1 Authoritative Validator Functions (`src/api/validators.py`)
Phase 6.4 must reference ONLY these exact validator functions:
- `validate_single_window_request(raw_payload: Any) -> CanonicalInputRecord`:
  Validates Format A (13-element canonical float list) or Format B (13-key named dictionary), validates string format of `window_id` (`WINDOW_ID_PATTERN`) and `timestamp` (`parse_timestamp()`), strictly rejects booleans, non-numeric values, NaN, and Infinity, maps Format B sequentially into canonical ordering without scaling, and returns an authoritative `CanonicalInputRecord`.
- `validate_stream_batch_request(raw_payload: Any) -> List[CanonicalInputRecord]`:
  Validates stream container `{"stream": [...]}`, enforces $1 \le \text{length} \le 5,000$ (`MAX_STREAM_RECORDS = 5000`), performs atomic upfront validation on every item via `validate_single_window_request`, and returns `List[CanonicalInputRecord]`.
- `validate_application_response(response_data: Union[Dict[str, Any], StandardInferenceResponse, ApplicationOutputRecord]) -> Dict[str, Any]`:
  Asserts outgoing response structural integrity across the complete 24-field nested Authority Matrix without altering or re-evaluating model outputs.

### 4.2 Authoritative Request & Response Schemas (`src/api/schemas.py`)
- `SingleWindowCanonicalRequest`: Dataclass for Format A (`window_id: str`, `timestamp: str`, `features: List[float]`).
- `SingleWindowNamedRequest`: Dataclass for Format B (`window_id: str`, `timestamp: str`, `features: Dict[str, float]`).
- `StreamBatchRequest`: Dataclass for stream batch ingestion (`stream: List[...]`).
- `AutoencoderResponse`: Dataclass for fields 5..7 (`reconstruction_mse: float`, `threshold: float`, `is_anomaly: int`).
- `XGBoostResponse`: Dataclass for fields 8..11 (`predicted_class_index: int`, `predicted_class_name: str`, `is_attack: int`, `class_probabilities: Optional[List[float]] = None`).
- `LSTMResponse`: Dataclass for fields 12..16 (`is_eligible: bool`, `ineligibility_reason: Optional[str]`, `forecast_probability: Optional[float]`, `threshold: float`, `forecast_decision: Union[int, str]`).
- `ThreatInferenceResponse`: Dataclass for fields 17..21 (`is_eligible: bool`, `threat_state_code: Optional[str]`, `threat_state_name: Optional[str]`, `priority_tier: Optional[str]`, `decision_tuple: Optional[List[int]]`).
- `ExecutionMetadataResponse`: Dataclass for fields 22..24 (`inference_latency_ms: float`, `schema_version: str = "1.0.0"`, `engine: str = "NexThreat-Phase5.2"`).
- `StandardInferenceResponse`: Complete 24-field authoritative response structure mapping directly from Phase 5 `ApplicationOutputRecord`.

### 4.3 Authoritative Exceptions & Sanitizers (`src/api/exceptions.py`)
- `APIError`: Base class for all NexThreat API exceptions.
- `APIValidationError`: Raised on schema or data validation failure (`code="INPUT_VALIDATION_ERROR"`, HTTP 400).
- `PayloadTooLargeError`: Raised when payload exceeds 10 MB (`code="PAYLOAD_TOO_LARGE"`, HTTP 413).
- `StreamTooLargeError`: Raised when stream exceeds 5,000 items (`code="STREAM_TOO_LARGE"`, HTTP 400).
- `InternalAPIError`: Raised on unexpected server errors (`code="INTERNAL_ERROR"`, HTTP 500).
- `format_api_error_response(...)`: Standardized error envelope formatter.
- `sanitize_error_message(msg: str) -> str`: Redacts Windows drive paths, Unix absolute paths, Python filenames, stack line numbers, and hex memory pointers.

### 4.4 Authoritative Server & Handlers (`src/api/handlers.py`, `src/api/server.py`)
- `NexThreatAPIHandler`: `BaseHTTPRequestHandler` subclass managing routing, header inspection, content negotiation, schema validation delegation, engine dispatch under lock, response formatting, and sanitized error serialization.
- `NexThreatAPIServer`: Lifecycle manager wrapping `ThreadingHTTPServer`, managing port binding, background thread execution, and clean shutdown.

### 4.5 Authoritative Constants
- `CANONICAL_FEATURE_KEYS`: List of 13 strings in fixed sequence:
  `["flow_count", "packet_rate", "byte_rate", "mean_flow_duration", "std_flow_duration", "short_flow_ratio", "mean_packet_size", "packet_length_variability", "fwd_bwd_packet_ratio", "unique_dst_ports", "unique_dst_ips", "tcp_flow_ratio", "syn_packet_ratio"]`
- `MAX_STREAM_RECORDS = 5000`
- `MAX_REQUEST_BYTES = 10485760` (10 MB)
- `AUTOENCODER_THRESHOLD = 0.003207791231673312`
- `LSTM_THRESHOLD = 0.3`
- `CANONICAL_STATE_CODES = {"S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7"}`
- `VALID_PRIORITY_TIERS = {"P1", "P2", "P3", "P4"}`
- `VALID_DATASET_DAYS = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Unknown"}`
- `WINDOW_ID_PATTERN = re.compile(r"^[0-9]{8}_[0-9]{4}$")`

### 4.6 Strict Negative Prohibition of Obsolete Aliases & Audit Scope Distinction
The obsolete symbols:
- `validate_window_request`
- `validate_stream_request`
- `WindowInferenceRequest`

**Scope Distinction**:
1. **Active Implementation & Documentation Surfaces**: Must contain **zero active use, import, declaration, or authoritative reference** to these obsolete symbols across:
   - `src/` (all Python source code)
   - `docs/api/` (all API guides and specifications)
   - active Phase 6.x design specifications
   - `integration_examples.json`
   - `openapi.json`
   - Phase 6.4 verification test logic
2. **Historical / Audit Reports**: Historical reports (e.g. Phase 6.2/6.3 verification reports or audit logs) may mention obsolete names only when recording historical defects, corrections, or negative-proof requirements. Gate D1 evaluates active references/definitions to prevent false failures while enforcing complete absence from active surfaces.
3. The authoritative active API symbols remain exclusively:
   - `validate_single_window_request`
   - `validate_stream_batch_request`
   - `SingleWindowCanonicalRequest`
   - `SingleWindowNamedRequest`
   - `StreamBatchRequest`
   No compatibility aliases or fallback mappings shall be introduced.

---

## 5. Baseline Conflict Analysis & Authoritative Resolution

### 5.1 Discrepancy Identification
A structural representation discrepancy exists between hypothetical flat-response templates and the accepted Phase 5 / Phase 6 runtime codebase.

The hypothetical flat list contains:
```text
window_id, timestamp, global_position, sequence_len, ae_loss, ae_threshold, ae_anomaly, xgb_probability, xgb_threshold, xgb_attack, lstm_probability, lstm_threshold, lstm_forecast, lstm_eligible, threat_state, threat_name, threat_level, action_recommended, confidence_score, model_agreement_count, processing_latency_ms, cold_start, discontinuous_flow, error_flag
```

However, the accepted and verified Phase 5.1 (`phase_5_1_application_integration_architecture_and_contract.md` Sec 17), Phase 5.2 (`src/application/schemas.py`), Phase 6.1 (`phase_6_1_api_backend_architecture_and_contract.md` Sec 8), Phase 6.2 (`src/api/schemas.py`, `src/api/validators.py`), and Phase 6.3 (`src/api/handlers.py`) define the **authoritative 24-field nested structure**:

```text
Root Level (4 fields):
  1. window_id: str
  2. timestamp: str
  3. global_position: Optional[int] (int >= 1, default null)
  4. dataset_day: Optional[str] (enum, default null)
autoencoder block (3 fields):
  5. reconstruction_mse: float (finite >= 0.0)
  6. threshold: float (= 0.003207791231673312)
  7. is_anomaly: int (0 or 1)
xgboost block (4 fields):
  8. predicted_class_index: int (0..7)
  9. predicted_class_name: str
 10. is_attack: int (0 or 1)
 11. class_probabilities: Optional[List[float]] (8 floats in [0, 1], default null)
lstm block (5 fields):
 12. is_eligible: bool
 13. ineligibility_reason: Optional[str] (null when eligible, non-empty str when ineligible)
 14. forecast_probability: Optional[float] (float in [0, 1] when eligible, null when ineligible)
 15. threshold: float (= 0.3)
 16. forecast_decision: Union[int, str] (0 or 1 when eligible, "unavailable" when ineligible)
threat_inference block (5 fields):
 17. is_eligible: bool
 18. threat_state_code: Optional[str] (S0..S7 when eligible, null when ineligible)
 19. threat_state_name: Optional[str] (string when eligible, null when ineligible)
 20. priority_tier: Optional[str] (P1..P4 when eligible, null when ineligible)
 21. decision_tuple: Optional[List[int]] (3 binary ints when eligible, null when ineligible)
execution_metadata block (3 fields):
 22. inference_latency_ms: float (finite >= 0.0)
 23. schema_version: str (= "1.0.0")
 24. engine: str (= "NexThreat-Phase5.2")
```

### 5.2 Authoritative Resolution
Under the governing principle **"Phase 6 exposes NexThreat; Phase 6 does not redefine NexThreat"**:
1. The **nested 24-field structure** defined in `src/api/schemas.py` (`StandardInferenceResponse`) and validated by `validate_application_response()` in `src/api/validators.py` is the **sole authoritative response contract**.
2. `sequence_len` is NOT a response field; per-window eligibility is represented by `lstm.is_eligible`, and buffer depth is exposed via `GET /status` (`lookback_depth`).
3. `confidence_score` and `action_recommended` are strictly prohibited by Phase 4.5 Section 5 and Phase 5.1 Section 4 (score fusion and automated intervention prohibition).
4. `error_flag` does not exist in inference responses; transport failures yield standard HTTP error envelopes (`HTTP 400/413/500`), guaranteeing that `HTTP 200 OK` inference responses are never ambiguous or tainted by an error flag.
5. All Phase 6.4 deliverables (OpenAPI, guides, examples, and tests) must adhere strictly to the authoritative nested 24-field schema.

---

## 6. API Surface & Route Specifications

The API surface consists of exactly four active operational endpoints and one explicitly prohibited route.

### 6.1 Route Inventory & Method Matrix

| Method | Path | Allowed Headers | Status Codes | Description |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/health` | None required | `200`, `503` | Evaluates Phase 4 model asset integrity and engine readiness. |
| `GET` | `/status` | None required | `200` | Telemetry endpoint returning processed count, lookback depth, and engine version. |
| `POST` | `/api/v1/infer/window` | `Content-Type: application/json`<br>`Content-Length: <int>` | `200`, `400`, `405`, `411`, `413`, `415`, `500` | Synchronous inference on single 1-minute window (Format A or Format B). |
| `POST` | `/api/v1/infer/stream` | `Content-Type: application/json`<br>`Content-Length: <int>` | `200`, `400`, `405`, `411`, `413`, `415`, `500` | Sequential batch inference on up to 5,000 windows maintaining lookback continuity. |
| ANY | `/api/v1/reset` | ANY | `404` | **PROHIBITED ROUTE**. Client state resets are forbidden. Emits `NOT_FOUND`. |

### 6.2 Route Enforcement Rules
- **Method Enforcement**: Calling any method other than `GET` on `/health` or `/status` returns `HTTP 405 Method Not Allowed` with header `Allow: GET`. Calling any method other than `POST` on `/api/v1/infer/window` or `/api/v1/infer/stream` returns `HTTP 405 Method Not Allowed` with header `Allow: POST`.
- **Public Reset Prohibition**: Any request to `/api/v1/reset` (GET, POST, PUT, DELETE, etc.) returns `HTTP 404 Not Found` with error code `NOT_FOUND` and message `"Endpoint '/api/v1/reset' does not exist. Public client resets are prohibited."`. It must NOT appear in OpenAPI paths.
- **Unregistered Paths**: Any request to an unknown route returns `HTTP 404 Not Found` with error code `NOT_FOUND`.
- **Media-Type Enforcement**: Missing or non-JSON `Content-Type` on POST requests returns `HTTP 415 Unsupported Media Type` (`code="UNSUPPORTED_MEDIA_TYPE"`).
- **Content-Length Enforcement**: Missing `Content-Length` on POST requests returns `HTTP 411 Length Required` (`code="LENGTH_REQUIRED"`). Invalid non-integer `Content-Length` returns `HTTP 400 Bad Request` (`code="BAD_REQUEST"`).

---

## 7. Verified `/health` Endpoint Semantics

Direct inspection of `src/api/handlers.py` (lines 278–297) confirms the exact implementation of `GET /health`:
- Invokes `verify_authoritative_33_files_integrity()` from `src.application.service`.
- Evaluates the 33 Phase 4 frozen artifacts against expected SHA-256 hashes from `data/model_reports/acceptance/phase_4_7_acceptance_report.json`.
- Confirms that the inference engine is initialized (`self.engine is not None`).
- **Healthy Response (`HTTP 200 OK`)**:
  ```json
  {
    "status": "HEALTHY",
    "integrity": "VERIFIED",
    "timestamp": "2026-09-15T09:45:00.000000Z"
  }
  ```
- **Degraded / Unhealthy Response (`HTTP 503 Service Unavailable`)**:
  ```json
  {
    "status": "UNHEALTHY",
    "integrity": "FAILED",
    "timestamp": "2026-09-15T09:45:00.000000Z"
  }
  ```
- **Contract Note**: `/health` outputs a dedicated status dictionary containing exactly `status`, `integrity`, and `timestamp`. It does NOT emit a standard `format_api_error_response` envelope.

---

## 8. Verified `/status` Endpoint Semantics

Direct inspection of `src/api/handlers.py` (lines 298–316) confirms the exact implementation of `GET /status`:
- Safely acquires `engine_lock` to read `_internal_position_counter` and `history_buffer.current_depth`.
- Outputs engine runtime telemetry without exposing internal file paths, memory addresses, or environment variables.
- **Status Response (`HTTP 200 OK`)**:
  ```json
  {
    "status": "READY",
    "processed_windows": 142,
    "lookback_depth": 10,
    "engine_version": "1.0.0",
    "timestamp": "2026-09-15T09:45:00.000000Z"
  }
  ```

---

## 9. Request Contract Specifications

### 9.1 Format A (Canonical Array Request)
Maps directly to `SingleWindowCanonicalRequest`.
- `window_id`: String strictly matching `^[0-9]{8}_[0-9]{4}$` (e.g. `"20170705_0900"`). Booleans and non-strings are rejected.
- `timestamp`: ISO 8601 string parseable by `parse_timestamp()` (e.g. `"2017-07-05T09:00:00"`).
- `features`: Array of exactly 13 finite numeric floats in fixed canonical order. Booleans, strings, nulls, NaNs, and Infs are rejected.

```json
{
  "window_id": "20170705_0900",
  "timestamp": "2017-07-05T09:00:00",
  "features": [
    124.0, 25.4, 18420.5, 0.45, 0.12, 0.35, 725.0, 150.2, 1.25, 4.0, 2.0, 0.85, 0.15
  ]
}
```

### 9.2 Format B (Named Object Request)
Maps directly to `SingleWindowNamedRequest`.
- `window_id`: Same validation as Format A.
- `timestamp`: Same validation as Format A.
- `features`: Dictionary containing exactly the 13 canonical keys. Missing or extraneous keys are rejected. All values must be finite numeric floats.

```json
{
  "window_id": "20170705_0900",
  "timestamp": "2017-07-05T09:00:00",
  "features": {
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
    "syn_packet_ratio": 0.15
  }
}
```

### 9.3 Canonical Feature Order
Both formats enforce the 13 features in `CANONICAL_FEATURE_KEYS`:
1. `flow_count`, 2. `packet_rate`, 3. `byte_rate`, 4. `mean_flow_duration`, 5. `std_flow_duration`, 6. `short_flow_ratio`, 7. `mean_packet_size`, 8. `packet_length_variability`, 9. `fwd_bwd_packet_ratio`, 10. `unique_dst_ports`, 11. `unique_dst_ips`, 12. `tcp_flow_ratio`, 13. `syn_packet_ratio`.

---

## 10. Stream Batch Contract & Operational Boundaries

### 10.1 Stream Container Schema (`StreamBatchRequest`)
Stream ingestion accepts a JSON object with root key `"stream"`:
```json
{
  "stream": [
    { "window_id": "20170705_0900", "timestamp": "2017-07-05T09:00:00", "features": [ ... ] },
    { "window_id": "20170705_0901", "timestamp": "2017-07-05T09:01:00", "features": { ... } }
  ]
}
```

### 10.2 Stream Boundaries & Enforcements
- **Stream Record Ceiling**: Maximum 5,000 records (`MAX_STREAM_RECORDS = 5000`). If exceeded, handler raises `StreamTooLargeError` $\implies$ `HTTP 400 Bad Request` (`code="STREAM_TOO_LARGE"`).
- **Stream Record Floor**: Stream cannot be empty (`len == 0`). Raises `APIValidationError` $\implies$ `HTTP 400 Bad Request` (`code="INPUT_VALIDATION_ERROR"`).
- **Payload Byte Ceiling**: Maximum 10 MB ($10,485,760$ bytes). If `Content-Length > MAX_REQUEST_BYTES`, returns `HTTP 413 Payload Too Large` (`code="PAYLOAD_TOO_LARGE"`).
- **Atomic Upfront Batch Validation**: Entire stream is validated via `validate_stream_batch_request()` before inference begins. Any validation failure terminates the request with zero model inference executed.
- **Sequential Ingestion Guarantee**: Inferences are processed sequentially under `engine_lock`, ensuring temporal lookback depth increases monotonically across contiguous records.
- **Success Response Structure**:
```json
{
  "processed_count": 2,
  "results": [
    { "window_id": "20170705_0900", ... },
    { "window_id": "20170705_0901", ... }
  ]
}
```

---

## 11. Cold Start & Sequence Lifecycle Specification

### 11.1 Cold-Start Semantics
The LSTM forecasting model requires a history tensor of shape $(10, 13)$ representing 10 consecutive 1-minute windows ($\Delta t = 60\,\text{s}$).
- **Cold-Start Quarantine**: The LSTM becomes eligible only after 10 committed historical windows satisfying the required strict 60-second continuity rule. The first eligible inference is the 11th window in the valid sequence.
- **Cold-Start Representation**: During cold start (first 10 windows):
  - `lstm.is_eligible = false`
  - `lstm.ineligibility_reason = "lstm_lookback_cold_start"`
  - `lstm.forecast_probability = null`
  - `lstm.forecast_decision = "unavailable"`
  - `threat_inference.is_eligible = false`
  - `threat_inference.threat_state_code = null`
  - `threat_inference.threat_state_name = null`
  - `threat_inference.priority_tier = null`
  - `threat_inference.decision_tuple = null`
- **Continuous Evaluation of AE and XGBoost**: The Autoencoder and XGBoost models operate strictly on the current window ($1 \times 13$) and evaluate with full fidelity during cold start. Anomaly flags (`is_anomaly`) and attack classifications (`is_attack`) are fully populated on every window.
- **Prohibited States**: Neither `LSTM_UNAVAILABLE` nor `UNKNOWN` is a threat state. Ineligible windows output strictly `null` for all threat-state fields.

### 11.2 Implementation-Grounded Temporal Continuity Verification Framework

#### 11.2.1 Governance Distinction & Principle
To preserve rigorous governance discipline while Phase 6.4 remains in the planning phase, the continuity specification clearly distinguishes three separate domains:
1. **The Inherited / Accepted Phase 5 Temporal Continuity Contract**: The contractual specifications established in Phase 5 (Sections 14 and 17) governing 60-second cadence, 10-window lookback buffer, calendar-day resets, and cold-start ineligibility.
2. **The Runtime Implementation to be Inspected**: The existing runtime source code in `src/application/state_manager.py` (specifically `TemporalHistoryBuffer`), `src/application/validators.py`, and `src/application/orchestrator.py` (`ApplicationInferenceEngine`), which executes the actual continuity logic.
3. **The Phase 6.4 Verification Suite to be Executed**: The forthcoming automated test suite (`src/api/verification/verify_phase_6_4.py`, Gate D8), which will programmatically execute test scenarios against the running engine to determine whether runtime behavior strictly conforms to the inherited contract.

> **Governance Principle**:
> *"Runtime behavior is authoritative. Phase 6.4 verification determines whether the runtime conforms to the inherited Phase 5 contract."*

The verification plan establishes the expected continuity behaviors as **verification targets** to be tested; it does not represent them as already verified prior to verification execution. Phase 6.4 does not redefine any temporal operator or introduce new runtime semantics.

#### 11.2.2 Explicit Continuity Verification Targets
The Phase 6.4 verification suite (`verify_phase_6_4.py`, Gate D8) must directly inspect and programmatically test the runtime implementation against the following operational verification targets:

1. **Valid 60-Second Continuity ($\Delta t = 60\,\text{s}$)**:
   - Target Evaluation: Consecutive records with `(current_dt - last_dt).total_seconds() == 60.0`.
   - Verification Target Behavior: History buffer appends the window; buffer depth increments monotonically from 1 up to 10; upon reaching 10 windows, LSTM eligibility is achieved.
2. **Sub-60-Second Delta ($\Delta t < 60\,\text{s}$)**:
   - Target Evaluation: Positive non-zero delta less than 60 seconds (e.g. 30s).
   - Verification Target Behavior: Evaluated as a temporal gap/cadence violation; history buffer is cleared/reset; returns `is_eligible = false`, `ineligibility_reason = "temporal_gap_discontinuity"`, lookback tensor is `null`.
3. **Super-60-Second Delta ($\Delta t > 60\,\text{s}$)**:
   - Target Evaluation: Delta exceeding 60 seconds (e.g. 120s).
   - Verification Target Behavior: Evaluated as a temporal gap; history buffer is cleared/reset; returns `is_eligible = false`, `ineligibility_reason = "temporal_gap_discontinuity"`, lookback tensor is `null`.
4. **Non-Monotonic Timestamp ($t_n < t_{n-1}$)**:
   - Target Evaluation: Incoming timestamp is chronologically earlier than the preceding timestamp.
   - Verification Target Behavior: Evaluated by `src/application/validators.py` as `current_dt <= last_dt`; immediately raises `InputValidationError` (`"Chronological ordering violation... Non-advancing time is rejected."`), triggering an HTTP 400 Bad Request response with zero model inference.
5. **Duplicate / Same Timestamp ($t_n == t_{n-1}$)**:
   - Target Evaluation: Incoming timestamp is identical to the preceding timestamp.
   - Verification Target Behavior: Evaluated under non-advancing time (`current_dt <= last_dt`); immediately raises `InputValidationError`, triggering an HTTP 400 Bad Request response with zero model inference.
6. **Same-Day Continuity**:
   - Target Evaluation: Monotonically advancing 60-second intervals occurring within the same calendar day (`current_dt.date() == last_dt.date()`).
   - Verification Target Behavior: Buffer accumulates historical state normally without spurious resets.
7. **Dataset-Day Boundary / Cross-Day Continuity ($t_n.\text{date}() \ne t_{n-1}.\text{date}()$)**:
   - Target Evaluation: Midnight date transition where date component advances.
   - Verification Target Behavior: Calendar date change flushes the lookback history buffer immediately; cross-day sequence continuity is prohibited; returns `is_eligible = false`, `ineligibility_reason = "lstm_lookback_cold_start"`, lookback tensor is `null`.
8. **10-Window Cold-Start Progression**:
   - Target Evaluation: Sequential ingestion of windows starting from a reset or empty buffer.
   - Verification Target Behavior: Windows 1 through 10 have lookback depth $< 10$, returning `is_eligible = false`, `ineligibility_reason = "lstm_lookback_cold_start"`, and a full 24-field response where `threat_inference` fields are `null` (not `threat_inference: null`). Window 11 (upon receiving the 10th historical window) attains depth 10, returning `is_eligible = true`, `ineligibility_reason = null`, and valid model evaluation.

---

## 12. Verified Error Contract & Error Taxonomy

### 12.1 Standardized Error Envelope
All error responses (except `/health` degraded status) strictly follow the envelope produced by `format_api_error_response()`:
```json
{
  "error": {
    "code": "INPUT_VALIDATION_ERROR",
    "message": "Field 'features' must contain exactly 13 values.",
    "status_code": 400,
    "timestamp": "2026-09-15T09:45:00.000000Z",
    "details": {}
  }
}
```

### 12.2 Verified Authoritative Error Code Taxonomy
Audit of `src/api/handlers.py` and `src/api/exceptions.py` confirms that exactly the following error codes are emitted by the runtime:

| Error Code | HTTP Status | Originating File & Function | Trigger Condition |
| :--- | :--- | :--- | :--- |
| `INPUT_VALIDATION_ERROR` | `400` | `handlers.py` lines 332, 340, 360, 424, 432, 455 | Schema mismatch, missing/extra fields, invalid window_id/timestamp, non-numeric or non-finite feature values. |
| `STREAM_TOO_LARGE` | `400` | `handlers.py` line 416; `exceptions.py` line 65 | Stream batch exceeds 5,000 records. |
| `BAD_REQUEST` | `400` | `handlers.py` lines 193, 228 | Invalid `Content-Length` header or failure reading request body stream. |
| `INVALID_JSON` | `400` | `handlers.py` lines 214, 221 | Request body is not valid UTF-8 or fails JSON decoding. |
| `NOT_FOUND` | `404` | `handlers.py` lines 107, 143, 163, 270 | Request to unknown endpoint or attempted access to `/api/v1/reset`. |
| `METHOD_NOT_ALLOWED` | `405` | `handlers.py` line 115 | Unsupported HTTP method on a valid endpoint. Includes `Allow` header. |
| `LENGTH_REQUIRED` | `411` | `handlers.py` line 183 | Missing `Content-Length` header on POST request. |
| `PAYLOAD_TOO_LARGE` | `413` | `handlers.py` line 202; `exceptions.py` line 52 | Payload byte size exceeds 10 MB ($10,485,760$ bytes). |
| `UNSUPPORTED_MEDIA_TYPE` | `415` | `handlers.py` line 173 | Missing or non-JSON `Content-Type` header on POST request. |
| `INTERNAL_ERROR` | `500` | `handlers.py` lines 349, 374, 381, 392, 440, 469 | Unhandled engine error, uninitialized engine, contract error, or serialization check failure. |
| `MODEL_EXECUTION_ERROR` | `500` | `handlers.py` lines 367, 462 | Failure during model matrix evaluation. |

**Audit Confirmation**:
- `RESET_PROHIBITED`: **Removed**. The runtime emits `code="NOT_FOUND"` with HTTP 404.
- `SERVICE_UNAVAILABLE`: **Removed from error envelopes**. `/health` returns a direct JSON status object `{"status": "UNHEALTHY", "integrity": "FAILED", "timestamp": ...}` at HTTP 503 rather than an error envelope.

### 12.3 Technical Information Sanitization (`sanitize_error_message`)
Error messages exposed to clients are automatically sanitized:
1. Windows filesystem paths (`C:\...`, `E:\...`) $\implies$ `[REDACTED_PATH]`
2. Unix absolute paths (`/home/...`, `/usr/...`, `/var/...`, `/tmp/...`) $\implies$ `[REDACTED_PATH]`
3. Python source files (`*.py`) $\implies$ `[REDACTED_SRC]`
4. Stack trace line numbers (`line 123`) $\implies$ `line [REDACTED]`
5. Hexadecimal memory pointers (`0x7fff...`) $\implies$ `[REDACTED_ADDR]`

---

## 13. ML Model Boundary & Threat State Registry

### 13.1 Model Inventory
Exactly three machine learning models are documented:
1. **Autoencoder**: `autoencoder_final.h5`
   - Decision Operator: $\text{Reconstruction MSE} > 0.003207791231673312 \implies \text{is\_anomaly} = 1$.
2. **XGBoost**: `xgboost_multiclass_final.json`
   - Model Architecture: 8-class supervised multiclass classifier receiving the raw, unscaled canonical 13-feature vector.
   - Authoritative 8 Classes (from `class_mapping.json`): `0: BENIGN`, `1: Brute Force`, `2: Bot`, `3: DoS`, `4: Infiltration`, `5: PortScan`, `6: Web Attack`, `7: DDoS`.
   - Prediction Method: Argmax over the 8 class probabilities ($\text{predicted\_class\_index} = \text{argmax}(P(\text{class}_i))$).
   - Attack Condition: $\text{predicted\_class\_index} \ne 0 \implies \text{is\_attack} = 1$ (class 0 indicates BENIGN traffic; classes 1..7 indicate attack traffic).
   - Threshold Policy: No probability threshold. There is NO XGBoost probability threshold of 0.5000. XGBoost is strictly an 8-class multiclass classifier and does not evaluate probability thresholds. Zero score fusion.
3. **LSTM**: `lstm_final.h5`
   - Decision Operator: $P(\text{attack}_{t+1}) \ge 0.3000 \implies \text{forecast\_decision} = 1$ (for eligible sequences).

### 13.2 Threat States (S0–S7)
Threat state resolution maps the decision tuple $[b_{\text{ae}}, b_{\text{xgb}}, b_{\text{lstm}}]$ bijectively into $\{S_0..S_7\}$:

| State Code | State Name | Priority Tier | Tuple `[ae, xgb, lstm]` | Operational Meaning |
| :--- | :--- | :--- | :--- | :--- |
| **S0** | `BENIGN_CONCORDANCE` | `P4` | `[0, 0, 0]` | All models agree traffic is normal. |
| **S1** | `LSTM_FORECAST_ONLY` | `P3` | `[0, 0, 1]` | Forecasted attack; current window appears normal. |
| **S2** | `XGB_ATTACK_ONLY` | `P2` | `[0, 1, 0]` | Known signature match; no temporal anomaly. |
| **S3** | `XGB_LSTM_CONSISTENCY` | `P1` | `[0, 1, 1]` | Active attack confirmed by temporal forecast. |
| **S4** | `AE_ANOMALY_ONLY` | `P3` | `[1, 0, 0]` | Novel structural anomaly; unclassified by XGBoost. |
| **S5** | `AE_LSTM_CONSISTENCY` | `P2` | `[1, 0, 1]` | Anomaly aligned with temporal forecast. |
| **S6** | `AE_XGB_CONSENSUS` | `P1` | `[1, 1, 0]` | Simultaneous anomaly and attack classification. |
| **S7** | `TRI_MODEL_CONSENSUS` | `P1` | `[1, 1, 1]` | Full tri-model consensus; highest severity. |

Prohibited: `S8`, `UNKNOWN`, and `LSTM_UNAVAILABLE` are strictly forbidden as threat states.

---

## 14. Response Schema Nullability & Execution Metadata Authority

### 14.1 Execution Metadata Runtime Authority & Requiredness
Direct inspection of `src/application/orchestrator.py` (lines 172–177) and `src/api/handlers.py` proves:
- The inference engine **unconditionally populates `execution_metadata` on every inference response**:
  ```python
  execution_metadata=ExecutionMetadataRecord(
      inference_latency_ms=latency_ms,
      schema_version="1.0.0",
      engine="NexThreat-Phase5.2",
  )
  ```
- Transport verification in `verify_phase_6_3.py` explicitly asserts presence of this object on all HTTP responses:
  `assert "execution_metadata" in body, "Missing execution_metadata in response"`
- In the underlying Python dataclass (`src/api/schemas.py`), `execution_metadata: Optional[ExecutionMetadataResponse] = None` is defined with a default for constructor flexibility. However, in the accepted **runtime API wire contract**, `execution_metadata` is **unconditionally present as a required object** across all valid inference responses.
- To maintain complete consistency:
  1. Response contract documentation specifies `execution_metadata` as a required object in all API responses.
  2. The OpenAPI schema defines `execution_metadata` as a required property of `StandardInferenceResponse`.
  3. Integration examples include `execution_metadata` in every response example (cold-start and eligible).

### 14.2 Exact Field-by-Field Nullability Matrix
- `window_id`: `string`, regex `^[0-9]{8}_[0-9]{4}$`, mandatory.
- `timestamp`: `string`, ISO 8601 format, mandatory.
- `global_position`: `integer` $\ge 1$ or `null`, optional in response dictionary.
- `dataset_day`: `string` enum (`Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday`, `Unknown`) or `null`, optional.
- `autoencoder`: object, mandatory.
  - `reconstruction_mse`: `number` $\ge 0.0$, mandatory.
  - `threshold`: `number`, constant `0.003207791231673312`, mandatory.
  - `is_anomaly`: `integer` in `{0, 1}`, mandatory.
- `xgboost`: object, mandatory.
  - `predicted_class_index`: `integer` in `0..7`, mandatory.
  - `predicted_class_name`: `string`, mandatory.
  - `is_attack`: `integer` in `{0, 1}`, mandatory.
  - `class_probabilities`: array of 8 `number` items in `[0.0, 1.0]` or `null`, optional.
- `lstm`: object, mandatory.
  - `is_eligible`: `boolean`, mandatory.
  - `ineligibility_reason`: `string` or `null` (strictly `null` when `is_eligible == true`; non-empty `string` when `is_eligible == false`).
  - `forecast_probability`: `number` in `[0.0, 1.0]` or `null` (strictly finite `number` when `is_eligible == true`; `null` when `is_eligible == false`).
  - `threshold`: `number`, constant `0.3`, mandatory.
  - `forecast_decision`: mixed type via `oneOf`: `{"type": "integer", "enum": [0, 1]}` or `{"type": "string", "enum": ["unavailable"]}` (strictly integer when `is_eligible == true`; strictly `"unavailable"` when `is_eligible == false`).
- `threat_inference`: object, mandatory.
  - `is_eligible`: `boolean`, mandatory (must match `lstm.is_eligible`).
  - `threat_state_code`: `string` enum (`S0`..`S7`) or `null` (strictly enum when `is_eligible == true`; strictly `null` when `is_eligible == false`).
  - `threat_state_name`: `string` or `null` (strictly non-empty string when `is_eligible == true`; strictly `null` when `is_eligible == false`).
  - `priority_tier`: `string` enum (`P1`..`P4`) or `null` (strictly enum when `is_eligible == true`; strictly `null` when `is_eligible == false`).
  - `decision_tuple`: array of 3 `integer` items in `{0, 1}` or `null` (strictly 3 binary ints when `is_eligible == true`; strictly `null` when `is_eligible == false`).
- `execution_metadata`: object, required in runtime API responses.
  - `inference_latency_ms`: `number` $\ge 0.0$, mandatory.
  - `schema_version`: `string`, constant `"1.0.0"`.
  - `engine`: `string`, constant `"NexThreat-Phase5.2"`.

---

## 15. Operational Runbook Specifications (`docs/api/operational_runbook.md`)

The operational runbook must document reality verified against `src/api/server.py` and `src/api/handlers.py`:
1. **Server Instantiation**: `NexThreatAPIServer(host="127.0.0.1", port=8000, engine=engine)`.
2. **Port Binding Semantics**: Static port binding vs. dynamic ephemeral allocation via `port=0`, accessing actual bound port via `server.actual_port`.
3. **Health Monitoring (`GET /health`)**: Explains underlying execution of `verify_authoritative_33_files_integrity()`, returning 200 OK when all 33 files match SHA-256 and engine is initialized, or 503 when integrity verification fails.
4. **Telemetry Inspection (`GET /status`)**: Telemetry fields (`processed_windows`, `lookback_depth`, `engine_version`).
5. **Shutdown Procedure & Operational Expectations**: Documents `server.stop()`, which calls `shutdown()`, `server_close()`, and joins the background server thread with a 2-second timeout. Clarified as an operational procedure/expectation rather than a guaranteed SLA.
6. **Thread Safety & Mutual Exclusion**: Details `engine_lock` serialized access around `ApplicationInferenceEngine`.
7. **Line-Ending Operational Requirement**: Documents that Git `core.autocrlf` must not mutate LF line endings on Windows checkouts in `data/model_reports/` to preserve byte-exact SHA-256 integrity.

---

## 16. Canonical Integration Examples Catalogue (`docs/api/integration_examples.json`)

All examples must be executable and strictly valid against `validate_single_window_request`, `validate_stream_batch_request`, `validate_application_response`, and `format_api_error_response`:
1. `format_a_request`: 13-element canonical float array.
2. `format_b_request`: 13 named canonical keys.
3. `stream_batch_request`: Container with 2 sequential valid windows.
4. `cold_start_response`: Window 1 response with `threat_inference` object containing null threat fields:
   ```json
   {
     "window_id": "20170705_0900",
     "timestamp": "2017-07-05T09:00:00",
     "global_position": 1,
     "dataset_day": "Wednesday",
     "autoencoder": {
       "reconstruction_mse": 0.0011245,
       "threshold": 0.003207791231673312,
       "is_anomaly": 0
     },
     "xgboost": {
       "predicted_class_index": 0,
       "predicted_class_name": "BENIGN",
       "is_attack": 0,
       "class_probabilities": [
         0.98510, 0.00210, 0.00140, 0.00420, 0.00110, 0.00310, 0.00120, 0.00180
       ]
     },
     "lstm": {
       "is_eligible": false,
       "ineligibility_reason": "lstm_lookback_cold_start",
       "forecast_probability": null,
       "threshold": 0.3,
       "forecast_decision": "unavailable"
     },
     "threat_inference": {
       "is_eligible": false,
       "threat_state_code": null,
       "threat_state_name": null,
       "priority_tier": null,
       "decision_tuple": null
     },
     "execution_metadata": {
       "inference_latency_ms": 2.180,
       "schema_version": "1.0.0",
       "engine": "NexThreat-Phase5.2"
     }
   }
   ```
5. `lstm_eligible_response`: Window 11+ response with `lstm.is_eligible = true`, `threat_state_code = "S7"`, `decision_tuple = [1, 1, 1]`, and `execution_metadata`.
6. `error_responses`: Verified catalogue of envelopes for `INPUT_VALIDATION_ERROR`, `STREAM_TOO_LARGE`, `BAD_REQUEST`, `INVALID_JSON`, `NOT_FOUND` (including unknown route and reset attempt), `METHOD_NOT_ALLOWED`, `LENGTH_REQUIRED`, `PAYLOAD_TOO_LARGE`, `UNSUPPORTED_MEDIA_TYPE`, `INTERNAL_ERROR`, `MODEL_EXECUTION_ERROR`, and `/health` unhealthy status (HTTP 503).

---

## 17. Deterministic Verification Gates (D1–D16)

The verification harness (`src/api/verification/verify_phase_6_4.py`) will execute 16 automated verification gates:

| Gate ID | Gate Name | Target Artifact | Verification Assertion & Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| **D1** | Authoritative Baseline Compliance & Active Alias Audit | Upstream State | Asserts that Phase 4 (33 files), Phase 5 (22 gates), Phase 6.2 (16 gates), and Phase 6.3 (20 gates) remain intact. Performs scan across active implementation and documentation surfaces (`src/`, `docs/api/`, active Phase 6.x specifications, integration examples, OpenAPI schema, verification logic) asserting zero active use or definition of obsolete aliases (`validate_window_request`, `validate_stream_request`, `WindowInferenceRequest`). |
| **D2** | OpenAPI 3.1.0 Syntax & Structural Verification | `docs/api/openapi.json` | Verifies JSON validity, `openapi: 3.1.0`, presence of `info`, `paths`, and `components.schemas` via stdlib structural validation. (Full formal OpenAPI 3.1 meta-schema validation is an external/manual audit activity). |
| **D3** | Endpoint Route & Method Completeness | `docs/api/openapi.json` | Asserts exactly `/health` (GET), `/status` (GET), `/api/v1/infer/window` (POST), and `/api/v1/infer/stream` (POST) exist. Asserts absence of `/api/v1/reset`. |
| **D4** | Format A Schema & Example Validity | OpenAPI & Examples | Validates Format A schema against `SingleWindowCanonicalRequest` dataclass with 13 canonical features (`flow_count` through `syn_packet_ratio`) and verifies example validity via `validate_single_window_request()`. |
| **D5** | Format B Schema & Example Validity | OpenAPI & Examples | Validates Format B schema against `SingleWindowNamedRequest` dataclass with 13 canonical keys (`flow_count` through `syn_packet_ratio`) and verifies example validity via `validate_single_window_request()`. |
| **D6** | Stream Schema & Boundary Specification | OpenAPI & Examples | Validates `StreamBatchRequest` schema, 5,000 ceiling, and container example via `validate_stream_batch_request()`. |
| **D7** | 24-Field Response Schema Conformance | OpenAPI & Schemas | Field-by-field verification comparing OpenAPI response schema against `StandardInferenceResponse` (exact 24 fields in 5 nested blocks + root: root [`window_id`, `timestamp`, `global_position`, `dataset_day`], autoencoder [`reconstruction_mse`, `threshold`, `is_anomaly`], xgboost [`predicted_class_index`, `predicted_class_name`, `is_attack`, `class_probabilities`], lstm [`is_eligible`, `ineligibility_reason`, `forecast_probability`, `threshold`, `forecast_decision`], threat_inference [`is_eligible`, `threat_state_code`, `threat_state_name`, `priority_tier`, `decision_tuple`], execution_metadata [`inference_latency_ms`, `schema_version`, `engine`]). Prohibits obsolete fields (`sequence_len`, `reconstruction_error`, `anomaly_score`, `attack_probability`, `predicted_class`, `latency_ms`). |
| **D8** | Implementation-Grounded Temporal Continuity Verification | Runtime Engine & Docs | Programmatically tests `TemporalHistoryBuffer` and orchestrator across exactly the 8 continuity verification cases matching Section 11.2.2: (1) Valid 60-second continuity, (2) Sub-60-second delta, (3) Super-60-second delta, (4) Non-monotonic timestamp, (5) Duplicate/same timestamp, (6) Same-day continuity, (7) Dataset-day boundary / cross-day continuity, and (8) 10-window cold-start progression. Confirms documentation accurately describes runtime behavior. |
| **D9** | Standardized Error Envelope Conformance | OpenAPI & Exceptions | Verifies error schema against `format_api_error_response()` signature and confirms exact runtime error code taxonomy. |
| **D10** | Security & Error Sanitization Specifications | Docs & Guide | Asserts presence of path, file, and address redaction specifications matching `sanitize_error_message()`. |
| **D11** | Payload & Stream Ceiling Specifications | Docs & OpenAPI | Verifies exact specification of 10 MB payload ceiling (HTTP 413) and 5,000 record stream ceiling (HTTP 400). |
| **D12** | Reset Endpoint Prohibition Documentation | OpenAPI & Docs | Asserts `/api/v1/reset` is NOT in OpenAPI paths and is documented as HTTP 404 with error code `NOT_FOUND` and security justification. |
| **D13** | Operational Runbook & Telemetry Specifications | `docs/api/operational_runbook.md` | Verifies coverage of server instantiation, port binding, `/health` 33-file check, `/status` telemetry, and graceful shutdown procedure. |
| **D14** | Phase 6.3 Baseline Immutability & Scope Audit | Codebase State | Audits all frozen files against accepted Phase 6.3 baseline evidence. Verifier does NOT assume commit `af958542828d6aa1564083c13ff109ab8a01d441` is authoritative merely because it exists; establishes sequentially: (1) commit exists, (2) commit corresponds to accepted Phase 6.3 boundary, (3) accepted tree is represented by commit; if unconfirmed, D14 MUST FAIL. Detects modified, deleted, renamed, or unexpected files across runtime/model/data boundaries. Enforces narrow planning-document exception for pre-existing plan revision (`phase_6_4_api_documentation_and_contract_specification_plan.md`); allows strictly the 7 authorized Phase 6.4 deliverables; fails on any unrelated changes. |
| **D15** | Canonical 13-Feature Ordering Integrity | OpenAPI & Docs | Verifies exact sequence of 13 features matching `CANONICAL_FEATURE_KEYS`: 1. `flow_count`, 2. `packet_rate`, 3. `byte_rate`, 4. `mean_flow_duration`, 5. `std_flow_duration`, 6. `short_flow_ratio`, 7. `mean_packet_size`, 8. `packet_length_variability`, 9. `fwd_bwd_packet_ratio`, 10. `unique_dst_ports`, 11. `unique_dst_ips`, 12. `tcp_flow_ratio`, 13. `syn_packet_ratio`. Strictly prohibits obsolete feature keys (`src_bytes`, `dst_bytes`, `count`, `srv_count`, `same_srv_rate`, `diff_srv_rate`, `logged_in`, etc.). |
| **D16** | Threat-State & Model Inventory Audit | OpenAPI & Docs | Asserts exact 3-model inventory: Autoencoder (reconstruction MSE threshold `0.003207791231673312`), XGBoost (8-class multiclass argmax classifier with attack condition `predicted_class_index != 0` and zero probability threshold), and LSTM (forecast probability threshold `0.3000`). Asserts exact canonical S0–S7 threat states (`S0: BENIGN_CONCORDANCE`, `S1: LSTM_FORECAST_ONLY`, `S2: XGB_ATTACK_ONLY`, `S3: XGB_LSTM_CONSISTENCY`, `S4: AE_ANOMALY_ONLY`, `S5: AE_LSTM_CONSISTENCY`, `S6: AE_XGB_CONSENSUS`, `S7: TRI_MODEL_CONSENSUS`). Strictly prohibits S8, UNKNOWN, LSTM_UNAVAILABLE as state, binary XGBoost descriptions, or score fusion. |

### 17.1 Gate D14 Authoritative Frozen-Baseline Integrity Verification Mechanism

#### 17.1.1 Authoritative Phase 6.3 Baseline Sources & Evidence Chain
To prevent circularity or drift, Phase 6.4 does not establish a new baseline or invent manifests. Instead, Gate D14 links strictly to the existing authoritative verification and version control evidence in the repository:

1. **Authoritative Phase 6.3 Verification Report**:
   - Path: `data/model_reports/application/phase_6_3_verification_report.json`
   - Authority: Accepted by Phase 6.3 governance (`"status": "ACCEPTED"`, `"verdict": "PASS"`, 20/20 gates).
   - Authoritative Scope & File Manifest:
     - `created`: `["src/api/handlers.py", "src/api/server.py", "src/api/verification/verify_phase_6_3.py", "data/model_reports/application/phase_6_3_api_endpoint_integration_and_transport_handlers_implementation_plan.md"]`
     - `modified`: `["src/api/__init__.py"]`
     - `untouched_frozen_baselines`: `["src/application/* (Phase 5)", "src/models/* (Phase 4)", "src/api/schemas.py (Phase 6.2)", "src/api/validators.py (Phase 6.2)", "src/api/exceptions.py (Phase 6.2)", "data/models/* (Phase 4)"]`
2. **Authoritative Phase 6.3 Git Commit Boundary & Sequential Authority Verification Procedure**:
   - Candidate Commit Reference: `af958542828d6aa1564083c13ff109ab8a01d441` (`af95854 Phase 6.3 completed`).
   - **Baseline Authority Verification Requirement**: The verifier must NOT assume that commit `af958542828d6aa1564083c13ff109ab8a01d441` is the authoritative Phase 6.3 baseline merely because the commit exists. The verification procedure in `verify_phase_6_4.py` must programmatically establish, in strict sequential order:
     1. **Commit Existence**: Verify that the commit object exists in repository history (`git cat-file -t af958542828d6aa1564083c13ff109ab8a01d441` returns `commit`).
     2. **Boundary Correspondence**: Verify that the commit message, author, and tree structure correspond strictly to the accepted Phase 6.3 repository boundary (`"Phase 6.3 completed"`).
     3. **Accepted Tree Representation**: Cross-reference git commit tree with `phase_6_3_verification_report.json` and `phase_6_3_verification_report.md` to establish that the tree represents the accepted Phase 6.3 deliverable boundary.
     4. **Baseline Authorization**: Only after steps 1, 2, and 3 pass unconditionally may the commit be utilized as the D14 comparison baseline.
     - **Failure Invariant**: If the verifier cannot establish that the commit is the accepted Phase 6.3 repository boundary, **Gate D14 MUST FAIL**. Do not treat commit existence alone as proof of baseline authority. Do not invent baseline hashes, baseline commits, baseline paths, acceptance state, or repository facts.
3. **Authoritative Phase 4.7 Cryptographic Hash Manifest**:
   - Path: `data/model_reports/acceptance/phase_4_7_acceptance_report.json`
   - Authority: Contains the authoritative SHA-256 hashes for all 33 frozen Phase 4 artifacts.

- **Baseline Governance Principle**: Phase 6.4 does NOT create a new baseline, invent new commits, or invent new hashes. It verifies and compares strictly against the confirmed, accepted Phase 6.3 baseline evidence.

#### 17.1.2 Concrete Immutability Verification Mechanism
Gate D14 in `src/api/verification/verify_phase_6_4.py` enforces the immutability of the accepted Phase 6.3 baseline across six explicit assertions:

- **Assertion A (Expected Frozen Paths Exist)**:
  - Verifies that every file in the Phase 6.3 baseline manifest (`src/api/handlers.py`, `src/api/server.py`, `src/api/__init__.py`, `src/api/schemas.py`, `src/api/validators.py`, `src/api/exceptions.py`, `src/api/verification/verify_phase_6_3.py`, all `src/application/*` files, all `src/models/*` files, all `data/models/*` assets) exists on disk (`Path.exists()`).
- **Assertion B (Byte-Level Content & Hash Identity)**:
  - For Phase 4 artifacts: Computes SHA-256 checksums of all 33 files on disk and asserts byte-exact identity with `phase_4_7_acceptance_report.json`.
  - For Phase 5, Phase 6.2, and Phase 6.3 runtime code: Checks against the verified Phase 6.3 git tree (`af95854`) via `git diff-index --quiet af95854 -- <path>` or git object blob comparison, verifying 0 bytes changed.
- **Assertion C (No Frozen Files Deleted)**:
  - Inspects `git status --porcelain` and `git diff --name-status af95854` to assert that zero files in the repository have deletion status (`D`).
- **Assertion D (No Frozen Files Renamed or Relocated)**:
  - Inspects `git status --porcelain` and `git diff --name-status af95854` to assert that zero files have rename status (`R`).
- **Assertion E (No Unexpected Runtime/API/Model Source Files Created or Modified)**:
  - Scans protected boundaries (`src/application/`, `src/models/`, `data/models/`, `src/api/`).
  - Asserts that within `src/application/`, `src/models/`, and `data/models/`, exactly zero modified or newly created files exist.
  - Asserts that within `src/api/`, the only newly created file relative to Phase 6.3 is strictly `src/api/verification/verify_phase_6_4.py`.
- **Assertion F (Changes Strictly Confined to Authorized Scope)**:
  - Asserts that across the entire repository working tree, any modifications or additions relative to the Phase 6.3 baseline commit (`af95854`) are strictly confined to the seven authorized Phase 6.4 deliverables plus the narrow planning-document exception defined in Section 17.1.3:
    1. `docs/api/openapi.json`
    2. `docs/api/api_integration_guide.md`
    3. `docs/api/operational_runbook.md`
    4. `docs/api/integration_examples.json`
    5. `src/api/verification/verify_phase_6_4.py`
    6. `data/model_reports/application/phase_6_4_verification_report.md`
    7. `data/model_reports/application/phase_6_4_verification_report.json`

#### 17.1.3 Narrow Planning-Document Exception Policy
To ensure that repository comparison rules in Gate D14 do not incorrectly fail when the Phase 6.4 planning document itself is revised, the following narrow and explicit exception is enforced:

1. **Pre-Existing Governance Artifact Recognition**:
   - The file `data/model_reports/application/phase_6_4_api_documentation_and_contract_specification_plan.md` is a **pre-existing governance/planning artifact** created during the planning stage.
   - It is NOT one of the seven Phase 6.4 implementation/verification deliverables.
   - Its revision (e.g. from Version 1.4.0 → Version 1.5.0) is permitted strictly as a planning-document update and does NOT constitute an unauthorized repository addition or deliverable breach.
2. **Strict Prohibition Against Broad Documentation Exemptions**:
   - Gate D14 must **NOT** broadly exempt arbitrary documentation files or paths.
   - The verifier must continue enforcing that all repository changes, other than the explicitly recognized Phase 6.4 planning document and the seven authorized Phase 6.4 deliverables, are unauthorized.
   - Any unrelated modifications to runtime code (`src/`), model assets (`data/models/`), application data (`data/`), or arbitrary documentation outside the explicit seven deliverables will trigger an immediate **Gate D14 FAILURE**.

#### 17.1.4 Explicit Limitation Marked for Final Audit Resolution
- **Limitation**: While `data/model_reports/application/phase_6_3_verification_report.json` provides the accepted file manifest and acceptance gate statuses, it does not embed a standalone JSON dictionary of pre-computed SHA-256 cryptographic hashes for the Phase 6.3 runtime files (`src/api/handlers.py`, `src/api/server.py`, `src/api/__init__.py`).
- **Resolution Strategy**: Standalone byte-level comparison (Assertion B) relies on comparing the working tree against the authoritative Phase 6.3 git commit `af95854` after confirming baseline correspondence. If the auditor requires standalone stdlib SHA-256 hashing for Phase 6.3 runtime files independent of git commands, an authoritative Phase 6.3 hash manifest must be officially approved and integrated as part of the final audit sign-off. Phase 6.4 does not invent an unapproved hash manifest.

---

## 18. Multi-Phase Regression & Verification Execution Rules

### 18.1 Multi-Phase Regression Suite
Execution of `verify_phase_6_4.py` executes full upstream regression:
1. **Phase 4 Regression**: Byte-exact SHA-256 hash check of all 33 frozen artifacts against `phase_4_7_acceptance_report.json`.
2. **Phase 5 Regression**: Execution of `Phase5_7_Verifier.run_all_checks()` asserting 22/22 PASS.
3. **Phase 6.2 Regression**: Execution of `Phase6_2_Verifier.run_all_gates()` asserting 16/16 PASS.
4. **Phase 6.3 Regression**: Execution of `Phase6_3_Verifier.run_all_gates()` asserting 20/20 PASS.

### 18.2 Cryptographic Hash Comparison vs. Text Comparison
- **Authoritative SHA-256 verification is byte-exact.** No CRLF/LF normalization, whitespace normalization, encoding conversion, or content transformation is permitted before hashing frozen artifacts.
- Documentation semantic checks may normalize platform newline conventions (`CRLF` vs `LF`) for text comparison where appropriate, but such normalization must never be used for authoritative cryptographic hash comparison.

### 18.3 Deterministic Verification & Runtime Metadata
- Verification logic, gate results, field ordering, schemas, and machine-readable result structure must be deterministic across supported execution environments.
- Dynamic runtime values such as execution timestamps, measured inference latency, environment-dependent absolute paths, and test duration are classified as runtime metadata rather than deterministic verification content, and must not be required to be byte-identical across separate runs.

### 18.4 Standard-Library Scope & OpenAPI Validation Methodology
- `verify_phase_6_4.py` itself must use only Python standard-library modules (`json`, `hashlib`, `re`, `pathlib`, `ast`, `http.client`, `unittest`, `time`, `typing`).
- When invoking already-authorized upstream verification suites (Phases 4, 5, 6.2, 6.3), the verifier may execute those existing suites under their already-established dependency requirements (e.g. numpy, scikit-learn, etc.).
- **OpenAPI Validation Methodology**: `verify_phase_6_4.py` performs deterministic structural/semantic checks using the standard library. It verifies required OpenAPI fields, paths, methods, schemas, references, response structures, and project-specific contract requirements. Full standards-compliant OpenAPI 3.1 validation, if required, is an **external/manual audit activity** unless an already-approved validator is present in the existing environment. Phase 6.4 must not introduce a new third-party dependency solely for OpenAPI validation.

---

## 19. Implementation Constraints & Acceptance Criteria

### 19.1 Implementation Constraints
1. **Zero Runtime Modifications**: Zero edits to pre-existing runtime files.
2. **Authoritative Naming Fidelity**: Only verified symbol names used.
3. **OpenAPI 3.1.0 Structural Validity**: Validates against structural rules without new third-party dependencies.
4. **Executable Examples**: Every example in `integration_examples.json` must pass Phase 6.2/6.3 validator execution.

### 19.2 Phase 6.4 Acceptance Sign-Off Criteria

Phase 6.4 governance strictly preserves the sequential delivery lifecycle:
```text
PLAN → AUDIT → APPROVAL → IMPLEMENTATION → VERIFICATION → ACCEPTANCE
```

Phase 6.4 shall be deemed complete and formally accepted when all of the following criteria are satisfied:

1. **Strict Seven-Artifact Authorization Boundary & Lifecycle Sequencing**:
   - **Plan Approval Timing**: Plan approval creates zero Phase 6.4 implementation or verification artifacts. The existing planning document (`data/model_reports/application/phase_6_4_api_documentation_and_contract_specification_plan.md`) is authorized strictly as the planning document and is formally distinguished from the seven implementation/verification deliverables so that it is not treated as an unauthorized artifact.
   - **Implementation Phase**: Creation of the implementation and verification artifacts occurs strictly after formal implementation authorization is granted.
   - **Verification Phase**: The two verification reports (`phase_6_4_verification_report.md` and `phase_6_4_verification_report.json`) are generated directly as outputs of the verification process.
   - **Completion State**: At implementation and verification completion, exactly the seven authorized Phase 6.4 deliverables exist and have been verified:
     1. `docs/api/openapi.json`
     2. `docs/api/api_integration_guide.md`
     3. `docs/api/operational_runbook.md`
     4. `docs/api/integration_examples.json`
     5. `src/api/verification/verify_phase_6_4.py`
     6. `data/model_reports/application/phase_6_4_verification_report.md`
     7. `data/model_reports/application/phase_6_4_verification_report.json`
   - **Negative Assurances**:
     - Zero unauthorized Phase 6.4 artifacts exist across the repository.
     - Zero frozen upstream artifacts (across Phase 4, Phase 5, Phase 6.2, and Phase 6.3) have been modified, deleted, or relocated.
2. **All 16 Deterministic Verification Gates Pass**:
   - `verify_phase_6_4.py` executes and passes all 16 verification gates (**D1–D16**) with 100% compliance (0 failures).
3. **Multi-Phase Upstream Regression Intact**:
   - Upstream regression suite confirms 0 regressions across all prior frozen baselines:
     - Phase 4.7 ML Baseline: 33 / 33 SHA-256 byte-exact match (0 mutations).
     - Phase 5 Application Integration: 22 / 22 functional gates PASS.
     - Phase 6.2 API Schemas & Validation: 16 / 16 schema/AST gates PASS.
     - Phase 6.3 API Transport Handlers: 20 / 20 transport gates PASS.
4. **Authoritative Verification Reporting & Sign-Off**:
   - `data/model_reports/application/phase_6_4_verification_report.md` and `.json` are generated with full gate outcomes, checksums, and formal sign-off.

---

## 20. Formal Governance Status Declaration

```text
================================================================================
FINAL GOVERNANCE DECLARATION:

PHASE 6.4 PLAN STATUS:
READY FOR FINAL AUDIT

IMPLEMENTATION AUTHORIZATION:
NOT GRANTED

RUNTIME MODIFICATION AUTHORIZATION:
NOT GRANTED

PHASE 4.7 IMMUTABILITY:
PRESERVED

PHASE 5 CONTRACT:
PRESERVED

PHASE 6.2 CONTRACT:
PRESERVED

PHASE 6.3 CONTRACT:
PRESERVED

NEXT ACTION:
FINAL AUDIT ONLY
================================================================================
```
