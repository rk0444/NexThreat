# NexThreat Operational Runbook & SRE Manual

```text
================================================================================
NEXTHREAT SECURE NETWORK TELEMETRY THREAT-DETECTION PLATFORM
SITE RELIABILITY ENGINEERING (SRE) RUNBOOK & LIFECYCLE SPECIFICATION
DOCUMENT VERSION : 1.0.0
GOVERNANCE       : PHASE 6.4 OPERATIONAL SPECIFICATION
================================================================================
```

---

## 1. Architectural Overview & Concurrency Model

The **NexThreat API Server** (`src/api/server.py`) hosts the multi-model threat-detection engine, bridging enterprise HTTP clients to the underlying machine learning inference pipeline.

### 1.1 Concurrency & Execution Architecture
- **Transport Layer**: Built upon Python's standard library `ThreadingHTTPServer` (`socketserver.ThreadingMixIn` + `http.server.HTTPServer`). Each incoming connection is serviced by an independent worker thread.
- **Inference Pipeline**: Backed by `ApplicationInferenceEngine` (`src/application/orchestrator.py`).
- **Thread Safety & State Synchronization**: Shared temporal sequence buffer state (`TemporalHistoryBuffer`) is protected by a dedicated reentrant threading lock (`threading.Lock`). Single-window and stream batch evaluations acquire this lock during state updates, ensuring strict chronological determinism and race-free operation.
- **Stateless Read Handlers**: `/health` and `/status` read operations execute without blocking active inference computations.

---

## 2. Server Instantiation & Configuration

### 2.1 Configuration Parameters

The server accepts operational parameters via command-line arguments and environment variables:

| Parameter | Environment Variable | Default Value | Description |
| :--- | :--- | :--- | :--- |
| **Host** | `NEXTHREAT_HOST` | `127.0.0.1` | Network interface IP address to bind |
| **Port** | `NEXTHREAT_PORT` | `8000` | TCP port to listen for incoming connections |
| **Workers** | `NEXTHREAT_WORKERS` | `4` | Concurrency thread pool ceiling |
| **Log Level** | `NEXTHREAT_LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

### 2.2 Starting the Service
Start the server using Python module execution:

```bash
# Standard local startup
python -m src.api.server --host 127.0.0.1 --port 8000

# Production container startup
NEXTHREAT_HOST=0.0.0.0 NEXTHREAT_PORT=8000 python -m src.api.server
```

### 2.3 Startup Verification Sequence
Upon initialization, the server executes the following sequence:
1. Instantiates `ApplicationInferenceEngine`.
2. Validates the existence and loads all three ML models (Autoencoder, XGBoost, LSTM).
3. Evaluates SHA-256 cryptographic checksums of all 33 frozen baseline artifacts against `data/model_reports/acceptance/phase_4_7_acceptance_report.json`.
4. Binds the listening TCP socket and starts accepting incoming client requests.

---

## 3. Health Monitoring & Cryptographic Auditing (`/health`)

The `/health` endpoint evaluates the internal operational readiness and cryptographic integrity of the platform.

### 3.1 Endpoint Specification
- **Method**: `GET`
- **Route**: `/health`
- **Response Headers**: `Content-Type: application/json`

### 3.2 Response Schema & Evaluation Criteria
```json
{
  "status": "HEALTHY",
  "pipeline_initialized": true,
  "integrity_verified": true,
  "model_inventory_count": 3,
  "active_threads": 1,
  "timestamp": "2026-09-15T00:00:00.123456+00:00"
}
```

| Field | Expected Healthy Value | Failure Indicator |
| :--- | :--- | :--- |
| `status` | `"HEALTHY"` | `"DEGRADED"` or `"UNHEALTHY"` (HTTP 503) |
| `pipeline_initialized` | `true` | `false` indicates inference models failed to load |
| `integrity_verified` | `true` | `false` indicates one or more baseline files failed SHA-256 validation |
| `model_inventory_count`| `3` | Any value $< 3$ indicates missing model dependencies |

### 3.3 SRE Monitoring Recommendations
- **Scrape Interval**: 10 seconds.
- **Probe Timeout**: 2 seconds.
- **Unhealthy Action**: If `/health` returns HTTP 503 or fails 3 consecutive probes, route traffic away and alert SRE on-call.

---

## 4. Runtime Telemetry & Operational Metrics (`/status`)

The `/status` endpoint exposes real-time runtime telemetry without exposing internal memory addresses or sensitive directory paths.

### 4.1 Endpoint Specification
- **Method**: `GET`
- **Route**: `/status`

### 4.2 Telemetry Schema
```json
{
  "uptime_seconds": 3600.5,
  "total_requests_served": 15420,
  "total_windows_inferred": 42100,
  "total_errors": 12,
  "active_sessions": 1,
  "engine_state": "IDLE",
  "model_latency_percentiles_ms": {
    "p50": 2.15,
    "p95": 3.82,
    "p99": 5.40
  },
  "memory_rss_bytes": 1150423040,
  "timestamp": "2026-09-15T01:00:00.654321+00:00"
}
```

### 4.3 Key Performance Indicators (KPIs)
- **Inference Latency ($p95$)**: Baseline $< 15\,\text{ms}$ per window. Latencies $> 50\,\text{ms}$ warrant investigation of host CPU throttling.
- **Error Rate**: Ratio of `total_errors / total_requests_served` should be $< 0.1\%$ under normal operation.
- **Memory RSS**: Expected footprint is $1.1\,\text{GB} \pm 200\,\text{MB}$. Sustained growth indicates memory leak.

---

## 5. Lifecycle Management & Graceful Shutdown

### 5.1 Shutdown Signals
The server traps `SIGINT` (Ctrl+C) and `SIGTERM` (container orchestrator termination).

### 5.2 Graceful Shutdown Procedure
When a termination signal is received:
1. Server transitions internal state to `SHUTDOWN_IN_PROGRESS`.
2. Listening TCP socket ceases accepting new connection attempts.
3. In-flight HTTP inference requests are allowed to finish execution (timeout ceiling: 15 seconds).
4. Temporal history buffers are flushed safely.
5. Socket handles and thread pools are released. Process exits with code `0`.

---

## 6. Resource Sizing & Capacity Limits

| Resource Dimension | Recommended Allocation | Hard Boundary / Ceiling |
| :--- | :--- | :--- |
| **CPU Allocation** | 2 dedicated vCPUs | Multi-core scaling for concurrent requests |
| **RAM Allocation** | 2.0 GB minimum | 1.2 GB steady-state resident memory |
| **Max Request Payload** | — | **10 MB** (`10,485,760` bytes) (HTTP 413) |
| **Max Stream Size** | — | **5,000 windows** per stream batch (HTTP 400) |
| **Network Cadence** | 1 window / 60 seconds | Windows must advance monotonically |

---

## 7. Incident Response & Troubleshooting Matrix

### 7.1 Scenario: Health Check Failure (HTTP 503)
- **Symptom**: `/health` returns HTTP 503 with `"status": "DEGRADED"` or `"integrity_verified": false`.
- **Root Cause**: One or more of the 33 frozen model or configuration artifacts in `data/models/` or `src/models/` has been altered, corrupted, or replaced.
- **Resolution**:
  1. Inspect server startup logs for checksum mismatch details.
  2. Execute `python -m src.api.verification.verify_phase_6_3` or run Phase 4 regression to isolate the mutated file.
  3. Restore corrupted artifacts from the immutable git baseline commit (`af95854`).

### 7.2 Scenario: Ingestion Error 413 `PAYLOAD_TOO_LARGE`
- **Symptom**: Client telemetry pipeline receives HTTP 413.
- **Root Cause**: Ingested payload exceeds the 10 MB boundary.
- **Resolution**: Verify telemetry batch chunking. If sending stream batches, ensure window count is $\le 5,000$ and individual JSON payloads do not exceed 10 MB.

### 7.3 Scenario: Ingestion Error 400 `INPUT_VALIDATION_ERROR` (Chronological Discontinuity)
- **Symptom**: Client receives HTTP 400 with `"Chronological ordering violation... Non-advancing time is rejected."`
- **Root Cause**: The client telemetry pipeline submitted a timestamp earlier than or equal to the previous window ($t_n \le t_{n-1}$).
- **Resolution**: Verify clock synchronization on the telemetry emitter (NTP sync). Ensure stream batches are sorted in strictly ascending chronological order before submission.

### 7.4 Scenario: Client Attempts to Call `/api/v1/reset`
- **Symptom**: Client receives HTTP 404 with `"Endpoint '/api/v1/reset' does not exist. Public client resets are prohibited."`
- **Root Cause**: Client attempted to invoke legacy state reset endpoint.
- **Resolution**: Inform client that public resets are prohibited for enterprise security. Temporal buffers reset automatically on calendar day transitions or cadence violations.
