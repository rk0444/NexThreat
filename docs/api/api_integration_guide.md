# NexThreat Enterprise API Integration Guide

```text
================================================================================
NEXTHREAT SECURE NETWORK TELEMETRY THREAT-DETECTION PLATFORM
API INTEGRATION GUIDE & DEVELOPER SPECIFICATION
DOCUMENT VERSION : 1.0.0
COMPLIANCE       : OPENAPI 3.1.0 / PHASE 6.4 CONTRACT
================================================================================
```

---

## 1. Executive Summary & Architecture

The **NexThreat Threat-Detection Platform** provides real-time, tri-model network telemetry anomaly detection, attack classification, and sequence forecasting. It exposes high-throughput, low-latency HTTP REST interfaces designed for direct integration with Security Operations Center (SOC) dashboards, Security Information and Event Management (SIEM) pipelines, and autonomous network monitoring systems.

### Multi-Model Core
Every 60-second telemetry window ingested by NexThreat is evaluated by three specialized machine learning models:
1. **Autoencoder (Unsupervised Reconstruction)**: Flags statistical divergence from benign network traffic baselines. Threshold: `0.003207791231673312`.
2. **XGBoost (Supervised Multiclass Classification)**: Evaluates raw unscaled telemetry against 8 distinct attack classes using multiclass argmax semantics. Attack condition: `predicted_class_index != 0`. Zero probability threshold.
3. **LSTM (Temporal Sequence Forecasting)**: Evaluates a 10-window rolling temporal history buffer ($\Delta t = 60\,\text{s}$) to forecast attack probability for the upcoming window. Threshold: `0.3000`.

The outcomes of all three models synthesize into a canonical **Threat State (S0 through S7)** mapped to an actionable **Priority Tier (P1 through P4)**.

---

## 2. Transport Protocol & Communication Parameters

| Parameter | Standard | Description |
| :--- | :--- | :--- |
| **Protocol** | HTTP/1.1 | Standard TCP HTTP transport |
| **Default Host / Port** | `127.0.0.1:8000` | Configurable via CLI args or environment variables |
| **Content-Type** | `application/json; charset=utf-8` | Strictly enforced for all POST requests (HTTP 415 on mismatch) |
| **Content-Length** | Required on all POSTs | Strictly enforced (HTTP 411 on omission) |
| **Max Payload Size** | 10 MB (`10,485,760` bytes) | Requests exceeding this size receive HTTP 413 `PAYLOAD_TOO_LARGE` |
| **Max Stream Records**| 5,000 windows | Stream batches exceeding 5,000 items receive HTTP 400 `STREAM_TOO_LARGE` |

---

## 3. Authoritative Endpoints Catalog

| Method | Route | Description | Expected Status |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Evaluates system health, pipeline initialization, and 33-file SHA-256 integrity | `200 OK` / `503 Service Unavailable` |
| `GET` | `/status` | Emits runtime operational telemetry, latencies, memory footprint, and metrics | `200 OK` |
| `POST` | `/api/v1/infer/window` | Single-window network telemetry inference (Format A or Format B) | `200 OK` / `4xx` / `500` |
| `POST` | `/api/v1/infer/stream` | Sequential batch telemetry stream inference (up to 5,000 records) | `200 OK` / `4xx` / `500` |
| `*` | `/api/v1/reset` | **PROHIBITED**. Returns HTTP 404 with error code `NOT_FOUND` | `404 Not Found` |

---

## 4. Input Payload Formats & The 13 Canonical Features

Clients may submit telemetry windows using either of two accepted wire formats:

### 4.1 Format A: Canonical Ordered Array
Recommended for high-performance integrations and streaming pipelines. Features are supplied as an ordered JSON array of exactly 13 floating-point numbers.

```json
{
  "window_id": "win_20260915_0001",
  "timestamp": "2026-09-15T00:01:00Z",
  "features": [
    142.0, 45.2, 38210.5, 12.4, 4.2, 0.15, 845.0, 120.5, 1.25, 18.0, 12.0, 0.92, 0.08
  ]
}
```

### 4.2 Format B: Named Map Adapter
Recommended for developer readability and loose coupling. Features are supplied as a JSON object containing all 13 canonical keys.

```json
{
  "window_id": "win_20260915_0001",
  "timestamp": "2026-09-15T00:01:00Z",
  "features": {
    "flow_count": 142.0,
    "packet_rate": 45.2,
    "byte_rate": 38210.5,
    "mean_flow_duration": 12.4,
    "std_flow_duration": 4.2,
    "short_flow_ratio": 0.15,
    "mean_packet_size": 845.0,
    "packet_length_variability": 120.5,
    "fwd_bwd_packet_ratio": 1.25,
    "unique_dst_ports": 18.0,
    "unique_dst_ips": 12.0,
    "tcp_flow_ratio": 0.92,
    "syn_packet_ratio": 0.08
  }
}
```

### 4.3 The Canonical 13 Features Authority Table

The feature array in Format A must strictly match this sequence, and Format B must provide all 13 keys:

| Index | Canonical Feature Key | Data Type | Physical Interpretation | Valid Domain |
| :-: | :--- | :--- | :--- | :--- |
| **1** | `flow_count` | Float | Number of bidirectional network flows aggregated in the 60s window | $\ge 0$ |
| **2** | `packet_rate` | Float | Average network packets transmitted per second | $\ge 0$ |
| **3** | `byte_rate` | Float | Average network volume transmitted in bytes per second | $\ge 0$ |
| **4** | `mean_flow_duration` | Float | Arithmetic mean duration of flows during the window (seconds) | $\ge 0$ |
| **5** | `std_flow_duration` | Float | Standard deviation of flow durations during the window (seconds) | $\ge 0$ |
| **6** | `short_flow_ratio` | Float | Ratio of sub-second flows to total flows | $[0.0, 1.0]$ |
| **7** | `mean_packet_size` | Float | Arithmetic mean packet payload size across all flows (bytes) | $\ge 0$ |
| **8** | `packet_length_variability`| Float | Standard deviation of packet sizes across all flows (bytes) | $\ge 0$ |
| **9** | `fwd_bwd_packet_ratio` | Float | Ratio of forward directional packets to backward packets | $\ge 0$ |
| **10** | `unique_dst_ports` | Float | Count of distinct destination transport layer ports targeted | $\ge 0$ |
| **11** | `unique_dst_ips` | Float | Count of distinct destination IP network layer addresses targeted | $\ge 0$ |
| **12** | `tcp_flow_ratio` | Float | Proportion of observed network flows utilizing TCP | $[0.0, 1.0]$ |
| **13** | `syn_packet_ratio` | Float | Proportion of observed TCP packets bearing the SYN flag set | $[0.0, 1.0]$ |

> **Prohibited Obsolete Features**: Legacy feature names such as `src_bytes`, `dst_bytes`, `count`, `srv_count`, `same_srv_rate`, `diff_srv_rate`, `dst_host_count`, and `logged_in` are strictly prohibited. Ingestion attempts with these keys will fail schema validation.

---

## 5. Temporal Continuity, Cold Start & Calendar Resets

### 5.1 Temporal Cadence Constraint
The NexThreat temporal engine operates on discrete 60-second intervals:
$$\Delta t = t_n - t_{n-1} = 60\,\text{seconds}$$

### 5.2 The 10-Window Cold-Start Progression
The LSTM sequence model requires a rolling context history of exactly 10 consecutive, uninterrupted 60-second windows ($k=10$ lookback depth):
- **Windows 1 through 9 (Cold-Start Period)**:
  - The history buffer increments depth from 1 to 9.
  - Autoencoder and XGBoost execute immediately and emit valid evaluations.
  - LSTM emits `is_eligible: false`, `ineligibility_reason: "lstm_lookback_cold_start"`, `forecast_probability: null`, `forecast_decision: "unavailable"`.
  - Consolidated Threat Inference emits `is_eligible: false`, `threat_state_code: null`, `threat_state_name: null`, `priority_tier: null`, `decision_tuple: null`.
- **Window 10+ (Fully Eligible)**:
  - Buffer reaches full capacity of 10 windows.
  - LSTM evaluates the lookback sequence and produces `forecast_probability`.
  - Consolidated Threat Inference synthesizes the full decision vector $[AE, XGB, LSTM]$ into states S0–S7.

### 5.3 Continuity Resets & Gap Violations
The rolling buffer is reset under any of the following operational conditions:
1. **Cadence Gap ($\Delta t > 60\,\text{s}$)**: Ingestion resumed after missed windows. Emits `ineligibility_reason: "temporal_gap_discontinuity"`.
2. **Sub-60-Second Delta ($\Delta t < 60\,\text{s}$)**: Bursted or unaligned windows reset buffer.
3. **Calendar Date Boundary Transition ($t_n.\text{date}() \ne t_{n-1}.\text{date}()$)**: When crossing midnight UTC, the buffer is automatically flushed to enforce dataset-day segregation.
4. **Chronological Violation ($t_n \le t_{n-1}$)**: Non-advancing or duplicate timestamps immediately fail with HTTP 400 `INPUT_VALIDATION_ERROR` with zero model inference performed.

---

## 6. Threat States & Priority Tiers

When all three models are eligible (Window 10+), the inference engine maps the binary decision vector $[AE, XGB, LSTM]$ to one of 8 canonical threat states:

| Threat State Code | Authoritative Threat State Name | Decision Vector $[AE, XGB, LSTM]$ | Priority Tier | Operational SOC Guidance |
| :-: | :--- | :-: | :-: | :--- |
| **S0** | `BENIGN_CONCORDANCE` | `[0, 0, 0]` | `P4_INFORMATIONAL` | Normal baseline traffic. No action required. |
| **S1** | `LSTM_FORECAST_ONLY` | `[0, 0, 1]` | `P3_ELEVATED` | Early warning: Sequence trajectory forecasts attack vulnerability. Heighten monitoring. |
| **S2** | `XGB_ATTACK_ONLY` | `[0, 1, 0]` | `P2_HIGH` | Active attack signatures detected by multiclass classifier. Initiate triage. |
| **S3** | `XGB_LSTM_CONSISTENCY` | `[0, 1, 1]` | `P1_CRITICAL` | Active attack concordant with sequence forecast. Urgent response required. |
| **S4** | `AE_ANOMALY_ONLY` | `[1, 0, 0]` | `P3_ELEVATED` | Statistical reconstruction anomaly without known attack signature. Zero-day risk. |
| **S5** | `AE_LSTM_CONSISTENCY` | `[1, 0, 1]` | `P2_HIGH` | Anomaly concordant with sequence forecast. Investigate payload patterns. |
| **S6** | `AE_XGB_CONSENSUS` | `[1, 1, 0]` | `P1_CRITICAL` | Dual-model consensus: statistical anomaly matching known attack signature. |
| **S7** | `TRI_MODEL_CONSENSUS` | `[1, 1, 1]` | `P1_CRITICAL` | Complete tri-model consensus: anomaly, classified attack, and forecast aligned. Critical incident. |

---

## 7. The Authoritative 24-Field Response Specification

Every inference response contains exactly 24 fields across 5 nested model blocks and root telemetry:

```json
{
  "window_id": "win_20260915_0010",
  "timestamp": "2026-09-15T00:10:00Z",
  "global_position": 10,
  "dataset_day": "2026-09-15",
  "autoencoder": {
    "reconstruction_mse": 0.001842,
    "threshold": 0.003207791231673312,
    "is_anomaly": 0
  },
  "xgboost": {
    "predicted_class_index": 0,
    "predicted_class_name": "Benign",
    "is_attack": 0,
    "class_probabilities": [
      0.9982, 0.0003, 0.0002, 0.0004, 0.0005, 0.0001, 0.0002, 0.0001
    ]
  },
  "lstm": {
    "is_eligible": true,
    "ineligibility_reason": null,
    "forecast_probability": 0.082,
    "threshold": 0.3,
    "forecast_decision": 0
  },
  "threat_inference": {
    "is_eligible": true,
    "threat_state_code": "S0",
    "threat_state_name": "BENIGN_CONCORDANCE",
    "priority_tier": "P4_INFORMATIONAL",
    "decision_tuple": [0, 0, 0]
  },
  "execution_metadata": {
    "inference_latency_ms": 2.18,
    "schema_version": "1.0.0",
    "engine": "NexThreat-Phase5.2"
  }
}
```

---

## 8. Error Handling & Security Redaction

### 8.1 Standardized Error Envelope
All error responses adhere to the standard envelope format:

```json
{
  "error": {
    "code": "INPUT_VALIDATION_ERROR",
    "message": "Invalid features array: expected 13 floats, got 12.",
    "status_code": 400,
    "timestamp": "2026-09-15T00:05:00.123456+00:00",
    "details": {
      "field": "features",
      "expected_length": 13,
      "received_length": 12
    }
  }
}
```

### 8.2 Standard Error Codes Taxonomy

| Error Code | HTTP Status | Trigger Condition |
| :--- | :-: | :--- |
| `INPUT_VALIDATION_ERROR` | `400` | Schema mismatch, missing fields, non-finite values, non-monotonic timestamps |
| `BAD_REQUEST` | `400` | Malformed JSON body or invalid Content-Length header |
| `STREAM_TOO_LARGE` | `400` | Stream batch contains $> 5,000$ records |
| `NOT_FOUND` | `404` | Non-existent route or attempt to call `/api/v1/reset` |
| `METHOD_NOT_ALLOWED` | `405` | Using invalid method (e.g. GET on `/api/v1/infer/window`) |
| `LENGTH_REQUIRED` | `411` | Omission of the `Content-Length` HTTP header |
| `PAYLOAD_TOO_LARGE` | `413` | Request body exceeds 10 MB (`10,485,760` bytes) |
| `UNSUPPORTED_MEDIA_TYPE`| `415` | Request Content-Type is not `application/json` |
| `INTERNAL_ERROR` | `500` | Unhandled API or runtime exception |
| `MODEL_EXECUTION_ERROR` | `500` | Runtime failure in ML tensor evaluation |
| `SERVICE_UNAVAILABLE` | `503` | Pipeline uninitialized or cryptographic verification failed |

### 8.3 Information Redaction & Leakage Prevention
In compliance with enterprise security requirements, all error strings are passed through `sanitize_error_message()`:
- **Filesystem Paths**: Windows drive paths (`C:\...`) and Unix directories (`/home/`, `/usr/`, `/var/`, etc.) are replaced with `[REDACTED_PATH]`.
- **Python Source Files**: Python script references (`*.py`) are replaced with `[REDACTED_SRC]`.
- **Stack Trace Lines**: Code line references (`line 123`) are replaced with `line [REDACTED]`.
- **Memory Addresses**: Hexadecimal memory pointers (`0x7fff...`) are replaced with `[REDACTED_ADDR]`.
