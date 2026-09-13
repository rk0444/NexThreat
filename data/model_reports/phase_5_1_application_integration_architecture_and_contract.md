# NexThreat — Phase 5.1 Specification
# Application Integration Architecture & Contract

**Document Version**: `1.0.0`  
**Status**: `ACCEPTED SPECIFICATION`  
**Phase**: `Phase 5.1 — Application Integration Architecture & Contract`  
**Project**: `NexThreat`  
**Problem Statement**: `AI-Based Network Attack Forecasting from Network Traffic Data`  
**Tagline**: `Detect anomalies. Forecast attacks. Prevent damage.`  
**Authoritative Baseline**: `Phase 4 (Phases 4.1 through 4.7 Accepted & Frozen)`  
**Repository Path**: `E:\Project\NexThreat`  

---

## 1. Document Metadata

- **Title**: NexThreat Phase 5.1 Application Integration Architecture & Contract Specification
- **System Architecture**: Pure Three-Model Independent Feed-Forward Pipeline with Deterministic Discrete Threat-State Logic
- **Scope Classification**: Architectural Design, Contract Specification, and Interface Definition (Non-Implementation)
- **Authoritative Prior Phases**:
  - Phase 4.1: Shared Model Training Infrastructure (`PASS`)
  - Phase 4.2: Autoencoder Anomaly Detection (`PASS`)
  - Phase 4.3: XGBoost Attack Classification (`PASS`)
  - Phase 4.4: LSTM Attack Forecasting (`PASS`)
  - Phase 4.5: Cross-Model Evaluation & Unified Threat Inference (`PASS`)
  - Phase 4.6: Cross-Model Verification / Hardening (`PASS`, 29/29 checks)
  - Phase 4.7: Final Integration & Acceptance Verification (`PASS`, 14/14 pillars, `PHASE 4 = ACCEPTED`)

---

## 2. Phase Objective

The objective of **Phase 5.1 — Application Integration Architecture & Contract** is to define the authoritative application-level architecture, contracts, boundaries, data flows, and validation specifications required to connect the already-accepted Phase 4 machine learning components into a single, deterministic application inference workflow.

Phase 5.1 formalizes:
1. The exact boundary between offline dataset preparation and the application inference runtime.
2. The authoritative One-Minute Window input contract.
3. The independent execution wrappers for Autoencoder, XGBoost, and LSTM models.
4. The authoritative cross-model join mechanics based strictly on `window_id`.
5. The exact preservation of the Phase 4.5 unified threat-state taxonomy (S0–S7) and neutral cold-start null semantics.
6. The complete JSON application output schema.
7. The verification and acceptance requirements for subsequent Phase 5.2 implementation.

This is a **specification and design phase only**. No model weights, thresholds, datasets, manifests, or Phase 4 source files are modified.

---

## 3. Scope

Phase 5.1 encompasses:
- Defining the formal application input boundary and schema.
- Defining the 1-minute window representation and feature encapsulation.
- Specifying the exact inference contracts for the three frozen models.
- Specifying cross-model identity linking via `window_id`.
- Specifying cold-start lookback handling (50 windows) and null threat-state rules.
- Defining the unified threat inference integration layer.
- Specifying the complete application output schema (categorized by `REQUIRED`, `OPTIONAL`, `NULLABLE`, `FORBIDDEN`).
- Defining error handling, validation boundaries, and determinism requirements.
- Creating the Component Responsibility Matrix and end-to-end data flow.
- Establishing testable verification and acceptance criteria for Phase 5.2.

---

## 4. Non-Scope

The following are strictly excluded from Phase 5.1:
- Writing application or service code (belongs to Phase 5.2).
- Building live network packet sniffers or PCAP capture agents.
- Creating REST APIs, gRPC endpoints, or web dashboards.
- Modifying or retraining any machine learning model.
- Refitting or recalculating any feature scaler or label encoder.
- Mutating decision thresholds ($\tau_{\text{ae}}, \tau_{\text{lstm}}$).
- Modifying Phase 4 source code, manifests, or verification reports.
- Performing autonomous remediation or network actuation (blocking IPs, updating firewall rules).

---

## 5. Phase 4 Baseline

Phase 4 represents the authoritative, complete, and accepted ML core of NexThreat. Its acceptance status is formally established:

```text
================================================================================
PHASE 4 ACCEPTANCE AUDIT (Phase 4.7)
================================================================================
Phase 4.1 — Shared Model Training Infrastructure       : PASS
Phase 4.2 — Autoencoder Development                    : PASS
Phase 4.3 — XGBoost Development                        : PASS
Phase 4.4 — LSTM Development                           : PASS
Phase 4.5 — Cross-Model Evaluation & Unified Inference  : PASS (19/19 Checks)
Phase 4.6 — Cross-Model Verification / Hardening       : PASS (29/29 Checks)
Phase 4.7 — Final Integration & Acceptance             : PASS (14/14 Pillars)

FINAL VERDICT: PHASE 4 = ACCEPTED
================================================================================
```

The Phase 4 baseline provides the immutable foundation for all Phase 5 designs.

---

## 6. Architectural Freeze

The architecture of NexThreat is permanently frozen at exactly **three specialized models**:

1. **Autoencoder** (Phase 4.2): Unsupervised statistical anomaly detection.
2. **XGBoost** (Phase 4.3): Supervised 8-class attack signature classification.
3. **LSTM** (Phase 4.4): Forward-looking sequence-based attack forecasting.

### Strictly Prohibited Constructs
The application integration layer must NEVER implement or permit:
- A fourth ML model or learning stage.
- Ensemble models, meta-learners, or model stacking (`VotingClassifier`, `StackingClassifier`).
- Numerical score fusion (weighted scoring, score averaging, normalized score combinations).
- Model retraining, online fine-tuning, or scaler refitting during application execution.
- Threshold mutation or adaptive threshold tuning.
- Autonomous network remediation (firewall reconfiguration, traffic dropping, route injection).
- Threat state `S8` or `LSTM_UNAVAILABLE` as a discrete threat state.
- Synthetic lookback sequences or cross-day sequence generation.

---

## 7. Repository Findings

Inspection of the existing NexThreat codebase reveals the following structural organization:

```text
E:\Project\NexThreat\
├── data/
│   ├── features/              <- Daily feature CSVs (1-minute window aggregated features)
│   ├── model_inputs/
│   │   ├── manifests/         <- Phase 3.2 split manifests & split integrity reports
│   │   └── metadata/          <- 81 attack segments (attack_segments.csv)
│   ├── model_ready/
│   │   ├── artifacts/         <- Frozen scalers (autoencoder_scaler.joblib, lstm_scaler.joblib)
│   │   └── metadata/          <- Feature columns metadata, LSTM sequence provenance (2,204 rows)
│   ├── models/
│   │   ├── autoencoder/       <- autoencoder.keras, best_model.keras, model_metadata.json
│   │   ├── xgboost/           <- xgboost_model.json, metadata.json, feature_schema.json
│   │   └── lstm/              <- lstm_model.keras, best_Candidate_C.keras
│   └── model_reports/
│       ├── autoencoder/       <- Phase 4.2 evaluation reports
│       ├── xgboost/           <- Phase 4.3 test reports
│       ├── lstm/              <- Phase 4.4 test reports & threshold_config.json
│       ├── comparison/        <- Phase 4.5 comparison reports & unified inference spec
│       ├── hardening/         <- Phase 4.6 verification report & markdown summary
│       └── acceptance/        <- Phase 4.7 acceptance report & markdown summary
├── src/
│   ├── preprocessing/         <- Raw PCAP flow cleaning and normalization
│   ├── windowing/             <- Grouping flows into 1-minute time windows
│   ├── feature_engineering/   <- Calculating 13 canonical features from flow windows
│   └── models/
│       ├── comparison/        <- TimelineSynchronizer, ThreatInferenceEngine, ConsistencyAnalyzer
│       └── verification/      <- verify_phase_4_5.py, verify_phase_4_6.py, verify_phase_4_7.py
```

### Key Architectural Discovery
In Phase 4.5/4.6/4.7, `MasterTimelineSynchronizer` demonstrated that model inference operates directly on **1-minute window feature records**, where each record contains `window_id` and the exact **13 canonical network features**. Upstream PCAP parsing and flow window aggregation are offline preprocessing steps in Phase 2, which are separated from the model inference boundary.

---

## 8. Application Integration Boundary

The application architecture strictly separates the **Offline Dataset Pipeline** from the **Application Inference Pipeline**:

```text
========================================================================================
OFFLINE DATASET PIPELINE (Phases 1 - 3: Complete & Frozen)
Raw PCAP Flows -> Cleaning -> Windowing -> Feature Extraction -> Manifest Splits -> Scalers
========================================================================================

========================================================================================
FUTURE APPLICATION INFERENCE PIPELINE (Phase 5)
[Upstream Traffic Source] (Live Capture / Replay)
       │
       ▼
[Upstream Ingestion & Feature Adapter] (Optional pre-processor: Flows -> 1-Min Features)
       │
       ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  CANONICAL ML INFERENCE APPLICATION BOUNDARY (Phase 5.1 Specification Focus)         │
│                                                                                      │
│  Input: One-Minute Feature-Vector Window Record                                      │
│         { window_id, timestamp, features[13] }                                       │
│                                                                                      │
│  Orchestration:                                                                      │
│    ├── 1. Feature Validation (Exact 13 features, invariant order, finite bounds)     │
│    ├── 2. Historical Buffer Update (FIFO buffer of past 10 valid windows for LSTM)   │
│    ├── 3. Independent Model Inference:                                               │
│    │     ├── Autoencoder Predictor -> reconstruction_mse -> anomaly_decision         │
│    │     ├── XGBoost Predictor     -> predicted_class   -> attack_decision           │
│    │     └── LSTM Predictor        -> forecast_prob     -> forecast_decision (or NA) │
│    ├── 4. Identity Linking via window_id                                             │
│    └── 5. Deterministic Discrete Threat Inference Engine -> State S0..S7 (or null)   │
│                                                                                      │
│  Output: Structured Application Threat Inference Record                              │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

The **Canonical ML Inference Application Boundary** accepts pre-aggregated One-Minute Feature-Vector Window Records. Any network packet capture or flow-level aggregation is an upstream operational adapter, isolating the ML core from transport-level networking details.

---

## 9. Canonical Input Contract

The application inference engine accepts a single, authoritative input contract: the **One-Minute Feature-Vector Window Record**.

### Schema Specification
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "OneMinuteFeatureWindowRecord",
  "type": "object",
  "required": [
    "window_id",
    "timestamp",
    "features"
  ],
  "additionalProperties": false,
  "properties": {
    "window_id": {
      "type": "string",
      "pattern": "^[0-9]{8}_[0-9]{4}$",
      "description": "Authoritative window identifier formatted as YYYYMMDD_HHMM (e.g. 20170703_1355)."
    },
    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO-8601 or standard datetime representing window start (e.g. 2017-07-03T13:55:00)."
    },
    "dataset_day": {
      "type": "string",
      "enum": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Unknown"],
      "description": "Day of the week partition for boundary enforcement."
    },
    "global_position": {
      "type": "integer",
      "minimum": 1,
      "description": "Optional chronological sequence index."
    },
    "features": {
      "type": "array",
      "minItems": 13,
      "maxItems": 13,
      "items": {
        "type": "number"
      },
      "description": "Exact 13 canonical network traffic features in strict canonical order."
    }
  }
}
```

### The 13 Canonical Features (Strict Invariant Order)
Every input record must supply the `features` array matching this exact sequence:

| Index | Feature Column Name | Data Type | Physical Meaning | Valid Range |
|:---:|---|:---:|---|:---:|
| **0** | `flow_count` | `float32` | Total flows terminated in window | $\ge 0$ |
| **1** | `packet_rate` | `float32` | Packets per second across window | $\ge 0$ |
| **2** | `byte_rate` | `float32` | Bytes per second across window | $\ge 0$ |
| **3** | `mean_flow_duration` | `float32` | Average flow duration in microseconds | $\ge 0$ |
| **4** | `std_flow_duration` | `float32` | Standard deviation of flow duration | $\ge 0$ |
| **5** | `short_flow_ratio` | `float32` | Fraction of flows $< 1.0$ second | $[0.0, 1.0]$ |
| **6** | `mean_packet_size` | `float32` | Average packet size in bytes | $\ge 0$ |
| **7** | `packet_length_variability` | `float32` | Std dev of packet length / variability | $\ge 0$ |
| **8** | `fwd_bwd_packet_ratio` | `float32` | Ratio of forward to backward packets | $\ge 0$ |
| **9** | `unique_dst_ports` | `float32` | Distinct destination port count | $\ge 0$ |
| **10** | `unique_dst_ips` | `float32` | Distinct destination IP count | $\ge 0$ |
| **11** | `tcp_flow_ratio` | `float32` | Fraction of flows using TCP protocol | $[0.0, 1.0]$ |
| **12** | `syn_packet_ratio` | `float32` | Fraction of packets with SYN flag set | $[0.0, 1.0]$ |

### Prohibited Input Elements
- No ground-truth labels (`is_attack`, `attack_category`, `label`).
- No raw IP addresses or metadata that could induce data leakage into the feature tensor.
- No model prediction feedback loops.

---

## 10. One-Minute Window Contract

A "Window" represents an atomic 60-second temporal aggregation of network traffic.
- **Duration**: Exactly 60.0 seconds ($[T_{\text{start}}, T_{\text{start}} + 60s)$).
- **Identifier**: `window_id` formatted as `YYYYMMDD_HHMM` (e.g. `20170703_1355` represents minute 13:55 on July 3, 2017).
- **Chronology**: Windows in a continuous session must have strictly advancing timestamps.
- **Independence**: Each window's features are computed purely from flows active/terminated during that window.

---

## 11. Autoencoder Integration Contract

- **Model Purpose**: Unsupervised anomaly detection on current window $t$.
- **Authoritative Model Artifact**: `data/models/autoencoder/final_model/autoencoder.keras`
- **Authoritative Scaler Artifact**: `data/model_ready/artifacts/autoencoder_scaler.joblib`
- **Authoritative Metadata**: `data/models/autoencoder/artifacts/model_metadata.json`
- **Frozen Anomaly Threshold**:
  $$\tau_{\text{ae}} = 0.003207791231673312$$
- **Inference Procedure**:
  1. Input: 1D array of 13 canonical raw features $X_{\text{raw}}(t)$.
  2. Scale: $X_{\text{scaled}} = \text{Scaler}_{\text{ae}}.\text{transform}(X_{\text{raw}})$.
  3. Reconstruct: $\hat{X}_{\text{scaled}} = \text{Autoencoder}(X_{\text{scaled}})$.
  4. Compute Reconstruction MSE:
     $$\text{MSE}(t) = \frac{1}{13} \sum_{j=1}^{13} \left(X_{\text{scaled}, j} - \hat{X}_{\text{scaled}, j}\right)^2$$
  5. Discrete Anomaly Decision:
     $$b_{\text{ae}}(t) = \begin{cases} 1 & \text{if } \text{MSE}(t) \ge \tau_{\text{ae}} \\ 0 & \text{otherwise} \end{cases}$$
- **Read-Only Invariant**: Scaler must NOT call `.fit()` or `.fit_transform()`. Model weights must NOT be updated.

---

## 12. XGBoost Integration Contract

- **Model Purpose**: Supervised attack-category classification on current window $t$.
- **Authoritative Model Artifact**: `data/models/xgboost/xgboost_model.json`
- **Authoritative Feature Schema**: `data/models/xgboost/feature_schema.json`
- **Authoritative Class Mapping**: `data/models/xgboost/class_mapping.json`
- **Classes**:
  - `0`: `BENIGN`
  - `1`: `Brute Force`
  - `2`: `Bot`
  - `3`: `DDoS`
  - `4`: `DoS`
  - `5`: `Heartbleed`
  - `6`: `Infiltration`
  - `7`: `PortScan`
- **Inference Procedure**:
  1. Input: 1D array of 13 canonical raw unscaled features $X_{\text{raw}}(t)$.
  2. Forward Pass: $P = \text{XGBoost}.\text{predict\_proba}(X_{\text{raw}}) \in \mathbb{R}^8$.
  3. Predicted Class:
     $$C(t) = \arg\max_{c \in \{0 \dots 7\}} P_c$$
  4. Discrete Binary Attack Decision:
     $$b_{\text{xgb}}(t) = \begin{cases} 1 & \text{if } C(t) \ne 0 \\ 0 & \text{if } C(t) = 0 \text{ (BENIGN)} \end{cases}$$
- **Invariant**: XGBoost operates on raw unscaled features. Probabilities are strictly non-fused.

---

## 13. LSTM Integration Contract

- **Model Purpose**: Sequence-based future attack forecasting targeting subsequent window $t$.
- **Authoritative Model Artifact**: `data/models/lstm/lstm_model.keras`
- **Authoritative Scaler Artifact**: `data/model_ready/artifacts/lstm_scaler.joblib`
- **Authoritative Threshold Config**: `data/model_reports/lstm/threshold_config.json`
- **Frozen Forecast Threshold**:
  $$\tau_{\text{lstm}} = 0.3000$$
- **Temporal Sequence Contract**:
  - Lookback Window: Exactly 10 historical consecutive 1-minute windows:
    $$[t-10, t-9, \dots, t-1]$$
  - Sequence Shape: $(10, 13)$
  - Target Window: Current window $t$.
- **Inference Procedure**:
  1. Precondition Check: Are 10 contiguous historical windows available within the SAME calendar day?
     - If **NO**: LSTM is `UNAVAILABLE` for window $t$ (Cold-Start Condition).
     - If **YES**: Proceed to step 2.
  2. Scale Sequence: $S_{\text{scaled}} = \text{Scaler}_{\text{lstm}}.\text{transform}(S_{10 \times 13})$.
  3. Forward Pass: $P_{\text{lstm}}(t) = \text{LSTM}(S_{\text{scaled}}) \in [0.0, 1.0]$.
  4. Discrete Forecast Decision:
     $$b_{\text{lstm}}(t) = \begin{cases} 1 & \text{if } P_{\text{lstm}}(t) \ge \tau_{\text{lstm}} \\ 0 & \text{otherwise} \end{cases}$$
- **Day-Boundary Invariant**: Sequences must NEVER cross midnight or span differing `dataset_day` partitions. Zero synthetic padding allowed.

---

## 14. Cross-Model Identity Contract

- **Authoritative Cross-Model Join Key**: `window_id` (`YYYYMMDD_HHMM`).
- All evidence for a traffic window (Autoencoder MSE, XGBoost class, LSTM forecast, unified threat state) must be associated strictly by matching `window_id`.
- `global_position` ($1 \dots 2454$) is preserved as an **independent chronological ordering invariant**, never a primary join key.
- The functional relationship $\text{window\_id} \to \text{global\_position}$ must be strictly 1-to-1.

---

## 15. Temporal / Cold-Start Contract

Across the authoritative master timeline ($N_{\text{master}} = 2454$):
- **Eligible Windows**: Exactly $N_{\text{eligible}} = 2404$ windows have complete 10-window lookback history.
- **Ineligible Cold-Start Windows**: Exactly $N_{\text{ineligible}} = 50$ windows (5 days $\times$ first 10 windows of each day: positions 1..10, 488..497, 976..985, 1485..1494, 1971..1980).

### Cold-Start Neutral Null Rules
For any window $t$ where historical lookback is insufficient or spans a day boundary:
1. `lstm_probability` = `null` (Python `None`)
2. `lstm_prediction` = `"unavailable"`
3. `is_eligible_for_threat_state` = `false`
4. `ineligibility_reason` = `"lstm_lookback_cold_start"`
5. `threat_state` = `null` (Python `None`)
6. `threat_state_code` = `null` (Python `None`)

Under no circumstances may the application:
- Invent synthetic lookback windows or zero-pad sequences.
- Borrow lookback from the previous day.
- Substitute a default prediction (e.g. 0 or 0.5).
- Create a threat state named `S8` or `LSTM_UNAVAILABLE`.

---

## 16. Unified Threat-State Contract

The unified threat inference layer implements the authoritative Phase 4.5 discrete truth table mapping $T: \{0, 1\}^3 \to \{S0 \dots S7\}$.

### Authoritative Canonical Threat-State Taxonomy

| State Code | Canonical State Name | Autoencoder ($b_{\text{ae}}$) | XGBoost ($b_{\text{xgb}}$) | LSTM ($b_{\text{lstm}}$) | Priority Tier | Operational Triage Action |
|:---:|---|:---:|:---:|:---:|---|---|
| **S0** | `BENIGN_CONCORDANCE` | 0 | 0 | 0 | Priority 4 | Normal baseline operations. All models concordant benign. |
| **S1** | `LSTM_FORECAST_ONLY` | 0 | 0 | 1 | Priority 3 | Forward warning; current traffic clean. Pre-position defenses. |
| **S2** | `XGB_ATTACK_ONLY` | 0 | 1 | 0 | Priority 3 | Known attack signature matched without statistical anomaly. |
| **S3** | `XGB_LSTM_CONSISTENCY` | 0 | 1 | 1 | Priority 2 | Forecasted signature attack active; low statistical deviation. |
| **S4** | `AE_ANOMALY_ONLY` | 1 | 0 | 0 | Priority 3 | Statistical anomaly without signature match (possible 0-day). |
| **S5** | `AE_LSTM_CONSISTENCY` | 1 | 0 | 1 | Priority 2 | Forecasted novel statistical anomaly active. High alert. |
| **S6** | `AE_XGB_CONSENSUS` | 1 | 1 | 0 | Priority 2 | Unpredicted sudden attack confirmed by AE and XGBoost. |
| **S7** | `TRI_MODEL_CONSENSUS` | 1 | 1 | 1 | Priority 1 | Immediate SOC Triage. Full consensus: forecasted & active. |

### Forbidden State Labels
The application must strictly reject: `S8`, `LSTM_UNAVAILABLE`, `confirmed_attack`, `zero_day_detection`, `guaranteed_prevention`, `CRITICAL_ATTACK`, `PROBABLE_ATTACK`.

---

## 17. Application Output Contract

The application outputs an authoritative JSON record for every processed window.

### JSON Output Schema Specification
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "NexThreatApplicationOutputRecord",
  "type": "object",
  "required": [
    "window_id",
    "timestamp",
    "autoencoder",
    "xgboost",
    "lstm",
    "threat_inference"
  ],
  "properties": {
    "window_id": {
      "type": "string",
      "description": "REQUIRED: Authoritative window identifier (YYYYMMDD_HHMM)."
    },
    "timestamp": {
      "type": "string",
      "description": "REQUIRED: Window start timestamp in ISO-8601 format."
    },
    "global_position": {
      "type": ["integer", "null"],
      "description": "OPTIONAL: Monotonic chronological index if part of a master sequence."
    },
    "dataset_day": {
      "type": "string",
      "description": "OPTIONAL: Partition calendar day (e.g. Monday)."
    },
    "autoencoder": {
      "type": "object",
      "required": [
        "reconstruction_mse",
        "threshold",
        "is_anomaly"
      ],
      "properties": {
        "reconstruction_mse": { "type": "number" },
        "threshold": { "type": "number", "const": 0.003207791231673312 },
        "is_anomaly": { "type": "integer", "enum": [0, 1] }
      }
    },
    "xgboost": {
      "type": "object",
      "required": [
        "predicted_class_index",
        "predicted_class_name",
        "is_attack"
      ],
      "properties": {
        "predicted_class_index": { "type": "integer", "minimum": 0, "maximum": 7 },
        "predicted_class_name": { "type": "string" },
        "is_attack": { "type": "integer", "enum": [0, 1] },
        "class_probabilities": {
          "type": ["array", "null"],
          "items": { "type": "number" },
          "description": "OPTIONAL: 8-class probability distribution."
        }
      }
    },
    "lstm": {
      "type": "object",
      "required": [
        "is_eligible",
        "forecast_probability",
        "forecast_decision"
      ],
      "properties": {
        "is_eligible": { "type": "boolean" },
        "ineligibility_reason": { "type": ["string", "null"] },
        "forecast_probability": { "type": ["number", "null"] },
        "threshold": { "type": "number", "const": 0.3 },
        "forecast_decision": { "type": ["integer", "string"], "enum": [0, 1, "unavailable"] }
      }
    },
    "threat_inference": {
      "type": "object",
      "required": [
        "is_eligible",
        "threat_state_code",
        "threat_state_name",
        "priority_tier"
      ],
      "properties": {
        "is_eligible": { "type": "boolean" },
        "threat_state_code": { "type": ["string", "null"], "enum": ["S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", null] },
        "threat_state_name": { "type": ["string", "null"], "enum": [
          "BENIGN_CONCORDANCE",
          "LSTM_FORECAST_ONLY",
          "XGB_ATTACK_ONLY",
          "XGB_LSTM_CONSISTENCY",
          "AE_ANOMALY_ONLY",
          "AE_LSTM_CONSISTENCY",
          "AE_XGB_CONSENSUS",
          "TRI_MODEL_CONSENSUS",
          null
        ]},
        "priority_tier": { "type": ["string", "null"] },
        "decision_tuple": {
          "type": ["array", "null"],
          "items": { "type": "integer" },
          "minItems": 3,
          "maxItems": 3
        }
      }
    }
  }
}
```

### Schema Categorization
- **REQUIRED**: `window_id`, `timestamp`, `autoencoder.reconstruction_mse`, `autoencoder.is_anomaly`, `xgboost.predicted_class_name`, `xgboost.is_attack`, `lstm.is_eligible`, `lstm.forecast_decision`, `threat_inference.threat_state_name`.
- **OPTIONAL**: `global_position`, `dataset_day`, `xgboost.class_probabilities`.
- **NULLABLE**: `lstm.forecast_probability`, `threat_inference.threat_state_code`, `threat_inference.threat_state_name` (when `lstm.is_eligible == false`).
- **FORBIDDEN**: `combined_score`, `risk_score`, `ensemble_probability`, `S8`, `LSTM_UNAVAILABLE` as state.

---

## 18. Validation Contract

The application must validate incoming data at three strict checkpoints:

1. **Input Structural Validation**:
   - Record contains non-empty `window_id` matching `YYYYMMDD_HHMM`.
   - Feature array length exactly equals 13.
   - All 13 feature values are numeric (`float` or `int`), non-null, non-NaN, non-infinite.
2. **Feature Range Validation**:
   - `flow_count`, `packet_rate`, `byte_rate`, `mean_flow_duration`, `std_flow_duration`, `mean_packet_size`, `packet_length_variability`, `fwd_bwd_packet_ratio`, `unique_dst_ports`, `unique_dst_ips` $\ge 0.0$.
   - `short_flow_ratio`, `tcp_flow_ratio`, `syn_packet_ratio` $\in [0.0, 1.0]$.
3. **Temporal Sequence Validation**:
   - If historical buffer is provided for LSTM: sequence must contain exactly 10 prior consecutive windows, strictly chronological, all within the same calendar day.

---

## 19. Error Handling Contract

Errors must be deterministically classified into distinct categories:

| Error Category | Trigger Condition | Application Behavior |
|---|---|---|
| **`INPUT_VALIDATION_ERROR`** | Missing features, count $\ne 13$, NaN/Inf values, invalid `window_id` | Reject window; log error; do NOT invoke models. |
| **`TEMPORAL_ELIGIBILITY_CONDITION`** | Buffer $< 10$ windows or day boundary transition | Not an error: mark `lstm.is_eligible = false`, assign `threat_state = null`. |
| **`MODEL_EXECUTION_ERROR`** | Missing artifact, ONNX/Keras runtime fault, corrupted weights | Raise critical exception; halt pipeline; zero silent recovery. |
| **`INTEGRATION_CONTRACT_ERROR`** | `window_id` mismatch during join, non-canonical state generated | Raise fatal contract violation; fail fast. |

---

## 20. Artifact Immutability Contract

The application integration layer enforces a strict read-only boundary across Phase 4 artifacts.

### Authoritative Hash Boundary (Closed 33-File Inventory)
The 33 files established in Phase 4.7 represent the sole immutable boundary:
- 5 Phase 3.2 manifest/metadata files
- 8 Phase 3.3 scaler/encoder/metadata files
- 3 Phase 4.2 Autoencoder artifacts
- 4 Phase 4.3 XGBoost artifacts
- 3 Phase 4.4 LSTM artifacts
- 7 Phase 4.5 authoritative deliverables
- 3 Phase 4.6 authoritative deliverables

### Authoritative Read-Only Evidence Set
Model-specific reports (`autoencoder_evaluation_report.json`, `xgboost/test_report.json`, `lstm/test_report.json`, `model_infrastructure_verification_report.json`) are ingested purely as read-only references and are excluded from the 33-file hash boundary.

### Invariant Rules
- Application runtime loads artifacts via read-only memory mappings or safe loading functions.
- Any attempt to write to `data/models/`, `data/model_ready/`, or `data/model_inputs/` is strictly prohibited.

---

## 21. Determinism Contract

The application must deliver bit-exact discrete determinism and bounded continuous numerical reproducibility:

1. **Discrete Outputs**:
   - `autoencoder.is_anomaly`, `xgboost.predicted_class_index`, `xgboost.is_attack`, `lstm.forecast_decision`, `threat_inference.threat_state_code` must match 100% bit-for-bit across repeated runs on identical input.
2. **Continuous Outputs**:
   - `reconstruction_mse` and `forecast_probability` must replicate within:
     $$\text{atol} = 10^{-6}, \quad \text{rtol} = 10^{-5}$$
   - Variations must never cross decision boundaries ($\tau_{\text{ae}}, \tau_{\text{lstm}}$).

---

## 22. Security Boundary

NexThreat is an AI-based **detection, classification, and forecasting** system.
- **Permitted Operational Actions**:
  - Ingest traffic features.
  - Execute ML inference.
  - Publish threat state alerts to SOC analysts / triage queues.
  - Log audit trails.
- **Strictly Prohibited Operational Actions**:
  - Autonomous IP blocking (`iptables`, `netsh`, `ufw`).
  - Network interface modification.
  - Autonomous host termination (`taskkill`, `kill -9`).
  - Automated containment without human SOC confirmation.

---

## 23. Forbidden Behaviors

The following operations are formally forbidden in the application design:

```text
[FORBIDDEN] 1. Instantiating a 4th ML model.
[FORBIDDEN] 2. Computing combined_score, weighted_score, or ensemble_score.
[FORBIDDEN] 3. Calling .fit(), .fit_transform(), or retraining routines.
[FORBIDDEN] 4. Mutating tau_ae (0.00320779) or tau_lstm (0.3).
[FORBIDDEN] 5. Emitting S8 or LSTM_UNAVAILABLE as a threat state.
[FORBIDDEN] 6. Constructing LSTM sequences across midnight / day boundaries.
[FORBIDDEN] 7. Zero-padding or inventing synthetic lookback history.
[FORBIDDEN] 8. Reordering, adding, or removing features from the canonical 13 list.
[FORBIDDEN] 9. Using row index as a join key instead of window_id.
[FORBIDDEN] 10. Executing system shell commands or autonomous network remediation.
```

---

## 24. Component Responsibility Matrix

| Component Name | Responsibility | Inputs | Outputs | Authority Source | Strictly Forbidden Actions |
|---|---|---|---|---|---|
| **Input Adapter** | Receives and parses window records | JSON / Dict stream | Validated window structure | Phase 5.1 Input Contract | Feat. invention, reordering |
| **Feature Validator** | Asserts 13 features, types, bounds | Feature vector | Validated `float32[13]` | Phase 2.3 Contract | Silently imputing missing values |
| **Historical Buffer** | Manages lookback FIFO for LSTM | Current window features | 10-window tensor or NA | Phase 4.4 Contract | Cross-day lookback, synthetic padding |
| **Autoencoder Predictor** | Computes reconstruction MSE | 13 raw features | MSE, binary anomaly | Phase 4.2 Model & Scaler | Scaler refitting, threshold mutation |
| **XGBoost Predictor** | 8-class attack classification | 13 raw features | Class index, binary attack | Phase 4.3 Model & Schema | Score thresholding, prob. fusion |
| **LSTM Predictor** | Forward attack forecasting | $10 \times 13$ historical tensor | Probability, binary forecast | Phase 4.4 Model & Scaler | Invoking when $<10$ windows available |
| **Threat Inference Engine**| Discrete tuple truth table lookup | $(b_{\text{ae}}, b_{\text{xgb}}, b_{\text{lstm}})$ | State S0..S7 (or null) | Phase 4.5 Mapping | Score blending, emitting S8 |
| **Output Formatter** | Serializes application JSON record | Model outputs + State | Structured JSON schema | Phase 5.1 Output Contract | Emitting `combined_score` |

---

## 25. Data-Flow Specification

The step-by-step data flow through the application inference runtime:

```text
Step 1: Input Ingestion
        Window record received: { window_id, timestamp, features[13] }
          │
          ▼
Step 2: Schema & Value Validation
        Assert len(features) == 13, non-null, finite, within physical bounds.
          │
          ▼
Step 3: Historical Lookback Buffer Management
        - Push features into current-day FIFO buffer.
        - Evaluate LSTM eligibility: len(buffer) >= 10 and all same calendar day?
          ├── If YES: Extract tensor S[10, 13] -> is_lstm_eligible = true
          └── If NO : is_lstm_eligible = false
          │
          ▼
Step 4: Independent Model Inferences
        ├── Autoencoder Pass:
        │     X_raw -> Scaler_ae -> Autoencoder -> MSE -> b_ae = (MSE >= 0.00320779)
        │
        ├── XGBoost Pass:
        │     X_raw -> XGBoost.predict_proba -> C = argmax(P) -> b_xgb = (C != 0)
        │
        └── LSTM Pass:
              ├── If is_lstm_eligible:
              │     S[10,13] -> Scaler_lstm -> LSTM -> P_lstm -> b_lstm = (P_lstm >= 0.3)
              └── If NOT eligible:
                    b_lstm = "unavailable", P_lstm = null
          │
          ▼
Step 5: Cross-Model Identity Verification
        Verify b_ae, b_xgb, and b_lstm all correspond to identical window_id.
          │
          ▼
Step 6: Deterministic Threat State Evaluation
        ├── If b_lstm == "unavailable":
        │     threat_state = null, threat_state_code = null
        └── If b_lstm in {0, 1}:
              (b_ae, b_xgb, b_lstm) -> Table Lookup T -> S0 .. S7
          │
          ▼
Step 7: Output Serialization
        Format validated JSON record matching Phase 5.1 Output Schema.
```

---

## 26. Interface / API Boundary Recommendation

For the upcoming Phase 5.2 implementation, the recommended modular interface consists of three clear Python abstractions:

1. `class FeatureVectorWindow`: Encapsulates a validated 1-minute window record.
2. `class IndependentModelPredictors`: Encapsulates read-only predictors (`AutoencoderPredictor`, `XGBoostPredictor`, `LSTMPredictor`) using pure NumPy/ONNX/Booster runtimes.
3. `class UnifiedInferenceService`: High-level orchestration service providing:
   ```python
   def process_window(self, window: FeatureVectorWindow) -> ApplicationOutputRecord:
       ...
   ```

---

## 27. Phase 5.2 Implementation Prerequisites

Before Phase 5.2 implementation begins, confirm:
1. Phase 5.1 specification is formally accepted.
2. The 33 authoritative frozen Phase 4 artifacts remain unmodified.
3. Dedicated directory `src/application/` (or `src/inference/`) is defined for Phase 5 implementation.
4. Test datasets (e.g. sample replay windows from Monday–Friday features) are identified for regression verification.

---

## 28. Verification Requirements

Phase 5.2 implementation must be verified against this specification using automated test checks:
- **Test V1**: Canonical 13-feature order and naming assertion.
- **Test V2**: Feature count $= 13$ assertion.
- **Test V3**: Input validation rejects malformed vectors (NaN, Inf, negative counts).
- **Test V4**: Pure read-only model artifact loading (0 refits, 0 retraining).
- **Test V5**: Exact threshold enforcement ($\tau_{\text{ae}} = 0.003207791231673312$, $\tau_{\text{lstm}} = 0.3$).
- **Test V6**: Identity matching by `window_id`.
- **Test V7**: 50 cold-start windows produce `threat_state: null` and `lstm: unavailable`.
- **Test V8**: Exactly S0–S7 threat states emitted for eligible windows (0 S8, 0 `LSTM_UNAVAILABLE`).
- **Test V9**: Zero numerical score fusion (AST check).
- **Test V10**: Zero autonomous remediation (AST check).
- **Test V11**: Multi-pass determinism check.
- **Test V12**: Output schema conformance validation.

---

## 29. Acceptance Criteria

Phase 5.1 specification is **`ACCEPTED`** if and only if:
1. Repository inspection is complete across Phases 2, 3, and 4.
2. Phase 4 acceptance remains intact and uncompromised.
3. The application integration boundary is strictly defined.
4. All three model inference contracts are specified without modification.
5. The 13-feature contract is preserved in invariant order.
6. The temporal lookback and cold-start null semantics are rigorously specified.
7. The S0–S7 unified threat-state taxonomy is reproduced verbatim.
8. No fourth model, score fusion, retraining, or autonomous remediation is permitted.
9. Closed 33-file artifact hash boundary is preserved.
10. Component responsibility matrix and data flow are fully defined.

---

## 30. Open Questions / Explicit Assumptions

- **Assumption 1**: The application inference layer receives pre-aggregated 1-minute feature vectors as its canonical input boundary. Raw packet-to-flow aggregation is handled upstream.
- **Assumption 2**: In live deployment, network packet drops or clock skew are resolved by the upstream ingestion adapter before creating `window_id`.
- **Assumption 3**: System time advances monotonically; out-of-order windows must be buffered and sorted chronologically before invoking the LSTM lookback buffer.

---

## 31. Final Specification Verdict

```text
================================================================================
PHASE 5.1 SPECIFICATION VERDICT: ACCEPTED
================================================================================
The Application Integration Architecture & Contract Specification is fully
defined, contract-compliant, architecturally frozen, and ready for Phase 5.2
implementation upon formal authorization.
================================================================================
```
