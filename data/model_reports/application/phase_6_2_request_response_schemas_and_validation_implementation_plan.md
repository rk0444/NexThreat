# NexThreat — Phase 6.2 Implementation Plan (Revision 8)
# Request/Response Schemas & Validation Implementation Plan
## Final Authority Matrix Reconciliation & Targeted Audit Corrections Specification

**Document Version**: `8.0.0`  
**Phase**: `Phase 6.2 — Request/Response Schemas & Validation`  
**Status**: `PLAN ONLY — IMPLEMENTATION NOT AUTHORIZED`  
**Project**: `NexThreat — AI-Based Network Attack Forecasting from Network Traffic Data`  
**Tagline**: `Detect anomalies. Forecast attacks. Prevent damage.`  
**Authoritative Upstream Baselines**:
- `Phase 4 (Phases 4.1–4.7 ACCEPTED & FROZEN, 33/33 Artifacts SHA-256 Verified)`
- `Phase 5 (Phases 5.1–5.7 ACCEPTED & FROZEN, 22/22 Functional Gates Verified)`
- `Phase 6.1 (API / Backend Architecture & Contract Specification, APPROVED)`
**Repository Path**: `E:\Project\NexThreat`  
**Target Output Artifact**: `data/model_reports/application/phase_6_2_request_response_schemas_and_validation_implementation_plan.md`

---

## 1. Revision History & Audit Reconciliation

| Revision | Date | Status | Key Changes & Blockers Resolved |
|:---:|:---:|:---:|---|
| `1.0.0` | 2026-09-14 | REJECTED / AUDIT BLOCKERS | Initial plan drafted. Audited and identified five critical blockers: unauthorized physical domain bounds on features, contradictory dependency policy, overly permissive `Union[int, str]`, missing authority matrix, and vague response requirements. |
| `2.0.0` | 2026-09-14 | REJECTED / AUDIT BLOCKERS | Corrected initial blockers, but audit identified remaining authority ambiguities: `forecast_decision` string representation provenance, threshold ownership confusion, `class_probabilities` tolerance authority, `dataset_day` enum authority, `execution_metadata.schema` field naming, unclassified numerical rules, and missing audit gate V16. |
| `3.0.0` | 2026-09-14 | REJECTED / AUDIT BLOCKERS | Reconciled major fields, but audit required full field-by-field matrix, removal of 1e-4 tolerance, and strengthened V16 audit gate. |
| `4.0.0` | 2026-09-14 | REJECTED / AUDIT BLOCKERS | Addressed field citations and removed 1e-4 tolerance. However, review required explicit inclusion of the actual complete 24-field Authority Matrix, dedicated explanation separating upstream authority from validation permission, expansion of V16 to audit all schema attributes, exact timestamp parsing semantics, and verification of all citations against the repository. |
| `5.0.0` | 2026-09-14 | REJECTED / AUDIT BLOCKER | Audit identified that Section 5 lacked the fully rendered, untruncated 24-field Authority Matrix with every single field detailed directly in place across all 13 attributes; V16 required explicit auditing of all 16 attributes across the 24 fields; and the final audit table prematurely claimed PASS. |
| `6.0.0` | 2026-09-14 | REJECTED / AUDIT BLOCKER | Audit identified that Section 5 field-count and structure required reconciliation: `schema_version` and `engine` were combined into a single entry; `features` representation required formal verification of Format A vs. Format B; threshold fields required explicit verification as authoritative response fields; and Gate V16 required direct field-by-field auditing against the physical matrix. |
| `7.0.0` | 2026-09-14 | REJECTED / AUDIT BLOCKER | Audit identified two specific targeted blockers: (1) contradictory float32/coercion language where elements were claimed parsed as float32 while coercion was prohibited; (2) unsupported "bit-for-bit" terminology describing response field correspondence. |
| `8.0.0` | 2026-09-14 | **READY FOR FINAL AUDIT** | **Revision 8 (Targeted Audit Corrections)**:<br>1. **Resolved Float32 / Coercion Contradiction**: Inspected authoritative Phase 5 (`CanonicalInputRecord#L21: features: List[float]`, `validators.py:L140-164`) and Phase 6.1 (Sec 7.2, 9.1); established that `float32` is an internal model/numpy array representation instantiated inside Phase 5 (`validators.py:L149`), not an API contract requirement. Removed unauthorized float32 requirement from Phase 6.2; established that API contract accepts standard numeric finite floats (`List[float]`) without unauthorized conversion or coercion.<br>2. **Replaced Unsupported Phrasing**: Replaced "bit-for-bit" phrasing with precise structural correspondence language: "field-for-field and structurally correspond to the authoritative Phase 5 ApplicationOutputRecord and Phase 5.1 Section 17 response schema."<br>3. **Preserved Complete 24-Field Matrix**: Preserved the physically embedded 24-field response matrix (Fields 1 to 24) with all 13 required attributes directly visible per field.<br>4. **Preserved Independent Field Structure**: Preserved separate matrix rows for `execution_metadata.schema_version` (Field 23) and `execution_metadata.engine` (Field 24).<br>5. **Preserved Threshold Response Boundaries**: Preserved response integrity checks for `autoencoder.threshold` (Field 6) and `lstm.threshold` (Field 15) with zero threshold calculation/application.<br>6. **Preserved Gate V16 Field-by-Field Audit**: Maintained 16-dimension audit against the 24-field matrix.<br>7. **Preserved All Approved Safeguards**: Zero 1e-4 tolerance, exact `parse_timestamp` semantics, zero ML inference duplication, zero Phase 4/5 mutations. |

---

## 2. Governing Principle & Authoritative Hierarchy

The governing axiom of Phase 6 remains immutable:
> **Phase 6 exposes NexThreat; Phase 6 does not redefine NexThreat.**

Phase 6.2 implements only the request/response schema and validation boundary defined by the accepted Phase 6.1 specification and inherited Phase 4/5 contracts. It must not create competing application semantics.

```text
================================================================================
AUTHORITATIVE CONTRACT HIERARCHY
================================================================================
Phase 4 Frozen Contracts (33 Artifacts SHA-256, 3 Models, Frozen Thresholds)
              ↓
Phase 5 Accepted Contracts / Runtime (10-Step Orchestrator, State Manager, S0–S7)
              ↓
Phase 6.1 Accepted Architecture & Contract Specification
              ↓
Phase 6.2 Schema & Validation Implementation Plan (CURRENT REVISION 8 PLAN)
              ↓
Phase 6.3+ Endpoint Integration & Transport Handlers
================================================================================
```

### Core Rule on Validation Authority
A rule being technically reasonable, conventional, useful, secure, or present only as an internal defensive implementation detail does **NOT** make it a Phase 6.2 API contract. Every Phase 6.2 validation rule must trace directly to Phase 4, Phase 5, or Phase 6.1. If authority cannot be established from accepted upstream sources, it is excluded.

---

## 3. Explicit Separation: Upstream Authority vs. Phase 6.2 Validation Permission

A critical architectural distinction is enforced throughout this plan:

> **An upstream field, property, or rule being authoritative does NOT, by itself, authorize Phase 6.2 to introduce independent semantic validation.**
> 
> **Phase 6.2 may validate only the representation constraints that are explicitly permitted by Phase 4, Phase 5, or Phase 6.1.**
> 
> **Phase 6.2 must not reproduce upstream model decision logic, threshold application, state-machine logic, or other runtime semantics merely because those semantics exist upstream.**

This separation guarantees that Phase 6.2 strictly does **NOT** allow:
1. **Autoencoder Threshold Logic**: Phase 4 and Phase 5 own `AUTOENCODER_THRESHOLD = 0.003207791231673312` (`src/application/config.py#L39`). Phase 6.2 does **not** evaluate feature reconstruction errors, compare errors against threshold, or derive anomaly decisions. Phase 6.2 performs representation integrity checks on serialized outputs only.
2. **LSTM Threshold Logic**: Phase 4 and Phase 5 own `LSTM_THRESHOLD = 0.3` (`src/application/config.py#L40`). Phase 6.2 does **not** evaluate probabilities against threshold or determine forecast decisions.
3. **XGBoost Classification Logic**: Phase 4 and Phase 5 own the 8-class decision tree and argmax logic. Phase 6.2 does **not** compute probabilities, evaluate class boundaries, or infer attack presence.
4. **Threat State-Machine Logic ($S0..S7$)**: Phase 5 `src/application/threat_engine.py` owns the truth table $T: \{0,1\}^3 \to \{S0..S7\}$. Phase 6.2 does **not** recalculate threat states from decision tuples; it validates that the returned state code is a valid member of the discrete set `{"S0".."S7"}` (or `null` when ineligible).
5. **Model Inference Logic**: Phase 6.2 executes zero neural network or tree inference.
6. **Score Fusion / Weighted Voting**: No weighted score, ensemble metric, or meta-model calculation is permitted.
7. **Forecasting Logic / Temporal Tracking**: Phase 5 `state_manager.py` owns 60-second continuity, temporal lookback depth, and gap purging. Phase 6.2 maintains no history buffers.
8. **Preprocessing / Scaling Logic**: Phase 4 `robust_scaler.pkl` and `minmax_scaler.pkl` are applied inside Phase 5. Phase 6.2 does not scale, fit, or transform raw features.

---

## 4. Specific Upstream Authority Reconciliations

### 4.1 Resolution of Request `features` Representation & Elimination of Float32 Contradiction
- **Upstream Source Inspection**:
  - `Phase 5.1 Specification` Section 7.2 (`data/model_reports/phase_5_1_application_integration_architecture_and_contract.md#L242-247`):
    ```json
    "features": {
      "type": "array",
      "items": { "type": "number" },
      "minItems": 13,
      "maxItems": 13,
      "description": "13 canonical network traffic features in fixed order."
    }
    ```
  - `src/application/schemas.py:CanonicalInputRecord` (line 21): `features: List[float]` (standard Python float sequence).
  - `src/application/validators.py` (lines 140–164): Accepts a sequence of 13 numeric values. Lines 151–158 verify numeric type and reject booleans. Line 159 evaluates `f_val = float(val)`. Non-finite values are rejected at line 160. Line 149 allocates an internal numpy array: `features_array = np.empty(13, dtype=np.float32)`.
- **Contract Determination on Float32**:
  - `float32` is strictly an **internal Phase 5 runtime and numpy model representation** instantiated inside `src/application/validators.py:L149` for feeding into scikit-learn/PyTorch scalers.
  - The external API and application schema contract defined by `CanonicalInputRecord#L21` accepts standard Python `float` (JSON numbers).
  - Phase 6.2 is **NOT** authorized to require or perform conversion to `float32`. Requiring `float32` in the API contract is unsupported by upstream authority.
- **Contract Determination on Coercion and Normalization**:
  - **Coercion**: Strictly prohibited. Non-numeric types (strings `"25.4"`, booleans `true`/`false`, objects, `null`) are rejected without coercion. Valid integer inputs (e.g. `124`) are accepted as standard numbers and represented as standard Python floats in `List[float]`.
  - **Normalization**: Strictly prohibited. Phase 6.2 does not normalize, scale, center, or clip feature values.
- **Contract Determination on Formats A & B**:
  - **Format A (Canonical Array)**: Direct pass-through of 13 numeric floats in canonical order.
  - **Format B (Named Object Adapter)**: Authoritative in Phase 6.1 Section 7.1 and 7.2 (`phase_6_1_api_backend_architecture_and_contract.md#L296-350`). Exactly 13 named keys (`flow_count`, `packet_rate`, `byte_rate`, `mean_flow_duration`, `std_flow_duration`, `short_flow_ratio`, `mean_packet_size`, `packet_length_variability`, `fwd_bwd_packet_ratio`, `unique_dst_ports`, `unique_dst_ips`, `tcp_flow_ratio`, `syn_packet_ratio`).
  - **Dictionary-to-Array Adapter Authority**: Phase 6.1 Section 7.1 lines 301–302 explicitly authorizes the API layer adapter to validate Format B and map it into the canonical 13-element list of floats before passing to the Phase 5 pipeline.

### 4.2 Resolution of Threshold Response Fields
- **Forensic Verification**:
  - `autoencoder.threshold`: Formally established as an authoritative response field in:
    - `Phase 5.1 Specification` Section 17 (`phase_5_1_application_integration_architecture_and_contract.md#L459`): `"threshold": { "type": "number", "const": 0.003207791231673312 }` under `autoencoder`.
    - `src/application/schemas.py:AutoencoderOutputRecord` (line 27): `threshold: float`.
    - `Phase 6.1 Specification` Section 8.1 (`phase_6_1_api_backend_architecture_and_contract.md#L388`): `"threshold": 0.003207791231673312`.
  - `lstm.threshold`: Formally established as an authoritative response field in:
    - `Phase 5.1 Specification` Section 17 (`phase_5_1_application_integration_architecture_and_contract.md#L492`): `"threshold": { "type": "number", "const": 0.3 }` under `lstm`.
    - `src/application/schemas.py:LSTMOutputRecord` (line 63): `threshold: float`.
    - `Phase 6.1 Specification` Section 8.1 (`phase_6_1_api_backend_architecture_and_contract.md#L410`): `"threshold": 0.3`.
- **Phase 6.2 Boundary**: Both threshold fields are **AUTHORITATIVE RESPONSE FIELDS**. They must be preserved in the response schema. Phase 6.2 is permitted to perform a **Response Integrity Check** confirming the serialized field value equals the frozen constant. Phase 6.2 is **STRICTLY FORBIDDEN** from calculating, applying, comparing, or mutating thresholds.

### 4.3 De-authorization of API `class_probabilities` Sum Tolerance (`1e-4`)
- **Forensic Audit**: In Phase 5 runtime code (`src/application/validators.py` lines 253–257), `abs(prob_sum - 1.0) > 1e-4` exists as an internal assert-only defensive check within the application core.
- **Contract Determination**: In the formal Phase 5.1 specification (`data/model_reports/phase_5_1_application_integration_architecture_and_contract.md#L474-478`), `class_probabilities` is defined as:
  ```json
  "class_probabilities": {
    "type": ["array", "null"],
    "items": { "type": "number" },
    "description": "OPTIONAL: 8-class probability distribution."
  }
  ```
  Neither Phase 5.1 nor Phase 6.1 authorizes the API validation layer to independently impose a numerical sum tolerance.
- **Revision 8 Contract**: **Phase 6.2 MUST NOT independently validate XGBoost probability normalization using a `1e-4` tolerance.** API validation on `class_probabilities` is strictly structural: when present, it must be an array of length 8 with finite numeric values in $[0.0, 1.0]$. The `1e-4` sum tolerance remains an internal Phase 5 assertion and is completely removed from the Phase 6.2 API validation contract.

### 4.4 Timestamp Validation Authority & Exact Acceptance Semantics
- **Authoritative Source**:
  - `Phase 5.1 Specification` (`data/model_reports/phase_5_1_application_integration_architecture_and_contract.md#L226-230`):
    ```json
    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO-8601 or standard datetime representing window start (e.g. 2017-07-03T13:55:00)."
    }
    ```
  - `src/application/validators.py:parse_timestamp` (lines 46–67): Explicitly defines and enforces the accepted timestamp parsing formats:
    1. `"%Y-%m-%dT%H:%M:%S"`
    2. `"%Y-%m-%d %H:%M:%S"`
    3. `"%Y-%m-%dT%H:%M:%S.%f"`
    4. `"%Y-%m-%d %H:%M:%S.%f"`
    5. Fallback via `datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))`.
  - `Phase 6.1 Specification` Section 5.1 and Section 8.3.
- **Phase 6.2 Permitted Validation**: Validates that incoming `timestamp` is a non-empty string that successfully parses under the exact accepted datetime semantics defined in `src/application/validators.py:parse_timestamp` without raising `InputValidationError`. Phase 6.2 does not impose an arbitrary narrower grammar.

### 4.5 Feature `finite` Validation Authority
- **Authoritative Source**:
  - `Phase 5.1 Specification` (`data/model_reports/phase_5_1_application_integration_architecture_and_contract.md#L545`): "All 13 features are present, numeric, non-NaN, and non-infinite."
  - `Phase 5.1 Specification` (`data/model_reports/phase_5_1_application_integration_architecture_and_contract.md#L561`): "`INPUT_VALIDATION_ERROR`: Missing features, count != 13, NaN/Inf values, invalid window_id -> Reject window."
  - `src/application/validators.py` (lines 160–164): Explicitly checks `math.isnan(f_val) or math.isinf(f_val)` and raises `InputValidationError("NaN and Inf are forbidden")`.
  - `src/application/stream_adapter.py` (lines 66–70): Rejects non-finite values.
  - `Phase 6.1 Specification` Section 9.2 Rule 3: Explicitly bans `NaN`, `+Infinity`, `-Infinity`.
- **Phase 6.2 Permitted Validation**: Fully authorized **INHERITED CONTRACT**. API validation strictly rejects `NaN`, `+Infinity`, and `-Infinity` values across all feature elements.

### 4.6 `global_position >= 1` Authority
- **Authoritative Source**:
  - `Phase 5.1 Specification` (`data/model_reports/phase_5_1_application_integration_architecture_and_contract.md#L236-240`):
    ```json
    "global_position": { "type": "integer", "minimum": 1, "description": "Optional chronological sequence index." }
    ```
  - `Phase 5.1 Specification` (`data/model_reports/phase_5_1_application_integration_architecture_and_contract.md#L442-445`):
    ```json
    "global_position": { "type": ["integer", "null"], "minimum": 1 }
    ```
  - `src/application/validators.py` (lines 363–364):
    ```python
    if not isinstance(app_record.global_position, int) or app_record.global_position < 1:
        raise IntegrationContractError(f"Invalid global_position in application output: {app_record.global_position}")
    ```
  - `Phase 6.1 Specification` Section 8.3: `global_position: Integer >= 1`.
- **Phase 6.2 Permitted Validation**: Fully authorized **INHERITED CONTRACT**. In response validation, `global_position` (when present and non-null) must be an integer $\ge 1$.

### 4.7 `inference_latency_ms >= 0.0` Authority
- **Authoritative Source**:
  - `src/application/validators.py` (lines 378–383):
    ```python
    if (not isinstance(app_record.execution_metadata.inference_latency_ms, (int, float, np.number))
        or app_record.execution_metadata.inference_latency_ms < 0.0):
        raise IntegrationContractError(f"Invalid inference_latency_ms in metadata: {app_record.execution_metadata.inference_latency_ms}")
    ```
  - `src/application/verification/verify_phase_5_6.py` (line 347): `assert out.execution_metadata.inference_latency_ms >= 0.0`.
  - `Phase 6.1 Specification` Section 8.3 and Section 18.
- **Phase 6.2 Permitted Validation**: Fully authorized **REPRESENTATION INTEGRITY CHECK**. Asserts that reported latency from Phase 5 is numeric and non-negative.

### 4.8 Payload Size (10 MB) and Stream Batch Size (5,000) Authority
- **Authoritative Source**:
  - `src/application/service.py` (lines 34–35):
    ```python
    MAX_REQUEST_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
    MAX_STREAM_RECORDS: int = 5000
    ```
  - `src/application/service.py` (lines 204–210, 247–253): Enforces HTTP 413 `PAYLOAD_TOO_LARGE` for bytes $> 10\,\text{MB}$ and HTTP 400 `STREAM_TOO_LARGE` for records $> 5,000$.
  - `Phase 6.1 Specification` Section 6.1, Section 14, Section 15.2.
- **Phase 6.2 Permitted Validation**: Fully authorized **INHERITED CONTRACT**. Transport-layer operational boundaries: max payload $10\,\text{MB}$, max stream batch size $5,000$ records.

### 4.9 `dataset_day` Enum vs. Nullability Separation
- **Authoritative Source**:
  - `Phase 5.1 Specification` (`data/model_reports/phase_5_1_application_integration_architecture_and_contract.md#L231-235`):
    ```json
    "dataset_day": {
      "type": "string",
      "enum": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Unknown"]
    }
    ```
  - `Phase 5.1 Specification` (`data/model_reports/phase_5_1_application_integration_architecture_and_contract.md#L446-449`):
    `"dataset_day": { "type": "string", "description": "OPTIONAL: Partition calendar day (e.g. Monday)." }`
  - `src/application/validators.py:VALID_DAYS` (line 43) and `derive_dataset_day()` (lines 69–77).
- **Phase 6.2 Contract Structure**:
  - **Type**: `string | null`
  - **Nullable**: `YES` (`true`)
  - **Allowed Non-Null Enum Values**: Strictly `{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Unknown"}`.
  - **Nullability Distinction**: `null` represents the absence of a day partition (nullable), while the non-null string domain is strictly the 6-member enum set.

### 4.10 LSTM `forecast_decision` Representation Authority
- **Authoritative Source**:
  - `Phase 5.1 Specification` (`data/model_reports/phase_5_1_application_integration_architecture_and_contract.md#L493`):
    ```json
    "forecast_decision": { "type": ["integer", "string"], "enum": [0, 1, "unavailable"] }
    ```
  - `src/application/schemas.py:LSTMOutputRecord` (line 64):
    `forecast_decision: Union[int, str]  # 0, 1, or "unavailable"`
  - `src/application/validators.py:validate_lstm_output` (lines 280, 294):
    Asserts `forecast_decision in (0, 1)` when `is_eligible = True`, and `forecast_decision == "unavailable"` when `is_eligible = False`.
- **Phase 6.2 Permitted Validation**:
  - **Type**: `int | str`
  - **Allowed Values**: Exactly `0`, `1`, or `"unavailable"`.
  - **Nullable**: `NO` (never null).
  - **Ineligible Behavior**: Takes the constant string `"unavailable"` when `is_eligible = False`.
  - **CRITICAL DISTINCTION**: The string `"unavailable"` is an **LSTM model-output field value**. It is **NOT** a threat state. Threat state remains `null` when LSTM is ineligible. `LSTM_UNAVAILABLE` remains strictly forbidden as a threat state.

---

## 5. Complete 24-Field Authority Matrix

The following embedded matrix establishes the complete authority, exact citations, and permitted validation scope for every field across the Phase 6.2 schemas. The response schema `ApplicationOutputRecord` consists of **exactly 24 independently auditable fields**.

### 5.1 Request Contract Specification (Input Schema)

| Request Field | Type | Req? | Null? | Enum / Format | Numerical Constraint | Semantic Constraint | Transformation / Adapter | Upstream Authority | Permitted Validation |
|---|:---:|:---:|:---:|---|---|---|---|---|---|
| `window_id` | `str` | Yes | No | Regex `^[0-9]{8}_[0-9]{4}$` | None | Timeline join key; format `YYYYMMDD_HHMM` | Preserve exact string identity; no coercion | Phase 5.1 Sec 7.1 L223; `validators.py:L41,127`; Phase 6.1 Sec 7.1 L303 | Assert non-empty string matching regex; reject integer, boolean, null. |
| `timestamp` | `str` | Yes | No | Accepted datetime formats (`parse_timestamp`) | None | Window start time in UTC / local traffic time | Parse via accepted datetime formats to validate | Phase 5.1 Sec 7.1 L228; `validators.py:L46-67`; Phase 6.1 Sec 7.1 L311 | Assert non-empty string parseable under exact Phase 5 datetime semantics. |
| `features` (Format A) | `List[float]` | Yes | No | None | Length $== 13$; elements finite | 13 canonical features in fixed order | Direct pass-through; preserve float numeric values | Phase 4.1; Phase 5.1 Sec 7.2 L242; `validators.py:L140-164`; Phase 6.1 Sec 7.2 L308-328 | Assert length 13, numeric elements, finite (no `NaN`, `+Inf`, `-Inf`, `bool`). No normalization/scaling. |
| `features` (Format B) | `Dict[str, float]` | Yes | No | Exact 13 canonical keys | 13 keys; all values finite | Canonical named feature dictionary | Authorized adapter maps 13 named keys to canonical 13-element float array | Phase 6.1 Sec 7.1 & 7.2 L296-350 | Assert exact 13 keys present, 0 extra keys, numeric, finite; map to array. No normalization/scaling. |

---

### 5.2 Complete 24-Field Response Authority Master Table

| # | Field Path | Type | Req? | Null? | Enum / Format | Numerical Constraint | Semantic Constraint | Transformation / Coercion | Authority Layer | Exact Source File | Exact Source Section / Class / Function | Exact Line Reference | Phase 6.2 Permitted Validation |
|:---:|---|:---:|:---:|:---:|---|---|---|---|:---:|---|---|:---:|---|
| 1 | `window_id` | `str` | Yes | No | Regex `^[0-9]{8}_[0-9]{4}$` | None | Timeline join key; format `YYYYMMDD_HHMM` | No coercion; preserve string identity | Phase 5.1 / 5.5 / 6.1 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 7.1 & 17`; `WINDOW_ID_PATTERN`, `validate_canonical_input` | `p5_1:L223,436,544`; `validators.py:L41,127` | Assert non-empty `str`, regex match. Reject `int`, `bool`, `null`. |
| 2 | `timestamp` | `str` | Yes | No | Exact accepted datetime formats | None | Window start time in UTC / local traffic time | Parse via accepted datetime formats; serialize as string | Phase 5.1 / 5.5 / 6.1 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 7.1 & 17`; `parse_timestamp` | `p5_1:L228,440`; `validators.py:L46-67` | Assert non-empty `str`, parseable via accepted datetime semantics. |
| 3 | `global_position` | `int` | Opt | Yes | None | Integer $\ge 1$ | Timeline order index only; not a model join key | None | Phase 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 7.1 & 17`; `validate_application_output_record` | `p5_1:L238,443`; `validators.py:L363` | Response validation: if present and non-null, assert `int >= 1`. |
| 4 | `dataset_day` | `str` | Opt | Yes | `Monday`..`Friday`, `Unknown` | None | Day of week partition; null when unpartitioned | None | Phase 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 7.1 & 17`; `VALID_DAYS`, `derive_dataset_day` | `p5_1:L233,447`; `validators.py:L43,69-77` | Response validation: if present and non-null, assert in 6-member enum set. |
| 5 | `autoencoder.reconstruction_mse` | `float` | Yes | No | None | Finite float $\ge 0.0$ | Autoencoder reconstruction error metric | None | Phase 4.2 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 10 & 17`; `validate_autoencoder_output` | `p5_1:L458`; `validators.py:L197-201` | Response integrity check: assert finite float $\ge 0.0$. |
| 6 | `autoencoder.threshold` | `float` | Yes | No | Constant `0.003207791231673312` | Matches Phase 4 frozen constant | Frozen Autoencoder decision boundary | None | Phase 4.2 / 5.1 / 5.2 / 6.1 | `src/application/config.py`; `src/application/schemas.py`; `phase_6_1_specification.md` | `AUTOENCODER_THRESHOLD`; `AutoencoderOutputRecord`; `Phase 6.1 Sec 8.1` | `config.py:L39`; `schemas.py:L27`; `p6_1:L388` | Response integrity check: assert matches upstream constant. |
| 7 | `autoencoder.is_anomaly` | `int` | Yes | No | `enum: [0, 1]` | Discrete integer $\in \{0, 1\}$ | Autoencoder decision: $1 \iff \text{MSE} > \tau_{\text{ae}}$ | None (strictly integer, reject boolean) | Phase 4.2 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 10 & 17`; `validate_autoencoder_output` | `p5_1:L460`; `validators.py:L206-211` | Response validation: assert `int in (0, 1)`. Reject `bool`. |
| 8 | `xgboost.predicted_class_index` | `int` | Yes | No | Range `0..7` | Discrete integer $\in [0..7]$ | XGBoost argmax predicted class index | None | Phase 4.3 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 11 & 17`; `validate_xgboost_output` | `p5_1:L471`; `validators.py:L223-227` | Response validation: assert `int in range(8)`. |
| 9 | `xgboost.predicted_class_name` | `str` | Yes | No | 8-class name string | None | Human-readable attack class name | None | Phase 4.3 / 5.1 / 5.5 | `src/application/config.py`; `src/application/validators.py` | `XGBOOST_INDEX_TO_CLASS`; `validate_xgboost_output` | `config.py:L63-73`; `validators.py:L228` | Response validation: assert matches authoritative class mapping. |
| 10 | `xgboost.is_attack` | `int` | Yes | No | `enum: [0, 1]` | Discrete integer $\in \{0, 1\}$ | XGBoost decision: $1 \iff \text{class\_index} > 0$ | None (strictly integer, reject boolean) | Phase 4.3 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 11 & 17`; `validate_xgboost_output` | `p5_1:L473`; `validators.py:L234-239` | Response validation: assert `int in (0, 1)`. Reject `bool`. |
| 11 | `xgboost.class_probabilities` | `List[float]` | Opt | Yes | None | Length 8; elements finite in $[0.0, 1.0]$ | 8-class probability distribution vector | None (NO 1e-4 sum tolerance in API) | Phase 4.3 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/schemas.py` | `Phase 5.1 Sec 11 & 17`; `XGBoostOutputRecord` | `p5_1:L474`; `schemas.py:L43` | Response validation: if present, assert length 8, finite floats in $[0.0, 1.0]$. |
| 12 | `lstm.is_eligible` | `bool` | Yes | No | `true` / `false` | None | Lookback buffer depth $\ge 10$ check | None (strictly boolean, reject integer) | Phase 4.4 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 12 & 17`; `validate_lstm_output` | `p5_1:L489`; `validators.py:L265-289` | Response validation: assert boolean type (`true`/`false`). |
| 13 | `lstm.ineligibility_reason` | `str` | Cond | Yes | None | None | Reason when `is_eligible=false`; null when eligible | None | Phase 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 12 & 17`; `validate_lstm_output` | `p5_1:L490`; `validators.py:L286,298` | Response validation: assert non-null string iff `is_eligible=false`. |
| 14 | `lstm.forecast_probability` | `float` | Cond | Yes | None | Finite float in $[0.0, 1.0]$ when eligible | Future attack probability; null when ineligible | None | Phase 4.4 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 12 & 17`; `validate_lstm_output` | `p5_1:L491`; `validators.py:L270-274` | Response validation: assert finite float in $[0.0, 1.0]$ iff eligible. |
| 15 | `lstm.threshold` | `float` | Yes | No | Constant `0.3` | Matches Phase 4 frozen constant | Frozen LSTM decision boundary | None | Phase 4.4 / 5.1 / 5.2 / 6.1 | `src/application/config.py`; `src/application/schemas.py`; `phase_6_1_specification.md` | `LSTM_THRESHOLD`; `LSTMOutputRecord`; `Phase 6.1 Sec 8.1` | `config.py:L40`; `schemas.py:L63`; `p6_1:L410` | Response integrity check: assert matches upstream constant. |
| 16 | `lstm.forecast_decision` | `int` / `str` | Yes | No | `enum: [0, 1, "unavailable"]` | `0` or `1` when eligible; `"unavailable"` if not | LSTM decision; never a threat state | None | Phase 4.4 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 17`; `validate_lstm_output` | `p5_1:L493`; `validators.py:L280,294` | Response validation: assert in `{0, 1, "unavailable"}`. |
| 17 | `threat_inference.is_eligible` | `bool` | Yes | No | `true` / `false` | None | Threat engine eligibility (equals `lstm.is_eligible`) | None (strictly boolean, reject integer) | Phase 4.5 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 14 & 17`; `validate_threat_inference_output` | `p5_1:L505`; `validators.py:L312-327` | Response validation: assert boolean type (`true`/`false`). |
| 18 | `threat_inference.threat_state_code` | `str` | Cond | Yes | `enum: ["S0".."S7"]` | None | Unified threat state code; null if ineligible | None | Phase 4.5 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/threat_engine.py` | `Phase 5.1 Sec 14 & 17`; `evaluate_threat_state` | `p5_1:L506`; `threat_engine.py:L56` | Response validation: if eligible, assert in `{"S0".."S7"}`. Reject `S8`. |
| 19 | `threat_inference.threat_state_name` | `str` | Cond | Yes | Exact canonical names | None | Canonical state name; null if ineligible | None | Phase 4.5 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/threat_engine.py` | `Phase 5.1 Sec 14 & 17`; `evaluate_threat_state` | `p5_1:L507-517`; `threat_engine.py:L57` | Response validation: if eligible, assert matches canonical state name mapping. |
| 20 | `threat_inference.priority_tier` | `str` | Cond | Yes | `enum: ["P1".."P4"]` | None | Operational triage tier; null if ineligible | None | Phase 4.5 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/threat_engine.py` | `Phase 5.1 Sec 14 & 17`; `evaluate_threat_state` | `p5_1:L518`; `threat_engine.py:L71` | Response validation: if eligible, assert in `{"P1".."P4"}`. |
| 21 | `threat_inference.decision_tuple` | `List[int]` | Cond | Yes | Length 3; elements $\in \{0, 1\}$ | Values in $\{0, 1\}$ | Decision triplet `[b_ae, b_xgb, b_lstm]`; null if inelig | None | Phase 4.5 / 5.1 / 5.5 | `phase_5_1_specification.md`; `src/application/validators.py` | `Phase 5.1 Sec 14 & 17`; `validate_threat_inference_output` | `p5_1:L519-524`; `validators.py:L350-353` | Response validation: if eligible, assert 3 ints $\in \{0, 1\}$. |
| 22 | `execution_metadata.inference_latency_ms` | `float` | Yes | No | None | Finite float $\ge 0.0$ | Inference processing time in milliseconds | None | Phase 5.1 / 5.5 | `src/application/schemas.py`; `src/application/validators.py` | `ExecutionMetadataRecord`; `validate_application_output_record` | `schemas.py:L96`; `validators.py:L379` | Response validation: assert finite float $\ge 0.0$. |
| 23 | `execution_metadata.schema_version` | `str` | Yes | No | Constant `"1.0.0"` | None | API contract version identifier | None | Phase 5.2 / 6.1 | `src/application/schemas.py`; `phase_6_1_specification.md` | `ExecutionMetadataRecord`; `Phase 6.1 Sec 8.1` | `schemas.py:L97`; `phase_6_1:L360,422` | Response integrity check: assert exact constant string `"1.0.0"`. |
| 24 | `execution_metadata.engine` | `str` | Yes | No | Constant `"NexThreat-Phase5.2"` | None | Execution engine release identifier | None | Phase 5.2 / 6.1 | `src/application/schemas.py`; `phase_6_1_specification.md` | `ExecutionMetadataRecord`; `Phase 6.1 Sec 8.1` | `schemas.py:L98`; `phase_6_1:L361,423` | Response integrity check: assert exact constant string `"NexThreat-Phase5.2"`. |

---

### 5.3 Exhaustive Field-by-Field Authority Specification (Fields 1 to 24)

Every single field in the 24-field response matrix is expanded below with its complete 13-attribute evidence record directly visible in place:

#### Field 1: `window_id`
1. **Field**: `window_id`
2. **Type**: `str`
3. **Required / Optional**: Required (in both request payload and response record).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: Regex `^[0-9]{8}_[0-9]{4}$`.
6. **Numerical Constraint**: None.
7. **Semantic Constraint**: Timeline join key and temporal window identifier formatted as `YYYYMMDD_HHMM`.
8. **Transformation / Normalization / Conversion / Coercion**: None; preserve exact string identity without mutation.
9. **Authority Layer**: Phase 5.1 / Phase 5.5 / Phase 6.1.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`, `data/model_reports/application/phase_6_1_api_backend_architecture_and_contract.md`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 7.1 & 17`; `WINDOW_ID_PATTERN` & `validate_canonical_input`; `Phase 6.1 Sec 7.1 & 8.3`.
12. **Exact Line Reference**: `phase_5_1:L223,436,544`; `validators.py:L41,127-133`; `phase_6_1:L236,368`.
13. **Phase 6.2 Permitted Validation**: In request validation: Assert non-empty string matching `WINDOW_ID_PATTERN`. In response validation: Assert non-empty string matching pattern. Reject integer, boolean, null, or malformed strings. Phase 6.2 does not generate or alter window IDs.

#### Field 2: `timestamp`
1. **Field**: `timestamp`
2. **Type**: `str`
3. **Required / Optional**: Required (in both request payload and response record).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: Exact datetime formats supported by `src/application/validators.py:parse_timestamp`: `"%Y-%m-%dT%H:%M:%S"`, `"%Y-%m-%d %H:%M:%S"`, `"%Y-%m-%dT%H:%M:%S.%f"`, `"%Y-%m-%d %H:%M:%S.%f"`, or `datetime.datetime.fromisoformat()`.
6. **Numerical Constraint**: None.
7. **Semantic Constraint**: Window start timestamp in UTC or local network traffic time.
8. **Transformation / Normalization / Conversion / Coercion**: Parse via accepted datetime formats to confirm structural validity; serialize as string in canonical records.
9. **Authority Layer**: Phase 5.1 / Phase 5.5 / Phase 6.1.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`, `data/model_reports/application/phase_6_1_api_backend_architecture_and_contract.md`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 7.1 & 17`; `parse_timestamp`; `Phase 6.1 Sec 5.1 & 8.3`.
12. **Exact Line Reference**: `phase_5_1:L228,440`; `validators.py:L46-67`; `phase_6_1:L237,369`.
13. **Phase 6.2 Permitted Validation**: Assert non-empty string that parses successfully under the exact accepted datetime semantics of `src/application/validators.py:parse_timestamp` without raising `InputValidationError`. Phase 6.2 does not enforce an arbitrary narrower grammar.

#### Field 3: `global_position`
1. **Field**: `global_position`
2. **Type**: `int`
3. **Required / Optional**: Optional (in request and response).
4. **Nullable / Non-nullable**: Nullable (`int | null`).
5. **Enum / Format**: None.
6. **Numerical Constraint**: Integer $\ge 1$.
7. **Semantic Constraint**: Monotonic chronological sequence index if part of a master dataset timeline; not a model join key.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 7.1 & 17`; `validate_application_output_record`.
12. **Exact Line Reference**: `phase_5_1:L238,443`; `validators.py:L363`.
13. **Phase 6.2 Permitted Validation**: In response validation: if present and non-null, assert `int >= 1`. Phase 6.2 does not compute or increment sequence indices.

#### Field 4: `dataset_day`
1. **Field**: `dataset_day`
2. **Type**: `str`
3. **Required / Optional**: Optional (in request and response).
4. **Nullable / Non-nullable**: Nullable (`str | null`).
5. **Enum / Format**: Discrete enum: `{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Unknown"}`.
6. **Numerical Constraint**: None.
7. **Semantic Constraint**: Partition calendar day of traffic capture; null when unpartitioned.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 7.1 & 17`; `VALID_DAYS`, `derive_dataset_day`.
12. **Exact Line Reference**: `phase_5_1:L233,447`; `validators.py:L43,69-77`.
13. **Phase 6.2 Permitted Validation**: In response validation: if present and non-null, assert string belongs to the 6-member enum set. Distinct from nullability. Phase 6.2 does not calculate or assign day partitions.

#### Field 5: `autoencoder.reconstruction_mse`
1. **Field**: `autoencoder.reconstruction_mse`
2. **Type**: `float`
3. **Required / Optional**: Required (in response).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: None.
6. **Numerical Constraint**: Finite float $\ge 0.0$.
7. **Semantic Constraint**: Autoencoder mean squared reconstruction error.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 4.2 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 10 & 17`; `validate_autoencoder_output`.
12. **Exact Line Reference**: `phase_5_1:L458`; `validators.py:L197-201`.
13. **Phase 6.2 Permitted Validation**: In response validation: assert finite float $\ge 0.0$. Phase 6.2 does not calculate or infer reconstruction error.

#### Field 6: `autoencoder.threshold`
1. **Field**: `autoencoder.threshold`
2. **Type**: `float`
3. **Required / Optional**: Required (in response).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: Constant `0.003207791231673312`.
6. **Numerical Constraint**: Bit-exact match with Phase 4 frozen constant.
7. **Semantic Constraint**: Frozen Autoencoder anomaly decision boundary.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 4.2 / Phase 5.1 / Phase 5.2 / Phase 6.1.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/config.py`, `src/application/schemas.py`, `src/application/validators.py`, `data/model_reports/application/phase_6_1_api_backend_architecture_and_contract.md`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 17`; `AutoencoderOutputRecord`; `AUTOENCODER_THRESHOLD`; `validate_autoencoder_output`; `Phase 6.1 Sec 8.1`.
12. **Exact Line Reference**: `phase_5_1:L459`; `config.py:L39`; `schemas.py:L27`; `validators.py:L202`; `phase_6_1:L388`.
13. **Phase 6.2 Permitted Validation**: Response integrity check: assert returned threshold matches upstream constant. Phase 6.2 does not define, evaluate, apply, or mutate the threshold.

#### Field 7: `autoencoder.is_anomaly`
1. **Field**: `autoencoder.is_anomaly`
2. **Type**: `int`
3. **Required / Optional**: Required (in response).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: Discrete integer `enum: [0, 1]`.
6. **Numerical Constraint**: Discrete integer $\in \{0, 1\}$.
7. **Semantic Constraint**: Autoencoder decision: $1 \iff \text{reconstruction\_mse} > \tau_{\text{ae}}$.
8. **Transformation / Normalization / Conversion / Coercion**: None (strictly discrete integer; boolean `true`/`false` rejected).
9. **Authority Layer**: Phase 4.2 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 10 & 17`; `validate_autoencoder_output`.
12. **Exact Line Reference**: `phase_5_1:L460`; `validators.py:L206-211`.
13. **Phase 6.2 Permitted Validation**: In response validation: assert `int in (0, 1)`. Reject boolean. Phase 6.2 does not evaluate MSE against threshold.

#### Field 8: `xgboost.predicted_class_index`
1. **Field**: `xgboost.predicted_class_index`
2. **Type**: `int`
3. **Required / Optional**: Required (in response).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: Range `0..7`.
6. **Numerical Constraint**: Discrete integer $\in [0..7]$.
7. **Semantic Constraint**: Argmax index of predicted attack class.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 4.3 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 11 & 17`; `validate_xgboost_output`.
12. **Exact Line Reference**: `phase_5_1:L471`; `validators.py:L223-227`.
13. **Phase 6.2 Permitted Validation**: In response validation: assert `int in range(8)`. Phase 6.2 does not calculate argmax or tree inferences.

#### Field 9: `xgboost.predicted_class_name`
1. **Field**: `xgboost.predicted_class_name`
2. **Type**: `str`
3. **Required / Optional**: Required (in response).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: 8 canonical class names (`BENIGN`, `DoS`, `PortScan`, `DDoS`, `BruteForce`, `Botnet`, `WebAttack`, `Infiltration`).
6. **Numerical Constraint**: None.
7. **Semantic Constraint**: Canonical attack class label corresponding to predicted class index.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 4.3 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `src/application/config.py`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `XGBOOST_INDEX_TO_CLASS`; `validate_xgboost_output`.
12. **Exact Line Reference**: `config.py:L63-73`; `validators.py:L228`.
13. **Phase 6.2 Permitted Validation**: In response validation: assert string matches the authoritative class mapping for `predicted_class_index`. Phase 6.2 does not infer class names.

#### Field 10: `xgboost.is_attack`
1. **Field**: `xgboost.is_attack`
2. **Type**: `int`
3. **Required / Optional**: Required (in response).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: Discrete integer `enum: [0, 1]`.
6. **Numerical Constraint**: Discrete integer $\in \{0, 1\}$.
7. **Semantic Constraint**: XGBoost binary decision: $1 \iff \text{predicted\_class\_index} > 0$.
8. **Transformation / Normalization / Conversion / Coercion**: None (strictly discrete integer; boolean rejected).
9. **Authority Layer**: Phase 4.3 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 11 & 17`; `validate_xgboost_output`.
12. **Exact Line Reference**: `phase_5_1:L473`; `validators.py:L234-239`.
13. **Phase 6.2 Permitted Validation**: In response validation: assert `int in (0, 1)`. Reject boolean. Phase 6.2 does not compute the binary decision.

#### Field 11: `xgboost.class_probabilities`
1. **Field**: `xgboost.class_probabilities`
2. **Type**: `List[float]`
3. **Required / Optional**: Optional (in response).
4. **Nullable / Non-nullable**: Nullable (`List[float] | null`).
5. **Enum / Format**: None.
6. **Numerical Constraint**: Vector length 8; all elements finite numbers in $[0.0, 1.0]$.
7. **Semantic Constraint**: 8-class probability distribution over canonical attack taxonomy.
8. **Transformation / Normalization / Conversion / Coercion**: None (NO 1e-4 sum tolerance in Phase 6.2 API validation).
9. **Authority Layer**: Phase 4.3 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/schemas.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 11 & 17`; `XGBoostOutputRecord`.
12. **Exact Line Reference**: `phase_5_1:L474`; `schemas.py:L43`.
13. **Phase 6.2 Permitted Validation**: In response validation: if present and non-null, assert length 8 with finite floats in $[0.0, 1.0]$. Phase 6.2 does not re-sum probabilities or enforce sum tolerance.

#### Field 12: `lstm.is_eligible`
1. **Field**: `lstm.is_eligible`
2. **Type**: `bool`
3. **Required / Optional**: Required (in response).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: Boolean `true` or `false`.
6. **Numerical Constraint**: None.
7. **Semantic Constraint**: Flag indicating whether sequence history meets minimum lookback buffer depth $\ge 10$.
8. **Transformation / Normalization / Conversion / Coercion**: None (strictly boolean; reject integers `0`/`1`).
9. **Authority Layer**: Phase 4.4 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 12 & 17`; `validate_lstm_output`.
12. **Exact Line Reference**: `phase_5_1:L489`; `validators.py:L265-289`.
13. **Phase 6.2 Permitted Validation**: In response validation: assert boolean type. Phase 6.2 does not evaluate buffer depth or sequence tracking.

#### Field 13: `lstm.ineligibility_reason`
1. **Field**: `lstm.ineligibility_reason`
2. **Type**: `str`
3. **Required / Optional**: Conditional (in response).
4. **Nullable / Non-nullable**: Nullable (`str | null`; non-null iff `is_eligible = false`, null when `is_eligible = true`).
5. **Enum / Format**: None.
6. **Numerical Constraint**: None.
7. **Semantic Constraint**: Diagnostic explanation for forecast ineligibility (e.g. cold start, temporal gap).
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 12 & 17`; `validate_lstm_output`.
12. **Exact Line Reference**: `phase_5_1:L490`; `validators.py:L286,298`.
13. **Phase 6.2 Permitted Validation**: In response validation: assert non-null string if `is_eligible = false`; assert `null` if `is_eligible = true`. Phase 6.2 does not generate reasons.

#### Field 14: `lstm.forecast_probability`
1. **Field**: `lstm.forecast_probability`
2. **Type**: `float`
3. **Required / Optional**: Conditional (in response).
4. **Nullable / Non-nullable**: Nullable (`float | null`; non-null iff `is_eligible = true`, null when `is_eligible = false`).
5. **Enum / Format**: None.
6. **Numerical Constraint**: Finite float in $[0.0, 1.0]$ when eligible.
7. **Semantic Constraint**: Predicted future attack probability for next time window ($t+1$).
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 4.4 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 12 & 17`; `validate_lstm_output`.
12. **Exact Line Reference**: `phase_5_1:L491`; `validators.py:L270-274`.
13. **Phase 6.2 Permitted Validation**: In response validation: assert finite float in $[0.0, 1.0]$ if `is_eligible = true`; assert `null` if `is_eligible = false`. Phase 6.2 does not execute sequence inference.

#### Field 15: `lstm.threshold`
1. **Field**: `lstm.threshold`
2. **Type**: `float`
3. **Required / Optional**: Required (in response).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: Constant `0.3`.
6. **Numerical Constraint**: Matches Phase 4 frozen constant `0.3`.
7. **Semantic Constraint**: Frozen LSTM forecast decision boundary.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 4.4 / Phase 5.1 / Phase 5.2 / Phase 6.1.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/config.py`, `src/application/schemas.py`, `src/application/validators.py`, `data/model_reports/application/phase_6_1_api_backend_architecture_and_contract.md`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 17`; `LSTMOutputRecord`; `LSTM_THRESHOLD`; `validate_lstm_output`; `Phase 6.1 Sec 8.1`.
12. **Exact Line Reference**: `phase_5_1:L492`; `config.py:L40`; `schemas.py:L63`; `validators.py:L275`; `phase_6_1:L410`.
13. **Phase 6.2 Permitted Validation**: Response integrity check: assert returned threshold matches upstream constant `0.3`. Phase 6.2 does not define, evaluate, apply, or mutate the threshold.

#### Field 16: `lstm.forecast_decision`
1. **Field**: `lstm.forecast_decision`
2. **Type**: `int` or `str` (`Union[int, str]`).
3. **Required / Optional**: Required (in response).
4. **Nullable / Non-nullable**: Non-nullable (never null).
5. **Enum / Format**: Discrete domain `enum: [0, 1, "unavailable"]`.
6. **Numerical Constraint**: Discrete integer $\in \{0, 1\}$ when eligible; constant string `"unavailable"` when ineligible.
7. **Semantic Constraint**: Binary forecast decision when history is available, or `"unavailable"` sentinel value. Distinct from threat state `LSTM_UNAVAILABLE`.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 4.4 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 17`; `validate_lstm_output`.
12. **Exact Line Reference**: `phase_5_1:L493`; `validators.py:L280,294`.
13. **Phase 6.2 Permitted Validation**: In response validation: assert value is in `{0, 1, "unavailable"}`. Phase 6.2 does not evaluate forecast probabilities or make decisions.

#### Field 17: `threat_inference.is_eligible`
1. **Field**: `threat_inference.is_eligible`
2. **Type**: `bool`
3. **Required / Optional**: Required (in response).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: Boolean `true` or `false`.
6. **Numerical Constraint**: None.
7. **Semantic Constraint**: Threat engine eligibility (equals `lstm.is_eligible`).
8. **Transformation / Normalization / Conversion / Coercion**: None (strictly boolean; reject integers `0`/`1`).
9. **Authority Layer**: Phase 4.5 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 14 & 17`; `validate_threat_inference_output`.
12. **Exact Line Reference**: `phase_5_1:L505`; `validators.py:L312-327`.
13. **Phase 6.2 Permitted Validation**: In response validation: assert boolean type. Phase 6.2 does not evaluate threat engine eligibility.

#### Field 18: `threat_inference.threat_state_code`
1. **Field**: `threat_inference.threat_state_code`
2. **Type**: `str`
3. **Required / Optional**: Conditional (in response).
4. **Nullable / Non-nullable**: Nullable (`str | null`; non-null iff `is_eligible = true`, null when `is_eligible = false`).
5. **Enum / Format**: Discrete enum: `{"S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7"}`.
6. **Numerical Constraint**: None.
7. **Semantic Constraint**: Unified multi-model threat state code. Prohibited states `S8`, `UNKNOWN`, or `LSTM_UNAVAILABLE` are banned.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 4.5 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/threat_engine.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 14 & 17`; `evaluate_threat_state`.
12. **Exact Line Reference**: `phase_5_1:L506`; `threat_engine.py:L56`.
13. **Phase 6.2 Permitted Validation**: In response validation: if eligible, assert code is in `{"S0".."S7"}`. If ineligible, assert `null`. Strictly reject `S8` or any other code. Phase 6.2 does not calculate threat states.

#### Field 19: `threat_inference.threat_state_name`
1. **Field**: `threat_inference.threat_state_name`
2. **Type**: `str`
3. **Required / Optional**: Conditional (in response).
4. **Nullable / Non-nullable**: Nullable (`str | null`; non-null iff `is_eligible = true`, null when `is_eligible = false`).
5. **Enum / Format**: 8 canonical state names: `BENIGN_CONCORDANCE`, `LSTM_FORECAST_ONLY`, `XGB_ATTACK_ONLY`, `XGB_LSTM_CONSISTENCY`, `AE_ANOMALY_ONLY`, `AE_LSTM_CONSISTENCY`, `AE_XGB_CONSENSUS`, `TRI_MODEL_CONSENSUS`.
6. **Numerical Constraint**: None.
7. **Semantic Constraint**: Canonical descriptive name for unified threat state.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 4.5 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/threat_engine.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 14 & 17`; `evaluate_threat_state`.
12. **Exact Line Reference**: `phase_5_1:L507-517`; `threat_engine.py:L57`.
13. **Phase 6.2 Permitted Validation**: In response validation: if eligible, assert name matches the canonical state name corresponding to `threat_state_code`. If ineligible, assert `null`. Phase 6.2 does not evaluate state names.

#### Field 20: `threat_inference.priority_tier`
1. **Field**: `threat_inference.priority_tier`
2. **Type**: `str`
3. **Required / Optional**: Conditional (in response).
4. **Nullable / Non-nullable**: Nullable (`str | null`; non-null iff `is_eligible = true`, null when `is_eligible = false`).
5. **Enum / Format**: Discrete enum: `{"P1", "P2", "P3", "P4"}`.
6. **Numerical Constraint**: None.
7. **Semantic Constraint**: Operational incident response triage priority tier.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 4.5 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/threat_engine.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 14 & 17`; `evaluate_threat_state`.
12. **Exact Line Reference**: `phase_5_1:L518`; `threat_engine.py:L71`.
13. **Phase 6.2 Permitted Validation**: In response validation: if eligible, assert tier is in `{"P1", "P2", "P3", "P4"}`. If ineligible, assert `null`. Phase 6.2 does not derive triage priority.

#### Field 21: `threat_inference.decision_tuple`
1. **Field**: `threat_inference.decision_tuple`
2. **Type**: `List[int]`
3. **Required / Optional**: Conditional (in response).
4. **Nullable / Non-nullable**: Nullable (`List[int] | null`; non-null iff `is_eligible = true`, null when `is_eligible = false`).
5. **Enum / Format**: Array of length exactly 3; elements $\in \{0, 1\}$.
6. **Numerical Constraint**: Exactly 3 integers each belonging to $\{0, 1\}$.
7. **Semantic Constraint**: Tri-model decision triplet `[b_ae, b_xgb, b_lstm]`.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 4.5 / Phase 5.1 / Phase 5.5.
10. **Exact Source File**: `data/model_reports/phase_5_1_application_integration_architecture_and_contract.md`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `Phase 5.1 Sec 14 & 17`; `validate_threat_inference_output`.
12. **Exact Line Reference**: `phase_5_1:L519-524`; `validators.py:L350-353`.
13. **Phase 6.2 Permitted Validation**: In response validation: if eligible, assert array length 3 with integer elements in $\{0, 1\}$. If ineligible, assert `null`. Phase 6.2 does not construct or modify decision tuples.

#### Field 22: `execution_metadata.inference_latency_ms`
1. **Field**: `execution_metadata.inference_latency_ms`
2. **Type**: `float`
3. **Required / Optional**: Required (in response metadata).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: None.
6. **Numerical Constraint**: Finite float $\ge 0.0$.
7. **Semantic Constraint**: Total inference execution duration in milliseconds.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 5.1 / Phase 5.5 / Phase 6.1.
10. **Exact Source File**: `src/application/schemas.py`, `src/application/validators.py`.
11. **Exact Source Section / Class / Function**: `ExecutionMetadataRecord`; `validate_application_output_record`.
12. **Exact Line Reference**: `schemas.py:L96`; `validators.py:L379`.
13. **Phase 6.2 Permitted Validation**: Response validation: assert finite float $\ge 0.0$. Phase 6.2 does not calculate or simulate inference execution latency.

#### Field 23: `execution_metadata.schema_version`
1. **Field**: `execution_metadata.schema_version`
2. **Type**: `str`
3. **Required / Optional**: Required (in response metadata).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: Constant string `"1.0.0"`.
6. **Numerical Constraint**: None.
7. **Semantic Constraint**: API contract schema version identifier.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 5.2 / Phase 6.1.
10. **Exact Source File**: `src/application/schemas.py`, `data/model_reports/application/phase_6_1_api_backend_architecture_and_contract.md`.
11. **Exact Source Section / Class / Function**: `ExecutionMetadataRecord`; `Phase 6.1 Sec 8.1`.
12. **Exact Line Reference**: `schemas.py:L97`; `phase_6_1:L360,422`.
13. **Phase 6.2 Permitted Validation**: Response integrity check: assert exact constant string value `"1.0.0"`. Phase 6.2 does not mutate version identifiers.

#### Field 24: `execution_metadata.engine`
1. **Field**: `execution_metadata.engine`
2. **Type**: `str`
3. **Required / Optional**: Required (in response metadata).
4. **Nullable / Non-nullable**: Non-nullable.
5. **Enum / Format**: Constant string `"NexThreat-Phase5.2"`.
6. **Numerical Constraint**: None.
7. **Semantic Constraint**: Execution engine release identifier.
8. **Transformation / Normalization / Conversion / Coercion**: None.
9. **Authority Layer**: Phase 5.2 / Phase 6.1.
10. **Exact Source File**: `src/application/schemas.py`, `data/model_reports/application/phase_6_1_api_backend_architecture_and_contract.md`.
11. **Exact Source Section / Class / Function**: `ExecutionMetadataRecord`; `Phase 6.1 Sec 8.1`.
12. **Exact Line Reference**: `schemas.py:L98`; `phase_6_1:L361,423`.
13. **Phase 6.2 Permitted Validation**: Response integrity check: assert exact constant string value `"NexThreat-Phase5.2"`. Phase 6.2 does not mutate engine release identifiers.

---

## 6. Numerical Validation Rule Classification

Every numerical validation rule implemented or verified by Phase 6.2 is categorized into exactly one of two classes:

```text
================================================================================
NUMERICAL VALIDATION RULE CLASSIFICATION
================================================================================
Class A: INHERITED CONTRACT
         Rules explicitly established by accepted Phase 4, Phase 5, or Phase 6.1.
Class B: REPRESENTATION INTEGRITY CHECK
         Assertions verifying response representation integrity without
         introducing new application, business, or model semantics.
================================================================================
```

| Rule Target | Exact Numerical Constraint | Classification | Upstream Authority Evidence |
|---|---|:---:|---|
| Feature Vector Cardinality | Length $== 13$ | **INHERITED CONTRACT** | Phase 4.1; Phase 5.1 Sec 7.2 line 242; `schemas.py:CanonicalInputRecord#L21` |
| Feature Element Numeric | Type is `float` or `int` (reject `bool`, `str`) | **INHERITED CONTRACT** | Phase 5.1 Sec 7.2 line 245; `validators.py` lines 151–158 |
| Feature Element Finite | Value not in `{NaN, +Inf, -Inf}` | **INHERITED CONTRACT** | Phase 5.1 Sec 18 line 545, 561; `validators.py` lines 160–164 |
| Max Request Payload Size | Request body bytes $\le 10,485,760$ ($10\,\text{MB}$) | **INHERITED CONTRACT** | `service.py` line 34; `Phase 6.1 Sec 6.1 line 208, Sec 15.2` |
| Max Stream Batch Size | Stream records $\le 5,000$ | **INHERITED CONTRACT** | `service.py` line 35; `Phase 6.1 Sec 14, Sec 15.2` |
| AE Anomaly Decision Values | Discrete integer $\in \{0, 1\}$ | **INHERITED CONTRACT** | Phase 4.2; Phase 5.1 Sec 10 line 460; `validators.py` line 207 |
| XGB Class Index Range | Discrete integer $\in [0..7]$ | **INHERITED CONTRACT** | Phase 4.3; Phase 5.1 Sec 11 line 471; `validators.py` line 224 |
| XGB Attack Decision Values | Discrete integer $\in \{0, 1\}$ | **INHERITED CONTRACT** | Phase 4.3; Phase 5.1 Sec 11 line 473; `validators.py` line 235 |
| XGB Probability Vector Length | Length $== 8$ (when present) | **INHERITED CONTRACT** | Phase 4.3; Phase 5.1 Sec 11 line 474; `validators.py` line 243 |
| LSTM Decision Values | Discrete integer $\in \{0, 1\}$ or string `"unavailable"` | **INHERITED CONTRACT** | Phase 5.1 Sec 17 line 493; `schemas.py:LSTMOutputRecord#L64` |
| Threat Decision Tuple Values | Exactly 3 integers each in $\{0, 1\}$ (when eligible) | **INHERITED CONTRACT** | Phase 4.5; Phase 5.1 Sec 14 line 516; `validators.py` lines 328–331 |
| Global Position Minimum | Integer $\ge 1$ (when present) | **INHERITED CONTRACT** | Phase 5.1 Sec 7.1 line 238, Sec 17 line 450; `validators.py` line 363 |
| AE Reconstruction MSE Range | Finite float $\ge 0.0$ | **REPRESENTATION INTEGRITY CHECK** | Phase 5.5 `validators.py` lines 197–201 |
| XGB Probability Range | Finite floats in $[0.0, 1.0]$ (when present) | **REPRESENTATION INTEGRITY CHECK** | Phase 5.5 `validators.py` lines 248–252 |
| LSTM Probability Range | Finite float in $[0.0, 1.0]$ (when eligible) | **REPRESENTATION INTEGRITY CHECK** | Phase 5.5 `validators.py` lines 271–274 |
| Latency Range | Finite float $\ge 0.0$ | **REPRESENTATION INTEGRITY CHECK** | Phase 5.5 `validators.py` lines 378–383; `verify_phase_5_6.py#L347` |

*Notice: Probability-sum tolerance (`1e-4`) has been removed from Phase 6.2 validation.*  
*Any rule not in the table above is unauthorized and prohibited from implementation.*

---

## 7. Authoritative Nullability & Type Disambiguation

### 7.1 Authoritative Nullability Table

| Field Path | Nullable? | Valid When Null | Prohibited When Null | Authoritative Source Evidence |
|---|:---:|---|---|---|
| `window_id` | **NO** | Never | All incoming/outgoing records | `schemas.py:CanonicalInputRecord#L19` |
| `timestamp` | **NO** | Never | All incoming/outgoing records | `schemas.py:CanonicalInputRecord#L20` |
| `features` | **NO** | Never | All incoming records | `schemas.py:CanonicalInputRecord#L21` |
| `global_position` | **YES** | When unsequenced/offline | In assembled responses where counter $> 0$ | `schemas.py:ApplicationOutputRecord#L119` |
| `dataset_day` | **YES** | When unpartitioned/unknown | When partition is actively set | `schemas.py:ApplicationOutputRecord#L120` |
| `autoencoder.reconstruction_mse` | **NO** | Never | All inference records | `schemas.py:AutoencoderOutputRecord#L26` |
| `autoencoder.threshold` | **NO** | Never | All inference records | `schemas.py:AutoencoderOutputRecord#L27` |
| `autoencoder.is_anomaly` | **NO** | Never | All inference records | `schemas.py:AutoencoderOutputRecord#L28` |
| `xgboost.predicted_class_index` | **NO** | Never | All inference records | `schemas.py:XGBoostOutputRecord#L40` |
| `xgboost.predicted_class_name` | **NO** | Never | All inference records | `schemas.py:XGBoostOutputRecord#L41` |
| `xgboost.is_attack` | **NO** | Never | All inference records | `schemas.py:XGBoostOutputRecord#L42` |
| `xgboost.class_probabilities` | **YES** | When probability vector export is disabled | When probability vector is populated | `schemas.py:XGBoostOutputRecord#L43` |
| `lstm.is_eligible` | **NO** | Never | All inference records | `schemas.py:LSTMOutputRecord#L60` |
| `lstm.ineligibility_reason` | **YES** | When `is_eligible = true` | When `is_eligible = false` | `schemas.py:LSTMOutputRecord#L61` |
| `lstm.forecast_probability` | **YES** | When `is_eligible = false` (cold start, gap, midnight) | When `is_eligible = true` | `schemas.py:LSTMOutputRecord#L62` |
| `lstm.threshold` | **NO** | Never | All inference records | `schemas.py:LSTMOutputRecord#L63` |
| `lstm.forecast_decision` | **NO** | Never (takes string `"unavailable"` when ineligible) | All inference records | `schemas.py:LSTMOutputRecord#L64` |
| `threat_inference.is_eligible` | **NO** | Never | All inference records | `schemas.py:ThreatInferenceRecord#L78` |
| `threat_inference.threat_state_code` | **YES** | When `is_eligible = false` (cold start, gap, midnight) | When `is_eligible = true` | `schemas.py:ThreatInferenceRecord#L79` |
| `threat_inference.threat_state_name` | **YES** | When `is_eligible = false` (cold start, gap, midnight) | When `is_eligible = true` | `schemas.py:ThreatInferenceRecord#L80` |
| `threat_inference.priority_tier` | **YES** | When `is_eligible = false` (cold start, gap, midnight) | When `is_eligible = true` | `schemas.py:ThreatInferenceRecord#L81` |
| `threat_inference.decision_tuple` | **YES** | When `is_eligible = false` (cold start, gap, midnight) | When `is_eligible = true` | `schemas.py:ThreatInferenceRecord#L82` |
| `execution_metadata.inference_latency_ms` | **NO** | Never | All assembled responses | `schemas.py:ExecutionMetadataRecord#L96` |
| `execution_metadata.schema_version` | **NO** | Never | All assembled responses | `schemas.py:ExecutionMetadataRecord#L97` |
| `execution_metadata.engine` | **NO** | Never | All assembled responses | `schemas.py:ExecutionMetadataRecord#L98` |

### 7.2 Strict Boolean vs. Integer Type Disambiguation
To prevent silent type coercion or data corruption:
- `autoencoder.is_anomaly`: Strictly discrete integer `0` or `1`. Booleans `true`/`false` are rejected.
- `xgboost.is_attack`: Strictly discrete integer `0` or `1`. Booleans `true`/`false` are rejected.
- `lstm.is_eligible`: Strictly boolean `true` or `false`. Integers `0`/`1` are rejected.
- `threat_inference.is_eligible`: Strictly boolean `true` or `false`. Integers `0`/`1` are rejected.
- `features` elements: Numeric floats or integers (validated as finite float values). Booleans `true`/`false` and string numbers are rejected.

---

## 8. Scope & Non-Scope Boundaries

### 8.1 In Scope for Phase 6.2
1. Request schemas: Single-window canonical array (Format A), single-window named dictionary (Format B), and stream batch container.
2. Response schemas: Standard inference response, cold-start telemetry response, and standardized error response that field-for-field and structurally correspond to the authoritative Phase 5 `ApplicationOutputRecord` and Phase 5.1 Section 17 response schema across all 24 fields.
3. Schema validation logic: Structural checks, field presence, strict type checking, finite number assertions, and `window_id` regex validation.
4. Feature adapter logic: Validation and canonical ordering of named feature dictionaries into 13-element canonical float vectors.
5. Threat-state response validation: Assert-only validation of discrete states `S0`..`S7` and rejection of `S8`, `UNKNOWN`, or `LSTM_UNAVAILABLE`.
6. Exception and error mapping: Structured, sanitized error response generator redacting filesystem paths, line numbers, and module names.
7. Automated verification suite: Gates V1 through V16, covering positive, negative, adversarial, and authority audit test cases.

### 8.2 Out of Scope for Phase 6.2
- Implementing HTTP endpoints, server daemons, or socket listeners (Phase 6.3 / Phase 6.4).
- Executing model inference, loading model weights, or recalculating predictions.
- Modifying model decision operators, thresholds, or scalers.
- Calculating or altering threat states ($S0..S7$).
- Implementing temporal history buffers or sequence lookbacks (Phase 5 `state_manager.py`).
- Implementing score fusion, weighted voting, or stacking meta-models.
- Implementing autonomous remediation, IP blocking, or firewall commands.
- Modifying any Phase 4 artifact or Phase 5 source code.

---

## 9. Proposed File & Module Boundaries

The implementation will be cleanly isolated within a dedicated `src/api/` package:

```text
src/
└── api/
    ├── __init__.py                [PROPOSED — IMPLEMENTATION PENDING APPROVAL]
    ├── schemas.py                 [PROPOSED — IMPLEMENTATION PENDING APPROVAL]
    ├── validators.py              [PROPOSED — IMPLEMENTATION PENDING APPROVAL]
    ├── exceptions.py              [PROPOSED — IMPLEMENTATION PENDING APPROVAL]
    └── verification/
        ├── __init__.py            [PROPOSED — IMPLEMENTATION PENDING APPROVAL]
        └── verify_phase_6_2.py    [PROPOSED — IMPLEMENTATION PENDING APPROVAL]
```

### Module Responsibilities
1. `src/api/schemas.py`: Strongly typed dataclasses defining external JSON request and response payloads matching Phase 6.1 Section 7 and 8.
2. `src/api/validators.py`: Pure validation functions adapting valid requests into `src.application.schemas.CanonicalInputRecord` without invoking inference.
3. `src/api/exceptions.py`: Custom API exception hierarchy and error response formatter `format_api_error_response()` producing standardized, sanitized error envelopes.
4. `src/api/verification/verify_phase_6_2.py`: Standalone verification script executing gates V1 through V16.

---

## 10. Detailed Verification Strategy (Gates V1 – V16)

```text
================================================================================
PHASE 6.2 VERIFICATION GATE CATALOGUE
================================================================================
V1  — Schema Existence & Interface Definition
V2  — Required Fields Validation
V3  — Type Validation & Strict Type Disambiguation
V4  — window_id Contract Validation (Inherited Regex)
V5  — Canonical Feature Contract Validation (13 Features, Order, Finite)
V6  — Timestamp Contract Validation (Authoritative Datetime Parsing Semantics)
V7  — Threat-State Contract Validation (S0–S7, Prohibited States Banned)
V8  — Nullability Contract Validation (Authoritative Null Bounds)
V9  — Standardized Error Schema & Sanitization Validation
V10 — Zero Inference on Invalid Input Guarantee
V11 — Phase 5 Input Contract Semantic Preservation
V12 — Phase 5 Output Response Semantic Preservation
V13 — Zero Semantic Duplication AST Audit
V14 — Phase 4 Frozen Artifact Integrity (33/33 SHA-256)
V15 — Phase 5 Regression Suite Execution (22/22 Gates)
V16 — 24-Field Authority Matrix Field-by-Field Audit
================================================================================
```

### Gate Specifications

#### Gate V1: Schema Existence & Interface Definition
- **Purpose**: Verify that all proposed Phase 6.2 dataclass schemas, validators, and exception classes exist and import cleanly without error.
- **Pass Criteria**: `src/api/schemas.py`, `src/api/validators.py`, and `src/api/exceptions.py` import with 0 errors; all required classes present.

#### Gate V2: Required Fields Validation
- **Purpose**: Verify that payloads missing any required field are rejected deterministically.
- **Pass Criteria**: Payloads missing `window_id`, `timestamp`, or `features` raise `APIValidationError`.

#### Gate V3: Type Validation & Strict Type Disambiguation
- **Purpose**: Verify that incorrect data types are rejected and no silent type coercion occurs.
- **Pass Criteria**: Integer `window_id` (e.g. `123`), boolean features (`true`/`false`), and string numbers (`"25.4"`) are strictly rejected. `is_anomaly` and `is_attack` assert integer type (rejecting boolean).

#### Gate V4: `window_id` Contract Validation
- **Purpose**: Verify that `window_id` adheres strictly to the inherited Phase 5 regex `^[0-9]{8}_[0-9]{4}$`.
- **Pass Criteria**: Valid IDs (e.g., `"20170703_1355"`) pass; malformed IDs (e.g., `"2017073_1355"`, `"20170703-1355"`, `"abc_1234"`) fail.

#### Gate V5: Canonical Feature Contract Validation
- **Purpose**: Verify strict adherence to the 13 canonical features, ordering, and finite value constraints across both Format A (array) and Format B (named object adapter).
- **Pass Criteria**: Exactly 13 canonical features accepted; missing features, extra features, `NaN`, `+Infinity`, and `-Infinity` are rejected; named feature dictionaries are adapted into the exact canonical order. No feature scaling or coercion.

#### Gate V6: Timestamp Contract Validation
- **Purpose**: Verify structural timestamp parsing matching the exact accepted formats defined in `src/application/validators.py:parse_timestamp`.
- **Pass Criteria**: Valid ISO-8601 and standard datetime strings parse cleanly; malformed strings, numbers, or empty strings raise `APIValidationError`.

#### Gate V7: Threat-State Contract Validation
- **Purpose**: Verify that outgoing response validation enforces discrete states `S0`..`S7` and rejects prohibited states.
- **Pass Criteria**: Threat state codes `S0` through `S7` pass validation; codes `S8`, `UNKNOWN`, or `LSTM_UNAVAILABLE` raise `APIValidationError`.

#### Gate V8: Nullability Contract Validation
- **Purpose**: Verify that `null` is accepted only in fields where explicitly permitted by the authoritative contract.
- **Pass Criteria**: Null in `threat_state_code` or `forecast_probability` during cold start is accepted; null in `window_id`, `timestamp`, `features`, or `autoencoder` records is rejected.

#### Gate V9: Standardized Error Schema & Sanitization Validation
- **Purpose**: Verify that error envelopes match the Phase 6.1 contract and redact sensitive runtime paths.
- **Pass Criteria**: Error payload matches `{ "error": { "code", "message", "status_code", "timestamp", "details" } }`; Windows/Unix paths, Python filenames, and memory addresses are redacted.

#### Gate V10: Zero Inference on Invalid Input Guarantee
- **Purpose**: Certify that invalid requests are halted at the validation boundary and never invoke model predictors.
- **Pass Criteria**: Instrumenting/mocking `ApplicationInferenceEngine` confirms exactly 0 model calls occur when input validation fails.

#### Gate V11: Phase 5 Input Contract Semantic Preservation
- **Purpose**: Verify that the API adapter produces a `CanonicalInputRecord` conforming strictly to the accepted Phase 5 input contract.
- **Pass Criteria**: The API adapter must produce a `CanonicalInputRecord` whose fields, values, types, feature order, and semantics conform exactly to the accepted Phase 5 input contract, without unauthorized transformation.

#### Gate V12: Phase 5 Output Response Semantic Preservation
- **Purpose**: Verify that serializing an accepted Phase 5 `ApplicationOutputRecord` preserves all field values and semantics across all 24 fields.
- **Pass Criteria**: Every API response field must have an identified upstream authority, and serialization must preserve the source application's field values and semantics without unauthorized mutation, omission, reinterpretation, or invention, ensuring that responses field-for-field and structurally correspond to the authoritative Phase 5 `ApplicationOutputRecord` and Phase 5.1 Section 17 response schema.

#### Gate V13: Zero Semantic Duplication AST Audit
- **Purpose**: Programmatically verify that `src/api/` contains zero duplicated ML or threat decision logic.
- **Pass Criteria**: AST analysis confirms 0 model predictor definitions, 0 scaler references, 0 threshold comparisons, 0 score fusion, and 0 S0–S7 decision logic implementations.

#### Gate V14: Phase 4 Frozen Artifact Integrity
- **Purpose**: Verify that all 33 Phase 4 frozen artifacts maintain bit-exact SHA-256 integrity.
- **Pass Criteria**: All 33 files match baseline SHA-256 digests (0 mutations, 0 missing).

#### Gate V15: Phase 5 Regression Suite Execution
- **Purpose**: Certify zero regression across the accepted Phase 5 application layer.
- **Pass Criteria**: Execution of the Phase 5.7 verification suite yields 22 / 22 PASS.

#### Gate V16: 24-Field Authority Matrix Field-by-Field Audit
- **Purpose**: Exhaustive, automated audit independently verifying the proposed Phase 6.2 implementation directly against the complete 24-field Authority Matrix (Section 5).
- **Audit Verification Mechanism**: Gate V16 iterates field-by-field through all 24 fields and programmatic schema definitions, verifying all 16 attributes:
  1. `Field name`: Exact match to authoritative schema property.
  2. `Type`: Exact type compliance (no unauthorized types or unions).
  3. `Requiredness`: Required vs. Optional status matches upstream contract.
  4. `Nullability`: Nullable vs. Non-nullable matches authoritative null bounds.
  5. `Enum`: Discrete enum domain strictly matches upstream definition (no expansion or restriction).
  6. `Format`: Formatting constraints (e.g. regex, datetime) match upstream parser.
  7. `Numerical constraints`: Upper, lower, or discrete bounds match upstream rules.
  8. `Semantic constraints`: Meaning, role, and domain interpretation strictly preserved.
  9. `Transformations`: Zero unauthorized transformations permitted.
  10. `Normalization`: Zero feature or probability normalization in API layer.
  11. `Conversions`: Only authorized adapter conversions (Format B dictionary to canonical list of floats).
  12. `Coercions`: Zero silent type coercions (e.g. boolean to int, string to number).
  13. `Defaults`: Zero defaults that mask missing required data.
  14. `Validation rules`: Every validator traces to upstream contract.
  15. `Exact upstream authority`: Validated against Phase 4, Phase 5, or Phase 6.1 baseline file, section, and line.
  16. `Phase 6.2 permission to enforce`: Verified that Phase 6.2 only performs representation validation and does not execute model logic.
- **Mandatory Failure Criteria**: Gate V16 must strictly **FAIL** if:
  - Any field in `src/api/` is not in the authoritative matrix.
  - Any authoritative field is missing or omitted from response schemas.
  - Any field name is altered, aliased, or typo'd.
  - Any type is altered or coerced without authority.
  - Requiredness or nullability is modified.
  - An unauthorized enum value, numerical bound, or format rule is added.
  - An unauthorized transformation, normalization, or coercion is detected.
  - A default value masks missing or invalid inputs.
  - Any validation rule lacks exact source citation.
  - Any model decision logic, threshold comparison, or state determination is duplicated.
- **Pass Criteria**: 100% of the 24 fields pass all 16 audit dimensions with exact upstream traceability, 0 unauthorized rules, and 0 semantic duplications.
- **Operational Constraint**: V16 is strictly an audit and verification mechanism; it implements zero runtime behavioral logic.

---

## 11. Adversarial Negative Test Matrix

```text
================================================================================
ADVERSARIAL NEGATIVE TEST MATRIX
================================================================================
Payload Structure:
- Empty object {}
- Null payload null
- Array root []
- Primitive string "traffic_record"
- Primitive integer 12345

Field Presence & Types:
- Missing window_id
- Integer window_id: {"window_id": 201707031355}
- Missing timestamp
- Numeric timestamp: {"timestamp": 1499080500}
- Missing features container
- Null features container: {"features": null}
- String features container: {"features": "124, 25.4, ..."}

Feature Cardinality & Values:
- Truncated feature array (12 elements)
- Oversized feature array (14 elements)
- Feature vector with boolean: [124.0, true, 18420.5, ...]
- Feature vector with string: [124.0, "25.4", 18420.5, ...]
- Feature vector with NaN: [124.0, NaN, 18420.5, ...]
- Feature vector with +Infinity: [124.0, Infinity, 18420.5, ...]
- Feature vector with -Infinity: [124.0, -Infinity, 18420.5, ...]
- Named dictionary with missing key: (missing "syn_packet_ratio")
- Named dictionary with extra key: (extra "flow_duration_raw")

Threat-State Invariants:
- Response with threat state "S8"
- Response with threat state "UNKNOWN"
- Response with threat state "LSTM_UNAVAILABLE"

Stream Containers:
- Empty stream container: {"stream": []}
- Oversized stream container (> 5,000 records)
- Mixed valid and invalid records in stream
================================================================================
```

---

## 12. Final Audit Table

| Audit Area / Item | Status | Verification & Reconciliation Summary |
|---|:---:|---|
| **Float32 / Coercion Authority Resolution** | **INCORPORATED — READY FOR FINAL AUDIT** | Traced to `CanonicalInputRecord#L21: features: List[float]` and `validators.py:L140-164`. Determined that `float32` is an internal model/numpy representation instantiated inside Phase 5 (`validators.py:L149`), not an API contract requirement. Unauthorized float32 requirement removed from Phase 6.2; API contract accepts finite numeric floats (`List[float]`) without unauthorized conversion or coercion. |
| **Structural Field Correspondence Terminology** | **INCORPORATED — READY FOR FINAL AUDIT** | Replaced unsupported "bit-for-bit" phrasing across all sections with precise structural terminology: responses field-for-field and structurally correspond to the authoritative Phase 5 `ApplicationOutputRecord` and Phase 5.1 Section 17 response schema. |
| **Physical 24-Field Matrix Embedding** | **INCORPORATED — READY FOR FINAL AUDIT** | Complete 24-field matrix physically embedded in Section 5 with full 13-attribute breakdown per field (file, section, line citations, requiredness, nullability, numerical constraints, permitted validation). |
| **Exact 24-Field Count & Structure** | **INCORPORATED — READY FOR FINAL AUDIT** | Response contract strictly establishes 24 separate fields. `schema_version` (Field 23) and `engine` (Field 24) are completely separated without combining notation. |
| **`features` Representation Resolution** | **INCORPORATED — READY FOR FINAL AUDIT** | Request schema verified: Phase 5 authorizes Format A (13-element canonical array); Phase 6.1 Sec 7.2 authorizes Format B (13-key named object adapter) and dictionary-to-array conversion; ordering invariant confirmed; normalization prohibited. |
| **Threshold Response Fields Resolution** | **INCORPORATED — READY FOR FINAL AUDIT** | Verified `autoencoder.threshold` (Field 6) and `lstm.threshold` (Field 15) are authoritative response fields in Phase 5.1 Sec 17, Phase 5.2 schemas, and Phase 6.1 Sec 8.1. Response integrity check only; zero threshold calculation permitted. |
| **Separation of Upstream Authority vs. Validation Permission** | **INCORPORATED — READY FOR FINAL AUDIT** | Section 3 explicitly establishes that upstream authority does not authorize independent semantic validation; Phase 6.2 performs representation validation only and cannot reproduce model logic. |
| **Gate V16 Field-by-Field Audit** | **INCORPORATED — READY FOR FINAL AUDIT** | Rewritten into a concrete field-by-field audit comparing proposed code directly against the 24-field matrix across all 16 dimensions with rigorous failure criteria. |
| **Timestamp Authority & Semantics** | **INCORPORATED — READY FOR FINAL AUDIT** | Traced to `Phase 5.1 Sec 7.1 line 228`, `src/application/validators.py:parse_timestamp` (lines 46–67), and `Phase 6.1 Sec 8.3`. Exact accepted datetime parsing semantics enforced without vague generalisms. |
| **Feature Finite Authority** | **INCORPORATED — READY FOR FINAL AUDIT** | Traced to `Phase 5.1 Sec 18 lines 545, 561` and `validators.py` lines 160–164. Rejection of `NaN`, `+Inf`, `-Inf` is fully authorized. |
| **`global_position` Authority** | **INCORPORATED — READY FOR FINAL AUDIT** | Traced to `Phase 5.1 Sec 7.1 line 238, Sec 17 line 443` (`minimum: 1`) and `validators.py:L363`. Minimum constraint $\ge 1$ explicitly verified. |
| **Latency Authority** | **INCORPORATED — READY FOR FINAL AUDIT** | Traced to `validators.py` lines 378–383 and `verify_phase_5_6.py:L347`. Non-negative float response check verified. |
| **Payload Limit Authority** | **INCORPORATED — READY FOR FINAL AUDIT** | Traced to `service.py:MAX_REQUEST_BYTES (10 MB)` line 34, lines 204–210, and `Phase 6.1 Sec 6.1, 15.2`. |
| **Stream Limit Authority** | **INCORPORATED — READY FOR FINAL AUDIT** | Traced to `service.py:MAX_STREAM_RECORDS (5000)` line 35, lines 247–253, and `Phase 6.1 Sec 14, 15.2`. |
| **`dataset_day` Authority** | **INCORPORATED — READY FOR FINAL AUDIT** | Traced to `Phase 5.1 Sec 7.1 lines 231–235, 446–449` and `validators.py:L43,69-77`. Enum `{"Monday".."Friday", "Unknown"}` strictly separated from field nullability. |
| **LSTM `forecast_decision` Authority** | **INCORPORATED — READY FOR FINAL AUDIT** | Traced to `Phase 5.1 Sec 17 line 493` (`enum: [0, 1, "unavailable"]`), `schemas.py:LSTMOutputRecord#L64`, and `validators.py:L280,294`. Distinct from prohibited threat state `LSTM_UNAVAILABLE`. |
| **Probability Tolerance Removal** | **INCORPORATED — READY FOR FINAL AUDIT** | `1e-4` tolerance is an internal Phase 5 assertion (`validators.py:L254`) and is **completely removed** from Phase 6.2 validation contract. |
| **Zero Code Mutation** | **INCORPORATED — READY FOR FINAL AUDIT** | Verified 0 runtime files modified or created. Only the implementation plan document was revised. |

---

## 13. Implementation Authorization Status

```text
================================================================================
PHASE 6.2 IMPLEMENTATION PLAN — REVISION 8
STATUS: READY FOR FINAL AUDIT
IMPLEMENTATION: NOT AUTHORIZED
================================================================================
```

*No runtime implementation will occur until explicit user approval of Revision 8 is granted.*
