
# NexThreat — Phase 4.5 Implementation Plan (Corrected & Re-Audited)

**Project**: NexThreat (“Detect anomalies. Forecast attacks. Prevent damage.”)  
**Authoritative Specification**: `phase_4_5_design_audit_and_specification_v2.9.md`  
**Document Title**: Phase 4.5 Implementation Plan: Cross-Model Evaluation, Consistency Audit, & Unified Threat Inference Architecture  
**Execution Mode**: PLANNING-ONLY CORRECTION & RE-AUDIT — ZERO IMPLEMENTATION CODE / ZERO ARTIFACT MUTATION  
**Target Repository**: `c:\SIH\NexThreat`  
**Authoritative Global Seed**: `42` (Applied locally without mutating prior-phase environments)  
**Implementation Plan Status**: **`PHASE 4.5 IMPLEMENTATION PLAN STATUS: READY FOR IMPLEMENTATION`** (All 4 specification authority blockers formally resolved in Specification v2.9)

---

## 1. Executive Summary

### 1.1 Context and Problem Statement
NexThreat addresses the Smart India Hackathon (SIH) problem statement: **"AI-Based Network Attack Forecasting from Network Traffic Data."**  
Across Phases 4.1 through 4.4, the project developed, trained, evaluated, and independently verified three dedicated, specialized AI models:
1. **Phase 4.2 — Autoencoder**: Current-window unsupervised anomaly detection (PASS / FROZEN).
2. **Phase 4.3 — XGBoost**: Current-window 8-class supervised attack categorization (PASS / FROZEN).
3. **Phase 4.4 — LSTM**: Forward-looking sequence-based attack forecasting targeting the subsequent window (PASS / FROZEN).

### 1.2 Nature of Phase 4.5
Phase 4.5 is a **deterministic post-model evaluation, consistency audit, temporal lead-time analysis, operational replay, and unified threat inference architecture**.  
It operates strictly downstream of the three frozen models and evaluates their complementary operational characteristics.

Phase 4.5 is **STRICTLY NOT**:
- A fourth machine learning model
- A meta-learner
- A stacking ensemble
- A voting model
- A neural fusion layer
- A risk/severity scoring model
- A weighted numerical fusion system
- A probability-calibration or blending layer
- An autonomous network remediation or actuation system

### 1.3 Core Governance & Four Resolved Authority Blockers
All four specification authority blockers identified in prior drafts have been formally resolved in Authoritative Specification v2.9:
1. **Blocker 1 — Campaign-Count Authority Resolution (83 vs 81) [RESOLVED]**: Reconciled to exactly **81 attack campaigns**, matching physical repository ground truth in `data/model_inputs/metadata/attack_segments.csv`.
2. **Blocker 2 — 13-Feature Contract Formal Sign-Off [RESOLVED]**: Grounded in the canonical 13-feature contract (`flow_count` through `syn_packet_ratio`) verified across Phases 2.3, 3.3, 4.3, and 4.4.
3. **Blocker 3 — Deterministic Jaccard Edge-Case Rule Confirmation [RESOLVED]**: Formally confirmed that when $\text{TP} + \text{FP} + \text{FN} = 0$, Jaccard is serialized as `null` with reason `"zero_positive_union"`.
4. **Blocker 4 — LSTM "Unavailable" vs 8-State Taxonomy & Scope-B Conservation Resolution [RESOLVED]**: Formally resolved by decoupling **model-output availability** from **threat-state eligibility**. Check K uniquely represents Scope-B conservation over complete tri-model evidence ($\sum_{i=0}^7 \text{Count}(S_i) \equiv N_{\text{eligible}}$), while master-timeline conservation holds as $N_{\text{master}} = N_{\text{eligible}} + N_{\text{ineligible}}$. The frozen 8-state taxonomy is strictly preserved, incomplete tuples receive no threat state, and the Eligibility-Contiguity Rule is enforced for all transition and dwell calculations. All sample counts are dynamically derived at runtime.

With all four authority blockers formally resolved and incorporated into Authoritative Specification v2.9, the project is **READY FOR IMPLEMENTATION**.

---

## 2. Repository Inspection Findings & Reconciliations

An exhaustive, read-only audit of the physical repository `c:\SIH\NexThreat` was conducted across all relevant code, preprocessed dataset files, model artifacts, metadata files, and manifests.

### 2.1 Reconciled 13-Feature Contract
Inspection of repository configuration, engineering, and model-ready metadata proves that the canonical NexThreat 13-feature contract established in Phase 2.3 and consumed across Phases 3.3, 4.2, 4.3, and 4.4 is:

1. `flow_count`
2. `packet_rate`
3. `byte_rate`
4. `mean_flow_duration`
5. `std_flow_duration`
6. `short_flow_ratio`
7. `mean_packet_size`
8. `packet_length_variability`
9. `fwd_bwd_packet_ratio`
10. `unique_dst_ports`
11. `unique_dst_ips`
12. `tcp_flow_ratio`
13. `syn_packet_ratio`

**Repository Evidence Supporting this Reconciled Contract**:
- `src/feature_engineering/config.py` (lines 104–118): Defines `FEATURE_COLUMNS` with these exact 13 names in this exact order.
- `data/model_ready/metadata/feature_columns.json` (lines 1–18): Contains `feature_count: 13` and `feature_columns` matching this exact list.
- `data/models/xgboost/feature_schema.json` (lines 1–23): Contains `feature_names` matching this exact list (`raw_unscaled: true`, `dtype: "float32"`).
- `src/models/lstm/config.py` (lines 29–43): Defines `LSTM_FEATURES` matching this exact list (`FEATURE_COUNT: 13`).
- `src/models/config.py` (lines 16–18): Imports `CANONICAL_FEATURE_COLUMNS` directly from `src.feature_engineering.config`.

*Correction Note*: The previous plan draft erroneously displayed an ungrounded alternative list (containing `total_packet_count`, `tcp_ratio`, etc.). That list is formally retracted and replaced by the single authoritative repository contract above.

### 2.2 Phase 4.2 Autoencoder Artifacts & Verification Interfaces
- **Model Checkpoints**: Located at `data/models/autoencoder/final_model/autoencoder.keras` (70,183 bytes) and `data/models/autoencoder/checkpoints/best_model.keras` (70,183 bytes). Binary comparison confirms they are 100% byte-identical.
- **Model Metadata**: Located at `data/models/autoencoder/artifacts/model_metadata.json`. Establishes the authoritative frozen decision threshold:
  $$\text{Selected Threshold} = 0.003207791231673312$$
  Threshold Percentile: 98.0%.
- **Scaler Preprocessing**: Scaled using `data/model_ready/artifacts/ae_scaler.joblib` (StandardScaler fitted exclusively on benign training data).
- **Test Benchmark Metrics**: Held-out test set ($N=408$ windows): Precision = 0.8125, Recall = 0.5417, F1 = 0.6500, AUROC = 0.7719.
- **Verification Authority**: `src/models/verification/verify_autoencoder.py` (Independent verification status: PASS).

### 2.3 Phase 4.3 XGBoost Artifacts & Verification Interfaces
- **Model Artifact**: Located at `data/models/xgboost/xgboost_model.json` (174,028 bytes).
- **Model Metadata**: Located at `data/models/xgboost/artifacts/model_metadata.json`.
- **Classification Paradigm**: 8-class multiclass classifier (0: Benign, 1: Bot, 2: Brute Force, 3: DDoS, 4: DoS, 5: Infiltration, 6: PortScan, 7: Web Attack).
- **Binary Conversion Rule for Phase 4.5**:
  $$y_{\text{xgb}\_\text{binary}} = \begin{cases} 0 & \text{if } \hat{y}_{\text{xgb}} = 0 \text{ (Benign)} \\ 1 & \text{if } \hat{y}_{\text{xgb}} \in \{1, 2, 3, 4, 5, 6, 7\} \text{ (Attack)} \end{cases}$$
- **Preprocessing Paradigm**: Consumes unscaled raw float32 features per `feature_schema.json`.
- **Test Benchmark Metrics**: Held-out test set ($N=319$ windows): Macro F1 = 0.8251, Weighted F1 = 0.8601, Multiclass Accuracy = 0.8652.
- **Verification Authority**: `src/models/verification/verify_xgboost.py` (Independent verification status: PASS).

### 2.4 Phase 4.4 LSTM Artifacts & Verification Interfaces
- **Model Checkpoints**: Located at `data/models/lstm/final_model/lstm_model.keras` (867,407 bytes) and `data/models/lstm/checkpoints/best_model.keras` (867,407 bytes). Binary comparison confirms they are 100% byte-identical.
- **Model Metadata**: Located at `data/models/lstm/artifacts/model_metadata.json`. Establishes the authoritative frozen decision threshold:
  $$\text{Optimal Decision Threshold} = 0.3000$$
- **Scaler Preprocessing**: Scaled using `data/model_ready/artifacts/lstm_scaler.joblib` (RobustScaler fitted exclusively on training sequences).
- **Test Benchmark Metrics**: Held-out test set ($N=286$ sequences): Test AUROC = 0.9406, Precision = 0.7600, Recall = 0.6129, F1 = 0.6786.
- **Verification Authority**: `src/models/verification/verify_lstm.py` (Independent verification status: PASS).
- **Primary SHA-256 Authority for `lstm_scaler.joblib`**: Phase 3.3 `src.models.verification.verify_model_infrastructure.BASELINE_MODEL_READY_HASHES`. The secondary entry in `data/model_reports/lstm/model_hashes.json` serves strictly as a cross-phase consistency check and can never override primary authority.

### 2.5 Master Dataset & Partition Timeline
- Master dataset: `data/model_inputs/master_features_dataset.csv` contains **2,454 represented master-timeline windows in `global_position` order** (covering the active dataset periods across Monday–Friday, with contiguous `global_position` indexing from 1 to 2,454, without implying that the full 7,200 minutes of Monday–Friday are continuously represented).

### 2.6 Held-Out Benchmark Partition Geometry
Held-out test window counts across models are partitioned strictly per their architectural requirements:
- **Autoencoder**: $N = 408$ windows (`data/model_ready/autoencoder/test_manifest.csv`).
- **XGBoost**: $N = 319$ windows (`data/model_ready/xgboost/test_manifest.csv`).
- **LSTM**: $N = 286$ sequences (`data/model_ready/lstm/test_manifest.csv`).

### 2.7 Synchronized Tri-Model Overlap ($N = 45$)
1. **Manifest-Level Mutual Intersection ($N = 51$)**:
   - The set intersection of `global_position` across all three test manifests contains exactly 51 windows:
     $$\{918\} \cup \{2072 \dots 2111\} \cup \{2383 \dots 2392\} = 51 \text{ windows}$$
2. **Invalid Lookback Exclusion (6 windows)**:
   - Window `918`: Lookback sequence requires windows 908–917. Window 908 falls in a cross-day gap/pre-split segment on Friday morning. Lookback is structurally invalid.
   - Windows `2383, 2384, 2385, 2386, 2387`: Occur at the boundary of Friday partition splits where lookback sequences cross partition boundaries without full contiguous training lookbacks.
   - Total excluded positions: $\{918, 2383, 2384, 2385, 2386, 2387\}$ (6 windows).
3. **Valid Synchronized Tri-Model Subset ($N = 45$)**:
   - Exactly $51 - 6 = 45$ windows:
     $$\{2072 \dots 2111\} \cup \{2388 \dots 2392\} = 40 + 5 = 45 \text{ windows}$$
   - Verified against physical repository manifests with exact integer precision.
   - *Verification Authority Rule*: These values are verification expectations derived from frozen repository evidence and MUST NOT serve as hardcoded runtime input data. Runtime synchronization must derive the sets dynamically from authoritative manifests and temporal validity rules.

### 2.8 Attack Campaign Discrepancy Evidence (83 vs 81)
- **Repository Ground Truth**:
  - `data/model_inputs/metadata/attack_segments.csv` contains **exactly 81 rows** (excluding header).
  - Per-day distribution: Tuesday = 4 segments, Wednesday = 21 segments, Thursday = 30 segments, Friday = 26 segments ($4 + 21 + 30 + 26 = 81$).
  - `data/model_inputs/metadata/attack_segment_summary.json` (line 5) explicitly records: `"total_attack_segments": 81`.
  - `src/dataset_preparation/analyze_attack_segments.py` (line 719) states: `"Attack windows are highly clustered into 81 distinct temporal bursts"`.
  - `src/dataset_preparation/analyze_split_strategies.py` (lines 5, 190, 510) establishes: `81 attack segments`.
- **Authoritative Resolution in Specification v2.9**:
  - Specification v2.9 formally resolves Blocker 1 by reconciling the campaign count to exactly **81 attack campaigns**, matching physical repository ground truth (`attack_segments.csv`).
  - The historical reference to 83 campaigns is identified as a line-count artifact (81 data rows + 1 header + 1 trailing newline = 83 lines in raw file).
  - Campaign enumeration remains dynamically derived from repository data (`attack_segments.csv`).
  - Blocker 1 is formally **RESOLVED**.

### 2.9 Scope-B Lookback Cold-Start Analysis
- **Lookback Window Requirement**: LSTM forward inference targeting window $t$ strictly requires a 10-window lookback history $[t-10, t-9, \dots, t-1]$ preceding window $t$.
- **Day Boundary Isolation Constraint**: In accordance with v2.9 Section 9 and Section 18, lookback sequences cannot cross midnight day boundaries.
- **Cold-Start Impact**:
  - For the first 10 windows of each day (Monday, Tuesday, Wednesday, Thursday, Friday), preceding lookback sequences are structurally unavailable within the same day.
  - At minimum, $5 \text{ days} \times 10 \text{ windows} = 50 \text{ windows}$ in Scope B cannot produce an LSTM forecast.
  - For these windows, the LSTM forecast output is mathematically and structurally `"unavailable"`. In Specification v2.9, this is formally treated as a model-output availability condition, decoupled from threat-state eligibility.

---

## 3. Frozen Architecture Contract

Phase 4.5 is strictly an evaluation, consistency, unified-inference, operational replay, and verification layer.

### 3.1 Temporal Alignment Contract
The temporal alignment across the three models is mathematically frozen as:

$$\text{Unified Threat State}(t) = \mathcal{T}\Big(\text{AE}(t), \; \text{XGB}(t), \; \text{LSTM}(t-1 \to t)\Big)$$

Where:
- $\text{AE}(t)$: Autoencoder reconstruction error on current window $t$, evaluated against frozen threshold $\tau_{\text{ae}} = 0.003207791231673312$.
- $\text{XGB}(t)$: XGBoost multiclass prediction on current window $t$, mapped to binary (Class $\ge 1 \implies 1$, Class $0 \implies 0$).
- $\text{LSTM}(t-1 \to t)$: LSTM attack forecast formulated from the historical lookback sequence ending at window $t-1$ ($[t-10, t-9, \dots, t-1]$), predicting attack likelihood in target window $t$, evaluated against frozen threshold $\tau_{\text{lstm}} = 0.3000$.

### 3.2 Invariant Architectural Prohibitions
To preserve architectural integrity, Phase 4.5 strictly forbids:
1. Instantiating a 4th machine learning model.
2. Introducing meta-learning, stacking, or blending networks.
3. Training or retraining any model or ensemble.
4. Weighted numerical fusion (e.g., $w_1 \cdot P_{\text{ae}} + w_2 \cdot P_{\text{xgb}} + w_3 \cdot P_{\text{lstm}}$).
5. Tuning, adjusting, or re-calibrating any model threshold.
6. Passing outputs of one model as input features to another model.
7. Implementing automated response, firewall rule generation, or packet drops.
8. Introducing a 9th state or an `"LSTM_UNAVAILABLE"` state into the 8-state taxonomy.
9. Treating `"unavailable"` as `0` or `1`, or fabricating an LSTM prediction.
10. Silently dropping windows from the Scope-B timeline to force conservation.
11. Inferring direct state transitions across ineligible/unavailable windows.
12. Continuing dwell-time calculations across ineligible/unavailable windows.

---

## 4. Input/Artifact Inventory

The complete inventory of all 22 Phase 3.2, 3.3, 4.2, 4.3, and 4.4 input artifacts required by Phase 4.5 is detailed below:

| Phase | Relative Path | Format | Size / Shape | Operational Role | Integrity Mechanism | Primary Authority Source | Secondary Cross-Check |
|:---:|---|:---:|:---:|---|:---:|---|---|
| **3.2** | `data/model_inputs/master_features_dataset.csv` | CSV | 2,454 rows x 18 cols | Master represented timeline (2,454 windows in `global_position` order) | `SHA256_AUTHORITY_ESTABLISHED` | `src.dataset_preparation.verify_phase_3_2_integrity.BASELINE_PHASE_3_2_HASHES` | None |
| **3.2** | `data/model_inputs/metadata/attack_segments.csv` | CSV | 81 rows | Campaign ground truth | `NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED` | Phase 3.1 metadata (`attack_segment_summary.json`) | None |
| **3.3** | `data/model_ready/autoencoder/{X,y}_*.npy` | NPY | 5 arrays | AE training & test partitions | `SHA256_AUTHORITY_ESTABLISHED` | `src.models.verification.verify_model_infrastructure.BASELINE_MODEL_READY_HASHES` | None |
| **3.3** | `data/model_ready/xgboost/{X,y}_*.npy` | NPY | 6 arrays | XGB training & test partitions | `SHA256_AUTHORITY_ESTABLISHED` | `src.models.verification.verify_model_infrastructure.BASELINE_MODEL_READY_HASHES` | None |
| **3.3** | `data/model_ready/lstm/{X,y}_*.npy` | NPY | 6 arrays | LSTM sequence partitions | `SHA256_AUTHORITY_ESTABLISHED` | `src.models.verification.verify_model_infrastructure.BASELINE_MODEL_READY_HASHES` | None |
| **3.3** | `data/model_ready/artifacts/ae_scaler.joblib` | JOBLIB | 1,223 bytes | AE StandardScaler | `SHA256_AUTHORITY_ESTABLISHED` | `src.models.verification.verify_model_infrastructure.BASELINE_MODEL_READY_HASHES` | None |
| **3.3** | `data/model_ready/artifacts/xgb_label_encoder.joblib` | JOBLIB | 647 bytes | XGB LabelEncoder | `SHA256_AUTHORITY_ESTABLISHED` | `src.models.verification.verify_model_infrastructure.BASELINE_MODEL_READY_HASHES` | None |
| **3.3** | `data/model_ready/artifacts/lstm_scaler.joblib` | JOBLIB | 1,442 bytes | LSTM RobustScaler | `SHA256_AUTHORITY_ESTABLISHED` | `src.models.verification.verify_model_infrastructure.BASELINE_MODEL_READY_HASHES` | `data/model_reports/lstm/model_hashes.json` |
| **3.3** | `data/model_ready/autoencoder/test_manifest.csv` | CSV | 408 rows | AE test window manifest | `SHA256_AUTHORITY_ESTABLISHED` | `src.models.verification.verify_model_infrastructure.BASELINE_MODEL_READY_HASHES` | None |
| **3.3** | `data/model_ready/xgboost/test_manifest.csv` | CSV | 319 rows | XGB test window manifest | `SHA256_AUTHORITY_ESTABLISHED` | `src.models.verification.verify_model_infrastructure.BASELINE_MODEL_READY_HASHES` | None |
| **3.3** | `data/model_ready/lstm/test_manifest.csv` | CSV | 286 rows | LSTM test sequence manifest | `SHA256_AUTHORITY_ESTABLISHED` | `src.models.verification.verify_model_infrastructure.BASELINE_MODEL_READY_HASHES` | None |
| **3.3** | `data/model_ready/metadata/feature_columns.json` | JSON | 13 features | Feature contract definition | `NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED` | AST / Structural Schema Audit | None |
| **4.2** | `data/models/autoencoder/final_model/autoencoder.keras` | KERAS | 70,183 bytes | Frozen Autoencoder checkpoint | `NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED` | Checkpoint byte-identity with `best_model.keras` | None |
| **4.2** | `data/models/autoencoder/artifacts/model_metadata.json` | JSON | ~1 KB | Threshold $\tau_{\text{ae}} = 0.00320779$ | `NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED` | Schema / Numerical Threshold Contract | None |
| **4.2** | `data/model_reports/autoencoder/evaluation_report.json` | JSON | ~3 KB | Phase 4.2 test benchmarks | `NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED` | Metric Schema Audit | None |
| **4.3** | `data/models/xgboost/xgboost_model.json` | JSON | 174,028 bytes | Frozen XGBoost model | `NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED` | JSON AST / Booster Tree Structure | None |
| **4.3** | `data/models/xgboost/artifacts/model_metadata.json` | JSON | ~1 KB | XGBoost hyperparameters | `NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED` | Schema / Hyperparameter Invariant | None |
| **4.3** | `data/models/xgboost/feature_schema.json` | JSON | ~1 KB | 13 unscaled raw features | `NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED` | Schema Contract Audit | None |
| **4.3** | `data/model_reports/xgboost/evaluation_report.json` | JSON | ~4 KB | Phase 4.3 test benchmarks | `NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED` | Metric Schema Audit | None |
| **4.4** | `data/models/lstm/final_model/lstm_model.keras` | KERAS | 867,407 bytes | Frozen LSTM checkpoint | `NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED` | Checkpoint byte-identity with `best_model.keras` | `data/model_reports/lstm/model_hashes.json` |
| **4.4** | `data/models/lstm/artifacts/model_metadata.json` | JSON | ~1 KB | Threshold $\tau_{\text{lstm}} = 0.3000$ | `NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED` | Schema / Numerical Threshold Contract | None |
| **4.4** | `data/model_reports/lstm/evaluation_report.json` | JSON | ~3 KB | Phase 4.4 test benchmarks | `NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED` | Metric Schema Audit | None |

---

## 5. Integrity & Immutability Plan

### 5.1 Three-State Integrity Model Enforcement
1. **State 1 (`SHA256_AUTHORITY_ESTABLISHED`)**:
   - Dynamic Expected Hash Retrieval: Expected SHA-256 hashes are loaded dynamically at runtime from the primary authority source. Zero hashes are hardcoded into Phase 4.5 code.
   - Dynamic Chunked Computation: Actual SHA-256 hashes are computed on disk using 64 KB chunks (`65,536 bytes`).
   - Expected-vs-Actual Comparison: Must match identically under the applicable artifact integrity rule.
   - Secondary Cross-Check Validation: If a secondary report or cross-phase check exists, it is compared against the primary authority.
   - **Content Integrity vs Filesystem Metadata**: SHA-256 verifies file content integrity. A filesystem timestamp change alone does not modify file content and therefore does not alter SHA-256. If metadata integrity is required, it must be verified through a separate, dedicated metadata check.
2. **State 2 (`NON_SHA_INTEGRITY_MECHANISM_ESTABLISHED`)**:
   - For artifacts without precomputed SHA manifests in the repository, the specification explicitly notes: `"Primary SHA-256 Authority: NOT ESTABLISHED IN EXISTING REPOSITORY"`.
   - The established structural or identity verification mechanism is executed.
   - The absence of an expected SHA-256 hash is **not** treated as an automatic failure, and no fake checksum authority is fabricated.
3. **State 3 (`NO_INTEGRITY_AUTHORITY_ESTABLISHED`)**:
   - If an artifact has neither a SHA authority nor an established non-SHA mechanism, verification immediately triggers **`FAIL / NOT APPROVED`**.

### 5.2 Single Primary Authority & Secondary Evidence Principles
To eliminate ambiguity, Phase 4.5 strictly enforces that **every SHA-governed artifact possesses exactly one Primary Authority**:
- **`lstm_scaler.joblib`**: The sole Primary SHA-256 Authority is Phase 3.3 `src.models.verification.verify_model_infrastructure.BASELINE_MODEL_READY_HASHES`. The entry in `data/model_reports/lstm/model_hashes.json` is strictly a secondary cross-check.
- **Rule of Authority Hierarchy**:
  1. Secondary evidence can **never** override primary authority.
  2. Any disagreement between primary and secondary evidence is reported as an integrity inconsistency, resulting in immediate failure.
  3. A secondary report is never promoted to primary authority.
  4. No hardcoded or invented SHA-256 values are introduced.

### 5.3 Reconciling Raw SHA-256 vs LF-Normalized Text Integrity
On Windows workstations, Git checkouts with `core.autocrlf = true` convert LF to CRLF for CSV and JSON files, altering binary hash values while preserving textual content. The verifier enforces a rigorous distinction between binary byte identity and authorized text normalization:

1. **Binary Artifacts (`.npy`, `.joblib`, `.keras`)**:
   - Exact raw chunked SHA-256 matching is mandatory.
   - Result classification: **`RAW_HASH_MATCH`** (Raw file bytes exactly match the authoritative SHA-256 baseline).
   - Any mismatch triggers immediate failure. Normalization is never applied to binary files.
2. **Text Artifacts (CSV, JSON manifests and datasets)**:
   - Compute raw SHA-256 first.
   - If raw SHA matches the authoritative baseline, report **`RAW_HASH_MATCH`**.
   - If raw SHA mismatches: compute SHA-256 after CRLF $\to$ LF normalization (`content.replace(b'\r\n', b'\n')`).
   - If normalized content matches the authoritative baseline, report **`NORMALIZED_TEXT_HASH_MATCH`** (Raw bytes differ due to Windows line endings, but the authorized LF-normalized textual content matches the authoritative baseline).
   - **Critical Semantic Distinction**: An LF-normalized text match must **NEVER** be described as "byte-identical" or binary byte identity. The implementation plan must not silently treat normalized text equivalence as raw binary byte identity.

---

## 6. Scope-A Evaluation Plan

### 6.1 Preserving Independent Test Benchmarks
Scope A preserves the individual held-out benchmark evaluations established and verified in Phases 4.2, 4.3, and 4.4:
- **Autoencoder Benchmark**: Evaluated over $N = 408$ windows from `data/model_ready/autoencoder/test_manifest.csv`.
- **XGBoost Benchmark**: Evaluated over $N = 319$ windows from `data/model_ready/xgboost/test_manifest.csv`.
- **LSTM Benchmark**: Evaluated over $N = 286$ sequences from `data/model_ready/lstm/test_manifest.csv`.

**Critical Governance Constraint**: The synchronized tri-model concordance subset ($N = 45$) must **NEVER** replace or override the authoritative individual test benchmarks ($N=408, 319, 286$).

### 6.2 Metric Harvesting and Dynamic Verification
Phase 4.5 reads the authoritative metrics from prior evaluation reports and cross-verifies them dynamically:
- Autoencoder: Precision, Recall, F1, AUROC, Reconstruction Error distribution.
- XGBoost: Accuracy, Macro F1, Weighted F1, Multiclass Confusion Matrix.
- LSTM: Precision, Recall, F1, AUROC, True Positive / False Positive rates.

All harvested metrics are compiled into `cross_model_evaluation_report.json` under `scope_a_individual_benchmarks`.

---

## 7. Cross-Model Synchronization Plan

### 7.1 Target-Synchronized Tri-Model Subset ($N = 45$)
To compute pairwise consistency and tri-model threat states under held-out conditions without data leakage:
1. Extract manifest test window positions: $\mathcal{W}_{\text{ae}} \; (N=408)$, $\mathcal{W}_{\text{xgb}} \; (N=319)$, $\mathcal{W}_{\text{lstm}} \; (N=286)$.
2. Compute mutual set intersection:
   $$\mathcal{I}_{\text{manifest}} = \mathcal{W}_{\text{ae}} \cap \mathcal{W}_{\text{xgb}} \cap \mathcal{W}_{\text{lstm}} = 51 \text{ windows}$$
3. Apply Lookback Validity Filter:
   For each target window $t \in \mathcal{I}_{\text{manifest}}$, verify that the required 10 preceding lookback windows $[t-10, \dots, t-1]$:
   - Exist within the represented master-timeline windows in `global_position` order.
   - Do not cross day boundaries.
   - Do not violate partition split isolation.
4. Exclude the 6 invalid lookback positions:
   $$\mathcal{E} = \{918, 2383, 2384, 2385, 2386, 2387\}$$
5. Resulting Valid Synchronized Subset:
   $$\mathcal{S}_{\text{sync}} = \mathcal{I}_{\text{manifest}} \setminus \mathcal{E}, \quad |\mathcal{S}_{\text{sync}}| = 45 \text{ windows}$$

### 7.2 Complete Binary Validity of Scope A ($N = 45$)
Unlike Scope B, every target window in Scope A ($N=45$) possesses a valid, verified 10-window lookback within its split partition. Consequently, for every window in Scope A:
- $\text{AE}(t) \in \{0, 1\}$
- $\text{XGB}(t) \in \{0, 1\}$
- $\text{LSTM}(t-1 \to t) \in \{0, 1\}$

All 45 windows form complete binary triplets, satisfying the 8-state taxonomy contract and preserving exact state conservation ($\sum_{k=0}^7 \text{Count}(S_k) \equiv 45$).

---

## 8. Consistency Metrics Plan

### 8.1 Metric Formulations
For each model pair ($(\text{AE}, \text{XGB})$, $(\text{XGB}, \text{LSTM})$, $(\text{AE}, \text{LSTM})$):
1. **Cohen's Kappa ($\kappa$)**:
   $$\kappa = \frac{P_o - P_e}{1 - P_e}$$
   Where $P_o = \frac{\text{TP} + \text{TN}}{N}$ and $P_e = P_{y=1} \cdot P_{\hat{y}=1} + P_{y=0} \cdot P_{\hat{y}=0}$.
2. **Jaccard Similarity Index ($J$)**:
   $$J(A, B) = \frac{|A \cap B|}{|A \cup B|} = \frac{\text{TP}}{\text{TP} + \text{FP} + \text{FN}}$$
3. **Matthews Correlation Coefficient (MCC)**:
   $$\text{MCC} = \frac{\text{TP} \cdot \text{TN} - \text{FP} \cdot \text{FN}}{\sqrt{(\text{TP}+\text{FP})(\text{TP}+\text{FN})(\text{TN}+\text{FP})(\text{TN}+\text{FN})}}$$
4. **Raw Agreement & Disagreement**:
   $$\text{Agreement} = \frac{\text{TP} + \text{TN}}{N}, \quad \text{Disagreement} = 1.0 - \text{Agreement}$$
5. **Confusion Matrix (2x2)**:
   $$M = \begin{bmatrix} \text{TN} & \text{FP} \\ \text{FN} & \text{TP} \end{bmatrix}$$

### 8.2 Deterministic Edge-Case Handling Rules

#### Matthews Correlation Coefficient (MCC) Guardrail
If any sum in the denominator is zero (zero marginal variance):
- $\text{MCC}$ is mathematically undefined.
- Serialized value: `null`.
- Serialized reason: `"mcc_undefined_reason": "zero_marginal_variance"`.
- Substituting `0.0` is **STRICTLY PROHIBITED**.

#### Deterministic Jaccard Edge-Case Rule
When $\text{TP} + \text{FP} + \text{FN} = 0$, the union of positive attack predictions between both models is empty (both models predicted 100% negative/benign across all evaluated windows).
- **Mathematical Condition**: $\text{TP} + \text{FP} + \text{FN} = 0 \iff |A \cup B| = 0$ (Zero positive union).
- **Authoritative Rule (v2.9 Check O Compliance)**:
  - In accordance with v2.9 Check O (*"Uncomputed metrics in design schemas are null, never fake zero values"*), when $|A \cup B| = 0$, division by zero ($0/0$) occurs and Jaccard similarity is mathematically undefined.
  - Serialized value: `null`.
  - Serialized metadata reason: `"jaccard_undefined_reason": "zero_positive_union"`.
  - Substituting `0.0`, `1.0`, or any numeric value is **STRICTLY PROHIBITED**.
- **Verification Criterion (Check O)**: If $\text{TP} + \text{FP} + \text{FN} = 0$, `jaccard_similarity` must equal `null` and `jaccard_undefined_reason` must equal `"zero_positive_union"`. Any numeric substitution constitutes a hard failure.

### 8.3 Dual Scope Computation & Pairwise Eligibility
- **Scope A ($N = 45$)**: Evaluated over all 45 synchronized windows (all pairs have complete binary predictions).
- **Scope B ($N = 2,454$)**:
  - `ae_vs_xgboost`: Both models evaluate all 2,454 windows independently ($N=2,454$).
  - `xgboost_vs_lstm` and `ae_vs_lstm`: Evaluated across the dynamically derived eligible subset possessing complete binary predictions per the decoupled availability/eligibility architecture ($N_{\text{eligible}}$).

---

## 9. Eight-State Unified Inference Plan

### 9.1 Exhaustive Taxonomy & Operational Meaning
The 3 binary outputs ($\text{AE}(t), \text{XGB}(t), \text{LSTM}(t-1 \to t)$) yield $2^3 = 8$ mutually exclusive permutations. Each permutation maps deterministically to exactly one canonical neutral state:

| State Code | Canonical State Name | AE(t) | XGB(t) | LSTM(t-1→t) | Investigation Priority | Operational Meaning |
|:---:|---|:---:|:---:|:---:|---|---|
| **S0** | `BENIGN_CONCORDANCE` | 0 | 0 | 0 | Priority 4 (Routine) | Normal baseline; all 3 models concordant benign. Routine logging. |
| **S1** | `LSTM_FORECAST_ONLY` | 0 | 0 | 1 | Priority 3 (Early Warning) | Forward-looking attack forecast; current traffic clean. Pre-emptive monitoring. |
| **S2** | `XGB_ATTACK_ONLY` | 0 | 1 | 0 | Priority 3 (Isolated Signature) | Known attack signature detected without AE anomaly error. Single-model alert. |
| **S3** | `XGB_LSTM_CONSISTENCY` | 0 | 1 | 1 | Priority 2 (Elevated Investigation) | Forecasted signature attack active; low AE reconstruction error. Multi-model evidence. |
| **S4** | `AE_ANOMALY_ONLY` | 1 | 0 | 0 | Priority 3 (Statistical Divergence) | Unsupervised structural anomaly without matching signature or forecast. |
| **S5** | `AE_LSTM_CONSISTENCY` | 1 | 0 | 1 | Priority 2 (Anomalous Attack Activity) | Forecasted anomaly active; unclassified by supervised signature model. |
| **S6** | `AE_XGB_CONSENSUS` | 1 | 1 | 0 | Priority 2 (Unforecasted Attack Inset) | Known attack confirmed by AE and XGB without prior LSTM warning (zero-day/sudden). |
| **S7** | `TRI_MODEL_CONSENSUS` | 1 | 1 | 1 | Priority 1 (Maximum Confidence) | Tri-model consensus: forecasted, signature-matched, and anomaly-verified attack. |

### 9.2 Strict Taxonomy Invariance
- Exactly these 8 neutral states are permitted.
- Introducing a 9th state (such as `S8: LSTM_UNAVAILABLE` or `PARTIAL_EVALUATION`) is **STRICTLY PROHIBITED**.
- Unsupported semantic labels (`confirmed_attack`, `zero_day_detection`, `novel_attack_confirmation`, `guaranteed_prevention`, `autonomous_response`) are **STRICTLY PROHIBITED**.

### 9.3 Binary Triplet Requirement for Unified 8-State Eligibility
The mapping function $\mathcal{T}(b_{\text{ae}}, b_{\text{xgb}}, b_{\text{lstm}}) \to S_k$ is mathematically defined **ONLY** over the binary domain:

$$\text{Domain}(\mathcal{T}) = \{0, 1\}^3$$

Therefore:
- Any window with a complete binary tuple $(b_1, b_2, b_3) \in \{0, 1\}^3$ is **ELIGIBLE** for unified 8-state mapping.
- Any window where any model output is non-binary (such as $(b_1, b_2, \text{"unavailable"})$) is **INELIGIBLE** for the 8-state mapping.
- Forcing an incomplete tuple into $S_0 \dots S_7$ by treating `"unavailable"` as `0` or `1` is an architectural violation that falsifies model evidence.

### 9.4 Explicit Eligibility-Contiguity Rule for State Transitions and Dwell Time
To prevent spurious temporal correlations across missing data intervals, unified inference enforces the following architectural invariant:

> **Eligibility-Contiguity Rule**: State transitions and dwell-time sequences MUST be computed only across temporally consecutive eligible target windows. If an ineligible window occurs between two eligible windows, the ineligible window terminates the current eligible sequence. The next eligible window MUST NOT be treated as temporally adjacent to the preceding eligible window. An LSTM "unavailable" window therefore breaks state-transition and dwell-time continuity. No transition may be inferred across an unavailable/ineligible interval.

**Concrete Operational Example**:
- If the chronological sequence of target window states is:
  $$\dots \to S_3(t) \to \text{"unavailable"}(t+1) \to S_7(t+2) \to \dots$$
  The empirical state transition matrix MUST NOT record $S_3 \to S_7$ as a direct transition. The transition sequence from $S_3(t)$ terminates immediately. Window $t+2$ begins a fresh sequence.
- Dwell-time sequences are strictly subject to the same contiguity constraint: The dwell-time run for $S_3$ terminates immediately prior to window $t+1$ and MUST NOT span across or through the unavailable interval. Window $t+2$ ($S_7$) initiates a new, separate dwell sequence of length 1.

---

## 10. Scope-B Operational Replay Plan

### 10.1 Fundamental Distinction: Model Output Availability vs Unified 8-State Eligibility
To eliminate architectural contradictions, Phase 4.5 explicitly decouples **Model Output Availability** from **Unified 8-State Eligibility**:

1. **Model Output Availability (All 2,454 Windows)**:
   - For every window $t \in [1, 2454]$ among the represented master-timeline windows in `global_position` order (covering the active dataset periods across Monday–Friday, without implying that the full 7,200 minutes are continuously represented):
     - **Autoencoder Inference**: Evaluated independently for window $t$ on features scaled via `ae_scaler.joblib`. Yields binary $b_{\text{ae}}(t) \in \{0, 1\}$ via threshold $\tau_{\text{ae}} = 0.003207791231673312$.
     - **XGBoost Inference**: Evaluated independently for window $t$ on raw unscaled features. Yields 8-class prediction mapped to binary $b_{\text{xgb}}(t) \in \{0, 1\}$.
     - **LSTM Inference**: Attempted **ONLY** when its required historical lookback sequence $[t-10, \dots, t-1]$ is structurally valid (exists within the dataset, does not cross day boundaries, and does not violate partition isolation). If valid, yields binary $b_{\text{lstm}}(t-1 \to t) \in \{0, 1\}$ via threshold $\tau_{\text{lstm}} = 0.3000$.
     - **Unavailable Representation**: If the LSTM lookback is structurally invalid (e.g., windows 1–10 of each day), the LSTM forecast output is explicitly serialized as:
       $$y_{\text{lstm}}(t-1 \to t) = \text{"unavailable"}$$
     - **Prohibition Against Falsification**: A window with an unavailable LSTM result must **NOT** be falsely represented as a binary LSTM decision (neither `0` nor `1`).

2. **Unified 8-State Eligibility**:
   - A window can enter the 8-state mapping $\mathcal{T}$ **IF AND ONLY IF** all three model decisions are valid binary values ($b_{\text{ae}}, b_{\text{xgb}}, b_{\text{lstm}} \in \{0, 1\}$).
   - Windows with an incomplete tuple $(b_{\text{ae}}, b_{\text{xgb}}, \text{"unavailable"})$ **CANNOT** be mapped into any of the 8 canonical states ($S_0 \dots S_7$) without violating the frozen taxonomy.
   - For ineligible windows, operational replay conceptual representation explicitly records:
     ```json
     {
       "lstm_prediction": "unavailable",
       "is_eligible_for_threat_state": false,
       "threat_state": null,
       "ineligibility_reason": "lstm_lookback_unavailable"
     }
     ```
   - For eligible windows:
     ```json
     {
       "lstm_prediction": 0,
       "is_eligible_for_threat_state": true,
       "threat_state": "BENIGN_CONCORDANCE"
     }
     ```
   - In accordance with the Eligibility-Contiguity Rule (Section 9.4), state transitions and dwell runs are computed exclusively across contiguous sequences of eligible windows.

### 10.2 Formal Resolution of Blocker 4 in Authoritative Specification v2.9
Authoritative Specification v2.9 formally resolves the Scope-B conservation blocker by decoupling model-output availability from threat-state eligibility:
- **Scope-B Conservation Law**:
  $$N_{\text{master}} = N_{\text{eligible}} + N_{\text{ineligible}}$$
  $$\sum_{i=0}^7 \text{Count}(S_i) \equiv N_{\text{eligible}}$$
  $$\sum_{i=0}^7 \text{Count}(S_i) + N_{\text{ineligible}} \equiv N_{\text{master}}$$
- **Dynamic Derivation**: $N_{\text{master}}$, $N_{\text{eligible}}$, and $N_{\text{ineligible}}$ are dynamically derived at runtime from repository data. They are NOT hardcoded as immutable authority (though repository ground truth independently verifies expected values: $N_{\text{master}} = 2,454$, $N_{\text{eligible}} = 2,404$, $N_{\text{ineligible}} = 50$).
- **Taxonomy Preservation**: The 8 canonical states $S_0 \dots S_7$ are strictly preserved over $\{0, 1\}^3$. No 9th state ($S_8$ or `LSTM_UNAVAILABLE` as a threat state) is permitted.
- **Prohibition Against Falsification**: `"unavailable"` is never coerced to `0` or `1`, and no windows are dropped from the operational timeline.

### 10.3 Resolution Governance: Blocker 4 Formal Sign-Off
- Blocker 4 is formally **RESOLVED** via the adoption of Authoritative Specification v2.9.
- State-mapping logic, transition continuity, and deliverable schemas in Phase 4.5 adhere strictly to this decoupled availability/eligibility architecture.

### 10.4 Strict Operational Quarantine
Scope B is an **operational replay only**. It is strictly quarantined from:
- Model training or fine-tuning.
- Hyperparameter tuning.
- Decision threshold selection or modification.
- Feature selection.
- Any benchmark metric reporting.

---

## 11. Temporal Lead-Time Plan

### 11.1 Lead-Time Metric Formulation
For each attack campaign segment $c$ with start window $T_{\text{onset}}$:
$$\Delta t_{\text{lead}} = T_{\text{onset}} - T_{\text{first\_forecast}}$$
Where:
- $T_{\text{onset}}$: The global window index of campaign onset from `attack_segments.csv`.
- $T_{\text{first\_forecast}}$: The window index at which the earliest forecast was generated in a contiguous, unbroken sequence of positive LSTM attack forecasts ($\hat{y}_{\text{lstm}} = 1$) leading directly into $T_{\text{onset}}$ without intervening benign forecasts ($\hat{y}_{\text{lstm}} = 0$) or lookback unavailability. Specifically:
  - The single-step forecast directly targeting $T_{\text{onset}}$ is formulated at window $T_{\text{onset}} - 1$ ($\text{LSTM}(T_{\text{onset}} - 1 \to T_{\text{onset}})$). If this forecast is positive ($\hat{y} = 1$), an early warning is established.
  - The sequence is traced backward through preceding consecutive single-step forecasts ($\text{LSTM}(t - 1 \to t) = 1$); $T_{\text{first\_forecast}}$ is the generation window ($t - 1$) of the earliest positive forecast in this continuous pre-attack alert run, yielding $\Delta t_{\text{lead}} = T_{\text{onset}} - T_{\text{first\_forecast}} \ge 1$ windows.
  - If the forecast at $T_{\text{onset}} - 1$ targeting $T_{\text{onset}}$ is benign ($\hat{y} = 0$), no early warning was raised entering campaign onset, and the campaign is classified as unwarned ($\Delta t_{\text{lead}} = 0$).
  - If the forecast targeting $T_{\text{onset}}$ cannot be evaluated due to sequence or day boundaries (lookback cold-start within windows 1–10 of a day), lead time is serialized as `"unavailable"`.

### 11.2 Sequence Boundary & Cold-Start Rules
1. **Chronological Ordering**: Windows are processed strictly in chronological order.
2. **Day Boundary Isolation**: Lookback sequences cannot cross day boundaries (midnight cutoffs). If an attack begins within windows 1–10 of a day, preceding forecasts are structurally unavailable.
3. **Partition & Split Boundary Isolation**: Sequences cannot cross train/val/test split boundaries.
4. **Unavailable Representation**: When a valid preceding sequence is unavailable, lead time **MUST** be serialized as `"unavailable"`. Substituting `0` or fabricating values is strictly prohibited (as `0` signifies concurrent detection without early warning).

### 11.3 Strict Separation: Target Window Unavailability vs Campaign Unwarned Status
The plan strictly distinguishes two entirely different concepts:
1. **Target Window LSTM Unavailability**: A technical property of a specific window $t$ where historical lookback $[t-10 \dots t-1]$ is structurally absent (e.g., windows 1–10 of a day). The forecast output is `"unavailable"`.
2. **Campaign Pre-Warning Status**: An operational property of an attack campaign starting at $T_{\text{onset}}$:
   - **Pre-Warned**: An LSTM attack forecast was generated at $T_{\text{onset}} - \Delta t$ targeting $T_{\text{onset}}$ ($\Delta t \ge 1$).
   - **Unwarned**: Preceding lookback sequences were available, but the model predicted benign ($y=0$), resulting in no early warning before attack onset.
   - **Unavailable Lookback**: Preceding sequences crossed a day or split boundary, meaning no forecast could be evaluated. This is serialized as lead time = `"unavailable"`, not `0` and not unwarned.

### 11.4 Formal Resolution of Blocker 1 (81 Campaigns)
- **Specification Authority Resolution**: Authoritative Specification v2.9 formally resolves Blocker 1 by reconciling the campaign count to exactly **81 attack campaigns**, matching physical repository ground truth in `data/model_inputs/metadata/attack_segments.csv` (Tue: 4, Wed: 21, Thu: 30, Fri: 26).
- **Consumption Points of Resolved Campaign Count**:
  The authoritative campaign count ($C = 81$) is consumed in exactly 5 locations:
  1. `data/model_reports/comparison/temporal_lead_time_report.json`:
     - Top-level integer scalar `"total_campaigns_analyzed": 81`.
     - Array `"campaign_evaluations"`: exactly 81 evaluated campaign objects.
  2. `src/models/comparison/lead_time_analyzer.py`:
     - Iteration loop enumerating attack campaigns dynamically derived from `attack_segments.csv`.
     - Computation of aggregate statistics across all 81 campaigns in `"overall_lead_time_summary"`.
  3. `data/model_reports/comparison/tri_model_threat_matrix.json`:
     - Operational campaign coverage summary reporting total campaigns analyzed (81) and pre-warning proportion.
  4. `src/models/verification/verify_phase_4_5.py` (Check Q — Lead-Time Validity):
     - Dynamic assertion verifying that `len(report["campaign_evaluations"]) == report["total_campaigns_analyzed"] == 81`.
  5. `data/model_reports/comparison/phase_4_5_summary.md`:
     - Tabular campaign-level lead-time summary section and early-warning distribution breakdown across all 81 analyzed campaigns.

---

## 12. Deliverable Generation Plan

Phase 4.5 produces **exactly 7 deliverables (6 JSON + 1 Markdown)** in `data/model_reports/comparison/`:

```text
data/model_reports/comparison/
├── cross_model_evaluation_report.json
├── model_consistency_report.json
├── tri_model_threat_matrix.json
├── temporal_lead_time_report.json
├── unified_inference_spec.json
├── phase_4_5_verification_report.json
└── phase_4_5_summary.md
```

### 12.1 `cross_model_evaluation_report.json`
- Top-level metadata: phase, timestamp, execution mode.
- `scope_a_individual_benchmarks`:
  - `autoencoder`: Sample count ($N=408$), precision, recall, f1, auroc, threshold ($0.003207791231673312$).
  - `xgboost`: Sample count ($N=319$), accuracy, macro_f1, weighted_f1, class_names.
  - `lstm`: Sample count ($N=286$), precision, recall, f1, auroc, threshold ($0.3000$).
- `scope_a_synchronized_subset`: Sample count ($N=45$), synchronized binary metrics across models.
- `scope_b_operational_replay`: Total windows ($N=2,454$), positive detection counts per model, explicit unavailable count for LSTM.

### 12.2 `model_consistency_report.json`
- `scope_a_pairwise_consistency` ($N=45$):
  - Pairs: `ae_vs_xgboost`, `xgboost_vs_lstm`, `ae_vs_lstm`.
  - Metrics per pair: `cohens_kappa`, `jaccard_similarity`, `jaccard_undefined_reason`, `matthews_corrcoef`, `mcc_undefined_reason`, `raw_agreement_rate`, `raw_disagreement_rate`, `confusion_matrix`.
- `scope_b_pairwise_consistency`:
  - `ae_vs_xgboost` ($N=2,454$).
  - Pairwise metrics involving LSTM computed over dynamically derived eligible windows ($N_{\text{eligible}}$).

### 12.3 `tri_model_threat_matrix.json`
- `scope_a_synchronized_test_intersection` ($N=45$): Counts, percentages, and sample window lists for states $S_0$ through $S_7$. Conservation verified ($N=45$).
- `scope_b_operational_replay`:
  - `total_master_timeline_windows`: Dynamically derived count of all represented master-timeline windows (expected: 2,454).
  - `eligible_windows_count`: Dynamically derived count of windows with complete tri-model evidence (expected: 2,404).
  - `ineligible_windows_count`: Dynamically derived count of windows with incomplete evidence (expected: 50).
  - `ineligibility_breakdown`: Categorized accounting of ineligibility reasons (e.g., `{"lstm_lookback_cold_start": 50}`).
  - `state_distribution`: Counts of canonical states $S_0$ through $S_7$ evaluated strictly over eligible windows.
  - `conservation_verified`: Boolean verifying both $\sum \text{Count}(S_k) == N_{\text{eligible}}$ and $\sum \text{Count}(S_k) + N_{\text{ineligible}} == N_{\text{master}}$.
- `state_transition_matrix`: $8 \times 8$ empirical transition probability matrix $P(S_j(t) \mid S_i(t-1))$ computed strictly over contiguous sequences of eligible windows per the Eligibility-Contiguity Rule (Section 9.4).
- `dwell_time_statistics`: Mean and max consecutive window dwell time per state, terminated by ineligible/unavailable windows.

### 12.4 `temporal_lead_time_report.json`
- `total_campaigns_analyzed`: Consumes the authoritative campaign count (81).
- `overall_lead_time_summary`: Mean lead time, median lead time, pre-warned count, unwarned count, unavailable lookback count, pre-warning success rate.
- `campaign_evaluations`: List of evaluated campaign objects containing segment ID, day, attack type, onset window, first forecast window, lead time steps, and pre-warning status.

### 12.5 `unified_inference_spec.json`
- Operational specification of the 8 canonical states.
- Priority levels and SOC investigation workflows.
- Input contracts, scaling rules, threshold definitions.
- State mapping logic, pseudocode, and Eligibility-Contiguity Rule.

### 12.6 `phase_4_5_verification_report.json`
- Independent audit output for Checks A through S.
- Overall status: `"PASS"` or `"FAIL"`.
- Individual check dictionary with status, evidence, and timestamps.

### 12.7 `phase_4_5_summary.md`
- High-level executive narrative synthesizing Phase 4.5 results.
- Architecture summary, individual benchmark table, consistency audit findings, 8-state distribution tables, lead-time early warning analysis, and governance sign-offs.

---

## 13. Verification Checks A–S

The independent verification suite `src/models/verification/verify_phase_4_5.py` will audit the pipeline across 19 objective checks:

### Master Summary Table

| Check ID | Check Name | Objective Pass Criteria | Failure Condition | Output Location |
|---|---|---|---|---|
| **Check A** | Frozen Artifact Existence | All required Phase 3.2, 3.3, 4.2, 4.3, 4.4 input artifacts exist on disk. | Any required file missing. | `phase_4_5_verification_report.json` |
| **Check B** | SHA-256 Integrity & Authority Hierarchy | State 1 artifacts match expected SHA from primary authority under applicable rule (`RAW_HASH_MATCH` for binary, `RAW_HASH_MATCH` or `NORMALIZED_TEXT_HASH_MATCH` for text); secondary cross-checks agree; State 2 artifacts pass non-SHA structural checks; zero hardcoded hashes. | Any SHA mismatch, cross-manifest conflict, or invariant failure. | `phase_4_5_verification_report.json` |
| **Check C** | Phase 3.3 Content Immutability | All Phase 3.3 content remains cryptographically consistent with its authoritative baseline under the applicable artifact integrity rule (`RAW_HASH_MATCH` for binary files; `RAW_HASH_MATCH` or authorized `NORMALIZED_TEXT_HASH_MATCH` for text files). | Unauthorized content/hash modification, deletion, or failure of defined integrity mechanism. Filesystem timestamp changes alone do not constitute failure. | `phase_4_5_verification_report.json` |
| **Check D** | Feature Contract | All models consume exactly the canonical 13 features in invariant order (`flow_count` through `syn_packet_ratio`). | Feature count $\ne 13$, wrong order, or unexpected columns. | `phase_4_5_verification_report.json` |
| **Check E** | Model Independence | Phase 4.5 orchestration must invoke the three frozen models independently and must not pass one model’s output into another model or use model outputs as cross-model features. | Any model output imported or passed as feature to another model. | `phase_4_5_verification_report.json` |
| **Check F** | Threshold Authority | Runtime threshold values must exactly equal the values loaded from the authoritative frozen model metadata artifacts. Expected values may be recorded as audit evidence, but must not be hardcoded as Phase 4.5 threshold authority. | Hardcoded thresholds used as runtime authority, modified values, or rounding applied to comparators. | `phase_4_5_verification_report.json` |
| **Check G** | LSTM Temporal Alignment | Sequence alignment verified: $\text{AE}(t)$, $\text{XGB}(t)$, $\text{LSTM}(t-1 \to t)$. | Reverse alignment ($\text{LSTM}_{t \to t+1}$ used for $t$) or missing sequence offset. | `phase_4_5_verification_report.json` |
| **Check H** | Partition Overlap | Manifest-level mutual test intersection confirmed as exactly $N = 51$ windows. These values are verification expectations derived from frozen repository evidence and MUST NOT serve as hardcoded runtime input data. Runtime synchronization must derive the sets dynamically from authoritative manifests and temporal validity rules. | Overlap count $\ne 51$ or hardcoded set used as runtime input. | `phase_4_5_verification_report.json` |
| **Check I** | Synchronized Overlap | Target-synchronized tri-model subset confirmed as exactly $N = 45$ windows under Scope-A contract. These values are verification expectations derived from frozen repository evidence and MUST NOT serve as hardcoded runtime input data. Runtime synchronization must derive the sets dynamically from authoritative manifests and temporal validity rules. | Synchronized count $\ne 45$, invalid lookback included, or hardcoded set used as runtime input. | `phase_4_5_verification_report.json` |
| **Check J** | State Taxonomy & Neutrality (No Falsification) | Exactly 8 canonical neutral states (`S0`–`S7`) exist; zero legacy semantic labels; zero 9th states; incomplete tuples receive null threat state (`threat_state: null`); `"unavailable"` is never coerced to `0` or `1`. | Forbidden label found, missing state, extra state, or coercion of `"unavailable"` to numeric value. | `phase_4_5_verification_report.json` |
| **Check K** | Scope-B Conservation | Scope-B operational replay satisfies exact sample conservation over complete tri-model eligible windows: $\sum \text{Count}(S_k) \equiv N_{\text{eligible}}$, and master-timeline accounting satisfies: $N_{\text{eligible}} + N_{\text{ineligible}} \equiv N_{\text{master}}$ (expected repository verification counts: $2,404 + 50 = 2,454$). All sample counts dynamically derived at runtime. | Eligible sum $\ne N_{\text{eligible}}$, master sum $\ne N_{\text{master}}$, or sample counts not dynamically derived. | `phase_4_5_verification_report.json` |
| **Check L** | No Numerical Fusion | AST and source inspection confirms zero score-blending or linear weighting formulas. | Weighted formula or combined score calculation found. | `phase_4_5_verification_report.json` |
| **Check M** | No Autonomous Remediation | Scan only Phase 4.5 implementation modules and Phase 4.5 verification logic for subprocess execution, network socket manipulation, firewall commands, packet-control commands, or actuation APIs. Pre-existing functionality outside the Phase 4.5 implementation scope is not considered a Phase 4.5 violation unless Phase 4.5 imports, invokes, or modifies it for autonomous remediation. | Remediation logic or actuation commands present in Phase 4.5 scope or invoked by Phase 4.5. | `phase_4_5_verification_report.json` |
| **Check N** | Metric Schema Completeness | Kappa, Jaccard, and MCC all present in report schemas. | Any required metric missing from schema. | `phase_4_5_verification_report.json` |
| **Check O** | Null Handling | Undefined MCC and Jaccard serialized as `null` with reason metadata, never fake `0.0` or `1.0`. | Metric defaults to zero or numeric substitution when denominator is zero. | `phase_4_5_verification_report.json` |
| **Check P** | Scope Separation | Scope A held-out benchmark and Scope B operational replay are strictly quarantined. | Scope B metrics reported as test benchmarks. | `phase_4_5_verification_report.json` |
| **Check Q** | Lead-Time Validity | Sequence boundaries and day boundaries enforced; unavailable forecasts marked `"unavailable"`; exactly 81 attack campaigns analyzed. | Day boundary crossing, `0` substituted for unavailable forecast, or campaign count mismatch ($\ne 81$). | `phase_4_5_verification_report.json` |
| **Check R** | Deliverable Completeness | The Phase 4.5 required deliverable set contains exactly seven specified files (6 JSON + 1 Markdown). All seven exist, are valid, and satisfy schemas. Unexpected additional Phase 4.5 deliverables prohibited. | Any of the 7 required Phase 4.5 deliverables missing/invalid, or unexpected Phase 4.5 deliverable found. Unrelated repository files unaffected. | `phase_4_5_verification_report.json` |
| **Check S** | Specification Self-Consistency & Resolution Verification | Plan contains zero unacknowledged internal contradictions; all four authority blockers formally resolved in Specification v2.9. | Unacknowledged internal contradiction in code/schemas; competing primary authorities; or unresolved authority conflict. | `phase_4_5_verification_report.json` |

---

### Detailed Specification for Checks A through S

#### Check A: Frozen Artifact Existence
- **Objective**: Verify that all 22 required Phase 3.2, 3.3, 4.2, 4.3, and 4.4 input artifacts physically exist on disk.
- **Implementation Approach**: `verify_phase_4_5.py` iterates over every file path defined in `src/models/comparison/config.py:REQUIRED_ARTIFACT_PATHS`, calling `path.is_file()` and recording byte sizes.
- **Objective PASS Criteria**: All 22 required files exist on disk with positive byte size.
- **Hard Failure Condition**: Any required file is missing or has 0 bytes.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_a_artifact_existence`.

#### Check B: SHA-256 Integrity & Authority Hierarchy
- **Objective**: Enforce the Three-State Integrity Model with single primary authority per SHA artifact.
- **Implementation Approach**: For State-1 artifacts, load expected hashes dynamically from primary authority dictionaries (`BASELINE_MODEL_READY_HASHES`, `BASELINE_PHASE_3_2_HASHES`). Compute actual SHA-256 in 64 KB chunks. For binary files, require exact `RAW_HASH_MATCH`. For text files, apply Section 5.3 normalization logic (`RAW_HASH_MATCH` or authorized `NORMALIZED_TEXT_HASH_MATCH`). Verify secondary cross-checks against primary. For State-2 artifacts, execute structural/byte-identity audits.
- **Objective PASS Criteria**: 100% hash match against primary authority for all State-1 artifacts under applicable rule (`RAW_HASH_MATCH` for binary; `RAW_HASH_MATCH` or `NORMALIZED_TEXT_HASH_MATCH` for text); secondary cross-checks match primary authority; all State-2 structural checks pass; zero hardcoded hashes in Phase 4.5 code.
- **Hard Failure Condition**: Any hash mismatch, any secondary evidence overriding primary authority, or any artifact in State 3.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_b_integrity_authority_hierarchy`.

#### Check C: Phase 3.3 Content Immutability
- **Objective**: Guarantee that Phase 4.5 execution does not modify the content of Phase 3.3 model-ready datasets, scalers, encoders, or manifests.
- **Implementation Approach**: Compute SHA-256 hashes for all SHA-governed Phase 3.3 files before and after Phase 4.5 execution and compare against the authoritative baseline (`BASELINE_MODEL_READY_HASHES`). For text artifacts subject to the explicitly authorized LF-normalization rule, apply the text-integrity semantics defined in Section 5.3.
- **Objective PASS Criteria**: All Phase 3.3 content remains cryptographically consistent with its authoritative baseline under the applicable artifact integrity rule (`RAW_HASH_MATCH` for binary files; `RAW_HASH_MATCH` or authorized `NORMALIZED_TEXT_HASH_MATCH` for text files).
- **Hard Failure Condition**: Any Phase 3.3 file has an unauthorized content/hash modification, deletion, or failure of its separately defined integrity mechanism. A filesystem timestamp change alone MUST NOT constitute a SHA-256/content immutability failure unless timestamp integrity is independently defined and verified by a dedicated metadata authority/check.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_c_phase_3_3_immutability`.

#### Check D: Canonical 13-Feature Contract
- **Objective**: Verify that all three models consume the exact canonical 13 features in invariant order with model-specific preprocessing.
- **Implementation Approach**: Dynamically inspect `data/model_ready/metadata/feature_columns.json`, `data/models/xgboost/feature_schema.json`, and input tensors. Assert `len(columns) == 13` and exact string equality against the reconciled canonical feature list.
- **Objective PASS Criteria**: Exact match in feature names, exact ordering from `flow_count` to `syn_packet_ratio`, dimensionality = 13, and valid preprocessing contracts (AE: StandardScaler; XGB: raw unscaled; LSTM: RobustScaler).
- **Hard Failure Condition**: Dimensionality $\ne 13$, column reordering, missing column, or unexpected feature names.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_d_13_feature_contract`.

#### Check E: Model Independence
- **Objective**: Ensure complete structural decoupling of all three models during inference.
- **Implementation Approach**: Perform AST parsing and inspection on `src/models/comparison/cross_model_evaluator.py`, `threat_inference_engine.py`, and `lead_time_analyzer.py` to confirm no model's output tensor or score is passed as an input argument to any other model.
- **Objective PASS Criteria**: Phase 4.5 orchestration must invoke the three frozen models independently and must not pass one model’s output into another model or use model outputs as cross-model features.
- **Hard Failure Condition**: Any output of Model A imported into, concatenated with, or fed as a feature to Model B or C.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_e_model_independence`.

#### Check F: Threshold Authority
- **Objective**: Confirm that decision thresholds are dynamically loaded from frozen model artifacts without alteration or rounding.
- **Implementation Approach**: Read $\tau_{\text{ae}}$ from `data/models/autoencoder/artifacts/model_metadata.json` and $\tau_{\text{lstm}}$ from `data/models/lstm/artifacts/model_metadata.json`. Compare runtime thresholds against authoritative values.
- **Objective PASS Criteria**: Runtime threshold values must exactly equal the values loaded from the authoritative frozen model metadata artifacts. Expected values may be recorded as audit evidence, but must not be hardcoded as Phase 4.5 threshold authority.
- **Hard Failure Condition**: Hardcoded threshold values, numerical rounding, or modified threshold comparators.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_f_threshold_authority`.

#### Check G: LSTM Temporal Alignment
- **Objective**: Verify the forward-looking temporal alignment contract: $\text{AE}(t) + \text{XGB}(t) + \text{LSTM}(t-1 \to t)$.
- **Implementation Approach**: Inspect sequence slicing logic in `timeline_synchronizer.py` and `lead_time_analyzer.py`. Assert that for target window $t$, the LSTM input sequence spans $[t-10, \dots, t-1]$ and predicts target window $t$.
- **Objective PASS Criteria**: Window $t$ evaluated by AE reconstruction error at $t$, XGBoost prediction at $t$, and LSTM forecast formed at $t-1$ targeting $t$.
- **Hard Failure Condition**: Concurrent alignment violation (using LSTM input sequence $[t-9, \dots, t]$ to predict $t+1$ for window $t$) or missing sequence offset.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_g_temporal_alignment`.

#### Check H: Manifest Partition Overlap ($N = 51$)
- **Objective**: Confirm the mathematical intersection of the three frozen test manifests equals exactly 51 windows.
- **Implementation Approach**: Load `test_manifest.csv` for AE ($N=408$), XGB ($N=319$), and LSTM ($N=286$). Compute `set(ae_pos) & set(xgb_pos) & set(lstm_pos)` and evaluate length and members.
- **Objective PASS Criteria**: Set intersection contains exactly 51 integer positions matching $\{918\} \cup \{2072 \dots 2111\} \cup \{2383 \dots 2392\}$. These values are verification expectations derived from frozen repository evidence and MUST NOT serve as hardcoded runtime input data. Runtime synchronization must derive the sets dynamically from authoritative manifests and temporal validity rules.
- **Hard Failure Condition**: Intersection size $\ne 51$ or position mismatch.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_h_mutual_overlap_51`.

#### Check I: Valid Synchronized Subset ($N = 45$)
- **Objective**: Verify that after removing the 6 invalid lookback positions, the valid synchronized test subset contains exactly 45 windows.
- **Implementation Approach**: Filter the 51 mutual overlap windows through lookback boundary validation (rejecting cross-day gaps and partition boundary lookback violations). Verify exclusion of $\{918, 2383, 2384, 2385, 2386, 2387\}$.
- **Objective PASS Criteria**: Synchronized test window set contains exactly 45 contiguous positions ($\{2072 \dots 2111\} \cup \{2388 \dots 2392\}$). These values are verification expectations derived from frozen repository evidence and MUST NOT serve as hardcoded runtime input data. Runtime synchronization must derive the sets dynamically from authoritative manifests and temporal validity rules.
- **Hard Failure Condition**: Subset size $\ne 45$ or inclusion of any invalid lookback window.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_i_synchronized_subset_45`.

#### Check J: State Taxonomy & Neutrality (No Falsification)
- **Objective**: Enforce the exact 8 canonical neutral states ($S_0$ through $S_7$), eliminate legacy speculative labels, forbid any 9th state, and strictly prohibit falsification (no coercion of `"unavailable"` to `0` or `1`; incomplete tuples receive null threat state).
- **Implementation Approach**: Inspect all keys, values, and string literals in generated JSON reports, source files, and Markdown summaries for forbidden semantic strings (`confirmed_attack`, `zero_day_detection`, `novel_attack_confirmation`, `guaranteed_prevention`, `autonomous_response`) or unauthorized states (e.g., `S8`, `LSTM_UNAVAILABLE`). Assert that incomplete tuples serialize with `"threat_state": null` and `"is_eligible_for_threat_state": false`.
- **Objective PASS Criteria**: Exactly 8 states present (`BENIGN_CONCORDANCE` through `TRI_MODEL_CONSENSUS`); zero occurrences of forbidden semantic labels; zero extra states; zero falsified binary values for unavailable predictions.
- **Hard Failure Condition**: Any missing state, unknown state code, 9th state introduced, presence of any forbidden label, or coercion of `"unavailable"` into numeric binary `0` or `1`.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_j_state_taxonomy`.

#### Check K: Scope-B Conservation
- **Objective**: Verify that Scope-B operational replay strictly satisfies sample conservation over eligible windows ($\sum_{i=0}^7 \text{Count}(S_i) \equiv N_{\text{eligible}}$) and complete master-timeline window accounting ($N_{\text{eligible}} + N_{\text{ineligible}} \equiv N_{\text{master}}$), with all sample counts dynamically derived at runtime.
- **Implementation Approach**:
  - Evaluate Scope-B threat-state distributions strictly over complete tri-model evidence ($N_{\text{eligible}}$). Assert that $\sum_{k=0}^7 \text{Count}(S_k) == N_{\text{eligible}}$.
  - Evaluate master-timeline accounting across all represented windows ($N_{\text{master}}$). Assert that $N_{\text{eligible}} + N_{\text{ineligible}} == N_{\text{master}}$.
  - Verify that $N_{\text{master}}$, $N_{\text{eligible}}$, and $N_{\text{ineligible}}$ are dynamically derived at runtime from repository data, and that expected verification values ($2,454 = 2,404 + 50$) are verified without hardcoding.
- **Objective PASS Criteria**: Scope-B operational replay satisfies $\sum_{i=0}^7 \text{Count}(S_i) \equiv N_{\text{eligible}}$, and master-timeline accounting satisfies $N_{\text{eligible}} + N_{\text{ineligible}} \equiv N_{\text{master}}$, with all counts derived dynamically at runtime.
- **Hard Failure Condition**: Eligible Scope-B sum $\ne N_{\text{eligible}}$, master-timeline sum $\ne N_{\text{master}}$, or sample counts not dynamically derived.
- **Governance Status**: **FORMALLY RESOLVED** in Specification v2.9 via Separation of Availability from Eligibility.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_k_scope_b_conservation`.

#### Check L: No Numerical Fusion
- **Objective**: Guarantee that no composite risk scores, linear combinations, or blended probabilities are computed.
- **Implementation Approach**: AST scan of `src/models/comparison/` checking for arithmetic operations combining continuous outputs (probabilities, reconstruction errors) from different models (e.g., $w_1 \cdot P_1 + w_2 \cdot P_2$).
- **Objective PASS Criteria**: Source code contains zero numerical score fusion; threat states derived purely from binary thresholded decisions.
- **Hard Failure Condition**: Any continuous score blending or weighted arithmetic combination detected.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_l_no_numerical_fusion`.

#### Check M: No Autonomous Remediation
- **Objective**: Guarantee that Phase 4.5 contains no automated network actuation, firewall manipulation, or packet blocking.
- **Implementation Approach**: Scan only Phase 4.5 implementation modules and Phase 4.5 verification logic for subprocess execution, network socket manipulation, firewall commands, packet-control commands, or actuation APIs. Pre-existing functionality outside the Phase 4.5 implementation scope is not considered a Phase 4.5 violation unless Phase 4.5 imports, invokes, or modifies it for autonomous remediation.
- **Objective PASS Criteria**: No autonomous remediation, actuation, firewall manipulation, packet-control command, or network-blocking logic is present in Phase 4.5 modules or invoked by Phase 4.5.
- **Hard Failure Condition**: Any network remediation command, blocking action, packet-control command, or actuation logic present in Phase 4.5 modules or verification logic, or any Phase 4.5 module importing, invoking, or modifying external functionality for autonomous remediation.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_m_no_autonomous_remediation`.

#### Check N: Metric Schema Completeness
- **Objective**: Verify that all required consistency metrics are present in report schemas.
- **Implementation Approach**: Load `model_consistency_report.json` and validate that every pairwise evaluation contains all mandatory metric fields and the applicable null-reason fields: `cohens_kappa`, `jaccard_similarity`, `matthews_corrcoef`, `raw_agreement_rate`, `raw_disagreement_rate`, `confusion_matrix`, and null reason fields.
- **Objective PASS Criteria**: All mandatory consistency fields present for all three pairs across Scope A and eligible Scope B evaluations.
- **Hard Failure Condition**: Any required consistency metric missing from the report structure.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_n_metric_schema_completeness`.

#### Check O: Null Handling (MCC & Jaccard)
- **Objective**: Verify that mathematically undefined metrics serialize as `null` with explicit reason metadata, never fake zeros or numeric fallbacks.
- **Implementation Approach**: Audit metric calculation routines. Assert that if denominator is zero in MCC, output is `null` with `"mcc_undefined_reason": "zero_marginal_variance"`. Assert that if $\text{TP} + \text{FP} + \text{FN} = 0$ in Jaccard, output is `null` with `"jaccard_undefined_reason": "zero_positive_union"`.
- **Objective PASS Criteria**: Undefined metrics serialize as JSON `null` accompanied by exact reason strings; substituting `0.0` or `1.0` is strictly absent.
- **Hard Failure Condition**: Substituting `0.0`, `1.0`, or any numeric value when denominator is zero, or omitting reason metadata.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_o_null_handling`.

#### Check P: Scope Separation
- **Objective**: Guarantee that Scope A held-out benchmark evaluation and Scope B operational replay are strictly isolated.
- **Implementation Approach**: Verify that no Scope B replay data is present in `cross_model_evaluation_report.json:scope_a_individual_benchmarks` and that test manifest masks are strictly respected during Scope A evaluation.
- **Objective PASS Criteria**: Scope A benchmarks evaluate only held-out test splits; Scope B operational metrics are quarantined under separate replay keys.
- **Hard Failure Condition**: Any conflation of held-out test benchmarks with operational replay data.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_p_scope_separation`.

#### Check Q: Lead-Time Validity
- **Objective**: Verify that attack forecasting lead time strictly enforces sequence boundaries, day boundaries, and matches the authoritative 81-campaign count.
- **Implementation Approach**: Audit `temporal_lead_time_report.json`. Validate that every campaign's lead time respects day boundaries (no lookbacks crossing midnight). Confirm that unavailable lookbacks serialize as `"unavailable"` (not `0`). Verify that `total_campaigns_analyzed` equals 81.
- **Objective PASS Criteria**: Zero cross-day sequence leakage; unavailable forecasts serialized as `"unavailable"`; evaluated campaign count matches 81 exactly.
- **Hard Failure Condition**: Day boundary crossing, substituting `0` for unavailable sequence, or campaign count mismatch ($\ne 81$).
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_q_lead_time_validity`.

#### Check R: Deliverable Completeness
- **Objective**: Verify that the complete set of required Phase 4.5 deliverables exists and is valid.
- **Implementation Approach**: Verify the existence and parse integrity of the seven specified Phase 4.5 deliverables under `data/model_reports/comparison/`.
- **Objective PASS Criteria**: The Phase 4.5 required deliverable set contains exactly seven specified files: six JSON reports and one Markdown summary (`cross_model_evaluation_report.json`, `model_consistency_report.json`, `tri_model_threat_matrix.json`, `temporal_lead_time_report.json`, `unified_inference_spec.json`, `phase_4_5_verification_report.json`, and `phase_4_5_summary.md`). All seven required deliverables must exist, be valid, and satisfy their schemas. Unexpected additional Phase 4.5 deliverables are prohibited.
- **Hard Failure Condition**: Any of the seven required Phase 4.5 deliverables is missing, has invalid JSON/Markdown syntax, fails schema validation, or any unexpected additional Phase 4.5 deliverable is present. Check R does not require or imply the deletion of unrelated repository files or prior-phase artifacts.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_r_deliverable_completeness`.

#### Check S: Specification Self-Consistency & Authority Resolution Verification
- **Objective**: Guarantee that the implementation plan contains zero unacknowledged internal contradictions, preserves single primary authority per SHA artifact, and verifies that all four authority blockers are formally resolved in Authoritative Specification v2.9.
- **Implementation Approach**: Audit the implementation plan and codebase configuration for:
  1. **Internal Implementation-Plan Contradictions** (e.g., conflicting assumptions across sections, treating unavailable as 0 in one place while prohibiting it in another, permitting 9 states while requiring 8, direct transitions across ineligible windows violating the Eligibility-Contiguity Rule, or competing primary SHA authorities). Any such internal contradiction constitutes an immediate failure.
  2. **Formal Blocker Resolutions** (Blocker 1: 81 campaign count; Blocker 2: 13-feature contract formal sign-off; Blocker 3: Jaccard undefined edge-case confirmation; Blocker 4: Decoupled availability and threat-state eligibility with Scope-B conservation over $N_{\text{eligible}}$). Confirm that all four are formally resolved in Specification v2.9.
- **Objective PASS Criteria**: PASS for specification self-consistency means the implementation plan contains no unacknowledged internal contradiction and all four authority blockers are formally resolved in Specification v2.9.
- **Hard Failure Condition**: Any unacknowledged internal contradiction in code or schemas; competing primary authorities; or unresolved authority conflict.
- **Governance Status**: **PASS** — Specification v2.9 provides full authoritative resolution for all four blockers.
- **Output Location**: `phase_4_5_verification_report.json -> checks -> check_s_specification_self_consistency`.

---

## 14. Error Handling & Failure Conditions

Phase 4.5 execution will **FAIL IMMEDIATELY** upon encountering any of the following 21 conditions:
1. Expected-vs-actual SHA-256 mismatch for any State-1 artifact under its applicable rule (`RAW_HASH_MATCH` for binary, `RAW_HASH_MATCH` or `NORMALIZED_TEXT_HASH_MATCH` for text).
2. Structural or identity invariant failure for any State-2 artifact.
3. Unresolved evidence gap for any artifact (State 3: `NO_INTEGRITY_AUTHORITY_ESTABLISHED`).
4. Any prior-phase scaler or encoder refitted or modified.
5. Any frozen decision threshold altered or overridden.
6. A fourth ML model, meta-learner, or neural fusion layer instantiated.
7. Model outputs coupled or fed as inputs into other models.
8. Combined numerical scoring or linear coefficient blending formulas implemented.
9. Uncalibrated numbers presented as composite probabilities.
10. Held-out test metrics and operational replay metrics combined or conflated.
11. Individual model test benchmarks ($N=408, 319, 286$) replaced by the mutual intersection ($N=45$).
12. Temporal leakage (using $\text{LSTM}_{t \to t+1}$ instead of $\text{LSTM}_{t-1 \to t}$ for window $t$).
13. Threat state distribution fails to sum exactly to eligible sample count ($\sum \text{Count}(S_i) \ne N_{\text{eligible}}$) or master timeline accounting fails ($N_{\text{eligible}} + N_{\text{ineligible}} \ne N_{\text{master}}$).
14. An incomplete tuple $(b_1, b_2, \text{"unavailable"})$ mapped to any of the 8 canonical states.
15. A ninth state or `"LSTM_UNAVAILABLE"` state introduced into the taxonomy.
16. State transitions or dwell-time runs computed across ineligible/unavailable windows in violation of the Eligibility-Contiguity Rule.
17. Sequences cross day or partition boundaries in violation of temporal isolation rules.
18. Attack forecasting lead time substitutes `0` for unavailable lookback sequences instead of `"unavailable"`.
19. Uncomputed or undefined metrics serialized as fake `0.0` or `1.0` instead of `null` with reason metadata.
20. Any of the 7 required deliverables missing from `data/model_reports/comparison/`, invalid syntax, or unexpected additional Phase 4.5 deliverable present.
21. Any legacy semantic label (`confirmed_attack`, `zero_day_detection`, etc.) introduced into reports or code.

---

## 15. Determinism & Reproducibility Plan

### 15.1 Scoped Local Determinism
- **No Retroactive Mutation**: Phase 4.5 must **NOT** modify global environment variables (`PYTHONHASHSEED`, `TF_DETERMINISTIC_OPS`) or retroactively mutate prior-phase training environments.
- **Local Seed Configuration**: Where a deterministic seed is required by a specific computation, `seed = 42` is passed locally to the relevant function.
- **Purely Deterministic Computation**: Because Phase 4.5 performs zero model training, zero stochastic sampling, and zero optimization, all array indexing, thresholding, confusion matrix counting, and state mapping operations are inherently deterministic.

### 15.2 Invariant Ordering & Serialization
1. **Window Ordering**: Windows are processed strictly by `global_position` (1 to 2,454).
2. **Campaign Ordering**: Attack segments are processed strictly by `segment_id` and `global_start_position`.
3. **Feature Ordering**: Feature columns adhere strictly to the canonical 13-feature contract.
4. **JSON Serialization**: Reports serialized using `ScientificJSONEncoder` with sorted keys and fixed schemas.
5. **Path Portability**: All paths in reports converted to project-relative POSIX format (`to_project_relative()`).

---

## 16. Implementation Sequence

The proposed codebase structure introduces a dedicated, modular package:

```text
src/models/comparison/
├── __init__.py
├── config.py                      # Canonical constants, thresholds, paths, taxonomy
├── integrity.py                   # Dynamic Three-State integrity & authority verification
├── timeline_synchronizer.py       # Master 2,454 timeline alignment & scope quarantine
├── cross_model_evaluator.py       # Scope A & Scope B metric evaluation pipelines
├── consistency_analyzer.py        # Kappa, Jaccard, MCC with null handling
├── threat_inference_engine.py     # Deterministic 8-state mapping, conservation, & Eligibility Contiguity
├── lead_time_analyzer.py          # Early-warning lead-time evaluation across segments
└── report_generator.py            # Deliverable serialization (6 JSON + 1 MD)

src/models/verification/
└── verify_phase_4_5.py            # Independent Verification Suite (Checks A–S)
```

### Module Responsibilities & Signatures
1. `src/models/comparison/config.py`: Centralize paths, thresholds, state taxonomies, priority definitions, and expected sample counts.
2. `src/models/comparison/integrity.py`: Dynamic Three-State integrity verification. Dynamically reads `BASELINE_PHASE_3_2_HASHES` and `BASELINE_MODEL_READY_HASHES`. Enforces `RAW_HASH_MATCH` for binary artifacts and authorized `NORMALIZED_TEXT_HASH_MATCH` for text files.
3. `src/models/comparison/timeline_synchronizer.py`: Loads the 2,454 represented master-timeline windows in `global_position` order. Aligns model predictions to windows. Extracts Scope A ($N=45$) and isolates Scope B ($N=2,454$). Identifies cold-start lookback windows.
4. `src/models/comparison/cross_model_evaluator.py`: Evaluates individual test benchmarks ($N=408, 319, 286$) and synchronized cross-model evaluations.
5. `src/models/comparison/consistency_analyzer.py`: Computes Kappa, Jaccard, MCC, raw agreement, and confusion matrices with strict `null` guardrails for zero-division edge cases.
6. `src/models/comparison/threat_inference_engine.py`: Maps binary output tuples to the 8 canonical states. Validates conservation over eligible windows. Rejects incomplete tuples. Computes state transition matrix and dwell times strictly enforcing the Eligibility-Contiguity Rule.
7. `src/models/comparison/lead_time_analyzer.py`: Evaluates early-warning lead time across attack campaigns using the authoritative campaign count ($C = 81$). Enforces sequence boundaries and marks missing lookbacks as `"unavailable"`.
8. `src/models/comparison/report_generator.py`: Assembles and serializes the 7 required deliverables in `data/model_reports/comparison/`.
9. `src/models/verification/verify_phase_4_5.py`: Executes Checks A through S and writes `phase_4_5_verification_report.json`.

---

## 17. Acceptance Criteria

Phase 4.5 will be accepted when:
1. All 7 required deliverable files physically exist in `data/model_reports/comparison/`.
2. All 19 verification checks (Checks A through S) in `src/models/verification/verify_phase_4_5.py` report `"status": "PASS"`.
3. Overall verification status in `phase_4_5_verification_report.json` is `"status": "PASS"`.
4. Threat state distributions across eligible scopes satisfy conservation: $\sum \text{Count}(S_k) \equiv N_{\text{eligible}}$.
5. State transitions and dwell times strictly satisfy the Eligibility-Contiguity Rule without bridging across ineligible windows.
6. Zero model training, zero threshold tuning, and zero continuous score fusion code exists.
7. Phase 3.3 model-ready artifacts remain 100% cryptographically consistent under their applicable integrity rules (`RAW_HASH_MATCH` for binary, `RAW_HASH_MATCH` or `NORMALIZED_TEXT_HASH_MATCH` for text).
8. All 4 authority blockers in Section 19 are formally resolved by Authoritative Specification v2.9.

---

## 18. Risks & Evidence Gaps

1. **Campaign-Count Authority**:
   - Formally resolved to 81 attack campaigns in Specification v2.9 matching physical repository ground truth in `attack_segments.csv`.
2. **Small Synchronized Held-Out Intersection ($N = 45$)**:
   - Mutual overlap of held-out test sets yields 45 valid windows. This is statistically sufficient for concordance demonstration but requires Scope-B operational replay for comprehensive operational behavior.
3. **LSTM Lookback Cold-Start & Availability Accounting**:
   - At the beginning of each day (first 10 windows), LSTM forecasts are unavailable due to strict day boundary enforcement. In Specification v2.9, this is treated strictly as a model-output availability condition decoupled from threat-state eligibility, with dynamic conservation holding over eligible windows ($N_{\text{eligible}}$).
4. **Early Campaign Window Availability**:
   - In the first 10 windows of each day, LSTM forecasts targeting window $t$ cannot be formed without crossing day boundaries. Attacks initiating in these early windows cannot be pre-warned and must be marked `"unavailable"`.
5. **Cross-Platform Text Line Endings**:
   - Git checkout on Windows converts LF to CRLF for CSV and JSON files. While binary files are unaffected, text verification logic enforces `NORMALIZED_TEXT_HASH_MATCH` to prevent false cryptographic immutability failures without conflating text normalization with binary byte identity.

---

## 19. Implementation Blockers & Final Readiness Assessment

### 19.1 Four Resolved Authority Blockers
All four authority blockers are **FORMALLY RESOLVED** by Authoritative Specification v2.9:

1. **Blocker 1 — 81 Campaign-Count Authority Decision [RESOLVED]**:
   - *Resolution*: Authoritative Specification v2.9 reconciles the campaign count to exactly **81 attack campaigns**, matching physical repository ground truth in `data/model_inputs/metadata/attack_segments.csv` (Tue: 4, Wed: 21, Thu: 30, Fri: 26). The historical 83 count was an artifact of counting total lines in the CSV file (81 data rows + 1 header + 1 trailing newline).
2. **Blocker 2 — Authoritative 13-Feature Contract Formal Sign-Off [RESOLVED]**:
   - *Resolution*: Canonical 13-feature contract (`flow_count` through `syn_packet_ratio`) is 100% verified across Phase 2.3, Phase 3.3, Phase 4.3, and Phase 4.4 repository truth, and formally signed off in Specification v2.9.
3. **Blocker 3 — Deterministic Jaccard Edge-Case Rule Confirmation [RESOLVED]**:
   - *Resolution*: Confirmed that when $\text{TP} + \text{FP} + \text{FN} = 0$, Jaccard similarity is serialized as `null` with `"jaccard_undefined_reason": "zero_positive_union"`. Numeric substitutions are strictly prohibited.
4. **Blocker 4 — LSTM "Unavailable" vs 8-State Taxonomy & Scope-B Conservation Authority Resolution [RESOLVED]**:
   - *Resolution*: Authoritative Specification v2.9 formally decouples **model-output availability** from **threat-state eligibility**. Check K uniquely represents Scope-B conservation over complete tri-model evidence ($\sum_{i=0}^7 \text{Count}(S_i) \equiv N_{\text{eligible}}$), and master-timeline conservation holds as $N_{\text{eligible}} + N_{\text{ineligible}} \equiv N_{\text{master}}$. All sample counts are dynamically derived at runtime (expected: $N_{\text{master}} = 2,454$, $N_{\text{eligible}} = 2,404$, $N_{\text{ineligible}} = 50$). Ineligible windows receive no threat state (`threat_state: null`). The Eligibility-Contiguity Rule is strictly enforced: state transitions and dwell times are computed exclusively across contiguous sequences of eligible windows without bridging across gaps.

### 19.2 Final Status Declaration
With all four specification-authority blockers formally resolved in Specification v2.9 and the implementation plan fully reconciled and consistency-audited, the governance status is:

```text
================================================================================
PHASE 4.5 IMPLEMENTATION PLAN STATUS:
READY FOR IMPLEMENTATION
================================================================================
```
