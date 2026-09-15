# NexThreat Phase 6.5 — Production Packaging & Containerization Implementation Plan

```text
================================================================================
NEXTHREAT SECURE NETWORK TELEMETRY THREAT-DETECTION PLATFORM
PHASE 6.5 — PRODUCTION PACKAGING & CONTAINERIZATION IMPLEMENTATION PLAN
DOCUMENT VERSION : 3.0.0
DATE             : 2026-09-15
GOVERNANCE STAGE : PLAN ONLY — IMPLEMENTATION NOT AUTHORIZED
STATUS           : READY FOR FINAL AUDIT
================================================================================
```

---

## 1. Executive Summary

### 1.1 Objective & Purpose
The primary objective of **Phase 6.5 — Production Packaging & Containerization** is to design and formalize a hermetic, reproducible, enterprise-hardened production packaging specification for the NexThreat Multi-Model Network Telemetry Threat-Detection platform.

Phase 6.5 translates the verified Python application runtime and HTTP transport services (accepted across Phases 5, 6.2, 6.3, and 6.4) into an immutable, secure Open Container Initiative (OCI)-compliant container image and reproducible operational environment. This specification guarantees that NexThreat can be deployed, booted, scaled, and operated reliably across diverse cloud, on-premises, and air-gapped infrastructure without environment drift or runtime degradation.

### 1.2 Foundational Governing Principles
Two inviolable governing principles define the operational boundaries of Phase 6.5:

> **"Phase 6 exposes NexThreat; Phase 6 does not redefine NexThreat."**  
> *(Phase 6 Architectural Charter)*

> **"Phase 6.5 packages NexThreat; Phase 6.5 does not re-architect NexThreat."**  
> *(Phase 6.5 Packaging Charter)*

The overarching implementation rule is:
> **Package the accepted system exactly as it exists. Do not introduce new application semantics merely to facilitate containerization.**

### 1.3 "No Invented Contracts" Governance Rule
> **NO INVENTED CONTRACTS RULE**: Phase 6.5 packages and exposes the already-authorized NexThreat system. Phase 6.5 MUST NOT redefine, extend, tighten, weaken, or invent application, API, model, validation, transport, or threat-state contracts.

Any requirement not supported by:
- the accepted Phase 4.7 baseline,
- accepted Phase 5.x contracts,
- accepted Phase 6.2 schema specifications,
- accepted Phase 6.3 transport implementations,
- accepted Phase 6.4 API contracts,
- or verified current repository behavior

must **NOT** be presented as an existing contract. This rule applies universally across all design decisions, configuration schemas, Dockerfile instructions, Compose declarations, and verification gates (C1–C16).

### 1.4 Governance Workflow Stage
The NexThreat engineering governance lifecycle follows the strict mandatory sequence:

```text
Plan → Audit → Corrections → Approval → Implementation → Verification → Acceptance
```

- **Current Stage**: **PLAN ONLY — IMPLEMENTATION NOT AUTHORIZED**.
- **Status**: **READY FOR FINAL AUDIT**.
- **Revision 3.0.0 Update**: Document Version 3.0.0 incorporates all corrections resulting from the formal audit of Revision 2.0.0, resolving five material blockers:
  1. Complete transitive dependency/hash lock specification distinguishing direct runtime dependencies from the full resolved closure for `linux/amd64`.
  2. Repository-authoritative engine initialization path (`NexThreatAPIServer(host=..., port=...)` default `engine=None` constructing `ApplicationInferenceEngine()`).
  3. Authoritative resolution of the 10 MB payload byte limit grounded in `src/application/service.py:34`, `src/api/handlers.py:199-205`, and Phase 6.4 Gate D11.
  4. Reset prohibition aligned with accepted HTTP semantics (`src/api/handlers.py:103-109` and Phase 6.4 Gate D12).
  5. Exact target architecture (`linux/amd64`) and requirement for resolving the immutable base-image SHA-256 digest prior to implementation.
- **Execution Mandate**: Implementation authorization is **NOT GRANTED**. No source code, Dockerfiles, compose files, shell scripts, container manifests, lockfiles, or verification test suites may be created or modified until this implementation plan receives formal audit sign-off and explicit approval.

### 1.5 Relationship to Upstream Accepted Phases
- **Phase 4.7 (Accepted ML Baseline)**: Inherits the immutable 33-file inventory and tri-model architecture (Autoencoder, XGBoost, LSTM). All 33 files retain their original repository-relative paths across all directories.
- **Phase 5.7 (Accepted Application Orchestration)**: Encapsulates the 10-step transactional orchestrator (`ApplicationInferenceEngine`), temporal state manager (`TemporalHistoryBuffer`), unified threat engine (`evaluate_threat_state`), 10-window lookback cold-start rule, and public reset prohibition.
- **Phase 6.2 (Accepted Schemas & Validators)**: Preserves the 24-field nested response structure, Format A and Format B single-window ingestion schemas, stream batch validation, and strict error envelope structures.
- **Phase 6.3 (Accepted Transport Handlers & Server)**: Packages the standard-library HTTP service (`NexThreatAPIServer`, `NexThreatAPIHandler`) serving `/health`, `/status`, `/api/v1/infer/window`, and `/api/v1/infer/stream`.
- **Phase 6.4 (Accepted API Contracts & Specifications)**: Packages the verified OpenAPI 3.1.0 specification, developer integration guide, operational runbook, integration examples catalogue, and verification harness baseline (16/16 D-Gates PASS). Phase 6.4 documentation remains completely immutable.

---

## 2. Authority & Precedence

### 2.1 Order of Precedence
In any instance of ambiguity, conflict, or tension between packaging requirements and upstream codebases, the following strict hierarchy of authority governs:

```text
[1. Phase 4.7 Accepted ML Baseline & 33-File SHA-256 Manifest]
                              ▲
[2. Phase 5.7 Application Runtime & Engine Invariants]
                              ▲
[3. Phase 6.2 Schema & Validation Authority Matrix]
                              ▲
[4. Phase 6.3 HTTP Transport Handlers & Server Architecture]
                              ▲
[5. Phase 6.4 Accepted API Specifications & Operational Runbook]
                              ▲
[6. Phase 6.5 Production Packaging & Containerization Plan]
```

### 2.2 Subordination of Packaging
The container packaging design is subordinate to all accepted upstream contracts:
1. **Container packaging cannot modify model behavior**: Model weights, scalers, manifests, and metadata files copied into the container must match their Phase 4.7 SHA-256 hashes to the byte.
2. **Container packaging cannot alter API contracts**: The routes exposed by the container must remain strictly `/health`, `/status`, `/api/v1/infer/window`, and `/api/v1/infer/stream`. The prohibited endpoint `/api/v1/reset` must continue to return HTTP 404.
3. **Container packaging cannot redefine error structures**: Error responses emitted inside the container must adhere structurally and semantically to the Phase 6.2/6.3/6.4 standardized error envelope `{code, message, status_code, timestamp, details}` with complete information sanitization, allowing for dynamic timestamps.
4. **Container packaging cannot introduce new concurrency models or worker pools**: Concurrency is governed by the accepted `ThreadingHTTPServer` and `engine_lock` mutex. No worker abstraction (such as `NEXTHREAT_WORKERS`) may be introduced.
5. **Container packaging cannot modify accepted Phase 6.4 documentation**: Phase 6.5 shall not add, expose, or implement `/api/v1/reset`. Existing Phase 6.4 documentation remains immutable, including its existing reset prohibition.
6. **Container packaging cannot introduce new dependencies to runtime code**: The runtime inference pipeline must remain free of unpinned external frameworks.

### 2.3 Explicit Authority Matrix
The following matrix establishes the authoritative source of truth for every packaging parameter and operational contract:

| Contract Domain | Parameter / Invariant | Authority / Source of Truth |
| :--- | :--- | :--- |
| **Python Version** | Python 3.14 (3.14.0 baseline) | `data/model_reports/hardening/infrastructure_metadata.json` (line 15) |
| **Base Image Family** | `python:3.14-slim` | Official Debian-based Python slim distribution; Phase 6.5 approved packaging contract |
| **Target Architecture** | `linux/amd64` | Phase 6.5 approved single build target architecture |
| **Base Image Digest** | Resolved immutable SHA-256 digest | Docker Hub / official OCI registry manifest for `python:3.14-slim` on `linux/amd64` |
| **Direct Dependencies** | 6 pinned runtime packages | Accepted Phase 5/6 runtime: `numpy==2.5.3`, `pandas==3.0.5`, `scikit-learn==1.9.1`, `joblib==1.6.0`, `xgboost==3.4.1`, `h5py==3.16.0` |
| **Transitive Closure** | Complete resolved dependency closure | Resolved package metadata for `linux/amd64` (including `scipy`, `narwhals`, `threadpoolctl`, `python-dateutil`, `tzdata`, etc.) |
| **33-File Inventory** | Phase 4.7 immutable inventory | `data/model_reports/acceptance/phase_4_7_acceptance_report.json` ("Pillar_1_PRE") |
| **Model Artifact Paths**| 33 exact repository-relative paths | `data/model_inputs/`, `data/model_ready/`, `data/models/`, `data/model_reports/`, `src/models/verification/` |
| **API Routes** | `/health`, `/status`, `/api/v1/infer/window`, `/api/v1/infer/stream` | Frozen `src/api/handlers.py`, Phase 6.3 and Phase 6.4 specifications |
| **Request / Response Schemas** | Format A, Format B, 24-field nested response | Frozen `src/api/schemas.py`, Phase 6.2 and Phase 6.4 specifications |
| **Validation Behavior** | Non-finite checks, type enforcement | Frozen `src/api/validators.py`, Phase 6.2 specification |
| **Engine Initialization** | Default initialization via `engine=None` | Frozen `src/api/server.py:33` delegating to `src/application/orchestrator.py:57-65` |
| **Health Behavior** | 3-field response (`status`, `integrity`, `timestamp`) | Frozen `src/api/handlers.py:278-296` delegating to `src/application/service.py:42-88` |
| **Status Behavior** | 5-field response (`status`, `processed_windows`, `lookback_depth`, `engine_version`, `timestamp`) | Frozen `src/api/handlers.py:298-315` |
| **Stream Record Limit**| Maximum 5,000 records per stream batch | Frozen `src/application/service.py:35`, `src/api/validators.py:29` (`MAX_STREAM_RECORDS = 5000`), Phase 6.4 Gate D11 |
| **Payload Byte Limit**  | Maximum 10 MB (10,485,760 bytes) HTTP 413 | Frozen `src/application/service.py:34` (`MAX_REQUEST_BYTES = 10 * 1024 * 1024`), `src/api/handlers.py:199-205`, Phase 6.4 Gate D11 |
| **Reset Behavior** | `/api/v1/reset` returns HTTP 404 `NOT_FOUND` | Frozen `src/api/handlers.py:103-109`; Phase 6.4 Gate D12 (`verify_phase_6_4.py:487-502`) |
| **Error Envelope** | Standardized `{code, message, status_code, timestamp, details}` | Frozen `src/api/exceptions.py:126-146`, Phase 6.2, 6.3, and 6.4 specifications |
| **Shutdown Behavior** | Server shutdown: 2.0s join timeout;<br>Container grace period: 15s | **Server shutdown**: Existing frozen `src/api/server.py:57-68` behavior (`server.stop()` with server-thread join timeout of 2.0s).<br>**Container shutdown grace period**: 15 seconds — Phase 6.5 approved container lifecycle requirement / implementation target (not an already-existing runtime artifact). |
| **Security Constraints** | Non-root UID 10001, `read_only: true`, `cap_drop: ALL` | Phase 6.5 security specification aligned with container best practices |
| **API Documentation**   | OpenAPI 3.1.0, runbook, integration guide | Frozen `docs/api/*` accepted in Phase 6.4 |

---

## 3. Current Repository Baseline

An exhaustive inspection of the current repository state (`c:\SIH\NexThreat` / `E:\Project\NexThreat`) was performed to establish ground truth prior to formulation of this plan.

### 3.1 Runtime Dependency Architecture (Pure NumPy Forward Passes)
A critical architectural discovery established during repository inspection:
- `src/application/predictors.py` implements **pure NumPy forward passes** for both the frozen Autoencoder and the frozen LSTM model.
- Weights are extracted from frozen `.keras` zip archives directly in memory using standard Python `zipfile` and `h5py`.
- XGBoost is executed via `xgboost.Booster` using unscaled 13-feature inputs.
- Feature scaling is executed via `joblib.load()` and `scikit-learn` scalers.
- **Heavy frameworks (TensorFlow, Keras, PyTorch) are NOT imported or required by the production runtime pipeline.**
- This architectural design allows the production container image to remain exceptionally compact, fast-booting, and free of massive CUDA/ML framework CVE surfaces.

### 3.2 Single Authoritative Python Runtime Target & Architecture
Inspection of authoritative repository evidence establishes the single compatible runtime target:
- `data/model_reports/hardening/infrastructure_metadata.json` line 15 explicitly defines: `"python_version": "3.14.0"`.
- Active execution environment: Python 3.14.7.
- **Single Approved Runtime Target**: **Python 3.14**.

To eliminate ambiguity and ensure build reproducibility, the plan defines the following explicit parameters:
1. **Python Language Version**: Exactly `Python 3.14` (CPython 3.14.0 compatible baseline).
2. **Base Image Family**: `python:3.14-slim` (official Debian-based minimal slim image).
3. **Target Architecture**: Exactly **`linux/amd64`**. No alternative architectures (such as `linux/arm64` or "architecture as available") are permitted.
4. **Immutable Base Image Digest Requirement**: The production Dockerfile must reference the exact immutable image digest corresponding to `python:3.14-slim` on `linux/amd64`.
   - The plan strictly prohibits fabricated digests and prohibits placeholder strings (such as `sha256:<DIGEST>`) in implementation deliverables.
   - The exact SHA-256 digest must be resolved from official registry metadata for `linux/amd64` prior to implementation and recorded in the Dockerfile and verification harness.
   - **Explicit Blocker Declaration**: `IMPLEMENTATION BLOCKED UNTIL EXACT BASE IMAGE DIGEST IS RESOLVED`.
   - The digest must be revalidated against the selected architecture prior to container build.

### 3.3 Authoritative Phase 4.7 33-File Artifact Boundary
The Phase 4.7 33-file SHA-256 inventory defined in `data/model_reports/acceptance/phase_4_7_acceptance_report.json` ("Pillar_1_PRE" -> "artifacts") is authoritative.

Inspection proves that **the 33 files do NOT all reside under `data/models/`**. Instead, they span multiple repository directories:
1. `data/model_inputs/manifests/split_manifest.json`
2. `data/model_inputs/manifests/train_manifest.json`
3. `data/model_inputs/manifests/val_manifest.json`
4. `data/model_inputs/manifests/test_manifest.json`
5. `data/model_inputs/metadata/attack_segments.csv`
6. `data/model_ready/artifacts/autoencoder_scaler.joblib`
7. `data/model_ready/artifacts/lstm_scaler.joblib`
8. `data/model_ready/artifacts/xgboost_label_encoder.joblib`
9. `data/model_ready/metadata/feature_columns.json`
10. `data/model_ready/metadata/label_encoding.json`
11. `data/model_ready/metadata/scaler_mean.json`
12. `data/model_ready/metadata/scaler_scale.json`
13. `data/model_ready/metadata/preprocessing_pipeline_spec.json`
14. `data/models/autoencoder/model.keras`
15. `data/models/autoencoder/threshold.json`
16. `data/models/autoencoder/reconstruction_threshold.json`
17. `data/models/xgboost/model.json`
18. `data/models/xgboost/best_iteration.json`
19. `data/models/xgboost/feature_names.json`
20. `data/models/xgboost/multiclass_mapping.json`
21. `data/models/lstm/model.keras`
22. `data/models/lstm/threshold.json`
23. `data/model_reports/lstm/lstm_operational_threshold_spec.json`
24. `data/model_reports/comparison/tri_model_comparison_matrix.json`
25. `data/model_reports/comparison/tri_model_comparison_report.md`
26. `data/model_reports/comparison/tri_model_comparison_report.json`
27. `data/model_reports/comparison/performance_matrix.json`
28. `data/model_reports/comparison/tri_model_decision_matrix.md`
29. `data/model_reports/comparison/tri_model_decision_matrix.json`
30. `data/model_reports/comparison/production_freeze_declaration.md`
31. `src/models/verification/verify_phase_4_6.py`
32. `data/model_reports/hardening/phase_4_7_verification_report.json`
33. `data/model_reports/hardening/phase_4_7_verification_report.md`

> **Authoritative Inventory Rule**: Containerization shall preserve the original relative path of every inventory member. No assumption may be made that all 33 files reside under `data/models/`. Do not relocate, rename, flatten, or reorganize any of the 33 files.

### 3.4 Repository-Authoritative Engine Initialization Path
Inspection of the actual frozen repository source establishes the exact engine initialization mechanism:
- `src/api/server.py` line 33:
  ```python
  def __init__(
      self,
      host: str = "127.0.0.1",
      port: int = 8000,
      engine: Optional[Any] = None,
  ) -> None:
      self.host = host
      self.port = port
      self.engine = engine if engine is not None else getattr(orchestrator, "ApplicationInferenceEngine")()
      self.engine_lock = threading.Lock()
      self.server: Optional[ThreadingHTTPServer] = None
      self._server_thread: Optional[threading.Thread] = None
  ```
- `src/application/orchestrator.py` lines 57–65:
  ```python
  def __init__(
      self,
      ae_predictor: Optional[AutoencoderPredictor] = None,
      xgb_predictor: Optional[XGBoostPredictor] = None,
      lstm_predictor: Optional[LSTMPredictor] = None,
  ):
      self.ae_predictor = ae_predictor or AutoencoderPredictor()
      self.xgb_predictor = xgb_predictor or XGBoostPredictor()
      self.lstm_predictor = lstm_predictor or LSTMPredictor()
  ```
- `src/api/server.py` lines 47–49:
  ```python
  def start(self, daemon: bool = True) -> None:
      handler_cls = NexThreatAPIHandler
      handler_cls.engine = self.engine
      handler_cls.engine_lock = self.engine_lock
      ...
  ```

**Authoritative Finding (Option A)**:
The frozen server **internally initializes the authorized engine when `engine=None`**. When `NexThreatAPIServer(host=..., port=...)` is instantiated without passing an engine, `self.engine` is automatically assigned an `ApplicationInferenceEngine()` instance constructed via `getattr(orchestrator, "ApplicationInferenceEngine")()`. This engine instantiation internally loads `AutoencoderPredictor()`, `XGBoostPredictor()`, and `LSTMPredictor()`, initializing all model binaries, scalers, and temporal history buffers.

When `server.start()` executes, `self.engine` is assigned to `NexThreatAPIHandler.engine`.

**Entrypoint Lifecycle Strategy**:
The Phase 6.5 entrypoint (`src/api/entrypoint.py`) relies directly on this existing, authoritative behavior by instantiating `server = NexThreatAPIServer(host=host, port=port)`. No custom engine factory or manual model-loading mechanism shall be invented.

**Expected Failure Semantics**:
If any required model artifact, scaler, or metadata file is missing or corrupted on disk, `ApplicationInferenceEngine()` instantiation raises an exception (e.g., `FileNotFoundError`, `ModelExecutionError`), aborting server startup. If the engine is uninitialized (`handler.engine is None`), the `/health` endpoint (`src/api/handlers.py:281-283`) evaluates `if self.engine is None: is_healthy = False` and returns HTTP 503 `status: "UNHEALTHY", integrity: "FAILED"`.

### 3.5 Existing Container & Deployment Artifacts
- Zero Dockerfiles, `.dockerignore` files, compose manifests, or container orchestration manifests currently exist in the repository.
- Git status confirms a clean working tree at authoritative commit `fa3984fdf762e8d81b9a8daa4c0fc356ec6c9065` (`fa3984f`), with only the Phase 6.5 planning document present as an untracked governance file.

---

## 4. Scope

The authorized scope of Phase 6.5 comprises exactly the following engineering activities:
1. **Multi-Stage Dockerfile Formulation**: Authoring a production-hardened, multi-stage `Dockerfile` targeting `linux/amd64` and utilizing a single pinned official minimal slim Python base image (`python:3.14-slim@sha256:<resolved_digest>`), compiling dependencies in an ephemeral build stage, and copying pure wheels and application source into an unprivileged runtime layer.
2. **Build Context Optimization (`.dockerignore`)**: Authoring a strict `.dockerignore` to eliminate build cache contamination, local environments (`venv/`), scratch files, git metadata, and local development caches.
3. **Cryptographically Pinned Dependency Closure (`requirements.lock`)**: Formulating an exact, version-pinned, hash-verified runtime dependency manifest encompassing the complete transitive dependency closure for `linux/amd64`, guaranteeing deterministic dependency installation via `--require-hashes`.
4. **Local Orchestration Manifest (`docker-compose.yml`)**: Authoring a standardized Compose specification exposing port 8000, configuring container resource reservations (2 vCPU, 2048 MB RAM), container stop grace period (`stop_grace_period: 15s`), native health check parameters, tmpfs mounts, read-only root filesystems, and restart policies.
5. **Container Entrypoint Runner (`src/api/entrypoint.py`)**: Authoring a dedicated production CLI runner wrapping `NexThreatAPIServer`, relying on its authoritative default engine initialization, parsing environment variables (`NEXTHREAT_HOST`, `NEXTHREAT_PORT`, `NEXTHREAT_LOG_LEVEL`), binding OS signal listeners (`SIGTERM`, `SIGINT`), and orchestrating graceful termination.
6. **Automated Verification Harness (`src/api/verification/verify_phase_6_5.py`)**: Authoring an automated verification suite executing 16 deterministic acceptance gates (**C1–C16**) and full upstream regression across Phases 4.7, 5.7, 6.2, 6.3, and 6.4.
7. **Verification & Acceptance Reports**: Generating machine-readable JSON and human-readable Markdown verification reports registering build outputs, image provenance, and gate results upon successful test execution.

---

## 5. Non-Scope

The following activities are strictly prohibited from Phase 6.5 execution:
1. **Machine Learning Model Adjustments**: Zero retraining, re-fitting, weight recalibration, architecture alteration, or threshold modification for Autoencoder, XGBoost, or LSTM models.
2. **Feature Schema or Ordering Modifications**: Zero changes to the 13 canonical features, their names, order, or validation criteria.
3. **Threat State Alterations**: Zero additions (such as S8), removals, redefinitions, or re-mappings of canonical threat states S0 through S7.
4. **API Interface Redesign**: Zero new HTTP routes, parameters, verbs, query strings, headers, or WebSocket/gRPC interfaces.
5. **Public Reset Endpoint**: Zero introduction or exposure of `/api/v1/reset`. It remains strictly forbidden and must return HTTP 404 across all HTTP verbs.
6. **Phase 6.4 Documentation Mutation**: Zero modifications to accepted Phase 6.4 documentation (`docs/api/*`). Phase 6.4 documentation remains immutable, including its existing reset prohibition.
7. **Concurrency Redefinition / Worker Pools**: Zero introduction of `NEXTHREAT_WORKERS` or alternative process/thread pooling abstractions. The existing `ThreadingHTTPServer` and mutex lock remain authoritative.
8. **External Partial Volume Mounting**: Zero partial mounting of `/secure/models -> /app/data/models`. All 33 files are embedded directly at their exact relative paths.
9. **Non-Deterministic Package Upgrades**: Zero `apt-get upgrade -y` instructions in Docker build steps.
10. **Transport-Layer In-Process Authentication**: Zero introduction of JWT validation, mTLS verification, API keys, or user databases into the Python application process. Authentication remains strictly an external API Gateway / reverse proxy concern.
11. **Cluster Orchestration Expansion**: Zero creation of Kubernetes Helm charts, DaemonSets, StatefulSets, ingress controllers, or cloud-specific service mesh configurations.
12. **Autonomous Remediation / SOAR Logic**: Zero automated IP blocking, firewall rule execution, interface dropping, or TCP reset packet injection.
13. **Refactoring Pre-Existing Runtime Code**: Zero modifications to frozen files in `src/application/*`, `src/models/*`, `data/models/*`, or pre-existing `src/api/*` runtime files (`src/api/server.py`, `src/api/handlers.py`, `src/api/schemas.py`, `src/api/validators.py`, `src/api/exceptions.py`, `src/api/__init__.py`).
14. **Invented Request Ceilings**: Zero arbitrary or invented payload limits. Only the authoritative 10 MB payload ceiling (`src/application/service.py:34`, `src/api/handlers.py:199-205`) and 5,000-record stream ceiling (`src/application/service.py:35`, `src/api/validators.py:29`) are verified.

---

## 6. Target Packaging Architecture

### 6.1 Component Topology & Data Flow
The packaged container operates as a self-contained, unprivileged microservice encapsulating the entire NexThreat multi-model detection pipeline:

```text
+-----------------------------------------------------------------------------+
|                     NEXTHREAT CONTAINER (linux/amd64)                       |
|                                                                             |
|  +-----------------------------------------------------------------------+  |
|  | Network Interface: 0.0.0.0:8000 (Non-Root User: nexthreat UID:10001)  |  |
|  +-----------------------------------------------------------------------+  |
|                                     │                                       |
|                                     ▼                                       |
|  +-----------------------------------------------------------------------+  |
|  | Container Entrypoint (src/api/entrypoint.py) [NEW Phase 6.5 File]     |  |
|  | - Signal Handlers: SIGTERM / SIGINT                                   |  |
|  | - Environment: NEXTHREAT_HOST, NEXTHREAT_PORT, NEXTHREAT_LOG_LEVEL     |  |
|  | - Server Lifecycle: NexThreatAPIServer(host=..., port=...)            |  |
|  |   (Relies on authoritative default engine=None initialization)        |  |
|  +-----------------------------------------------------------------------+  |
|                                     │                                       |
|                                     ▼                                       |
|  +-----------------------------------------------------------------------+  |
|  | HTTP Transport Server (src/api/server.py: NexThreatAPIServer) [FROZEN] |  |
|  | - Standard Library ThreadingHTTPServer                                |  |
|  | - Internal Engine Loader: getattr(orchestrator,                       |  |
|  |                           "ApplicationInferenceEngine")()             |  |
|  | - Endpoints: /health, /status, /api/v1/infer/window, /infer/stream     |  |
|  | - Prohibited Route: /api/v1/reset -> HTTP 404 NOT_FOUND               |  |
|  +-----------------------------------------------------------------------+  |
|                                     │                                       |
|                                     ▼                                       |
|  +-----------------------------------------------------------------------+  |
|  | Input Validation Layer (src/api/validators.py) [FROZEN]               |  |
|  | - Format A (13 Floats) / Format B (Named Map) Parsing                 |  |
|  | - Payload Byte Limit: 10 MB (MAX_REQUEST_BYTES HTTP 413)              |  |
|  | - Stream Batch Ceiling: 5,000 Records (MAX_STREAM_RECORDS HTTP 413)   |  |
|  +-----------------------------------------------------------------------+  |
|                                     │                                       |
|                                     ▼                                       |
|  +-----------------------------------------------------------------------+  |
|  | Application Inference Engine (src/application/orchestrator.py)[FROZEN]|  |
|  | - Thread-Safe Mutex Lock (threading.Lock)                             |  |
|  | - Temporal History Buffer (10-Window 60s Lookback State)              |  |
|  +-----------------------------------------------------------------------+  |
|          │                           │                           │          |
|          ▼                           ▼                           ▼          |
|  +---------------+           +---------------+           +---------------+  |
|  |  Autoencoder  |           |    XGBoost    |           |     LSTM      |  |
|  | (Pure NumPy)  |           | (xgb.Booster) |           | (Pure NumPy)  |  |
|  | MSE > Thresh  |           | 8-Class Argmax|           | Prob >= 0.300 |  |
|  +---------------+           +---------------+           +---------------+  |
|          │                           │                           │          |
|          └───────────────────────────┼───────────────────────────┘          |
|                                      ▼                                      |
|  +-----------------------------------------------------------------------+  |
|  | Unified Threat Engine (src/application/threat_engine.py) [FROZEN]     |  |
|  | - Truth Table T: {0, 1}^3 -> {S0..S7}                                 |  |
|  | - 10-Window Cold Start Quarantine (Threat State: null)                |  |
|  +-----------------------------------------------------------------------+  |
|                                      │                                      |
|                                      ▼                                      |
|  +-----------------------------------------------------------------------+  |
|  | 24-Field Response Serialization & Validation                          |  |
|  | - JSON Emission to Client (HTTP 200 OK)                               |  |
|  +-----------------------------------------------------------------------+  |
|                                                                             |
|  +-----------------------------------------------------------------------+  |
|  | Embedded Immutable Storage: /app (Read-Only Root, Non-Root UID: 10001)|  |
|  | - Preserves complete Phase 4.7 33-file relative path inventory        |  |
|  | Ephemeral Storage: /tmp (tmpfs, noexec, nosuid, nodev, size=64m)      |  |
|  +-----------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------+
```

### 6.2 Filesystem Segregation & Authoritative 33-File Artifact Boundary
Inside the container image, the filesystem is partitioned into strict immutable and ephemeral boundaries:
- `/app` (`WORKDIR`): Contains the frozen application source, documentation, and all 33 Phase 4.7 baseline artifacts preserving their exact relative paths. The entire directory is owned by `nexthreat:nexthreat` (UID 10001, GID 10001) with read-only runtime access.
- **Authoritative 33-File Preservation**:
  - `data/model_inputs/` (manifests, attack segments metadata)
  - `data/model_ready/` (scalers, encoders, feature metadata)
  - `data/models/` (Autoencoder, XGBoost, LSTM binaries and thresholds)
  - `data/model_reports/` (Phase 4.7 reports, comparison matrices, decision matrices)
  - `src/models/verification/` (`verify_phase_4_6.py`)
  No file is flattened or relocated into a generic `/app/data/models` directory.
- `/tmp`: Designated as the only writable directory, mounted explicitly as an ephemeral memory volume (`tmpfs`) with `noexec,nosuid,nodev` mount flags.
- `/` (Root Filesystem): Mounted completely read-only (`read_only: true`), preventing unauthorized runtime modifications.

---

## 7. Container Build Design

### 7.1 Multi-Stage Build Specification
To ensure strict supply chain isolation and minimal final image size, the container uses a two-stage build targeting `linux/amd64`:

#### Stage 1: `builder`
- **Target Platform**: `--platform=linux/amd64`.
- **Base Image**: `python:3.14-slim@sha256:<resolved_digest>` (pinned by exact immutable SHA-256 digest).
- **Responsibilities**:
  1. Installs minimal compilation utilities (`gcc`, `g++`, `make`) if binary wheel building is required.
  2. Packaging Tools Policy: **Do not perform uncontrolled upgrades of packaging tools (`pip`, `setuptools`, `wheel`)**. The build uses the packaging tools provided by the authoritative base image unless Phase 6.5 explicitly requires a pinned upgrade with complete hashes.
  3. Pre-compiles all dependencies from `requirements.lock` into isolated wheel archives stored in `/install/wheels` using `--require-hashes`.
  4. Discards compiler tools and cache files upon completion.
  5. **NO `apt-get upgrade -y`**: OS package upgrading during build is strictly eliminated to maintain build determinism.

#### Stage 2: `runtime`
- **Target Platform**: `--platform=linux/amd64`.
- **Base Image**: Identical immutable base image digest (`python:3.14-slim@sha256:<resolved_digest>`).
- **Responsibilities**:
  1. Installs pre-compiled wheels from `/install/wheels` without network access (`--no-index`, `--no-cache-dir`).
  2. Creates an unprivileged system group and user:
     `groupadd -g 10001 -r nexthreat && useradd -u 10001 -r -g nexthreat -d /app -s /usr/sbin/nologin nexthreat`
  3. Copies application directories (`src/`, `data/`, `docs/`) preserving exact relative paths.
  4. Establishes appropriate ownership and permissions ensuring runtime immutability while permitting unprivileged module imports and file reads.
  5. Configures operational environment variables and execution metadata.
  6. Drops privileges to `USER 10001:10001`.
  7. Declares exposed TCP port `8000`.
  8. Configures internal container `HEALTHCHECK`.
  9. Establishes process entrypoint: `["python", "-m", "src.api.entrypoint"]`.

### 7.2 Build Context Exclusions (`.dockerignore`)
The build context sent to the Docker daemon must be strictly sanitized to avoid credential leakage, local caching, and unneeded files. The `.dockerignore` file will explicitly exclude:

```text
# Git metadata & IDE configuration
.git/
.gitignore
.gitattributes
.vscode/
.idea/
*.swp
*.swo

# Python bytecode & caching
__pycache__/
*.py[cod]
*$py.class
*.so
.pytest_cache/
.coverage
htmlcov/
.mypy_cache/

# Local virtual environments
venv/
.venv/
env/
.env/

# Scratch files & temporary logs
scratch/
*.log
*.tmp
outputs/plots/
outputs/reports/

# Unused raw data & development workspaces
data/raw/
data/processed/
data/windows/
saved_models/

# Documentation planning drafts & markdown notes (excluding docs/)
*.markdown
*.draft
```

### 7.3 OCI Standard Image Metadata Labels
The final image embeds standard OCI labels (`org.opencontainers.image.*`):
- `org.opencontainers.image.title="NexThreat Threat-Detection Platform"`
- `org.opencontainers.image.description="Multi-model real-time network telemetry threat-detection API"`
- `org.opencontainers.image.version="1.0.0"`
- `org.opencontainers.image.vendor="NexThreat"`
- `org.opencontainers.image.schema-version="1.0.0"`
- `org.opencontainers.image.licenses="Proprietary"`

---

## 8. Runtime Configuration

### 8.1 Environment Variables Matrix
The container runtime is fully configurable via standard environment variables without requiring image rebuilds or config file mutations:

| Environment Variable | Allowed Values | Default Value | Operational Purpose |
| :--- | :--- | :---: | :--- |
| `NEXTHREAT_HOST` | IPv4 / Hostname | `0.0.0.0` | IP address bound by the HTTP server (`0.0.0.0` in container) |
| `NEXTHREAT_PORT` | `1024` – `65535` | `8000` | TCP port exposed and listened on |
| `NEXTHREAT_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` | Global logging verbosity level |
| `PYTHONHASHSEED` | Integer | `42` | Python hash seed for hash randomization determinism |
| `PYTHONUNBUFFERED` | `1`, `0` | `1` | Forces stdout/stderr flush immediately without block buffering |
| `PYTHONDONTWRITEBYTECODE` | `1`, `0` | `1` | Prevents Python from writing `.pyc` files on read-only filesystems |
| `PYTHONPATH` | Path | `/app` | Sets Python module resolution root |

> **Concurrency Rule**: `NEXTHREAT_WORKERS` is completely omitted from the environment matrix, Compose configuration, and runtime design. The accepted server architecture uses `ThreadingHTTPServer` with `engine_lock` mutex synchronization. Introducing a worker-pool abstraction is unauthorized.

### 8.2 Reproducibility Note on `PYTHONHASHSEED`
`PYTHONHASHSEED` may provide deterministic Python hash randomization behavior where relevant, but it does not by itself guarantee complete application, dependency, filesystem, or container build reproducibility. Reproducibility is achieved through the combined enforcement of immutable base image digests, pinned dependency hashes in `requirements.lock`, sanitized build contexts, and deterministic build recipes.

### 8.3 Authoritative Request Limits (Byte Ceiling vs Record Count)
Inspection of the authoritative codebase resolves two distinct, non-conflated ceilings:
1. **HTTP Payload Byte-Size Ceiling**:
   - Explicitly established in `src/application/service.py:34`: `MAX_REQUEST_BYTES: int = 10 * 1024 * 1024` (10 MB).
   - Enforced in `src/api/handlers.py:199-205`: requests exceeding `MAX_REQUEST_BYTES` are rejected with HTTP 413 `PAYLOAD_TOO_LARGE` before body parsing.
   - Formally asserted and verified in Phase 6.4 Gate D11 (`verify_phase_6_4.py:471-480`).
   - Retained as an authoritative, inherited contract.
2. **Stream Batch Record Ceiling**:
   - Explicitly established in `src/application/service.py:35` and `src/api/validators.py:29`: `MAX_STREAM_RECORDS = 5000`.
   - Enforced in `src/api/validators.py:145-156`: stream arrays exceeding 5,000 items are rejected with HTTP 413 `STREAM_TOO_LARGE`.
   - Formally asserted and verified in Phase 6.4 Gate D11.
   - Retained as an authoritative, inherited contract.

> **Ceiling Separation Invariant**: The 5,000-record stream ceiling is a domain array constraint and must not be conflated with the 10 MB HTTP request body byte limit ($5,000\text{ records} \neq 10\text{ MB}$).

### 8.4 Prohibited Configuration Items
- **Zero Hardcoded Secrets**: No passwords, private keys, API tokens, or HMAC secrets shall be present in the Dockerfile, image layers, or default environment values.
- **Zero In-Container Certificates**: TLS termination is handled externally by an ingress reverse proxy (Nginx, Envoy, Traefik). No SSL certificate management is executed inside the Python process.

---

## 9. Model Artifact Handling & Immutability

### 9.1 Authoritative 33-File Inventory Packaging
All 33 frozen model, scaler, and metadata artifacts originating from Phase 4.7 are baked directly into the container image layer at their authoritative relative paths under `/app`:
- `data/model_inputs/` (split manifests, attack segments metadata)
- `data/model_ready/` (scalers, encoders, feature column metadata)
- `data/models/` (Autoencoder `.keras`, XGBoost `.json`, LSTM `.keras`, thresholds)
- `data/model_reports/` (Phase 4.7 reports, comparison matrices, decision matrices)
- `src/models/verification/` (`verify_phase_4_6.py`)

Containerization shall preserve the original relative path of every inventory member. No assumption may be made that all 33 files reside under `data/models/`.

### 9.2 Separation of Build-Time, Image, and Runtime Verification Layers
The plan establishes three distinct, non-overlapping verification layers:
1. **Build/Repository Integrity**: Before and during image construction, the verification harness audits the host repository to verify that all 33 Phase 4.7 baseline files match their authoritative SHA-256 hashes defined in `data/model_reports/acceptance/phase_4_7_acceptance_report.json`.
2. **Image Cryptographic Integrity**: Verification gates confirm that files copied into the container image preserve their exact relative paths, exact bytes, and exact SHA-256 hashes. Dockerfile `COPY` instructions alone do not constitute cryptographic verification; verification must be explicitly asserted by the test harness.
3. **Runtime Integrity**: Evaluated at startup and during health checks via the accepted application health behavior without redefining API contracts.

### 9.3 Existing Application `/health` Behavior vs Packaging Verification
The revised plan strictly separates accepted application health behavior from packaging integrity verification:
- **Accepted Application `/health` Contract**:
  - In `src/api/handlers.py`, `_handle_health` invokes `verify_authoritative_33_files_integrity()` from `src.application.service`.
  - If all 33 files match and `self.engine is not None`: Emits HTTP 200 with the exact 3-field response:
    ```json
    {
      "status": "HEALTHY",
      "integrity": "VERIFIED",
      "timestamp": "2026-09-15T12:00:00.000000+00:00"
    }
    ```
  - If any file is missing/corrupted or the engine is uninitialized: Emits HTTP 503 with:
    ```json
    {
      "status": "UNHEALTHY",
      "integrity": "FAILED",
      "timestamp": "2026-09-15T12:00:00.000000+00:00"
    }
    ```
  - Phase 6.5 preserves this exact contract. It does NOT return file lists, error counts, or mutated fields.
- **Packaging Integrity Verification**:
  - Independent verification executed by `verify_phase_6_5.py` (Gate C7) that audits the container filesystem, verifies every individual file hash, and validates file permissions.

### 9.4 Removal of External Model Volume Mounting
The proposal to mount an external volume (`/secure/models -> /app/data/models`) is **REMOVED**. Because the authoritative 33-file inventory spans five separate directory branches, mounting a partial volume to `data/models` would cause severe artifact fragmentation, break the cryptographic boundary, and introduce unnecessary deployment complexity. All 33 authoritative artifacts are embedded directly into the immutable container image layer.

---

## 10. Security Hardening

The packaging specification enforces strict alignment with container security best practices:

### 10.1 Non-Root Service Account
- The container executes under an unprivileged, dedicated system user:
  - Username: `nexthreat`
  - Group: `nexthreat`
  - UID: `10001`
  - GID: `10001`
  - Shell: `/usr/sbin/nologin`
  - Home: `/app`
- Running as UID 0 (`root`) is strictly prohibited.

### 10.2 Linux Capabilities & Privilege De-escalation
- **Capability Drop**: All default Linux capabilities are dropped (`--cap-drop ALL`). NexThreat does not require `NET_ADMIN`, `SYS_ADMIN`, `CHOWN`, or `SETUID`.
- **Privilege Escalation Prevention**: Containers run with `--security-opt no-new-privileges:true`, ensuring processes cannot gain higher privileges via `setuid` binaries.

### 10.3 Read-Only Root Filesystem & Ephemeral Memory Partitioning
- **Read-Only Root**: The entire container root filesystem (`/`) is mounted read-only (`--read-only` or `read_only: true` in Compose).
- **Ephemeral Scratch**: Temporary file creation is confined strictly to `/tmp`, mounted as a memory-backed volume:
  `--tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m`

### 10.4 User & File Permissions Design
- The security objective is that application source code and model artifacts must be immutable at runtime.
- In conjunction with `read_only: true`, permissions inside `/app` are set so that:
  - Directories permit traversal and reads (`0555` or `0755`).
  - Python files and data artifacts permit unprivileged reads (`0444` or `0644`).
- With `PYTHONDONTWRITEBYTECODE=1`, Python does not attempt to write `.pyc` files on the read-only filesystem.
- Permissions do not impose restrictions that prevent required runtime reads, module imports, or clean startup.

### 10.5 Acceptance-Time Vulnerability Policy
Rather than making unsupported permanent zero-CVE claims, Phase 6.5 defines a strict acceptance-time vulnerability management policy:
- **Scan Tooling**: Automated image scanning via **Trivy** or **Grype**.
- **Acceptance Threshold**:
  - `CRITICAL` Severity: **0 allowable vulnerabilities** at time of acceptance.
  - `HIGH` Severity: Managed according to policy (0 allowable in application runtime dependencies; OS-level items evaluated and recorded).
- **Audit Documentation**: Scan tool, scan tool version, scan timestamp, and complete CVE report must be permanently recorded in `phase_6_5_verification_report.json`.
- **Disclaimer**: Container packaging aligns with applicable container security best practices; no container image can guarantee zero future CVEs permanently as vulnerability databases expand over time.

---

## 11. Health & Lifecycle

### 11.1 Native Container Health Check
The Dockerfile defines a native health check leveraging Python's standard library (eliminating `curl` or `wget` dependencies from the minimal image):

```dockerfile
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import http.client, sys; conn = http.client.HTTPConnection('127.0.0.1', 8000, timeout=2); conn.request('GET', '/health'); resp = conn.getresponse(); sys.exit(0 if resp.status == 200 else 1)"
```

- **Interval**: Probe runs every 10 seconds.
- **Timeout**: 3-second probe execution ceiling.
- **Start Period**: 5-second grace period for model loading and initial health evaluation.
- **Retries**: 3 consecutive failures transitions container state to `unhealthy`.

### 11.2 Signal Handling & Container Graceful Shutdown
The container entrypoint (`src/api/entrypoint.py`) implements clean process lifecycle management:
1. **Signal Registration**: Registers handlers for `SIGTERM` (Docker stop / container termination) and `SIGINT` (Ctrl+C).
2. **Termination Sequence**:
   - Logs: `"Received termination signal (%s). Initiating graceful shutdown..."`.
   - Triggers internal stop event.
   - Invokes `server.stop()`, which shuts down `ThreadingHTTPServer` and closes the listening socket.
   - Joins server thread cleanly.
   - Exits cleanly with code `0`.
3. **Container-Level Graceful Shutdown Policy**:
   - The planned `docker-compose.yml` manifest specifies `stop_grace_period: 15s` as an approved container lifecycle requirement and implementation target.
   - This affords the container orchestrator up to 15 seconds to allow active in-flight requests to conclude before issuing `SIGKILL`.
   - The Python application itself respects its actual lifecycle (`src/api/server.py:65` joins server thread with a 2-second timeout) without inventing an internal 15-second wait timer.

---

## 12. Observability & Telemetry

### 12.1 Standardized Container Logging
- **Output Streams**: All application access logs, server lifecycle events, and error messages are written directly to `stdout` (for `INFO` and `DEBUG`) and `stderr` (for `WARNING` and `ERROR`).
- **Unbuffered I/O**: `PYTHONUNBUFFERED=1` guarantees zero output block-buffering, ensuring immediate log line capture by container log forwarders.
- **Format**: Conforms to standard UTC ISO-8601 formatting:
  `%(asctime)s [%(levelname)s] [%(name)s] %(message)s`

### 12.2 Information Sanitization in Logs & Responses
- In strict adherence to Phase 6.2, 6.3, and 6.4 standards:
  - Zero raw exception tracebacks emitted to external callers.
  - Zero local filesystem paths (e.g. `/app/...`, `c:\...`) leaked in API error responses.
  - Zero IP addresses or network identifiers leaked in error messages.
  - Internal server errors emit sanitized code `INTERNAL_ERROR` or `MODEL_EXECUTION_ERROR`.

### 12.3 Authoritative Runtime Telemetry (`GET /status`)
Inspection of `src/api/handlers.py` lines 298–315 confirms the exact accepted `/status` response contract:

```json
{
  "status": "READY",
  "processed_windows": 0,
  "lookback_depth": 0,
  "engine_version": "1.0.0",
  "timestamp": "2026-09-15T12:00:00.000000+00:00"
}
```

Phase 6.5 reproduces this contract exactly. No new fields (such as `memory_rss_bytes`) are added to the runtime response. Container resource telemetry (memory, CPU) is monitored externally via container runtime mechanisms (`docker stats`, cgroups), preserving runtime API immutability.

### 12.4 Error Envelope Compliance
Error responses must remain structurally and semantically compliant with the accepted Phase 6.2/6.3/6.4 error contract:
- Schema: `{code, message, status_code, timestamp, details}`
- Sanitization: Internal paths and tracebacks strictly sanitized.
- Dynamic Fields: Dynamic UTC ISO-8601 timestamps are permitted and expected.

---

## 13. Reproducibility & Supply-Chain Integrity

### 13.1 Complete Dependency Lock Strategy (`requirements.lock`)
To ensure complete supply-chain determinism, the plan explicitly distinguishes direct runtime dependencies from the complete transitive closure:

#### A. Authorized Direct Runtime Dependencies
Preserves the exact versions validated and frozen across upstream phases:
- `numpy==2.5.3`
- `pandas==3.0.5`
- `scikit-learn==1.9.1`
- `joblib==1.6.0`
- `xgboost==3.4.1`
- `h5py==3.16.0`

#### B. Complete Resolved Dependency Closure
The `requirements.lock` file must not be limited to direct dependencies. It must contain the **complete, closed transitive dependency graph** required by the direct packages on the target platform (`linux/amd64`). At minimum, this accounts for all required transitive dependencies, including but not limited to:
- `scipy` (required by `scikit-learn`)
- `narwhals` (required by `pandas`)
- `threadpoolctl` (required by `scikit-learn`)
- `python-dateutil` (required by `pandas`)
- `tzdata` (required by `pandas`)
- Any additional transitive wheel dependencies determined during exact platform-specific resolution.

#### C. Cryptographic Hash Requirements
Every package entry in `requirements.lock` must include:
- Exact pinned semantic version.
- Distribution specification (e.g. `linux/amd64` wheel or source distribution).
- Cryptographic SHA-256 hash(es) corresponding to the target platform distribution.

Installation in the Dockerfile builder stage must execute with strict hash verification:
```bash
pip install --no-cache-dir --require-hashes -r requirements.lock
```

The plan explicitly prohibits:
- Unpinned or floating package versions.
- Dependency installation without hashes.
- Incomplete transitive dependency closures.
- Dynamic or unverified package resolution during the container image build.

#### D. Packaging Tools Policy
To prevent non-deterministic build failures, Phase 6.5 adopts the **preferred packaging tools approach**:
- Standard packaging tools (`pip`, `setuptools`, `wheel`) provided by the authoritative base image (`python:3.14-slim`) shall be used directly without uncontrolled runtime upgrades.
- If a packaging tool upgrade is demonstrated to be strictly required for wheel compilation during implementation, it must be explicitly pinned with its exact version and SHA-256 hash inside the lock specification.

#### E. Implementation Gate
Implementation of container build files is permitted **only after the complete dependency closure and its SHA-256 hashes have been fully resolved, verified for `linux/amd64`, and reviewed**.

### 13.2 Base Image Immutability & Target Architecture
To achieve deterministic container builds:
1. **Base Image Family**: `python:3.14-slim`.
2. **Target Architecture**: Exactly **`linux/amd64`**.
3. **Immutable Base Image Digest Requirement**: Prior to implementation, the exact SHA-256 digest for `python:3.14-slim` on `linux/amd64` must be retrieved from the official registry and recorded. The Dockerfile must declare:
   ```dockerfile
   FROM --platform=linux/amd64 python:3.14-slim@sha256:<resolved_digest> AS builder
   ...
   FROM --platform=linux/amd64 python:3.14-slim@sha256:<resolved_digest> AS runtime
   ```
4. **Mandatory Governance Block**: `IMPLEMENTATION BLOCKED UNTIL EXACT BASE IMAGE DIGEST IS RESOLVED`. Do not fabricate or substitute a placeholder digest in implementation deliverables.
5. **Controlled Package Installation**: No general `apt-get upgrade -y`. Only strictly required build-time packages are installed in the builder stage.
6. **Deterministic Build Context**: Strict `.dockerignore` excludes all transient local files.
7. **Recorded Image Provenance**: Final image ID, base digest, and build timestamp recorded in verification reports.

---

## 14. Production Deployment Model

### 14.1 Standalone Docker Execution
The canonical production invocation for running the standalone NexThreat container on `linux/amd64` with maximum security hardening:

```bash
docker run -d \
  --name nexthreat \
  --platform linux/amd64 \
  --restart on-failure:5 \
  --stop-timeout 15 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --user 10001:10001 \
  --cpus "2.0" \
  --memory "2048m" \
  -p 8000:8000 \
  -e NEXTHREAT_HOST=0.0.0.0 \
  -e NEXTHREAT_PORT=8000 \
  -e NEXTHREAT_LOG_LEVEL=INFO \
  -e PYTHONUNBUFFERED=1 \
  -e PYTHONHASHSEED=42 \
  nexthreat:1.0.0
```

### 14.2 Local & Single-Node Orchestration (`docker-compose.yml`)
The authoritative compose file encapsulates this configuration:

```yaml
version: "3.8"

services:
  nexthreat:
    image: nexthreat:1.0.0
    platform: linux/amd64
    build:
      context: .
      dockerfile: Dockerfile
    container_name: nexthreat-api
    restart: on-failure:5
    stop_grace_period: 15s
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=64m
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    user: "10001:10001"
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 2048M
        reservations:
          cpus: "1.0"
          memory: 1024M
    ports:
      - "8000:8000"
    environment:
      - NEXTHREAT_HOST=0.0.0.0
      - NEXTHREAT_PORT=8000
      - NEXTHREAT_LOG_LEVEL=INFO
      - PYTHONUNBUFFERED=1
      - PYTHONHASHSEED=42
      - PYTHONDONTWRITEBYTECODE=1
    healthcheck:
      test: ["CMD", "python", "-c", "import http.client, sys; conn = http.client.HTTPConnection('127.0.0.1', 8000, timeout=2); conn.request('GET', '/health'); resp = conn.getresponse(); sys.exit(0 if resp.status == 200 else 1)"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 5s
```

---

## 15. Planned Deliverables

The Phase 6.5 deliverable boundary is defined strictly and unambiguously, distinguishing implementation deliverables from verification-generated artifacts:

```text
Total Phase 6.5 Project Artifacts = 8

Implementation Deliverables (Created during implementation) = 6
Verification-Generated Reports (Generated after verification) = 2
```

### 15.1 Implementation Deliverables (6 Files)
| # | Artifact Path | Category | Purpose |
| :-: | :--- | :--- | :--- |
| **1** | `Dockerfile` | Container Specification | Multi-stage production container build specification (`linux/amd64`). |
| **2** | `.dockerignore` | Build Configuration | Build context filter preventing credential and cache leakage. |
| **3** | `docker-compose.yml` | Orchestration Manifest | Standardized compose manifest with security and resource limits. |
| **4** | `requirements.lock` | Supply-Chain Manifest | Complete transitive closure of hash-verified runtime dependencies. |
| **5** | `src/api/entrypoint.py` | Container Entrypoint | Production CLI runner with signal handling wrapping `NexThreatAPIServer`. |
| **6** | `src/api/verification/verify_phase_6_5.py` | Verification Tooling | Automated harness executing Gates C1–C16 and multi-phase regressions. |

### 15.2 Verification-Generated Artifacts (2 Files)
| # | Artifact Path | Category | Purpose |
| :-: | :--- | :--- | :--- |
| **7** | `data/model_reports/application/phase_6_5_verification_report.md` | Verification Report (MD) | Human-readable verification report and acceptance audit. |
| **8** | `data/model_reports/application/phase_6_5_verification_report.json` | Verification Report (JSON) | Machine-readable execution summary and cryptographic hash inventory. |

### 15.3 Pre-Existing Governance Planning Artifact
- `data/model_reports/application/phase_6_5_production_packaging_containerization_implementation_plan.md` is an authorized governance planning document. It is **NOT** counted among the implementation deliverables.

---

## 16. File-Level Change Matrix

The following table explicitly defines all files within the Phase 6.5 boundary, classifying their operational status and immutability rules:

| File Path | Action | Category | Immutable? | Authority | Verification Gate |
| :--- | :---: | :--- | :---: | :--- | :---: |
| `Dockerfile` | **NEW** | Packaging | NO (Phase 6.5 Deliverable) | Phase 6.5 Plan | Gate C1, C3 |
| `.dockerignore` | **NEW** | Packaging | NO (Phase 6.5 Deliverable) | Phase 6.5 Plan | Gate C4 |
| `docker-compose.yml` | **NEW** | Orchestration | NO (Phase 6.5 Deliverable) | Phase 6.5 Plan | Gate C5, C6 |
| `requirements.lock` | **NEW** | Dependencies | NO (Phase 6.5 Deliverable) | Phase 6.5 Plan | Gate C2 |
| `src/api/entrypoint.py` | **NEW** | Runtime Entrypoint | NO (Phase 6.5 Deliverable) | Phase 6.5 Plan | Gate C8 |
| `src/api/verification/verify_phase_6_5.py` | **NEW** | Verifier | NO (Phase 6.5 Deliverable) | Phase 6.5 Plan | Gate C1–C16 |
| `data/model_reports/application/phase_6_5_verification_report.md` | **NEW** | Report | NO (Generated Post-Test) | Phase 6.5 Plan | Gate C1–C16 |
| `data/model_reports/application/phase_6_5_verification_report.json` | **NEW** | Report | NO (Generated Post-Test) | Phase 6.5 Plan | Gate C1–C16 |
| `data/model_reports/application/phase_6_5_production_packaging_containerization_implementation_plan.md` | **REVISED** | Governance | Plan Only (v3.0.0) | Phase 6.5 Plan | Audit Sign-Off |
| `requirements.txt` | **UNTOUCHED** | Configuration | **YES** | Pre-existing Baseline | Gate C2 |
| `src/api/server.py` | **UNTOUCHED** | Runtime | **YES (FROZEN)** | Phase 6.3 Baseline | Gate C8 |
| `src/api/handlers.py` | **UNTOUCHED** | Runtime | **YES (FROZEN)** | Phase 6.3 Baseline | Gate C10 |
| `src/api/schemas.py` | **UNTOUCHED** | Runtime | **YES (FROZEN)** | Phase 6.2 Baseline | Gate C12 |
| `src/api/validators.py` | **UNTOUCHED** | Runtime | **YES (FROZEN)** | Phase 6.2 Baseline | Gate C12 |
| `src/api/exceptions.py` | **UNTOUCHED** | Runtime | **YES (FROZEN)** | Phase 6.2 Baseline | Gate C15 |
| `src/api/__init__.py` | **UNTOUCHED** | Runtime | **YES (FROZEN)** | Phase 6.3 Baseline | Gate C1 |
| `src/application/*` (all files) | **UNTOUCHED** | Runtime | **YES (FROZEN)** | Phase 5.7 Baseline | Gate C12 |
| `src/models/*` (all files) | **UNTOUCHED** | Runtime | **YES (FROZEN)** | Phase 4.7 Baseline | Gate C7 |
| `data/models/*` (all files) | **UNTOUCHED** | Assets | **YES (FROZEN)** | Phase 4.7 Baseline | Gate C7 |
| `docs/api/*` (all files) | **UNTOUCHED** | Documentation | **YES (FROZEN)** | Phase 6.4 Baseline | Gate C14 |

> **Explicit New-File Exception**: Existing Phase 6.3/6.4 `src/api/*` runtime files remain immutable. `src/api/entrypoint.py` is an explicitly authorized NEW Phase 6.5 file and is not a modification to any pre-existing Phase 6.3/6.4 runtime artifact.

---

## 17. Verification Strategy: Deterministic Acceptance Gates (C1–C16)

The verification harness (`src/api/verification/verify_phase_6_5.py`) defines exactly 16 deterministic acceptance gates aligned with approved contracts:

### Gate C1: Base Image, Architecture & Digest Specification Audit
- **Requirement**: Verifies that the Dockerfile specifies the single approved Python runtime target (Python 3.14), base image family `python:3.14-slim`, target architecture `linux/amd64`, and pins the production base image by an exact resolved immutable SHA-256 digest.
- **Assertion**: Base image declaration matches `FROM --platform=linux/amd64 python:3.14-slim@sha256:<resolved_digest>`; zero alternative targets, architectures, or unpinned tags permitted.

### Gate C2: Complete Dependency Closure & Hash Integrity Audit
- **Requirement**: Verifies `requirements.lock` contains the complete direct and transitive dependency closure (including `scipy`, `narwhals`, `threadpoolctl`, `python-dateutil`, `tzdata`), exact semantic versions, and SHA-256 hashes for all packages.
- **Assertion**: Complete dependency graph present; zero unpinned packages; hash format valid; installable with `--require-hashes`.

### Gate C3: Multi-Stage Dockerfile Structural Syntax & OCI Conformance Audit
- **Requirement**: Validates multi-stage Dockerfile syntax (`builder` and `runtime` stages), layer ordering, and OCI image metadata labels.
- **Assertion**: Contains valid `FROM ... AS builder`, `FROM ... AS runtime`, and standard OCI labels; contains zero `apt-get upgrade -y` commands.

### Gate C4: Build Context Boundary & `.dockerignore` Exclusion Audit
- **Requirement**: Verifies that `.dockerignore` explicitly excludes `.git`, `__pycache__`, `.env`, local `venv`, and development artifacts.
- **Assertion**: All security-sensitive paths present in `.dockerignore`.

### Gate C5: Non-Root Execution Security Profile Audit
- **Requirement**: Verifies that Dockerfile and compose manifests specify non-root execution (UID 10001, GID 10001), drop all capabilities (`cap_drop: ALL`), and enable `no-new-privileges`.
- **Assertion**: `USER 10001:10001` declared; zero root execution commands in runtime stage.

### Gate C6: Read-Only Root Filesystem & Ephemeral Storage Audit
- **Requirement**: Verifies configuration compatibility with `read_only: true` and temporary scratch storage restricted to `tmpfs /tmp`.
- **Assertion**: Compose manifest enforces `read_only: true` and `tmpfs` flags (`noexec,nosuid,nodev`).

### Gate C7: Phase 4.7 33-File Inventory & Relative Path Integrity Audit
- **Requirement**: Verifies that all 33 Phase 4.7 baseline model artifacts are specified for inclusion preserving their exact relative paths and match authoritative SHA-256 hashes defined in `data/model_reports/acceptance/phase_4_7_acceptance_report.json`.
- **Assertion**: 33/33 files present at exact relative paths with verified SHA-256 hashes. Affirms that Dockerfile `COPY` instructions alone do not constitute cryptographic verification.

### Gate C8: Container Entrypoint & Authoritative Engine Lifecycle Audit
- **Requirement**: Tests `src/api/entrypoint.py` integration with the frozen `NexThreatAPIServer` lifecycle (`start()`, signal handling, `stop()`), verifying that instantiation with `engine=None` successfully loads `ApplicationInferenceEngine()` via `src.application.orchestrator` without modifying `src/api/server.py`.
- **Assertion**: Server starts with authoritative default engine, catches `SIGTERM`/`SIGINT`, invokes `server.stop()`, and exits code 0.

### Gate C9: Environment Variable Parameter Handling Audit
- **Requirement**: Tests server configuration under supported environment variables (`NEXTHREAT_HOST`, `NEXTHREAT_PORT`, `NEXTHREAT_LOG_LEVEL`).
- **Assertion**: Server binds to configured host and port; verifies complete absence of `NEXTHREAT_WORKERS`.

### Gate C10: Container Health Probing Audit (`/health`)
- **Requirement**: Verifies the accepted Phase 6.3/6.4 `/health` contract under normal conditions (HTTP 200 `{"status": "HEALTHY", "integrity": "VERIFIED", "timestamp": ...}`) and failure conditions (HTTP 503 `{"status": "UNHEALTHY", "integrity": "FAILED", "timestamp": ...}`).
- **Assertion**: Response structure matches accepted 3-field contract without redefined fields.

### Gate C11: Container Telemetry Probing Audit (`/status`)
- **Requirement**: Verifies `GET /status` returns the accepted 5-field telemetry structure: `status`, `processed_windows`, `lookback_depth`, `engine_version`, and `timestamp`.
- **Assertion**: Response adheres strictly to accepted contract; zero unapproved telemetry fields (such as `memory_rss_bytes`).

### Gate C12: Single-Window Inference Execution Audit (Format A & B)
- **Requirement**: Executes single-window inference for both Format A (array) and Format B (map) inside the container environment.
- **Assertion**: Returns HTTP 200 with the authoritative 24-field nested response.

### Gate C13: Stream Batch Inference Execution Audit
- **Requirement**: Submits sequential stream batch ($10$ windows) through `/api/v1/infer/stream`.
- **Assertion**: Batch processes sequentially, increments global positions, and enforces $\le 5,000$ records ceiling.

### Gate C14: Reset Endpoint Prohibition Audit (`/api/v1/reset`)
- **Requirement**: Tests the accepted reset prohibition contract established in Phase 6.4 (verifying that `/api/v1/reset` is not exposed, returning HTTP 404 with code `"NOT_FOUND"`, matching Phase 6.4 Gate D12).
- **Assertion**: Returns HTTP 404 with standardized error message; Phase 6.4 documentation remains immutable.

### Gate C15: Error Sanitization & Semantic Conformance Audit
- **Requirement**: Submits invalid JSON, non-finite values (NaN/Inf), and malformed payloads to verify error sanitization.
- **Assertion**: Emits standardized error envelope `{code, message, status_code, timestamp, details}`; dynamic timestamps permitted; zero stack traces or internal paths leaked.

### Gate C16: Resource Ceiling & Capacity Enforcement Audit
- **Requirement**: Asserts container resource ceiling specifications (2 vCPU, 2048 MB RAM) and tests rejection of payloads $> 10$ MB (HTTP 413 `PAYLOAD_TOO_LARGE` via `MAX_REQUEST_BYTES`) and stream arrays $> 5,000$ records (HTTP 413 `STREAM_TOO_LARGE` via `MAX_STREAM_RECORDS`).
- **Assertion**: 10 MB payload ceiling and 5,000-record ceiling strictly enforced based on authoritative code contracts; Compose resource limits validated.

---

## 18. Upstream Multi-Phase Regression Protection

Phase 6.5 mandates complete, uncompromised backward regression testing against all prior accepted phases. The verification harness (`verify_phase_6_5.py`) will execute regressions based on the actual verified interfaces of existing suites:

1. **Phase 4.7 Regression (ML Baseline 33 Files)**:
   - Direct cryptographic audit of all 33 files against `data/model_reports/acceptance/phase_4_7_acceptance_report.json`.
   - Threshold: **33/33 byte-exact SHA-256 match**.
2. **Phase 5.7 Regression (Application Orchestrator)**:
   - Invocation via subprocess: `python -m src.application.verification.verify_phase_5_7`.
   - Threshold: **22/22 functional gates PASS**. Generated Phase 5 reports restored to prevent dirty working tree.
3. **Phase 6.2 Regression (Schemas & Validators)**:
   - Invocation via subprocess: `python -m src.api.verification.verify_phase_6_2`.
   - Threshold: **16/16 schema/AST gates PASS**.
4. **Phase 6.3 Regression (Transport Handlers & Server)**:
   - Invocation via Python test harness import: `Phase6_3_Verifier().run_all_gates()` with connection retry loop.
   - Threshold: **20/20 transport gates PASS**.
5. **Phase 6.4 Regression (API Documentation & Contracts)**:
   - Invocation via Python test harness import: `Phase6_4_Verifier().run_all_gates()`.
   - Threshold: **16/16 documentation and contract gates PASS**.

---

## 19. Security Acceptance Gates

To achieve production containerization sign-off, the packaging implementation must satisfy these explicit security criteria:
- **SEC-1 (Zero Root Execution)**: Container image must not contain `USER root` in its runtime stage. Must execute as UID `10001` (GID `10001`).
- **SEC-2 (Zero Capabilities)**: Process must execute with all Linux capabilities dropped (`cap_drop: ALL`) and `no-new-privileges: true`.
- **SEC-3 (Read-Only Root Filesystem)**: Container must boot and serve requests successfully with root filesystem mounted read-only (`read_only: true`).
- **SEC-4 (Artifact Immutability)**: All 33 Phase 4.7 baseline files must retain original relative paths, match authoritative SHA-256 hashes, and be protected against runtime mutation.
- **SEC-5 (Vulnerability Policy Compliance)**: Zero `CRITICAL` vulnerabilities at time of acceptance; `HIGH` vulnerabilities handled per policy; scan tool, version, and timestamp permanently recorded.
- **SEC-6 (Reset Route Prohibition)**: `/api/v1/reset` must remain strictly unreachable (HTTP 404); Phase 6.4 documentation remains immutable.
- **SEC-7 (Information Leakage Prevention)**: Zero raw tracebacks, internal filesystem paths, or IP addresses in error responses.

---

## 20. Implementation Sequence

> **FUTURE IMPLEMENTATION — NOT AUTHORIZED BY THIS TASK**  
> The following sequence is planned for execution ONLY AFTER this plan receives formal audit approval.

```text
Step 1: Base Image Digest & Platform Resolution
        - Retrieve and record exact immutable SHA-256 digest for python:3.14-slim on linux/amd64.
        - Validate digest against official registry.

Step 2: Complete Transitive Dependency Resolution & Lock
        - Resolve complete direct and transitive dependency closure for linux/amd64.
        - Generate requirements.lock with exact versions and SHA-256 hashes for all wheels.
        - Review lockfile ensuring zero unpinned or hash-less packages.

Step 3: Build Context & Local Orchestration Configuration
        - Author .dockerignore excluding all caches, git history, and scratch files.
        - Author docker-compose.yml defining resource boundaries, security options, stop grace period, and health checks.

Step 4: Container Entrypoint Formulation
        - Author src/api/entrypoint.py wrapping NexThreatAPIServer with signal handlers (SIGTERM/SIGINT).
        - Rely on authoritative default engine initialization (engine=None).
        - Test standalone signal forwarding and graceful shutdown.

Step 5: Multi-Stage Dockerfile Implementation
        - Author Dockerfile targeting linux/amd64 with builder and runtime stages using pinned digest.
        - Configure unprivileged user nexthreat (10001:10001), read-only permissions, and HEALTHCHECK.

Step 6: Verification Suite Construction & Execution
        - Author src/api/verification/verify_phase_6_5.py implementing Gates C1–C16 and multi-phase regression.
        - Execute verification harness: python -m src.api.verification.verify_phase_6_5
        - Validate 16/16 C-Gates PASS and 5/5 upstream regressions PASS.

Step 7: Verification Reporting & Final Sign-Off
        - Generate phase_6_5_verification_report.md and phase_6_5_verification_report.json.
        - Record SHA-256 checksums of all authorized deliverables.
```

---

## 21. Rollback & Recovery Strategy

If any failure occurs during eventual Phase 6.5 implementation or verification:
1. **Zero Impact on Runtime Baseline**: Because Phase 6.5 introduces only new packaging files (`Dockerfile`, `.dockerignore`, `docker-compose.yml`, `requirements.lock`, `src/api/entrypoint.py`, `verify_phase_6_5.py`), the accepted Phase 4.7–6.4 runtime remains completely unmutated.
2. **Targeted Working Tree Cleanup**: Any defective packaging file can be removed or reverted using targeted git commands without affecting the underlying model engine or project artifacts:
   ```bash
   git clean -fd -- Dockerfile .dockerignore docker-compose.yml requirements.lock src/api/entrypoint.py src/api/verification/verify_phase_6_5.py data/model_reports/application/phase_6_5_verification_report.md data/model_reports/application/phase_6_5_verification_report.json
   ```
   *Unconstrained `git clean -fd` across the entire workspace is strictly prohibited to prevent accidental removal of untracked development assets.*
3. **Repository Restoration**: Verified pre-Phase-6.5 HEAD baseline commit is `fa3984fdf762e8d81b9a8daa4c0fc356ec6c9065` (`fa3984f`). Reverting to this commit instantly restores the pristine, accepted Phase 6.4 state.

---

## 22. Acceptance Criteria

Phase 6.5 will be formally accepted if and only if all of the following objective criteria are met:
1. **Deliverable Scope Adherence**: Exactly the 6 implementation deliverables and 2 verification-generated reports are created. Zero extraneous files added.
2. **Zero Runtime Mutation**: `git diff fa3984fdf762e8d81b9a8daa4c0fc356ec6c9065 -- src/application/ src/models/ data/models/ src/api/handlers.py src/api/server.py src/api/validators.py src/api/schemas.py docs/api/` outputs exactly 0 bytes.
3. **16/16 C-Gates PASS**: All 16 deterministic container acceptance gates (C1–C16) execute with 100% pass rate.
4. **5/5 Upstream Regressions PASS**:
   - Phase 4.7 ML baseline: 33/33 SHA-256 match.
   - Phase 5.7 orchestrator: 22/22 gates pass.
   - Phase 6.2 schemas: 16/16 gates pass.
   - Phase 6.3 handlers: 20/20 gates pass.
   - Phase 6.4 documentation: 16/16 gates pass.
5. **Security Gates Compliance**: All 7 security acceptance gates (SEC-1 through SEC-7) verified.
6. **Container Health & Lifecycle**: Container starts cleanly, passes internal health checks, handles traffic, and terminates cleanly on `SIGTERM` with exit code `0`.

---

## 23. Revision History & Audit Trail

| Version | Date | Status | Purpose / Corrections Summary |
| :---: | :---: | :---: | :--- |
| **1.0.0** | 2026-09-15 | NOT APPROVED | Initial formulation of Phase 6.5 production packaging and containerization plan. |
| **2.0.0** | 2026-09-15 | NOT APPROVED | Comprehensive correction of 22 audit findings (eliminated Python 3.12 ambiguity, enforced 33-file inventory relative paths, removed `NEXTHREAT_WORKERS`, removed external partial volume, eliminated `apt-get upgrade -y`, aligned `/health` and `/status` semantics, calibrated security claims and permissions). |
| **3.0.0** | 2026-09-15 | READY FOR FINAL AUDIT | Resolution of five material blockers from Revision 2.0.0 audit:<br>1. Complete transitive dependency/hash lock specification distinguishing direct dependencies from the full resolved closure for `linux/amd64`.<br>2. Repository-authoritative engine initialization path (`NexThreatAPIServer(host=..., port=...)` default `engine=None` constructing `ApplicationInferenceEngine()`).<br>3. Authoritative resolution of 10 MB payload byte limit grounded in `src/application/service.py:34`, `src/api/handlers.py:199-205`, and Phase 6.4 Gate D11.<br>4. Reset prohibition aligned with accepted HTTP semantics (`src/api/handlers.py:103-109` and Phase 6.4 Gate D12).<br>5. Exact target architecture (`linux/amd64`) and requirement for resolving the immutable base-image SHA-256 digest prior to implementation. |

---

## 24. Final Plan Verdict

```text
================================================================================
NEXTHREAT PHASE 6.5 — PLAN REVISION 3.0.0
================================================================================

PLAN STATUS       : READY FOR FINAL AUDIT

IMPLEMENTATION    : NOT AUTHORIZED

RUNTIME CHANGES   : NONE

FROZEN BASELINE   : PRESERVED

CORRECTIONS       : 5 MATERIAL BLOCKERS RESOLVED

FINAL AUDIT       : REQUIRED BEFORE IMPLEMENTATION

================================================================================
```
