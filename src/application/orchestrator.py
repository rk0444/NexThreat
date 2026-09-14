"""
NexThreat Phase 5.5 — Application Inference Engine & Orchestrator.

Orchestrates the complete multi-model threat inference lifecycle for incoming
one-minute feature window records according to Phase 5.1 and Phase 5.5 specifications.
Enforces the transactional temporal buffer commit invariant (Step 9 commit after all validations pass).
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional, Union

import numpy as np

from src.application.config import (
    AUTOENCODER_THRESHOLD,
    LSTM_THRESHOLD,
)
from src.application.exceptions import (
    InputValidationError,
    ModelExecutionError,
    IntegrationContractError,
)
from src.application.predictors import (
    AutoencoderPredictor,
    XGBoostPredictor,
    LSTMPredictor,
)
from src.application.schemas import (
    CanonicalInputRecord,
    AutoencoderOutputRecord,
    XGBoostOutputRecord,
    LSTMOutputRecord,
    ThreatInferenceRecord,
    ExecutionMetadataRecord,
    ApplicationOutputRecord,
)
from src.application.state_manager import TemporalHistoryBuffer
from src.application.threat_engine import evaluate_threat_state
from src.application.validators import (
    validate_canonical_input,
    validate_autoencoder_output,
    validate_xgboost_output,
    validate_lstm_output,
    validate_threat_inference_output,
    validate_application_output_record,
)


class ApplicationInferenceEngine:
    """
    Unified Application Inference Engine.
    Encapsulates frozen model predictors and an instance-owned temporal lookback buffer.
    Enforces a strict 10-step transactional execution lifecycle.
    """

    def __init__(
        self,
        ae_predictor: Optional[AutoencoderPredictor] = None,
        xgb_predictor: Optional[XGBoostPredictor] = None,
        lstm_predictor: Optional[LSTMPredictor] = None,
    ):
        self.ae_predictor = ae_predictor or AutoencoderPredictor()
        self.xgb_predictor = xgb_predictor or XGBoostPredictor()
        self.lstm_predictor = lstm_predictor or LSTMPredictor()
        self.history_buffer = TemporalHistoryBuffer()
        self._internal_position_counter: int = 0

    def process_window(
        self,
        raw_input: Union[Dict[str, Any], CanonicalInputRecord],
    ) -> ApplicationOutputRecord:
        """
        Process a single One-Minute Feature-Vector Window Record.
        
        Exact 10-Step Execution Lifecycle:
        1. Input Validation: Validate external input contract and extract 13 canonical features.
           (If invalid, raises InputValidationError; zero buffer touch).
        2. Temporal Evaluation: Evaluate temporal lookback buffer (delegates to state_manager).
        3. Model Inference: Execute Autoencoder, XGBoost, and LSTM inference.
        4. Model Output Validation: Assert-only validation of AE, XGBoost, and LSTM outputs.
        5. Threat State Resolution: Evaluate unified threat state from model outputs.
        6. Threat State Validation: Assert-only validation of threat inference against truth table.
        7. Application Output Assembly: Assemble complete ApplicationOutputRecord.
        8. Application Output Validation: Assert-only validation of assembled ApplicationOutputRecord.
        9. Temporal Buffer Commit: Commit current window to history buffer and increment counter.
           (Transactional Invariant: executes strictly after all validations succeed).
        10. Return validated ApplicationOutputRecord.
        """
        start_time = time.perf_counter()

        # Step 1: Input Validation
        window_id, timestamp_str, timestamp_dt, dataset_day, features_array = validate_canonical_input(raw_input)

        # Step 2: Temporal Evaluation (state_manager is sole temporal authority)
        is_lstm_eligible, ineligibility_reason, lookback_tensor = (
            self.history_buffer.evaluate_and_get_lookback(timestamp_dt)
        )

        # Step 3: Model Inference
        # 3a. Autoencoder inference
        ae_mse, ae_anomaly = self.ae_predictor.predict_sample(features_array)
        ae_record = AutoencoderOutputRecord(
            reconstruction_mse=ae_mse,
            threshold=AUTOENCODER_THRESHOLD,
            is_anomaly=ae_anomaly,
        )

        # 3b. XGBoost inference
        xgb_class_idx, xgb_class_name, xgb_is_attack, xgb_probs = self.xgb_predictor.predict_sample(features_array)
        xgb_record = XGBoostOutputRecord(
            predicted_class_index=xgb_class_idx,
            predicted_class_name=xgb_class_name,
            is_attack=xgb_is_attack,
            class_probabilities=xgb_probs,
        )

        # 3c. LSTM inference
        if is_lstm_eligible and lookback_tensor is not None:
            lstm_prob, lstm_decision = self.lstm_predictor.predict_sequence(lookback_tensor)
            lstm_record = LSTMOutputRecord(
                is_eligible=True,
                ineligibility_reason=None,
                forecast_probability=lstm_prob,
                threshold=LSTM_THRESHOLD,
                forecast_decision=lstm_decision,
            )
            raw_b_lstm: Union[int, str] = lstm_decision
        else:
            lstm_record = LSTMOutputRecord(
                is_eligible=False,
                ineligibility_reason=ineligibility_reason,
                forecast_probability=None,
                threshold=LSTM_THRESHOLD,
                forecast_decision="unavailable",
            )
            raw_b_lstm = "unavailable"

        # Step 4: Model Output Validation (assert-only guards)
        validate_autoencoder_output(ae_record)
        validate_xgboost_output(xgb_record)
        validate_lstm_output(lstm_record)

        # Step 5: Threat-State Resolution
        threat_record = evaluate_threat_state(
            b_ae=ae_anomaly,
            b_xgb=xgb_is_attack,
            b_lstm=raw_b_lstm,
        )

        # Step 6: Threat-State Validation (assert-only guard)
        validate_threat_inference_output(
            threat_record=threat_record,
            b_ae=ae_anomaly,
            b_xgb=xgb_is_attack,
            b_lstm=raw_b_lstm,
        )

        # Step 7: Application Output Assembly
        next_position = self._internal_position_counter + 1
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        app_record = ApplicationOutputRecord(
            window_id=window_id,
            timestamp=timestamp_str,
            global_position=next_position,
            dataset_day=dataset_day,
            autoencoder=ae_record,
            xgboost=xgb_record,
            lstm=lstm_record,
            threat_inference=threat_record,
            execution_metadata=ExecutionMetadataRecord(
                inference_latency_ms=latency_ms,
                schema_version="1.0.0",
                engine="NexThreat-Phase5.2",
            ),
        )

        # Step 8: Application Output Validation (assert-only guard)
        validate_application_output_record(app_record)

        # Step 9: TEMPORAL BUFFER COMMIT (strictly at Step 9 after all validations succeed)
        self.history_buffer.commit_window(timestamp_dt, features_array)
        self._internal_position_counter = next_position

        # Step 10: Return Final Validated Output
        return app_record

    def reset_buffer(self) -> None:
        """Reset internal history buffer and sequence position counter."""
        self.history_buffer.clear()
        self._internal_position_counter = 0
