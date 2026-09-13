"""
NexThreat Phase 5.2 — Application Inference Engine & Orchestrator.

Orchestrates the complete multi-model threat inference lifecycle for incoming
one-minute feature window records according to Phase 5.1 specifications.
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
from src.application.validators import validate_canonical_input


class ApplicationInferenceEngine:
    """
    Unified Application Inference Engine.
    Encapsulates frozen model predictors and an instance-owned temporal lookback buffer.
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
        
        Lifecycle:
        1. Validate external input contract and extract 13 canonical features.
        2. Evaluate temporal lookback buffer (strict 60-second continuity & day boundary).
        3. Execute Autoencoder anomaly detection.
        4. Execute XGBoost attack-category classification.
        5. Execute LSTM forecasting (or mark unavailable if cold-start / discontinuous).
        6. Map discrete decisions to canonical threat state S0..S7 (or neutral null).
        7. Commit window to temporal history buffer.
        8. Format structured application output record.
        """
        start_time = time.perf_counter()

        # 1. Validate external input contract
        window_id, timestamp_str, timestamp_dt, dataset_day, features_array = validate_canonical_input(raw_input)

        # 2. Evaluate temporal lookback buffer
        is_lstm_eligible, ineligibility_reason, lookback_tensor = (
            self.history_buffer.evaluate_and_get_lookback(timestamp_dt)
        )

        # 3. Autoencoder inference
        ae_mse, ae_anomaly = self.ae_predictor.predict_sample(features_array)
        ae_record = AutoencoderOutputRecord(
            reconstruction_mse=ae_mse,
            threshold=AUTOENCODER_THRESHOLD,
            is_anomaly=ae_anomaly,
        )

        # 4. XGBoost inference
        xgb_class_idx, xgb_class_name, xgb_is_attack, xgb_probs = self.xgb_predictor.predict_sample(features_array)
        xgb_record = XGBoostOutputRecord(
            predicted_class_index=xgb_class_idx,
            predicted_class_name=xgb_class_name,
            is_attack=xgb_is_attack,
            class_probabilities=xgb_probs,
        )

        # 5. LSTM inference
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

        # 6. Unified threat-state evaluation
        threat_record = evaluate_threat_state(
            b_ae=ae_anomaly,
            b_xgb=xgb_is_attack,
            b_lstm=raw_b_lstm,
        )

        # 7. Commit current window to history buffer
        self.history_buffer.commit_window(timestamp_dt, features_array)

        # 8. Track internal sequence position
        self._internal_position_counter += 1

        # 9. Measure execution latency
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        # 10. Assemble complete application output record
        return ApplicationOutputRecord(
            window_id=window_id,
            timestamp=timestamp_str,
            global_position=self._internal_position_counter,
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

    def reset_buffer(self) -> None:
        """Reset internal history buffer and sequence position counter."""
        self.history_buffer.clear()
        self._internal_position_counter = 0
