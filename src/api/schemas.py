"""
NexThreat Phase 6.2 — API Request and Response Data Schemas.

Defines the external API request contracts (Format A and Format B) and the
authoritative 24-field response schemas strictly corresponding to Phase 5.1
Section 17 and Phase 6.1 Section 7 and 8.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Union

from src.application.schemas import (
    ApplicationOutputRecord,
    AutoencoderOutputRecord,
    ExecutionMetadataRecord,
    LSTMOutputRecord,
    ThreatInferenceRecord,
    XGBoostOutputRecord,
)

# Canonical 13-feature keys in authoritative sequential order (Phase 4 / Phase 5 / Phase 6.1)
CANONICAL_FEATURE_KEYS: List[str] = [
    "flow_count",
    "packet_rate",
    "byte_rate",
    "mean_flow_duration",
    "std_flow_duration",
    "short_flow_ratio",
    "mean_packet_size",
    "packet_length_variability",
    "fwd_bwd_packet_ratio",
    "unique_dst_ports",
    "unique_dst_ips",
    "tcp_flow_ratio",
    "syn_packet_ratio",
]


# =============================================================================
# REQUEST SCHEMAS
# =============================================================================

@dataclass(frozen=True)
class SingleWindowCanonicalRequest:
    """
    Format A: Authoritative canonical input record with ordered feature array.
    """
    window_id: str
    timestamp: str
    features: List[float]


@dataclass(frozen=True)
class SingleWindowNamedRequest:
    """
    Format B: Named object adapter request with 13 key-value feature mappings.
    """
    window_id: str
    timestamp: str
    features: Dict[str, float]


@dataclass(frozen=True)
class StreamBatchRequest:
    """
    Stream container for batch ingestion up to 5,000 records.
    """
    stream: List[Union[SingleWindowCanonicalRequest, SingleWindowNamedRequest, Dict[str, Any]]]


# =============================================================================
# RESPONSE SCHEMAS (24 AUTHORITATIVE FIELDS)
# =============================================================================

@dataclass(frozen=True)
class AutoencoderResponse:
    """
    Fields 5..7 of the 24-field Authority Matrix.
    """
    reconstruction_mse: float
    threshold: float
    is_anomaly: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reconstruction_mse": float(self.reconstruction_mse),
            "threshold": float(self.threshold),
            "is_anomaly": int(self.is_anomaly),
        }


@dataclass(frozen=True)
class XGBoostResponse:
    """
    Fields 8..11 of the 24-field Authority Matrix.
    """
    predicted_class_index: int
    predicted_class_name: str
    is_attack: int
    class_probabilities: Optional[List[float]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "predicted_class_index": int(self.predicted_class_index),
            "predicted_class_name": str(self.predicted_class_name),
            "is_attack": int(self.is_attack),
        }
        if self.class_probabilities is not None:
            d["class_probabilities"] = [float(p) for p in self.class_probabilities]
        else:
            d["class_probabilities"] = None
        return d


@dataclass(frozen=True)
class LSTMResponse:
    """
    Fields 12..16 of the 24-field Authority Matrix.
    """
    is_eligible: bool
    ineligibility_reason: Optional[str]
    forecast_probability: Optional[float]
    threshold: float
    forecast_decision: Union[int, str]  # 0, 1, or "unavailable"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_eligible": bool(self.is_eligible),
            "ineligibility_reason": str(self.ineligibility_reason) if self.ineligibility_reason is not None else None,
            "forecast_probability": float(self.forecast_probability) if self.forecast_probability is not None else None,
            "threshold": float(self.threshold),
            "forecast_decision": int(self.forecast_decision) if isinstance(self.forecast_decision, (int, bool)) else str(self.forecast_decision),
        }


@dataclass(frozen=True)
class ThreatInferenceResponse:
    """
    Fields 17..21 of the 24-field Authority Matrix.
    """
    is_eligible: bool
    threat_state_code: Optional[str]
    threat_state_name: Optional[str]
    priority_tier: Optional[str]
    decision_tuple: Optional[List[int]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_eligible": bool(self.is_eligible),
            "threat_state_code": str(self.threat_state_code) if self.threat_state_code is not None else None,
            "threat_state_name": str(self.threat_state_name) if self.threat_state_name is not None else None,
            "priority_tier": str(self.priority_tier) if self.priority_tier is not None else None,
            "decision_tuple": [int(x) for x in self.decision_tuple] if self.decision_tuple is not None else None,
        }


@dataclass(frozen=True)
class ExecutionMetadataResponse:
    """
    Fields 22..24 of the 24-field Authority Matrix.
    Preserves schema_version and engine as distinct independent fields.
    """
    inference_latency_ms: float
    schema_version: str = "1.0.0"
    engine: str = "NexThreat-Phase5.2"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "inference_latency_ms": round(float(self.inference_latency_ms), 3),
            "schema_version": str(self.schema_version),
            "engine": str(self.engine),
        }


@dataclass(frozen=True)
class StandardInferenceResponse:
    """
    Complete 24-field response record structurally corresponding to
    Phase 5 ApplicationOutputRecord and Phase 5.1 Section 17 schema.
    """
    window_id: str
    timestamp: str
    autoencoder: AutoencoderResponse
    xgboost: XGBoostResponse
    lstm: LSTMResponse
    threat_inference: ThreatInferenceResponse
    global_position: Optional[int] = None
    dataset_day: Optional[str] = None
    execution_metadata: Optional[ExecutionMetadataResponse] = None

    def to_dict(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {
            "window_id": str(self.window_id),
            "timestamp": str(self.timestamp),
        }
        if self.global_position is not None:
            output["global_position"] = int(self.global_position)
        if self.dataset_day is not None:
            output["dataset_day"] = str(self.dataset_day)

        output["autoencoder"] = self.autoencoder.to_dict()
        output["xgboost"] = self.xgboost.to_dict()
        output["lstm"] = self.lstm.to_dict()
        output["threat_inference"] = self.threat_inference.to_dict()

        if self.execution_metadata is not None:
            output["execution_metadata"] = self.execution_metadata.to_dict()

        return output

    @classmethod
    def from_application_record(cls, record: ApplicationOutputRecord) -> StandardInferenceResponse:
        """
        Construct StandardInferenceResponse from authoritative Phase 5 ApplicationOutputRecord.
        Preserves all 24 fields field-for-field and structurally.
        """
        ae = AutoencoderResponse(
            reconstruction_mse=record.autoencoder.reconstruction_mse,
            threshold=record.autoencoder.threshold,
            is_anomaly=record.autoencoder.is_anomaly,
        )
        xgb = XGBoostResponse(
            predicted_class_index=record.xgboost.predicted_class_index,
            predicted_class_name=record.xgboost.predicted_class_name,
            is_attack=record.xgboost.is_attack,
            class_probabilities=record.xgboost.class_probabilities,
        )
        lstm = LSTMResponse(
            is_eligible=record.lstm.is_eligible,
            ineligibility_reason=record.lstm.ineligibility_reason,
            forecast_probability=record.lstm.forecast_probability,
            threshold=record.lstm.threshold,
            forecast_decision=record.lstm.forecast_decision,
        )
        ti = ThreatInferenceResponse(
            is_eligible=record.threat_inference.is_eligible,
            threat_state_code=record.threat_inference.threat_state_code,
            threat_state_name=record.threat_inference.threat_state_name,
            priority_tier=record.threat_inference.priority_tier,
            decision_tuple=record.threat_inference.decision_tuple,
        )
        meta = None
        if record.execution_metadata is not None:
            meta = ExecutionMetadataResponse(
                inference_latency_ms=record.execution_metadata.inference_latency_ms,
                schema_version=record.execution_metadata.schema_version,
                engine=record.execution_metadata.engine,
            )

        return cls(
            window_id=record.window_id,
            timestamp=record.timestamp,
            autoencoder=ae,
            xgboost=xgb,
            lstm=lstm,
            threat_inference=ti,
            global_position=record.global_position,
            dataset_day=record.dataset_day,
            execution_metadata=meta,
        )
