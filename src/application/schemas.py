"""
NexThreat Phase 5.2 — Application Data Schemas.

Defines the external canonical input contract and the structured application
threat inference JSON output record adhering strictly to Phase 5.1 Section 17.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Union


@dataclass(frozen=True)
class CanonicalInputRecord:
    """
    Authoritative external input record.
    External client callers must provide exactly these three fields.
    """
    window_id: str
    timestamp: str
    features: List[float]


@dataclass(frozen=True)
class AutoencoderOutputRecord:
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
class XGBoostOutputRecord:
    predicted_class_index: int
    predicted_class_name: str
    is_attack: int
    class_probabilities: Optional[List[float]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "predicted_class_index": int(self.predicted_class_index),
            "predicted_class_name": self.predicted_class_name,
            "is_attack": int(self.is_attack),
        }
        if self.class_probabilities is not None:
            d["class_probabilities"] = [float(p) for p in self.class_probabilities]
        else:
            d["class_probabilities"] = None
        return d


@dataclass(frozen=True)
class LSTMOutputRecord:
    is_eligible: bool
    ineligibility_reason: Optional[str]
    forecast_probability: Optional[float]
    threshold: float
    forecast_decision: Union[int, str]  # 0, 1, or "unavailable"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_eligible": bool(self.is_eligible),
            "ineligibility_reason": self.ineligibility_reason,
            "forecast_probability": float(self.forecast_probability) if self.forecast_probability is not None else None,
            "threshold": float(self.threshold),
            "forecast_decision": int(self.forecast_decision) if isinstance(self.forecast_decision, (int, bool)) else str(self.forecast_decision),
        }


@dataclass(frozen=True)
class ThreatInferenceRecord:
    is_eligible: bool
    threat_state_code: Optional[str]
    threat_state_name: Optional[str]
    priority_tier: Optional[str]
    decision_tuple: Optional[List[int]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_eligible": bool(self.is_eligible),
            "threat_state_code": self.threat_state_code,
            "threat_state_name": self.threat_state_name,
            "priority_tier": self.priority_tier,
            "decision_tuple": [int(x) for x in self.decision_tuple] if self.decision_tuple is not None else None,
        }


@dataclass(frozen=True)
class ExecutionMetadataRecord:
    inference_latency_ms: float
    schema_version: str = "1.0.0"
    engine: str = "NexThreat-Phase5.2"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "inference_latency_ms": round(float(self.inference_latency_ms), 3),
            "schema_version": self.schema_version,
            "engine": self.engine,
        }


@dataclass(frozen=True)
class ApplicationOutputRecord:
    """
    Authoritative application output schema strictly conforming to Phase 5.1 Section 17.
    """
    window_id: str
    timestamp: str
    autoencoder: AutoencoderOutputRecord
    xgboost: XGBoostOutputRecord
    lstm: LSTMOutputRecord
    threat_inference: ThreatInferenceRecord
    global_position: Optional[int] = None
    dataset_day: Optional[str] = None
    execution_metadata: Optional[ExecutionMetadataRecord] = None

    def to_dict(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {
            "window_id": self.window_id,
            "timestamp": self.timestamp,
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
