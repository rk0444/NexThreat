"""
NexThreat Phase 5.2 — Application Inference Engine & Orchestration Service.

Operationalizes the accepted Phase 4 ML architecture according to the formal
Phase 5.1 Application Integration Architecture & Contract Specification.
"""

__version__ = "1.0.0"

from src.application.orchestrator import ApplicationInferenceEngine
from src.application.schemas import CanonicalInputRecord, ApplicationOutputRecord
from src.application.exceptions import (
    NexThreatApplicationError,
    InputValidationError,
    TemporalEligibilityCondition,
    ModelExecutionError,
    IntegrationContractError,
)

__all__ = [
    "ApplicationInferenceEngine",
    "CanonicalInputRecord",
    "ApplicationOutputRecord",
    "NexThreatApplicationError",
    "InputValidationError",
    "TemporalEligibilityCondition",
    "ModelExecutionError",
    "IntegrationContractError",
]
