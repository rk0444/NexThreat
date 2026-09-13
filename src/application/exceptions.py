"""
NexThreat Phase 5.2 — Application Error Hierarchy.

Deterministic error classification aligned with Phase 5.1 Section 19.
"""
from __future__ import annotations


class NexThreatApplicationError(Exception):
    """Base exception for all NexThreat application runtime errors."""
    pass


class InputValidationError(NexThreatApplicationError):
    """
    Raised when an incoming window record fails structural, typing, finite-bound,
    or monotonic chronology validation. Halts processing; zero model inference executed.
    """
    pass


class TemporalEligibilityCondition(NexThreatApplicationError):
    """
    Indicates that temporal context is insufficient for LSTM inference
    (e.g., lookback buffer < 10, day-boundary transition, or gap discontinuity).
    This is an operational state, not a fatal fault.
    """
    pass


class ModelExecutionError(NexThreatApplicationError):
    """
    Raised when model artifact loading, weight evaluation, or numerical execution fails.
    Zero silent fallback allowed.
    """
    pass


class IntegrationContractError(NexThreatApplicationError):
    """
    Raised when an architectural invariant or contract is violated
    (e.g., non-canonical state generated, score fusion attempted, or artifact mutation).
    """
    pass
