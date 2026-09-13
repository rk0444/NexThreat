"""
NexThreat Phase 5.2 — Threat Inference Engine.

Reuses the authoritative Phase 4 canonical S0-S7 mapping function
T: {0, 1}^3 -> {S0 .. S7} with neutral null semantics for cold-start / discontinuous windows.
Explicitly prohibits S8, LSTM_UNAVAILABLE as a threat state, and numerical score fusion.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union

from src.application.config import (
    CANONICAL_THREAT_STATES,
    INPUT_TUPLE_TO_STATE,
    INPUT_TUPLE_TO_CODE,
    FORBIDDEN_SEMANTIC_LABELS,
)
from src.application.exceptions import IntegrationContractError
from src.application.schemas import ThreatInferenceRecord


def evaluate_threat_state(
    b_ae: int,
    b_xgb: int,
    b_lstm: Union[int, str],
) -> ThreatInferenceRecord:
    """
    Evaluate the unified threat state from the model decision outputs.
    
    If LSTM is unavailable (cold-start, gap, or day boundary):
        Returns ThreatInferenceRecord with is_eligible=False, threat_state=None, code=None.
    If LSTM is available (0 or 1):
        Maps (b_ae, b_xgb, b_lstm) to canonical state S0..S7.
    """
    if b_lstm == "unavailable":
        return ThreatInferenceRecord(
            is_eligible=False,
            threat_state_code=None,
            threat_state_name=None,
            priority_tier=None,
            decision_tuple=None,
        )

    try:
        tuple_key = (int(b_ae), int(b_xgb), int(b_lstm))
    except (ValueError, TypeError) as e:
        raise IntegrationContractError(
            f"Invalid decision inputs: b_ae={b_ae}, b_xgb={b_xgb}, b_lstm={b_lstm}: {e}"
        ) from e

    if tuple_key not in INPUT_TUPLE_TO_CODE:
        raise IntegrationContractError(
            f"Decision tuple {tuple_key} does not exist in canonical {{0, 1}}^3 taxonomy."
        )

    state_code = INPUT_TUPLE_TO_CODE[tuple_key]
    state_name = INPUT_TUPLE_TO_STATE[tuple_key]

    # Prohibit forbidden state names
    if state_code in ("S8", "LSTM_UNAVAILABLE") or state_name in FORBIDDEN_SEMANTIC_LABELS:
        raise IntegrationContractError(
            f"Detected forbidden threat state label: code='{state_code}', name='{state_name}'"
        )

    state_meta = CANONICAL_THREAT_STATES[state_code]

    return ThreatInferenceRecord(
        is_eligible=True,
        threat_state_code=state_code,
        threat_state_name=state_name,
        priority_tier=state_meta["triage_tier"],
        decision_tuple=list(tuple_key),
    )
