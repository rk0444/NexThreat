"""
NexThreat Phase 4.4 — LSTM Future Attack Forecasting Module.

Provides model construction, training, threshold optimization, evaluation,
dataset verification, and independent auditing for the 10-window lookback,
next-window binary attack forecasting task.
"""
from __future__ import annotations

from src.models.lstm.config import (
    LSTM_FEATURES,
    SEQUENCE_LENGTH,
    FORECAST_HORIZON,
    RANDOM_SEED,
)
from src.models.lstm.model import (
    build_lstm_candidate,
    set_deterministic_seeds,
)
from src.models.lstm.evaluate import (
    evaluate_binary_forecasting,
    run_threshold_sweep,
)

__all__ = [
    "LSTM_FEATURES",
    "SEQUENCE_LENGTH",
    "FORECAST_HORIZON",
    "RANDOM_SEED",
    "build_lstm_candidate",
    "set_deterministic_seeds",
    "evaluate_binary_forecasting",
    "run_threshold_sweep",
]
