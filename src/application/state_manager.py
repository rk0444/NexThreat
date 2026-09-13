"""
NexThreat Phase 5.2 — Temporal History Buffer and State Manager.

Manages the instance-owned FIFO historical lookback buffer for the LSTM forecaster.
Enforces the strict 60-second temporal continuity invariant:
    T_current - T_previous == exactly 60 seconds
Any delta other than exactly 60 seconds invalidates continuity and clears the buffer.
Backward or duplicate timestamps raise InputValidationError.
Day-boundary transitions immediately purge the buffer. Zero cross-day sequences.
"""
from __future__ import annotations

import collections
import datetime
from typing import Deque, Optional, Tuple

import numpy as np

from src.application.exceptions import InputValidationError


class TemporalHistoryBuffer:
    """
    Instance-owned lookback buffer holding up to 10 contiguous 1-minute historical windows.
    """

    def __init__(self, sequence_length: int = 10, window_duration_seconds: int = 60):
        self.sequence_length = int(sequence_length)
        self.window_duration_seconds = int(window_duration_seconds)
        self._buffer: Deque[Tuple[datetime.datetime, np.ndarray]] = collections.deque(maxlen=self.sequence_length)

    def evaluate_and_get_lookback(
        self,
        current_dt: datetime.datetime,
    ) -> Tuple[bool, Optional[str], Optional[np.ndarray]]:
        """
        Evaluate temporal continuity against the current buffer state and return
        the 10-window lookback tensor if eligible.

        Returns:
            (is_eligible, ineligibility_reason, lookback_tensor_10x13_or_None)
        """
        if len(self._buffer) > 0:
            last_dt, _ = self._buffer[-1]

            # 1. Monotonicity assertion: backward or duplicate timestamps are strict errors
            if current_dt <= last_dt:
                raise InputValidationError(
                    f"Chronological ordering violation: current timestamp {current_dt} "
                    f"<= previous timestamp {last_dt}. Non-advancing time is rejected."
                )

            # 2. Day-boundary quarantine: reset buffer if crossing calendar day
            if current_dt.date() != last_dt.date():
                self._buffer.clear()
                return False, "lstm_lookback_cold_start", None

            # 3. Strict 60-second temporal continuity invariant
            delta_seconds = (current_dt - last_dt).total_seconds()
            if delta_seconds != float(self.window_duration_seconds):
                # Any delta other than exactly 60 seconds invalidates continuity
                self._buffer.clear()
                return False, "temporal_gap_discontinuity", None

        # 4. Sequence depth check
        if len(self._buffer) < self.sequence_length:
            return False, "lstm_lookback_cold_start", None

        # 5. Extract contiguous 10x13 lookback array
        # At this point, exactly 10 consecutive 60-second windows exist
        seq_list = [features for _, features in self._buffer]
        lookback_tensor = np.stack(seq_list, axis=0).astype(np.float32)
        return True, None, lookback_tensor

    def commit_window(self, current_dt: datetime.datetime, features: np.ndarray) -> None:
        """
        Append the current validated window features to the FIFO buffer for subsequent windows.
        """
        self._buffer.append((current_dt, np.array(features, dtype=np.float32, copy=True)))

    def clear(self) -> None:
        """Clear all historical windows in the buffer."""
        self._buffer.clear()

    @property
    def current_depth(self) -> int:
        """Return the current number of historical windows in the buffer."""
        return len(self._buffer)
