"""
NexThreat Phase 5.3 — Stream Ingestion Pipeline Adapter.

Adapts external file-based traffic feature streams (CSV files, JSON Lines)
into canonical Phase 5.1 input records.
Strictly ignores extraneous label/dataset columns to prevent ground-truth leakage.
Delegates all temporal continuity, gap purging, and lookback evaluation
directly to the authoritative Phase 5.2 ApplicationInferenceEngine.
"""
from __future__ import annotations

import csv
import json
import math
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional, Tuple, Union

import numpy as np

from src.application.config import CANONICAL_FEATURE_COLUMNS, FEATURE_COUNT
from src.application.exceptions import InputValidationError
from src.application.orchestrator import ApplicationInferenceEngine
from src.application.schemas import ApplicationOutputRecord, CanonicalInputRecord


class StreamIngestionAdapter:
    """
    Adapter that ingests CSV or JSONL files and streams them into an
    ApplicationInferenceEngine instance without altering Phase 5.2 temporal semantics.
    """

    def __init__(self, engine: Optional[ApplicationInferenceEngine] = None):
        self.engine = engine or ApplicationInferenceEngine()

    @staticmethod
    def parse_csv_row_to_canonical(row: Dict[str, Any], row_idx: int) -> CanonicalInputRecord:
        """
        Extract canonical fields from a CSV row mapping, ignoring extraneous metadata or ground-truth columns.
        """
        # 1. Resolve window_id
        if "window_id" not in row:
            raise InputValidationError(f"Row {row_idx}: Missing required column 'window_id'.")
        window_id = str(row["window_id"]).strip()

        # 2. Resolve timestamp (supports 'timestamp' or 'window_start')
        if "timestamp" in row:
            ts_str = str(row["timestamp"]).strip()
        elif "window_start" in row:
            ts_str = str(row["window_start"]).strip()
        else:
            raise InputValidationError(f"Row {row_idx}: Missing timestamp column ('timestamp' or 'window_start').")

        # 3. Extract exact 13 canonical features in strict invariant order
        features: List[float] = []
        for col in CANONICAL_FEATURE_COLUMNS:
            if col not in row:
                raise InputValidationError(f"Row {row_idx}: Missing canonical feature column '{col}'.")
            val_raw = row[col]
            try:
                val_float = float(val_raw)
            except (ValueError, TypeError) as e:
                raise InputValidationError(
                    f"Row {row_idx}: Feature '{col}' has non-numeric value '{val_raw}': {e}"
                ) from e

            if math.isnan(val_float) or math.isinf(val_float):
                raise InputValidationError(
                    f"Row {row_idx}: Feature '{col}' contains non-finite value '{val_float}'."
                )
            features.append(val_float)

        return CanonicalInputRecord(
            window_id=window_id,
            timestamp=ts_str,
            features=features,
        )

    def stream_csv_file(
        self,
        file_path: Union[str, Path],
    ) -> Generator[ApplicationOutputRecord, None, None]:
        """
        Read a CSV file sequentially and stream each canonical record through the engine.
        Delegates all temporal continuity and gap handling directly to the engine.
        """
        p = Path(file_path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Traffic CSV file not found: {p}")

        with open(p, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader, start=1):
                canonical_rec = self.parse_csv_row_to_canonical(row, idx)
                output_rec = self.engine.process_window(canonical_rec)
                yield output_rec

    def stream_jsonl_file(
        self,
        file_path: Union[str, Path],
    ) -> Generator[ApplicationOutputRecord, None, None]:
        """
        Read a JSON Lines (.jsonl) file sequentially and stream each record through the engine.
        """
        p = Path(file_path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Traffic JSONL file not found: {p}")

        with open(p, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    data = json.loads(clean_line)
                except json.JSONDecodeError as e:
                    raise InputValidationError(f"Line {idx}: Invalid JSON: {e}") from e

                output_rec = self.engine.process_window(data)
                yield output_rec

    def process_records_stream(
        self,
        records: Iterable[Union[Dict[str, Any], CanonicalInputRecord]],
    ) -> List[ApplicationOutputRecord]:
        """
        Process an in-memory iterable stream of records in exact supplied order.
        """
        results: List[ApplicationOutputRecord] = []
        for rec in records:
            out = self.engine.process_window(rec)
            results.append(out)
        return results
