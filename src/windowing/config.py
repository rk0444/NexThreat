"""
NexThreat Phase 2.2 — 1-Minute Chronological Window Creation Configuration.
"""
from pathlib import Path

# Project root path (3 levels up from src/windowing/config.py)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Data directories
DATA_DIR = PROJECT_ROOT / "data"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
WINDOWS_DATA_DIR = DATA_DIR / "windows"

# Window parameters
WINDOW_SIZE = "1min"

# Source column names
TIMESTAMP_COLUMN = "Timestamp"
LABEL_COLUMN = "Label"
FLOW_CATEGORY_COLUMN = "attack_category"

# Required input columns from Phase 2.1
REQUIRED_COLUMNS = [
    TIMESTAMP_COLUMN,
    LABEL_COLUMN,
    FLOW_CATEGORY_COLUMN
]

# Verified mapping from dataset key to Phase 2.1 processed filenames
INPUT_FILE_MAPPING = {
    "Monday": "Monday-WorkingHours_processed.csv",
    "Tuesday": "Tuesday-WorkingHours_processed.csv",
    "Wednesday": "Wednesday-workingHours_processed.csv",
    "Thursday": "Thursday-WorkingHours_processed.csv",
    "Friday": "Friday-WorkingHours_processed.csv"
}

# Mapping from dataset key to Phase 2.2 window output filenames
OUTPUT_FILE_MAPPING = {
    "Monday": "Monday_windows.csv",
    "Tuesday": "Tuesday_windows.csv",
    "Wednesday": "Wednesday_windows.csv",
    "Thursday": "Thursday_windows.csv",
    "Friday": "Friday_windows.csv"
}

# Required output schema column order
WINDOW_SCHEMA_COLUMNS = [
    "window_id",
    "window_start",
    "window_end",
    "date",
    "day_name",
    "window_index",
    "flow_count",
    "benign_flow_count",
    "attack_flow_count",
    "attack_ratio",
    "is_attack_window",
    "attack_category",
    "attack_categories_present"
]
