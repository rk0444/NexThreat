from pathlib import Path

# Project root path (3 levels up from this file: src/preprocessing/config.py)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Data directories
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DATA_DIR = PROJECT_ROOT / "data" / "processed"

# Timestamp format
TIMESTAMP_FORMAT = "%d/%m/%Y %I:%M:%S %p"

# The five CICIDS2017 dataset filenames
DATASET_FILENAMES = [
    "Monday-WorkingHours.csv",
    "Tuesday-WorkingHours.csv",
    "Wednesday-workingHours.csv",
    "Thursday-WorkingHours.csv",
    "Friday-WorkingHours.csv"
]

# Required critical columns
CRITICAL_COLUMNS = [
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Label"
]
