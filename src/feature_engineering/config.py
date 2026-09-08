from pathlib import Path


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"

PROCESSED_DATA_DIR = DATA_DIR / "processed"
WINDOWS_DATA_DIR = DATA_DIR / "windows"
FEATURES_DATA_DIR = DATA_DIR / "features"


# ============================================================
# WINDOW CONFIGURATION
# ============================================================

WINDOW_SIZE = "1min"

TIMESTAMP_COLUMN = "Timestamp"
WINDOW_ID_COLUMN = "window_id"


# ============================================================
# INPUT COLUMN NAMES
# ============================================================

FLOW_DURATION_COLUMN = "Flow Duration"

FWD_PACKET_COLUMN = "Total Fwd Packet"
BWD_PACKET_COLUMN = "Total Bwd packets"

FWD_BYTES_COLUMN = "Total Length of Fwd Packet"
BWD_BYTES_COLUMN = "Total Length of Bwd Packet"

PACKET_LENGTH_STD_COLUMN = "Packet Length Std"

DST_PORT_COLUMN = "Dst Port"
DST_IP_COLUMN = "Dst IP"

PROTOCOL_COLUMN = "Protocol"

SYN_FLAG_COLUMN = "SYN Flag Count"


# ============================================================
# FEATURE CONFIGURATION
# ============================================================

WINDOW_DURATION_SECONDS = 60

SHORT_FLOW_THRESHOLD_MICROSECONDS = 1_000_000

TCP_PROTOCOL_NUMBER = 6


# ============================================================
# REQUIRED PROCESSED DATA COLUMNS
# ============================================================

REQUIRED_PROCESSED_COLUMNS = [
    TIMESTAMP_COLUMN,
    FLOW_DURATION_COLUMN,
    FWD_PACKET_COLUMN,
    BWD_PACKET_COLUMN,
    FWD_BYTES_COLUMN,
    BWD_BYTES_COLUMN,
    PACKET_LENGTH_STD_COLUMN,
    DST_PORT_COLUMN,
    DST_IP_COLUMN,
    PROTOCOL_COLUMN,
    SYN_FLAG_COLUMN,
]


# ============================================================
# REQUIRED WINDOW COLUMNS
# ============================================================

REQUIRED_WINDOW_COLUMNS = [
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
    "attack_categories_present",
]


# ============================================================
# FINAL 13 NETWORK FEATURES
# ============================================================

FEATURE_COLUMNS = [
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


# ============================================================
# FILE MAPPINGS
# ============================================================

INPUT_FILE_MAPPING = {
    "Monday": "Monday-WorkingHours_processed.csv",
    "Tuesday": "Tuesday-WorkingHours_processed.csv",
    "Wednesday": "Wednesday-workingHours_processed.csv",
    "Thursday": "Thursday-WorkingHours_processed.csv",
    "Friday": "Friday-WorkingHours_processed.csv",
}


WINDOW_FILE_MAPPING = {
    "Monday": "Monday_windows.csv",
    "Tuesday": "Tuesday_windows.csv",
    "Wednesday": "Wednesday_windows.csv",
    "Thursday": "Thursday_windows.csv",
    "Friday": "Friday_windows.csv",
}


OUTPUT_FILE_MAPPING = {
    "Monday": "Monday_features.csv",
    "Tuesday": "Tuesday_features.csv",
    "Wednesday": "Wednesday_features.csv",
    "Thursday": "Thursday_features.csv",
    "Friday": "Friday_features.csv",
}


# ============================================================
# FINAL OUTPUT SCHEMA
# ============================================================

OUTPUT_SCHEMA_COLUMNS = [
    # Metadata
    "window_id",
    "window_start",
    "window_end",
    "date",
    "day_name",
    "window_index",

    # Network Features
    *FEATURE_COLUMNS,

    # Labels
    "is_attack_window",
    "attack_category",
    "attack_categories_present",
]