import logging

import numpy as np
import pandas as pd

from src.feature_engineering.config import (
    PROCESSED_DATA_DIR,
    WINDOWS_DATA_DIR,
    FEATURES_DATA_DIR,
    WINDOW_SIZE,
    TIMESTAMP_COLUMN,
    WINDOW_ID_COLUMN,
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
    WINDOW_DURATION_SECONDS,
    SHORT_FLOW_THRESHOLD_MICROSECONDS,
    TCP_PROTOCOL_NUMBER,
    REQUIRED_PROCESSED_COLUMNS,
    REQUIRED_WINDOW_COLUMNS,
    FEATURE_COLUMNS,
    INPUT_FILE_MAPPING,
    WINDOW_FILE_MAPPING,
    OUTPUT_FILE_MAPPING,
    OUTPUT_SCHEMA_COLUMNS,
)


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


# ============================================================
# VALIDATION FUNCTIONS
# ============================================================

def validate_required_columns(
    df: pd.DataFrame,
    required_columns: list[str],
    dataset_name: str,
) -> None:
    """
    Validate that all required columns exist.
    """

    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"{dataset_name} is missing required columns: "
            f"{missing_columns}"
        )


def validate_feature_output(df: pd.DataFrame) -> None:
    """
    Validate the final engineered feature dataset.
    """

    # --------------------------------------------------------
    # Schema validation
    # --------------------------------------------------------

    if list(df.columns) != OUTPUT_SCHEMA_COLUMNS:
        raise ValueError(
            "Output schema mismatch.\n"
            f"Expected: {OUTPUT_SCHEMA_COLUMNS}\n"
            f"Found: {list(df.columns)}"
        )

    # --------------------------------------------------------
    # Null validation
    # --------------------------------------------------------

    null_counts = df.isnull().sum()

    if null_counts.any():
        problematic_columns = null_counts[
            null_counts > 0
        ].to_dict()

        raise ValueError(
            f"Null values found in output: "
            f"{problematic_columns}"
        )

    # --------------------------------------------------------
    # Feature validation
    # --------------------------------------------------------

    for feature in FEATURE_COLUMNS:

        if (df[feature] < 0).any():
            raise ValueError(
                f"Negative values found in feature: {feature}"
            )

        if not np.isfinite(df[feature]).all():
            raise ValueError(
                f"Non-finite values found in feature: {feature}"
            )

    # --------------------------------------------------------
    # Ratio validation
    # --------------------------------------------------------

    ratio_features = [
        "short_flow_ratio",
        "tcp_flow_ratio",
        "syn_packet_ratio",
    ]

    for feature in ratio_features:

        invalid_ratio = (
            (df[feature] < 0)
            | (df[feature] > 1)
        )

        if invalid_ratio.any():

            raise ValueError(
                f"Ratio feature outside [0, 1]: {feature}"
            )

    logger.info(
        "Feature output validation passed successfully."
    )


# ============================================================
# FEATURE ENGINEERING
# ============================================================

def engineer_window_features(
    flows_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Aggregate flow-level records into 1-minute
    network behavior features.
    """

    logger.info(
        "Assigning flows to 1-minute windows..."
    )

    flows_df = flows_df.copy()

    flows_df[TIMESTAMP_COLUMN] = pd.to_datetime(
        flows_df[TIMESTAMP_COLUMN],
        errors="coerce",
    )

    if flows_df[TIMESTAMP_COLUMN].isna().any():

        raise ValueError(
            "Invalid timestamps found during "
            "feature engineering."
        )

    flows_df["_window_start"] = (
        flows_df[TIMESTAMP_COLUMN]
        .dt.floor(WINDOW_SIZE)
    )

    # --------------------------------------------------------
    # Derived flow-level values
    # --------------------------------------------------------

    flows_df["_total_packets"] = (
        flows_df[FWD_PACKET_COLUMN]
        + flows_df[BWD_PACKET_COLUMN]
    )

    flows_df["_total_bytes"] = (
        flows_df[FWD_BYTES_COLUMN]
        + flows_df[BWD_BYTES_COLUMN]
    )

    flows_df["_is_short_flow"] = (
        flows_df[FLOW_DURATION_COLUMN]
        <= SHORT_FLOW_THRESHOLD_MICROSECONDS
    ).astype(int)

    flows_df["_is_tcp"] = (
        flows_df[PROTOCOL_COLUMN]
        == TCP_PROTOCOL_NUMBER
    ).astype(int)

    # --------------------------------------------------------
    # Aggregate by window
    # --------------------------------------------------------

    logger.info(
        "Calculating 13 network features..."
    )

    grouped = flows_df.groupby(
        "_window_start",
        sort=True,
    )

    features = grouped.agg(

        flow_count=(
            FLOW_DURATION_COLUMN,
            "size",
        ),

        total_packets=(
            "_total_packets",
            "sum",
        ),

        total_bytes=(
            "_total_bytes",
            "sum",
        ),

        mean_flow_duration=(
            FLOW_DURATION_COLUMN,
            "mean",
        ),

        std_flow_duration=(
            FLOW_DURATION_COLUMN,
            "std",
        ),

        short_flow_count=(
            "_is_short_flow",
            "sum",
        ),

        packet_length_variability=(
            PACKET_LENGTH_STD_COLUMN,
            "mean",
        ),

        total_fwd_packets=(
            FWD_PACKET_COLUMN,
            "sum",
        ),

        total_bwd_packets=(
            BWD_PACKET_COLUMN,
            "sum",
        ),

        unique_dst_ports=(
            DST_PORT_COLUMN,
            "nunique",
        ),

        unique_dst_ips=(
            DST_IP_COLUMN,
            "nunique",
        ),

        tcp_flow_count=(
            "_is_tcp",
            "sum",
        ),

        total_syn_flags=(
            SYN_FLAG_COLUMN,
            "sum",
        ),
    ).reset_index()

    # --------------------------------------------------------
    # Derived window-level features
    # --------------------------------------------------------

    features["packet_rate"] = (
        features["total_packets"]
        / WINDOW_DURATION_SECONDS
    )

    features["byte_rate"] = (
        features["total_bytes"]
        / WINDOW_DURATION_SECONDS
    )

    features["short_flow_ratio"] = (
        features["short_flow_count"]
        / features["flow_count"]
    )

    features["mean_packet_size"] = np.where(
        features["total_packets"] > 0,
        features["total_bytes"]
        / features["total_packets"],
        0,
    )

    features["fwd_bwd_packet_ratio"] = (
        features["total_fwd_packets"]
        / (
            features["total_bwd_packets"]
            + 1
        )
    )

    features["tcp_flow_ratio"] = (
        features["tcp_flow_count"]
        / features["flow_count"]
    )

    features["syn_packet_ratio"] = np.where(
        features["total_packets"] > 0,
        features["total_syn_flags"]
        / features["total_packets"],
        0,
    )

    # --------------------------------------------------------
    # Handle single-flow std = NaN
    # --------------------------------------------------------

    features["std_flow_duration"] = (
        features["std_flow_duration"]
        .fillna(0)
    )

    # --------------------------------------------------------
    # Select required feature columns
    # --------------------------------------------------------

    features = features[
        [
            "_window_start",
            *FEATURE_COLUMNS,
        ]
    ]

    return features


# ============================================================
# MERGE FEATURES WITH PHASE 2.2 WINDOWS
# ============================================================

def merge_features_with_windows(
    windows_df: pd.DataFrame,
    features_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Merge engineered features with authoritative
    Phase 2.2 window metadata and labels.

    Phase 2.2 flow_count is retained as authoritative.
    """

    logger.info(
        "Merging features with Phase 2.2 windows..."
    )

    windows_df = windows_df.copy()
    features_df = features_df.copy()

    # --------------------------------------------------------
    # Parse window timestamps
    # --------------------------------------------------------

    windows_df["window_start"] = pd.to_datetime(
        windows_df["window_start"],
        errors="coerce",
    )

    if windows_df["window_start"].isna().any():
        raise ValueError(
            "Invalid window_start values found "
            "in Phase 2.2 window data."
        )

    # --------------------------------------------------------
    # Remove duplicate flow_count
    #
    # Phase 2.2 flow_count is authoritative and already
    # validated during window creation.
    # --------------------------------------------------------

    features_df = features_df.drop(
        columns=["flow_count"],
        errors="ignore",
    )

    # --------------------------------------------------------
    # Merge
    # --------------------------------------------------------

    merged = windows_df.merge(
        features_df,
        how="left",
        left_on="window_start",
        right_on="_window_start",
        validate="one_to_one",
    )

    # --------------------------------------------------------
    # Remove helper merge column
    # --------------------------------------------------------

    merged = merged.drop(
        columns=["_window_start"]
    )

    # --------------------------------------------------------
    # Fill EMPTY windows with zeros
    # --------------------------------------------------------

    for feature in FEATURE_COLUMNS:

        if feature not in merged.columns:
            raise ValueError(
                f"Feature missing after merge: {feature}"
            )

        merged[feature] = merged[feature].fillna(0)

    return merged


# ============================================================
# DATA TYPE ENFORCEMENT
# ============================================================

def enforce_output_types(
    df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Enforce consistent output data types.
    """

    df = df.copy()

    integer_features = [
        "flow_count",
        "unique_dst_ports",
        "unique_dst_ips",
    ]

    float_features = [
        feature
        for feature in FEATURE_COLUMNS
        if feature not in integer_features
    ]

    for feature in integer_features:

        df[feature] = (
            df[feature]
            .astype("int64")
        )

    for feature in float_features:

        df[feature] = (
            df[feature]
            .astype("float64")
        )

    df["window_index"] = (
        df["window_index"]
        .astype("int64")
    )

    df["is_attack_window"] = (
        df["is_attack_window"]
        .astype("int64")
    )

    return df


# ============================================================
# PROCESS SINGLE DATASET
# ============================================================

def process_dataset(
    dataset_name: str,
) -> pd.DataFrame:
    """
    Process one day's dataset.
    """

    processed_file = (
        PROCESSED_DATA_DIR
        / INPUT_FILE_MAPPING[dataset_name]
    )

    windows_file = (
        WINDOWS_DATA_DIR
        / WINDOW_FILE_MAPPING[dataset_name]
    )

    output_file = (
        FEATURES_DATA_DIR
        / OUTPUT_FILE_MAPPING[dataset_name]
    )

    logger.info(
        f"--- Processing {dataset_name} ---"
    )

    # --------------------------------------------------------
    # Load processed flows
    # --------------------------------------------------------

    logger.info(
        f"Loading processed flows: "
        f"{processed_file.name}"
    )

    flows_df = pd.read_csv(
        processed_file,
        low_memory=False,
    )

    validate_required_columns(
        flows_df,
        REQUIRED_PROCESSED_COLUMNS,
        f"{dataset_name} processed flows",
    )

    # --------------------------------------------------------
    # Load Phase 2.2 windows
    # --------------------------------------------------------

    logger.info(
        f"Loading windows: "
        f"{windows_file.name}"
    )

    windows_df = pd.read_csv(
        windows_file,
        low_memory=False,
    )

    validate_required_columns(
        windows_df,
        REQUIRED_WINDOW_COLUMNS,
        f"{dataset_name} windows",
    )

    # --------------------------------------------------------
    # Engineer features
    # --------------------------------------------------------

    features_df = engineer_window_features(
        flows_df
    )

    # --------------------------------------------------------
    # Merge with authoritative windows
    # --------------------------------------------------------

    final_df = merge_features_with_windows(
        windows_df,
        features_df,
    )

    # --------------------------------------------------------
    # Enforce schema
    # --------------------------------------------------------

    final_df = final_df[
        OUTPUT_SCHEMA_COLUMNS
    ]

    # --------------------------------------------------------
    # Enforce data types
    # --------------------------------------------------------

    final_df = enforce_output_types(
        final_df
    )

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    validate_feature_output(
        final_df
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    FEATURES_DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    final_df.to_csv(
        output_file,
        index=False,
    )

    logger.info(
        f"Saved features to: "
        f"{output_file}"
    )

    logger.info(
        f"Windows processed: "
        f"{len(final_df):,}"
    )

    return final_df


# ============================================================
# MASTER PIPELINE
# ============================================================

def main():
    """
    Run Phase 2.3 feature engineering
    for all datasets.
    """

    logger.info(
        "Starting NexThreat Phase 2.3 "
        "Feature Engineering Pipeline..."
    )

    all_results = {}

    for dataset_name in INPUT_FILE_MAPPING:

        result_df = process_dataset(
            dataset_name
        )

        all_results[dataset_name] = result_df

    # --------------------------------------------------------
    # Final Summary
    # --------------------------------------------------------

    logger.info(
        "================================================"
    )

    logger.info(
        "Phase 2.3 Feature Engineering Completed."
    )

    logger.info(
        "================================================"
    )

    for dataset_name, df in all_results.items():

        logger.info(
            f"{dataset_name}: "
            f"{len(df):,} windows"
        )


if __name__ == "__main__":
    main()