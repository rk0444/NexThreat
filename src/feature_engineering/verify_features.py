import logging

import numpy as np
import pandas as pd

from src.feature_engineering.config import (
    PROCESSED_DATA_DIR,
    WINDOWS_DATA_DIR,
    FEATURES_DATA_DIR,
    INPUT_FILE_MAPPING,
    WINDOW_FILE_MAPPING,
    OUTPUT_FILE_MAPPING,
    FEATURE_COLUMNS,
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
# VERIFICATION FUNCTIONS
# ============================================================

def verify_schema(features_df: pd.DataFrame, dataset_name: str) -> None:
    """Verify exact output schema."""

    if list(features_df.columns) != OUTPUT_SCHEMA_COLUMNS:
        raise ValueError(
            f"{dataset_name}: Schema mismatch.\n"
            f"Expected: {OUTPUT_SCHEMA_COLUMNS}\n"
            f"Found: {list(features_df.columns)}"
        )

    logger.info(f"{dataset_name}: Schema validation passed.")


def verify_null_and_infinite_values(
    features_df: pd.DataFrame,
    dataset_name: str,
) -> None:
    """Verify no null or infinite values exist."""

    null_counts = features_df.isnull().sum()

    if null_counts.any():
        raise ValueError(
            f"{dataset_name}: Null values found:\n"
            f"{null_counts[null_counts > 0].to_dict()}"
        )

    for feature in FEATURE_COLUMNS:
        if not np.isfinite(features_df[feature]).all():
            raise ValueError(
                f"{dataset_name}: Non-finite values found in {feature}"
            )

    logger.info(
        f"{dataset_name}: Null/infinite validation passed."
    )


def verify_feature_ranges(
    features_df: pd.DataFrame,
    dataset_name: str,
) -> None:
    """Verify logical feature ranges."""

    non_negative_features = FEATURE_COLUMNS

    for feature in non_negative_features:
        if (features_df[feature] < 0).any():
            raise ValueError(
                f"{dataset_name}: Negative values found in {feature}"
            )

    ratio_features = [
        "short_flow_ratio",
        "tcp_flow_ratio",
        "syn_packet_ratio",
    ]

    for feature in ratio_features:

        invalid_values = (
            (features_df[feature] < 0)
            | (features_df[feature] > 1)
        )

        if invalid_values.any():
            raise ValueError(
                f"{dataset_name}: {feature} outside [0, 1]"
            )

    logger.info(
        f"{dataset_name}: Feature range validation passed."
    )


def verify_window_count(
    features_df: pd.DataFrame,
    windows_df: pd.DataFrame,
    dataset_name: str,
) -> None:
    """Verify feature rows match Phase 2.2 window rows."""

    if len(features_df) != len(windows_df):
        raise ValueError(
            f"{dataset_name}: Window count mismatch. "
            f"Features={len(features_df)}, "
            f"Windows={len(windows_df)}"
        )

    logger.info(
        f"{dataset_name}: Window count validation passed "
        f"({len(features_df):,} windows)."
    )


def verify_window_ids(
    features_df: pd.DataFrame,
    windows_df: pd.DataFrame,
    dataset_name: str,
) -> None:
    """Verify all window IDs match exactly."""

    feature_ids = set(features_df["window_id"])
    window_ids = set(windows_df["window_id"])

    if feature_ids != window_ids:
        raise ValueError(
            f"{dataset_name}: Window ID mismatch between "
            "features and Phase 2.2 windows."
        )

    logger.info(
        f"{dataset_name}: Window ID consistency passed."
    )


def verify_flow_accounting(
    features_df: pd.DataFrame,
    windows_df: pd.DataFrame,
    processed_df: pd.DataFrame,
    dataset_name: str,
) -> None:
    """
    Verify flow counts across all pipeline stages.
    """

    feature_flow_count = features_df["flow_count"].sum()

    window_flow_count = windows_df["flow_count"].sum()

    processed_flow_count = len(processed_df)

    if not (
        feature_flow_count
        == window_flow_count
        == processed_flow_count
    ):
        raise ValueError(
            f"{dataset_name}: Flow accounting mismatch.\n"
            f"Features: {feature_flow_count}\n"
            f"Windows: {window_flow_count}\n"
            f"Processed: {processed_flow_count}"
        )

    logger.info(
        f"{dataset_name}: Flow accounting passed "
        f"({feature_flow_count:,} flows)."
    )


def verify_duplicate_windows(
    features_df: pd.DataFrame,
    dataset_name: str,
) -> None:
    """Verify no duplicate window IDs."""

    duplicates = features_df["window_id"].duplicated().sum()

    if duplicates > 0:
        raise ValueError(
            f"{dataset_name}: Found {duplicates} duplicate window IDs."
        )

    logger.info(
        f"{dataset_name}: Duplicate window validation passed."
    )


def verify_empty_window_features(
    features_df: pd.DataFrame,
    dataset_name: str,
) -> None:
    """
    Verify EMPTY windows contain zero-valued features.
    """

    empty_windows = features_df[
        features_df["flow_count"] == 0
    ]

    if empty_windows.empty:
        logger.info(
            f"{dataset_name}: No EMPTY windows present."
        )
        return

    non_zero_features = FEATURE_COLUMNS

    for feature in non_zero_features:

        if (empty_windows[feature] != 0).any():
            raise ValueError(
                f"{dataset_name}: EMPTY windows contain "
                f"non-zero values in {feature}"
            )

    logger.info(
        f"{dataset_name}: EMPTY window feature validation passed."
    )


def log_feature_summary(
    features_df: pd.DataFrame,
    dataset_name: str,
) -> None:
    """Log compact descriptive statistics."""

    logger.info(
        f"{dataset_name}: Feature summary:"
    )

    summary = features_df[
        FEATURE_COLUMNS
    ].describe().loc[
        ["min", "mean", "max"]
    ]

    for feature in FEATURE_COLUMNS:

        logger.info(
            f"{feature}: "
            f"min={summary.loc['min', feature]:.4f}, "
            f"mean={summary.loc['mean', feature]:.4f}, "
            f"max={summary.loc['max', feature]:.4f}"
        )


# ============================================================
# PROCESS SINGLE DATASET
# ============================================================

def verify_dataset(dataset_name: str) -> None:
    """Verify one feature dataset."""

    logger.info(
        f"================================================"
    )

    logger.info(
        f"Verifying {dataset_name}..."
    )

    features_file = (
        FEATURES_DATA_DIR
        / OUTPUT_FILE_MAPPING[dataset_name]
    )

    windows_file = (
        WINDOWS_DATA_DIR
        / WINDOW_FILE_MAPPING[dataset_name]
    )

    processed_file = (
        PROCESSED_DATA_DIR
        / INPUT_FILE_MAPPING[dataset_name]
    )

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    features_df = pd.read_csv(
        features_file,
        low_memory=False,
    )

    windows_df = pd.read_csv(
        windows_file,
        low_memory=False,
    )

    # Only row count is required from processed data,
    # so load efficiently.
    processed_df = pd.read_csv(
        processed_file,
        usecols=["Flow ID"],
        low_memory=False,
    )

    # --------------------------------------------------------
    # Run validations
    # --------------------------------------------------------

    verify_schema(
        features_df,
        dataset_name,
    )

    verify_null_and_infinite_values(
        features_df,
        dataset_name,
    )

    verify_feature_ranges(
        features_df,
        dataset_name,
    )

    verify_window_count(
        features_df,
        windows_df,
        dataset_name,
    )

    verify_window_ids(
        features_df,
        windows_df,
        dataset_name,
    )

    verify_flow_accounting(
        features_df,
        windows_df,
        processed_df,
        dataset_name,
    )

    verify_duplicate_windows(
        features_df,
        dataset_name,
    )

    verify_empty_window_features(
        features_df,
        dataset_name,
    )

    log_feature_summary(
        features_df,
        dataset_name,
    )

    logger.info(
        f"{dataset_name}: ALL VERIFICATIONS PASSED."
    )


# ============================================================
# MASTER VERIFICATION PIPELINE
# ============================================================

def main():

    logger.info(
        "Starting NexThreat Phase 2.3 Feature Verification..."
    )

    for dataset_name in OUTPUT_FILE_MAPPING:

        verify_dataset(dataset_name)

    logger.info(
        "================================================"
    )

    logger.info(
        "PHASE 2.3 FEATURE VERIFICATION COMPLETED."
    )

    logger.info(
        "ALL DATASETS PASSED INDEPENDENT VALIDATION."
    )

    logger.info(
        "================================================"
    )


if __name__ == "__main__":
    main()