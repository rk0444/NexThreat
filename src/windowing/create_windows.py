"""
NexThreat Phase 2.2 — 1-Minute Chronological Window Creation Pipeline.

Converts individual preprocessed CICIDS2017 flow datasets into fixed,
non-overlapping, chronological 1-minute tumbling windows.
"""
import logging
from pathlib import Path
import numpy as np
import pandas as pd

from src.windowing.config import (
    WINDOWS_DATA_DIR,
    PROCESSED_DATA_DIR,
    WINDOW_SIZE,
    TIMESTAMP_COLUMN,
    LABEL_COLUMN,
    FLOW_CATEGORY_COLUMN,
    REQUIRED_COLUMNS,
    INPUT_FILE_MAPPING,
    OUTPUT_FILE_MAPPING,
    WINDOW_SCHEMA_COLUMNS,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def load_processed_dataset(filepath: Path) -> pd.DataFrame:
    """Load preprocessed CSV dataset."""
    if not filepath.exists():
        raise FileNotFoundError(f"Input processed dataset not found: {filepath}")
    logger.info(f"Loading dataset from {filepath}")
    df = pd.read_csv(filepath)
    logger.info(f"Loaded {len(df):,} flows from {filepath.name}")
    return df


def validate_input_dataframe(df: pd.DataFrame, filepath: Path) -> None:
    """Validate required columns and labels of input DataFrame."""
    if df.empty:
        raise ValueError(f"Input dataset is empty: {filepath}")

    missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required columns {missing_cols} in {filepath}")

    # Verify that 'EMPTY' does not exist as an input flow label
    flow_categories = df[FLOW_CATEGORY_COLUMN].astype(str).str.strip()
    flow_labels = df[LABEL_COLUMN].astype(str).str.strip()
    if (flow_categories == "EMPTY").any() or (flow_labels == "EMPTY").any():
        raise ValueError(
            f"Invalid flow label 'EMPTY' detected in {filepath}. "
            f"'EMPTY' is reserved for zero-traffic windows only."
        )


def prepare_timestamps(df: pd.DataFrame, dataset_name: str) -> pd.DataFrame:
    """
    Parse Timestamp column, validate for NaT values, and sort chronologically.
    """
    df[TIMESTAMP_COLUMN] = pd.to_datetime(df[TIMESTAMP_COLUMN], errors="coerce")

    invalid_count = df[TIMESTAMP_COLUMN].isna().sum()
    if invalid_count > 0:
        raise ValueError(
            f"Found {invalid_count} invalid timestamps in {dataset_name} dataset."
        )

    # Sort chronologically
    df = df.sort_values(by=TIMESTAMP_COLUMN).reset_index(drop=True)
    return df


def assign_windows(df: pd.DataFrame) -> pd.DataFrame:
    """
    Assign fixed 1-minute tumbling window start boundary to each flow.
    """
    df["window_start_dt"] = df[TIMESTAMP_COLUMN].dt.floor(WINDOW_SIZE)
    return df


def calculate_window_statistics(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate flow_count, benign_flow_count, and attack_flow_count per window.
    """
    is_benign = df[FLOW_CATEGORY_COLUMN].astype(str).str.strip() == "BENIGN"

    grouped = df.groupby("window_start_dt")
    stats_df = pd.DataFrame({
        "flow_count": grouped.size(),
        "benign_flow_count": df[is_benign].groupby(df["window_start_dt"]).size(),
        "attack_flow_count": df[~is_benign].groupby(df["window_start_dt"]).size()
    }).fillna(0).reset_index()

    stats_df["flow_count"] = stats_df["flow_count"].astype(int)
    stats_df["benign_flow_count"] = stats_df["benign_flow_count"].astype(int)
    stats_df["attack_flow_count"] = stats_df["attack_flow_count"].astype(int)

    return stats_df


def determine_window_attack_labels(df: pd.DataFrame) -> pd.DataFrame:
    """
    Determine dominant attack category and present categories for attack windows.

    Rules applied:
    - Operates only on a copied attack-flow DataFrame.
    - BENIGN flows are completely excluded.
    - Heartbleed is mapped to 'ATTACK' for window-level aggregation.
    - Dominant category tie-breaker:
        1. Highest attack flow count
        2. Alphabetical order of attack category name
    - attack_categories_present: unique attack categories sorted alphabetically, joined by '|'.
    """
    is_attack = df[FLOW_CATEGORY_COLUMN].astype(str).str.strip() != "BENIGN"
    attack_df = df[is_attack].copy()

    if attack_df.empty:
        return pd.DataFrame(
            columns=["window_start_dt", "dominant_attack_category", "attack_categories_present"]
        )

    # Map Heartbleed -> ATTACK only on copied window aggregation dataframe
    attack_df["mapped_category"] = (
        attack_df[FLOW_CATEGORY_COLUMN]
        .astype(str)
        .str.strip()
        .replace({"Heartbleed": "ATTACK"})
    )

    # 1. Calculate category frequency per window
    cat_counts = (
        attack_df.groupby(["window_start_dt", "mapped_category"])
        .size()
        .reset_index(name="cat_flow_count")
    )

    # Tie-breaking:
    # Primary: Highest flow count descending
    # Secondary: Category name ascending (alphabetical order)
    cat_counts = cat_counts.sort_values(
        by=["cat_flow_count", "mapped_category"],
        ascending=[False, True]
    )

    # Dominant attack category is the first entry per window_start_dt
    dominant_df = cat_counts.drop_duplicates(
        subset=["window_start_dt"], keep="first"
    )[["window_start_dt", "mapped_category"]].rename(
        columns={"mapped_category": "dominant_attack_category"}
    )

    # 2. Attack categories present: unique, sorted alphabetically, joined with '|'
    present_series = (
        attack_df.groupby("window_start_dt")["mapped_category"]
        .unique()
        .apply(lambda cats: "|".join(sorted(cats)))
        .reset_index(name="attack_categories_present")
    )

    # Merge dominant category and categories present
    attack_labels_df = pd.merge(
        dominant_df, present_series, on="window_start_dt", how="inner"
    )
    return attack_labels_df


def generate_complete_timeline(
    first_window: pd.Timestamp, last_window: pd.Timestamp
) -> pd.DataFrame:
    """
    Generate a continuous 1-minute datetime range between first_window and last_window.
    """
    timeline = pd.date_range(start=first_window, end=last_window, freq=WINDOW_SIZE)
    return pd.DataFrame({"window_start_dt": timeline})


def assemble_window_dataset(
    timeline_df: pd.DataFrame,
    stats_df: pd.DataFrame,
    attack_labels_df: pd.DataFrame
) -> pd.DataFrame:
    """
    Merge timeline with traffic statistics and attack labels, apply 3-state logic,
    format metadata columns, and reorder to standard schema.
    """
    # Left join timeline with traffic statistics
    merged = pd.merge(timeline_df, stats_df, on="window_start_dt", how="left")

    # Left join with attack labels
    merged = pd.merge(merged, attack_labels_df, on="window_start_dt", how="left")

    # Fill traffic counts for empty windows
    merged["flow_count"] = merged["flow_count"].fillna(0).astype(int)
    merged["benign_flow_count"] = merged["benign_flow_count"].fillna(0).astype(int)
    merged["attack_flow_count"] = merged["attack_flow_count"].fillna(0).astype(int)

    # Define the 3 distinct states: EMPTY, BENIGN, ATTACK
    is_empty = merged["flow_count"] == 0
    is_benign = (merged["flow_count"] > 0) & (merged["attack_flow_count"] == 0)
    is_attack = merged["attack_flow_count"] > 0

    # Initialize output columns
    merged["is_attack_window"] = 0
    merged["attack_category"] = "EMPTY"
    merged["attack_ratio"] = 0.0

    # CASE 1: EMPTY WINDOW
    merged.loc[is_empty, "attack_categories_present"] = "EMPTY"

    # CASE 2: BENIGN WINDOW
    merged.loc[is_benign, "is_attack_window"] = 0
    merged.loc[is_benign, "attack_category"] = "BENIGN"
    merged.loc[is_benign, "attack_categories_present"] = "BENIGN"
    merged.loc[is_benign, "attack_ratio"] = 0.0

    # CASE 3: ATTACK WINDOW
    merged.loc[is_attack, "is_attack_window"] = 1
    merged.loc[is_attack, "attack_category"] = merged.loc[is_attack, "dominant_attack_category"]
    # attack_categories_present was populated during left-join with attack_labels_df
    merged.loc[is_attack, "attack_ratio"] = (
        merged.loc[is_attack, "attack_flow_count"] / merged.loc[is_attack, "flow_count"]
    )

    # Metadata columns
    merged["window_id"] = merged["window_start_dt"].dt.strftime("%Y%m%d_%H%M")
    merged["window_start"] = merged["window_start_dt"].dt.strftime("%Y-%m-%d %H:%M:%S")
    merged["window_end"] = (
        merged["window_start_dt"] + pd.Timedelta(seconds=59)
    ).dt.strftime("%Y-%m-%d %H:%M:%S")
    merged["date"] = merged["window_start_dt"].dt.strftime("%Y-%m-%d")
    merged["day_name"] = merged["window_start_dt"].dt.strftime("%A")
    merged["window_index"] = np.arange(len(merged), dtype=int)

    # Explicit type casting
    merged["flow_count"] = merged["flow_count"].astype(int)
    merged["benign_flow_count"] = merged["benign_flow_count"].astype(int)
    merged["attack_flow_count"] = merged["attack_flow_count"].astype(int)
    merged["is_attack_window"] = merged["is_attack_window"].astype(int)
    merged["window_index"] = merged["window_index"].astype(int)
    merged["attack_ratio"] = merged["attack_ratio"].astype(float)

    # Select and reorder columns according to WINDOW_SCHEMA_COLUMNS
    output_df = merged[WINDOW_SCHEMA_COLUMNS].copy()
    return output_df


def validate_window_output(
    windows_df: pd.DataFrame,
    original_df: pd.DataFrame,
    dataset_name: str
) -> None:
    """
    Run comprehensive validation suite on output windows DataFrame.
    """
    logger.info(f"Running validation checks for {dataset_name}...")

    # 1. No NaN / Null values
    null_counts = windows_df.isnull().sum()
    if null_counts.any():
        raise ValueError(
            f"Validation failed: Output contains null values in {dataset_name}:\n{null_counts[null_counts > 0]}"
        )

    # 2. Schema and column order
    if list(windows_df.columns) != WINDOW_SCHEMA_COLUMNS:
        raise ValueError(
            f"Validation failed: Column schema mismatch in {dataset_name}.\n"
            f"Expected: {WINDOW_SCHEMA_COLUMNS}\nFound: {list(windows_df.columns)}"
        )

    # 3. Flow accounting
    total_window_flows = windows_df["flow_count"].sum()
    original_flow_count = len(original_df)
    if total_window_flows != original_flow_count:
        raise ValueError(
            f"Flow accounting validation failed for {dataset_name}: "
            f"sum(flow_count)={total_window_flows} != original={original_flow_count}"
        )

    # 4. Attack accounting
    orig_is_attack = original_df[FLOW_CATEGORY_COLUMN].astype(str).str.strip() != "BENIGN"
    original_attack_count = orig_is_attack.sum()
    total_window_attacks = windows_df["attack_flow_count"].sum()
    if total_window_attacks != original_attack_count:
        raise ValueError(
            f"Attack accounting validation failed for {dataset_name}: "
            f"sum(attack_flow_count)={total_window_attacks} != original={original_attack_count}"
        )

    # 5. Benign accounting & sum integrity
    original_benign_count = (~orig_is_attack).sum()
    total_window_benign = windows_df["benign_flow_count"].sum()
    if total_window_benign != original_benign_count:
        raise ValueError(
            f"Benign accounting validation failed for {dataset_name}: "
            f"sum(benign_flow_count)={total_window_benign} != original={original_benign_count}"
        )
    if not (windows_df["flow_count"] == windows_df["benign_flow_count"] + windows_df["attack_flow_count"]).all():
        raise ValueError(f"Flow sum integrity failed for {dataset_name}: flow_count != benign + attack")

    # 6. Timeline continuity (every consecutive window must differ by exactly 1 minute)
    starts = pd.to_datetime(windows_df["window_start"])
    if len(windows_df) > 1:
        step_diffs = starts.diff().iloc[1:]
        if not (step_diffs == pd.Timedelta(minutes=1)).all():
            raise ValueError(
                f"Timeline continuity validation failed for {dataset_name}: "
                f"Non 1-minute steps detected."
            )

    # 7. Window count validation
    first_window = starts.iloc[0]
    last_window = starts.iloc[-1]
    expected_window_count = int((last_window - first_window).total_seconds() / 60) + 1
    if len(windows_df) != expected_window_count:
        raise ValueError(
            f"Window count validation failed for {dataset_name}: "
            f"len={len(windows_df)} != expected={expected_window_count}"
        )

    # 8. Window index validation (starts at 0, strictly consecutive)
    if not (windows_df["window_index"].values == np.arange(len(windows_df))).all():
        raise ValueError(f"Window index validation failed for {dataset_name}.")

    # 9. EMPTY window validation
    empty_mask = windows_df["flow_count"] == 0
    if empty_mask.any():
        empty_rows = windows_df[empty_mask]
        if not (
            (empty_rows["attack_category"] == "EMPTY").all() and
            (empty_rows["attack_categories_present"] == "EMPTY").all() and
            (empty_rows["is_attack_window"] == 0).all() and
            (empty_rows["attack_ratio"] == 0.0).all() and
            (empty_rows["benign_flow_count"] == 0).all() and
            (empty_rows["attack_flow_count"] == 0).all()
        ):
            raise ValueError(f"EMPTY window validation failed for {dataset_name}.")

    # 10. BENIGN window validation
    benign_mask = (windows_df["flow_count"] > 0) & (windows_df["attack_flow_count"] == 0)
    if benign_mask.any():
        benign_rows = windows_df[benign_mask]
        if not (
            (benign_rows["attack_category"] == "BENIGN").all() and
            (benign_rows["attack_categories_present"] == "BENIGN").all() and
            (benign_rows["is_attack_window"] == 0).all() and
            (benign_rows["attack_ratio"] == 0.0).all()
        ):
            raise ValueError(f"BENIGN window validation failed for {dataset_name}.")

    # 11. ATTACK window validation
    attack_mask = windows_df["attack_flow_count"] > 0
    if attack_mask.any():
        attack_rows = windows_df[attack_mask]
        if not (
            (attack_rows["attack_category"] != "EMPTY").all() and
            (attack_rows["attack_category"] != "BENIGN").all() and
            (attack_rows["attack_categories_present"] != "EMPTY").all() and
            (attack_rows["attack_categories_present"] != "BENIGN").all() and
            (attack_rows["is_attack_window"] == 1).all()
        ):
            raise ValueError(f"ATTACK window validation failed for {dataset_name}.")

    # 12. Attack ratio bounds
    if not ((windows_df["attack_ratio"] >= 0.0).all() and (windows_df["attack_ratio"] <= 1.0).all()):
        raise ValueError(f"Attack ratio bounds validation failed for {dataset_name}.")

    logger.info(f"All validation checks passed successfully for {dataset_name}.")


def save_windows(df: pd.DataFrame, filepath: Path) -> None:
    """Save processed window DataFrame to CSV without index."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(filepath, index=False)
    logger.info(f"Saved output: {filepath}")


def process_single_dataset(
    dataset_name: str, input_filename: str, output_filename: str
) -> None:
    """Execute the full 1-minute window creation pipeline for a single dataset."""
    input_filepath = PROCESSED_DATA_DIR / input_filename
    output_filepath = WINDOWS_DATA_DIR / output_filename

    logger.info(f"--- Starting window creation for {dataset_name} ({input_filename}) ---")

    # 1. Load dataset
    df = load_processed_dataset(input_filepath)

    # 2. Validate input DataFrame
    validate_input_dataframe(df, input_filepath)

    # 3. Parse and validate timestamps
    df = prepare_timestamps(df, dataset_name)
    logger.info(
        f"Timestamp range: {df[TIMESTAMP_COLUMN].min()} to {df[TIMESTAMP_COLUMN].max()}"
    )

    # 4. Assign window start
    df = assign_windows(df)

    # 5. Calculate window statistics
    logger.info("Aggregating flows into 1-minute windows...")
    stats_df = calculate_window_statistics(df)

    # 6. Determine dominant attack category and present categories
    attack_labels_df = determine_window_attack_labels(df)

    # 7. Generate complete 1-minute timeline
    first_window = df["window_start_dt"].min()
    last_window = df["window_start_dt"].max()
    timeline_df = generate_complete_timeline(first_window, last_window)
    logger.info(f"Generated complete timeline with {len(timeline_df):,} windows")

    # 8. Assemble full window dataset
    windows_df = assemble_window_dataset(timeline_df, stats_df, attack_labels_df)

    # Window state distribution metrics
    empty_count = (windows_df["flow_count"] == 0).sum()
    benign_count = ((windows_df["flow_count"] > 0) & (windows_df["attack_flow_count"] == 0)).sum()
    attack_count = (windows_df["attack_flow_count"] > 0).sum()

    logger.info(f"Empty windows created: {empty_count:,}")
    logger.info(f"Benign windows: {benign_count:,}")
    logger.info(f"Attack windows: {attack_count:,}")

    # 9. Run comprehensive validations
    validate_window_output(windows_df, df, dataset_name)

    # 10. Save CSV output
    save_windows(windows_df, output_filepath)
    logger.info(f"--- Completed window creation for {dataset_name} ---\n")


def main() -> None:
    """Execute the Phase 2.2 pipeline across all datasets."""
    logger.info("Starting NexThreat Phase 2.2 window creation pipeline...")

    # Ensure windows output directory exists
    WINDOWS_DATA_DIR.mkdir(parents=True, exist_ok=True)

    for dataset_name, input_filename in INPUT_FILE_MAPPING.items():
        output_filename = OUTPUT_FILE_MAPPING[dataset_name]
        try:
            process_single_dataset(dataset_name, input_filename, output_filename)
        except Exception as e:
            logger.error(
                f"Window creation failed for {dataset_name} ({input_filename}): {e}",
                exc_info=True
            )
            raise

    logger.info("Phase 2.2 completed successfully.")


if __name__ == "__main__":
    main()
