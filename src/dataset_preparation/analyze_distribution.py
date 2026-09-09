"""
NexThreat Phase 3.1A — Model Dataset Distribution Analysis Pipeline.

Analyzes the window-level label and attack category distribution across all 2,454
1-minute feature windows in data/features/ to establish an empirical basis for
subsequent train/validation/test splitting.
"""
import json
import logging
from pathlib import Path
import pandas as pd

from src.dataset_preparation.config import (
    FEATURES_DIR,
    METADATA_DIR,
    FEATURE_FILES,
    EXPECTED_TOTAL_WINDOWS,
    EXPECTED_DAILY_COUNTS,
    WINDOW_ID_COLUMN,
    ATTACK_CATEGORY_COLUMN,
    IS_ATTACK_COLUMN,
    SOURCE_IS_ATTACK_COLUMN,
    DATASET_DAY_COLUMN,
    REQUIRED_COLUMNS,
    RARE_CLASS_THRESHOLD,
    SPLIT_RATIOS,
    MIN_SPLIT_FEASIBLE,
    MIN_SUPERVISED_RECOMMENDED,
    BINARY_DISTRIBUTION_CSV,
    ATTACK_CATEGORY_DISTRIBUTION_CSV,
    DAILY_CATEGORY_DISTRIBUTION_CSV,
    RARE_CATEGORY_ANALYSIS_CSV,
    CATEGORY_TIMELINE_CSV,
    SPLIT_FEASIBILITY_CSV,
    DISTRIBUTION_SUMMARY_JSON,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def load_all_feature_datasets() -> pd.DataFrame:
    """
    Load all feature CSVs, validate file existence, map attack indicators,
    assign dataset_day, and concatenate chronologically into a master DataFrame.
    """
    dfs = []
    for day_name, filename in FEATURE_FILES.items():
        file_path = FEATURES_DIR / filename
        if not file_path.exists():
            raise FileNotFoundError(
                f"Required feature dataset not found: {file_path}"
            )

        logger.info(f"Loading {day_name} feature dataset...")
        day_df = pd.read_csv(file_path, low_memory=False)

        # Map is_attack_window to is_attack if not present
        if IS_ATTACK_COLUMN not in day_df.columns and SOURCE_IS_ATTACK_COLUMN in day_df.columns:
            day_df[IS_ATTACK_COLUMN] = day_df[SOURCE_IS_ATTACK_COLUMN]

        day_df[DATASET_DAY_COLUMN] = day_name
        logger.info(f"{day_name}: {len(day_df):,} windows loaded.")

        expected_count = EXPECTED_DAILY_COUNTS.get(day_name)
        if expected_count is not None and len(day_df) != expected_count:
            logger.warning(
                f"Unexpected window count for {day_name}: expected {expected_count}, got {len(day_df)}"
            )

        dfs.append(day_df)

    master_df = pd.concat(dfs, ignore_index=True)
    logger.info(f"Total windows loaded: {len(master_df):,}")
    return master_df


def validate_required_columns(df: pd.DataFrame) -> None:
    """
    Validate that all required columns exist, no duplicate windows exist,
    and total window count matches expectation.
    """
    missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_cols:
        raise ValueError(
            f"Missing required columns in combined dataset: {missing_cols}"
        )
    logger.info("Required columns validation passed.")

    # Validate duplicate dataset_day + window_id combinations
    duplicates = df.duplicated(subset=[DATASET_DAY_COLUMN, WINDOW_ID_COLUMN]).sum()
    if duplicates > 0:
        raise ValueError(
            f"Duplicate window validation failed: found {duplicates} duplicate "
            f"dataset_day + window_id combinations."
        )
    logger.info("Duplicate window validation passed.")

    # Validate expected total window count
    if len(df) != EXPECTED_TOTAL_WINDOWS:
        raise ValueError(
            f"Total window count mismatch: expected {EXPECTED_TOTAL_WINDOWS:,}, "
            f"found {len(df):,}."
        )
    logger.info(f"Total window count validation passed ({len(df):,} windows).")


def validate_label_consistency(df: pd.DataFrame) -> None:
    """
    Validate consistency between binary attack flag and categorical label:
      - is_attack == 0 must have attack_category == 'BENIGN'
      - is_attack == 1 must have attack_category != 'BENIGN'
    """
    inconsistent_benign = df[
        (df[IS_ATTACK_COLUMN] == 0) & (df[ATTACK_CATEGORY_COLUMN] != "BENIGN")
    ]
    inconsistent_attack = df[
        (df[IS_ATTACK_COLUMN] == 1) & (df[ATTACK_CATEGORY_COLUMN] == "BENIGN")
    ]

    total_inconsistent = len(inconsistent_benign) + len(inconsistent_attack)
    if total_inconsistent > 0:
        raise ValueError(
            f"Label consistency validation failed: {total_inconsistent} inconsistent windows found.\n"
            f"  - is_attack == 0 with non-BENIGN category: {len(inconsistent_benign)} windows\n"
            f"  - is_attack == 1 with BENIGN category: {len(inconsistent_attack)} windows"
        )
    logger.info("Label consistency validation passed.")


def analyze_binary_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze binary is_attack distribution (0 = BENIGN, 1 = ATTACK).
    """
    total_windows = len(df)
    counts = df[IS_ATTACK_COLUMN].value_counts().sort_index()

    binary_df = pd.DataFrame({
        "is_attack": counts.index.astype(int),
        "label": counts.index.map({0: "BENIGN", 1: "ATTACK"}),
        "window_count": counts.values.astype(int),
        "percentage": (counts.values / total_windows * 100).round(4),
    })
    return binary_df


def analyze_attack_categories(df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze multi-class attack_category distribution and flag rare classes.
    """
    total_windows = len(df)
    counts = df[ATTACK_CATEGORY_COLUMN].value_counts()

    cat_df = pd.DataFrame({
        "attack_category": counts.index.astype(str),
        "window_count": counts.values.astype(int),
        "percentage": (counts.values / total_windows * 100).round(4),
        "rare_class": counts.values < RARE_CLASS_THRESHOLD,
    })
    return cat_df


def analyze_daily_categories(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create cross-tabulation of attack categories across dataset days.
    """
    daily_df = pd.crosstab(
        df[DATASET_DAY_COLUMN],
        df[ATTACK_CATEGORY_COLUMN]
    )
    # Ensure chronological row order
    day_order = list(FEATURE_FILES.keys())
    daily_df = daily_df.reindex(day_order).fillna(0).astype(int)
    return daily_df


def analyze_rare_categories(category_distribution: pd.DataFrame) -> pd.DataFrame:
    """
    Filter rare categories (< RARE_CLASS_THRESHOLD) and provide actionable recommendations.
    """
    rare_df = category_distribution[category_distribution["rare_class"]].copy()
    rare_df["recommendation"] = (
        "Review for merging or exclusion from supervised classification"
    )
    return rare_df


def analyze_category_timeline(df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze the chronological occurrence range of each attack category.
    Preserves chronological order of appearance in the master dataset.
    """
    timeline_rows = []
    # Unique categories in chronological order of first appearance
    categories = df[ATTACK_CATEGORY_COLUMN].drop_duplicates().tolist()

    for cat in categories:
        cat_df = df[df[ATTACK_CATEGORY_COLUMN] == cat]
        first_row = cat_df.iloc[0]
        last_row = cat_df.iloc[-1]
        timeline_rows.append({
            "attack_category": cat,
            "window_count": int(len(cat_df)),
            "first_day": first_row[DATASET_DAY_COLUMN],
            "last_day": last_row[DATASET_DAY_COLUMN],
            "first_window_id": first_row[WINDOW_ID_COLUMN],
            "last_window_id": last_row[WINDOW_ID_COLUMN],
        })

    timeline_df = pd.DataFrame(timeline_rows)
    return timeline_df


def analyze_split_feasibility(category_distribution: pd.DataFrame) -> pd.DataFrame:
    """
    Estimate 70/15/15 train/validation/test sample allocation per category.

    Separate mathematical feasibility from practical supervised learning viability:
      - split_feasible = True if train >= 1, val >= 1, test >= 1
      - recommended_for_supervised_learning = True if train >= 10, val >= 2, test >= 2
    """
    rows = []
    for _, row in category_distribution.iterrows():
        cat = row["attack_category"]
        count = int(row["window_count"])

        train = int(round(count * SPLIT_RATIOS["train"]))
        val = int(round(count * SPLIT_RATIOS["validation"]))
        test = count - train - val

        split_feasible = (
            train >= MIN_SPLIT_FEASIBLE["train"]
            and val >= MIN_SPLIT_FEASIBLE["validation"]
            and test >= MIN_SPLIT_FEASIBLE["test"]
        )

        recommended_for_supervised = (
            train >= MIN_SUPERVISED_RECOMMENDED["train"]
            and val >= MIN_SUPERVISED_RECOMMENDED["validation"]
            and test >= MIN_SUPERVISED_RECOMMENDED["test"]
        )

        rows.append({
            "attack_category": cat,
            "window_count": count,
            "estimated_train": train,
            "estimated_validation": val,
            "estimated_test": test,
            "split_feasible": split_feasible,
            "recommended_for_supervised_learning": recommended_for_supervised,
        })

    feasibility_df = pd.DataFrame(rows)
    return feasibility_df


def generate_distribution_summary_json(
    df: pd.DataFrame,
    category_distribution: pd.DataFrame,
    rare_df: pd.DataFrame,
    feasibility_df: pd.DataFrame,
) -> dict:
    """
    Generate comprehensive JSON summary containing key dataset metrics.
    """
    total_windows = int(len(df))
    benign_windows = int((df[IS_ATTACK_COLUMN] == 0).sum())
    attack_windows = int((df[IS_ATTACK_COLUMN] == 1).sum())

    # Attack categories excluding BENIGN
    attack_cats = (
        df[df[IS_ATTACK_COLUMN] == 1][ATTACK_CATEGORY_COLUMN]
        .unique()
        .tolist()
    )

    rare_categories = rare_df["attack_category"].tolist()

    feasible_categories = feasibility_df[
        feasibility_df["split_feasible"]
    ]["attack_category"].tolist()

    not_feasible_categories = feasibility_df[
        ~feasibility_df["split_feasible"]
    ]["attack_category"].tolist()

    recommended_categories = feasibility_df[
        feasibility_df["recommended_for_supervised_learning"]
    ]["attack_category"].tolist()

    not_recommended_categories = feasibility_df[
        ~feasibility_df["recommended_for_supervised_learning"]
    ]["attack_category"].tolist()

    summary = {
        "total_windows": total_windows,
        "benign_windows": benign_windows,
        "attack_windows": attack_windows,
        "total_attack_categories": len(attack_cats),
        "total_categories": int(df[ATTACK_CATEGORY_COLUMN].nunique()),
        "rare_class_threshold": RARE_CLASS_THRESHOLD,
        "rare_categories": rare_categories,
        "categories_feasible_for_70_15_15_split": feasible_categories,
        "categories_not_feasible_for_70_15_15_split": not_feasible_categories,
        "categories_recommended_for_supervised_learning": recommended_categories,
        "categories_not_recommended_for_supervised_learning": not_recommended_categories,
    }
    return summary


def save_metadata_artifacts(
    binary_df: pd.DataFrame,
    category_df: pd.DataFrame,
    daily_df: pd.DataFrame,
    rare_df: pd.DataFrame,
    timeline_df: pd.DataFrame,
    feasibility_df: pd.DataFrame,
    summary_dict: dict,
) -> None:
    """
    Save all generated metadata CSV tables and JSON summary.
    """
    METADATA_DIR.mkdir(parents=True, exist_ok=True)

    binary_path = METADATA_DIR / BINARY_DISTRIBUTION_CSV
    category_path = METADATA_DIR / ATTACK_CATEGORY_DISTRIBUTION_CSV
    daily_path = METADATA_DIR / DAILY_CATEGORY_DISTRIBUTION_CSV
    rare_path = METADATA_DIR / RARE_CATEGORY_ANALYSIS_CSV
    timeline_path = METADATA_DIR / CATEGORY_TIMELINE_CSV
    feasibility_path = METADATA_DIR / SPLIT_FEASIBILITY_CSV
    summary_path = METADATA_DIR / DISTRIBUTION_SUMMARY_JSON

    binary_df.to_csv(binary_path, index=False)
    category_df.to_csv(category_path, index=False)
    daily_df.to_csv(daily_path, index=True, index_label="dataset_day")
    rare_df.to_csv(rare_path, index=False)
    timeline_df.to_csv(timeline_path, index=False)
    feasibility_df.to_csv(feasibility_path, index=False)

    with open(summary_path, "w") as f:
        json.dump(summary_dict, f, indent=4)

    logger.info(f"Saved binary distribution to: {binary_path}")
    logger.info(f"Saved category distribution to: {category_path}")
    logger.info(f"Saved daily distribution to: {daily_path}")
    logger.info(f"Saved rare category analysis to: {rare_path}")
    logger.info(f"Saved category timeline to: {timeline_path}")
    logger.info(f"Saved split feasibility analysis to: {feasibility_path}")
    logger.info(f"Saved distribution summary to: {summary_path}")


def main() -> None:
    """
    Execute the Phase 3.1A distribution analysis pipeline.
    """
    logger.info("Starting NexThreat Phase 3.1A Model Dataset Distribution Analysis")

    # 1. Load all feature datasets
    master_df = load_all_feature_datasets()

    # 2. Validate required columns and uniqueness
    validate_required_columns(master_df)

    # 3. Validate label consistency
    validate_label_consistency(master_df)

    # 4. Analyze binary distribution
    binary_df = analyze_binary_distribution(master_df)
    logger.info("\n=== BINARY DISTRIBUTION ===")
    logger.info("\n" + binary_df.to_string(index=False))

    # 5. Analyze attack category distribution
    category_df = analyze_attack_categories(master_df)
    logger.info("\n=== ATTACK CATEGORY DISTRIBUTION ===")
    logger.info("\n" + category_df.to_string(index=False))

    # 6. Analyze daily categories
    daily_df = analyze_daily_categories(master_df)
    logger.info("\n=== DAILY CATEGORY DISTRIBUTION ===")
    logger.info("\n" + daily_df.to_string())

    # 7. Analyze rare categories
    rare_df = analyze_rare_categories(category_df)
    logger.info("\n=== RARE CATEGORY ANALYSIS ===")
    logger.info("\n" + rare_df.to_string(index=False))

    # 8. Analyze category timeline
    timeline_df = analyze_category_timeline(master_df)
    logger.info("\n=== CATEGORY TIMELINE ===")
    logger.info("\n" + timeline_df.to_string(index=False))

    # 9. Analyze future split feasibility
    feasibility_df = analyze_split_feasibility(category_df)
    logger.info("\n=== SPLIT FEASIBILITY ANALYSIS ===")
    logger.info("\n" + feasibility_df.to_string(index=False))

    # 10. Generate summary JSON
    summary_dict = generate_distribution_summary_json(
        master_df, category_df, rare_df, feasibility_df
    )

    # 11. Save all artifacts
    save_metadata_artifacts(
        binary_df,
        category_df,
        daily_df,
        rare_df,
        timeline_df,
        feasibility_df,
        summary_dict,
    )

    logger.info("Phase 3.1A analysis completed successfully.")


if __name__ == "__main__":
    main()
