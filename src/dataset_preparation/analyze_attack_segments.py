"""
NexThreat Phase 3.1B — Chronological Attack Segment Analysis Pipeline.

Analyzes the chronological distribution of attack windows and BENIGN intervals
across all five CICIDS2017 dataset days to assess segment continuity, candidate
split boundary intersections, and class representation under naive chronological splits.
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
    ATTACK_SEGMENTS_CSV,
    BENIGN_GAPS_CSV,
    ATTACK_CATEGORY_SEGMENT_SUMMARY_CSV,
    PER_DAY_SPLIT_BOUNDARIES_CSV,
    PER_DAY_SPLIT_CATEGORY_COVERAGE_CSV,
    PER_DAY_SPLIT_CATEGORY_SUMMARY_CSV,
    GLOBAL_SPLIT_CATEGORY_COVERAGE_CSV,
    SPLIT_STRATEGY_RISK_ANALYSIS_CSV,
    ATTACK_SEGMENT_SUMMARY_JSON,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def load_feature_datasets() -> dict[str, pd.DataFrame]:
    """
    Load all five daily feature datasets independently, preserve chronological order,
    normalize attack indicator columns, assign 1-indexed day_position and global_position,
    and validate daily and total window counts.
    """
    daily_dfs: dict[str, pd.DataFrame] = {}
    global_pos = 1

    for day_name, filename in FEATURE_FILES.items():
        file_path = FEATURES_DIR / filename
        if not file_path.exists():
            raise FileNotFoundError(f"Required feature dataset not found: {file_path}")

        logger.info(f"Loading {day_name} feature dataset...")
        df = pd.read_csv(file_path, low_memory=False)

        # Normalize is_attack_window to is_attack if necessary
        if IS_ATTACK_COLUMN not in df.columns and SOURCE_IS_ATTACK_COLUMN in df.columns:
            df[IS_ATTACK_COLUMN] = df[SOURCE_IS_ATTACK_COLUMN]

        df[DATASET_DAY_COLUMN] = day_name

        # Validate expected daily count
        expected_count = EXPECTED_DAILY_COUNTS.get(day_name)
        if expected_count is not None and len(df) != expected_count:
            raise ValueError(
                f"Window count mismatch for {day_name}: expected {expected_count}, got {len(df)}"
            )

        # Assign positions
        df["day_position"] = range(1, len(df) + 1)
        df["global_position"] = range(global_pos, global_pos + len(df))
        global_pos += len(df)

        logger.info(f"{day_name}: {len(df):,} windows loaded.")
        daily_dfs[day_name] = df

    total_loaded = sum(len(df) for df in daily_dfs.values())
    if total_loaded != EXPECTED_TOTAL_WINDOWS:
        raise ValueError(
            f"Total window count mismatch: expected {EXPECTED_TOTAL_WINDOWS}, got {total_loaded}"
        )
    logger.info(f"Total windows loaded across all days: {total_loaded:,}")
    return daily_dfs


def validate_chronological_data(daily_dfs: dict[str, pd.DataFrame]) -> None:
    """
    Validate data integrity, uniqueness, and label consistency within each day.
    """
    for day_name, df in daily_dfs.items():
        # 1. Required columns
        missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
        if missing:
            raise ValueError(f"{day_name} is missing required columns: {missing}")

        # 2. No duplicate window IDs within day
        dups = df[WINDOW_ID_COLUMN].duplicated().sum()
        if dups > 0:
            raise ValueError(f"{day_name} contains {dups} duplicate window IDs.")

        # 3. No null values in attack_category or is_attack
        if df[ATTACK_CATEGORY_COLUMN].isnull().any():
            raise ValueError(f"{day_name} contains null values in '{ATTACK_CATEGORY_COLUMN}'.")
        if df[IS_ATTACK_COLUMN].isnull().any():
            raise ValueError(f"{day_name} contains null values in '{IS_ATTACK_COLUMN}'.")

        # 4. is_attack binary values (0 or 1)
        valid_binary = df[IS_ATTACK_COLUMN].isin([0, 1]).all()
        if not valid_binary:
            raise ValueError(f"{day_name} contains invalid non-binary values in '{IS_ATTACK_COLUMN}'.")

        # 5. Strict label consistency
        inconsistent_benign = df[(df[IS_ATTACK_COLUMN] == 0) & (df[ATTACK_CATEGORY_COLUMN] != "BENIGN")]
        inconsistent_attack = df[(df[IS_ATTACK_COLUMN] == 1) & (df[ATTACK_CATEGORY_COLUMN] == "BENIGN")]
        total_inconsistent = len(inconsistent_benign) + len(inconsistent_attack)
        if total_inconsistent > 0:
            raise ValueError(
                f"{day_name} label consistency failed: {total_inconsistent} inconsistent windows found."
            )

    logger.info("Chronological and label consistency validation passed for all days.")


def analyze_attack_segments(day_df: pd.DataFrame, dataset_day: str) -> list[dict]:
    """
    Identify contiguous blocks of identical non-BENIGN attack categories.
    A segment terminates when a BENIGN window appears or the attack category changes.
    """
    segments: list[dict] = []
    seg_idx = 1
    current: dict | None = None

    has_start_time = "window_start" in day_df.columns
    has_end_time = "window_end" in day_df.columns

    for _, row in day_df.iterrows():
        cat = str(row[ATTACK_CATEGORY_COLUMN]).strip()
        win_id = str(row[WINDOW_ID_COLUMN])
        day_pos = int(row["day_position"])
        glob_pos = int(row["global_position"])
        start_t = str(row["window_start"]) if has_start_time else ""
        end_t = str(row["window_end"]) if has_end_time else ""

        if cat != "BENIGN":
            if current is None:
                current = {
                    "dataset_day": dataset_day,
                    "segment_id": f"{dataset_day}_SEG_{seg_idx:03d}",
                    "attack_category": cat,
                    "start_window_id": win_id,
                    "end_window_id": win_id,
                    "day_start_position": day_pos,
                    "day_end_position": day_pos,
                    "global_start_position": glob_pos,
                    "global_end_position": glob_pos,
                    "window_count": 1,
                    "start_time": start_t,
                    "end_time": end_t,
                }
                seg_idx += 1
            elif current["attack_category"] == cat:
                current["end_window_id"] = win_id
                current["day_end_position"] = day_pos
                current["global_end_position"] = glob_pos
                current["window_count"] += 1
                current["end_time"] = end_t
            else:
                # Category changed without intervening BENIGN
                segments.append(current)
                current = {
                    "dataset_day": dataset_day,
                    "segment_id": f"{dataset_day}_SEG_{seg_idx:03d}",
                    "attack_category": cat,
                    "start_window_id": win_id,
                    "end_window_id": win_id,
                    "day_start_position": day_pos,
                    "day_end_position": day_pos,
                    "global_start_position": glob_pos,
                    "global_end_position": glob_pos,
                    "window_count": 1,
                    "start_time": start_t,
                    "end_time": end_t,
                }
                seg_idx += 1
        else:
            if current is not None:
                segments.append(current)
                current = None

    if current is not None:
        segments.append(current)

    return segments


def analyze_benign_gaps(
    day_df: pd.DataFrame, dataset_day: str, segments: list[dict]
) -> list[dict]:
    """
    Identify all BENIGN intervals (leading, between_attacks, trailing, all_benign_day)
    ensuring every BENIGN window belongs to exactly one gap.
    """
    gaps: list[dict] = []
    gap_idx = 1
    has_start_time = "window_start" in day_df.columns
    has_end_time = "window_end" in day_df.columns

    # Case 1: Entire day contains no attacks (e.g. Monday)
    if not segments:
        first_row = day_df.iloc[0]
        last_row = day_df.iloc[-1]
        gaps.append({
            "dataset_day": dataset_day,
            "gap_id": f"{dataset_day}_GAP_{gap_idx:03d}",
            "gap_type": "all_benign_day",
            "start_window_id": str(first_row[WINDOW_ID_COLUMN]),
            "end_window_id": str(last_row[WINDOW_ID_COLUMN]),
            "global_start_position": int(first_row["global_position"]),
            "global_end_position": int(last_row["global_position"]),
            "window_count": len(day_df),
            "previous_attack_category": "None",
            "next_attack_category": "None",
            "start_time": str(first_row["window_start"]) if has_start_time else "",
            "end_time": str(last_row["window_end"]) if has_end_time else "",
        })
        return gaps

    # Case 2: Days with attacks
    # A. Leading gap before first attack segment
    first_seg = segments[0]
    if first_seg["day_start_position"] > 1:
        lead_df = day_df.iloc[0 : first_seg["day_start_position"] - 1]
        first_row = lead_df.iloc[0]
        last_row = lead_df.iloc[-1]
        gaps.append({
            "dataset_day": dataset_day,
            "gap_id": f"{dataset_day}_GAP_{gap_idx:03d}",
            "gap_type": "leading",
            "start_window_id": str(first_row[WINDOW_ID_COLUMN]),
            "end_window_id": str(last_row[WINDOW_ID_COLUMN]),
            "global_start_position": int(first_row["global_position"]),
            "global_end_position": int(last_row["global_position"]),
            "window_count": len(lead_df),
            "previous_attack_category": "None",
            "next_attack_category": first_seg["attack_category"],
            "start_time": str(first_row["window_start"]) if has_start_time else "",
            "end_time": str(last_row["window_end"]) if has_end_time else "",
        })
        gap_idx += 1

    # B. Gaps between consecutive attack segments
    for i in range(len(segments) - 1):
        s_curr = segments[i]
        s_next = segments[i + 1]
        if s_next["day_start_position"] > s_curr["day_end_position"] + 1:
            between_df = day_df.iloc[
                s_curr["day_end_position"] : s_next["day_start_position"] - 1
            ]
            first_row = between_df.iloc[0]
            last_row = between_df.iloc[-1]
            gaps.append({
                "dataset_day": dataset_day,
                "gap_id": f"{dataset_day}_GAP_{gap_idx:03d}",
                "gap_type": "between_attacks",
                "start_window_id": str(first_row[WINDOW_ID_COLUMN]),
                "end_window_id": str(last_row[WINDOW_ID_COLUMN]),
                "global_start_position": int(first_row["global_position"]),
                "global_end_position": int(last_row["global_position"]),
                "window_count": len(between_df),
                "previous_attack_category": s_curr["attack_category"],
                "next_attack_category": s_next["attack_category"],
                "start_time": str(first_row["window_start"]) if has_start_time else "",
                "end_time": str(last_row["window_end"]) if has_end_time else "",
            })
            gap_idx += 1

    # C. Trailing gap after last attack segment
    last_seg = segments[-1]
    if last_seg["day_end_position"] < len(day_df):
        trail_df = day_df.iloc[last_seg["day_end_position"] : len(day_df)]
        first_row = trail_df.iloc[0]
        last_row = trail_df.iloc[-1]
        gaps.append({
            "dataset_day": dataset_day,
            "gap_id": f"{dataset_day}_GAP_{gap_idx:03d}",
            "gap_type": "trailing",
            "start_window_id": str(first_row[WINDOW_ID_COLUMN]),
            "end_window_id": str(last_row[WINDOW_ID_COLUMN]),
            "global_start_position": int(first_row["global_position"]),
            "global_end_position": int(last_row["global_position"]),
            "window_count": len(trail_df),
            "previous_attack_category": last_seg["attack_category"],
            "next_attack_category": "None",
            "start_time": str(first_row["window_start"]) if has_start_time else "",
            "end_time": str(last_row["window_end"]) if has_end_time else "",
        })

    return gaps


def analyze_category_segments(segments_df: pd.DataFrame) -> pd.DataFrame:
    """
    Summarize segment metrics grouped by attack category (excluding BENIGN).
    """
    if segments_df.empty:
        return pd.DataFrame(columns=[
            "attack_category",
            "total_windows",
            "number_of_segments",
            "average_segment_length",
            "minimum_segment_length",
            "maximum_segment_length",
            "dataset_days_present",
        ])

    rows = []
    for cat, group in segments_df.groupby("attack_category"):
        days_present = "|".join(sorted(group["dataset_day"].unique()))
        total_wins = int(group["window_count"].sum())
        num_segs = int(len(group))
        avg_len = round(float(group["window_count"].mean()), 2)
        min_len = int(group["window_count"].min())
        max_len = int(group["window_count"].max())

        rows.append({
            "attack_category": cat,
            "total_windows": total_wins,
            "number_of_segments": num_segs,
            "average_segment_length": avg_len,
            "minimum_segment_length": min_len,
            "maximum_segment_length": max_len,
            "dataset_days_present": days_present,
        })

    summary_df = pd.DataFrame(rows)
    summary_df = summary_df.sort_values(by="total_windows", ascending=False).reset_index(drop=True)
    return summary_df


def analyze_per_day_split_boundaries(
    daily_dfs: dict[str, pd.DataFrame], segments_df: pd.DataFrame
) -> pd.DataFrame:
    """
    Simulate per-day 70/15/15 chronological split boundaries and determine if boundaries
    cut through an active attack segment: segment_start <= boundary_position < segment_end.
    """
    boundary_rows: list[dict] = []

    for day_name, df in daily_dfs.items():
        n = len(df)
        train_size = int(round(n * 0.70))
        val_size = int(round(n * 0.15))
        test_size = n - train_size - val_size

        train_start = 1
        train_end = train_size
        val_start = train_end + 1
        val_end = train_end + val_size
        test_start = val_end + 1
        test_end = n

        day_segments = (
            segments_df[segments_df["dataset_day"] == day_name]
            if not segments_df.empty
            else pd.DataFrame()
        )

        # Boundary 1: Train/Validation (boundary_position = train_end)
        b1_inside = False
        b1_seg_id = "None"
        b1_cat = "None"

        if not day_segments.empty:
            for _, seg in day_segments.iterrows():
                # segment_start <= boundary_position < segment_end
                if seg["day_start_position"] <= train_end < seg["day_end_position"]:
                    b1_inside = True
                    b1_seg_id = seg["segment_id"]
                    b1_cat = seg["attack_category"]
                    break

        boundary_rows.append({
            "dataset_day": day_name,
            "total_windows": n,
            "train_start": train_start,
            "train_end": train_end,
            "validation_start": val_start,
            "validation_end": val_end,
            "test_start": test_start,
            "test_end": test_end,
            "boundary_name": "Train/Validation",
            "boundary_position": train_end,
            "boundary_inside_attack_segment": b1_inside,
            "segment_id": b1_seg_id,
            "attack_category": b1_cat,
        })

        # Boundary 2: Validation/Test (boundary_position = val_end)
        b2_inside = False
        b2_seg_id = "None"
        b2_cat = "None"

        if not day_segments.empty:
            for _, seg in day_segments.iterrows():
                if seg["day_start_position"] <= val_end < seg["day_end_position"]:
                    b2_inside = True
                    b2_seg_id = seg["segment_id"]
                    b2_cat = seg["attack_category"]
                    break

        boundary_rows.append({
            "dataset_day": day_name,
            "total_windows": n,
            "train_start": train_start,
            "train_end": train_end,
            "validation_start": val_start,
            "validation_end": val_end,
            "test_start": test_start,
            "test_end": test_end,
            "boundary_name": "Validation/Test",
            "boundary_position": val_end,
            "boundary_inside_attack_segment": b2_inside,
            "segment_id": b2_seg_id,
            "attack_category": b2_cat,
        })

    return pd.DataFrame(boundary_rows)


def analyze_per_day_category_coverage(
    daily_dfs: dict[str, pd.DataFrame]
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Simulate per-day 70/15/15 chronological partition and evaluate category distribution
    across Train, Validation, and Test splits.
    """
    coverage_rows: list[dict] = []
    all_assigned_rows: list[dict] = []

    for day_name, df in daily_dfs.items():
        n = len(df)
        train_size = int(round(n * 0.70))
        val_size = int(round(n * 0.15))
        train_end = train_size
        val_end = train_end + val_size

        splits = []
        for pos in range(1, n + 1):
            if pos <= train_end:
                splits.append("TRAIN")
            elif pos <= val_end:
                splits.append("VALIDATION")
            else:
                splits.append("TEST")

        day_annotated = df.copy()
        day_annotated["split"] = splits

        for cat in sorted(day_annotated[ATTACK_CATEGORY_COLUMN].unique()):
            sub = day_annotated[day_annotated[ATTACK_CATEGORY_COLUMN] == cat]
            tr = int((sub["split"] == "TRAIN").sum())
            va = int((sub["split"] == "VALIDATION").sum())
            te = int((sub["split"] == "TEST").sum())

            coverage_rows.append({
                "dataset_day": day_name,
                "attack_category": cat,
                "train_windows": tr,
                "validation_windows": va,
                "test_windows": te,
            })

            all_assigned_rows.append({
                "dataset_day": day_name,
                "attack_category": cat,
                "train": tr,
                "validation": va,
                "test": te,
            })

    coverage_df = pd.DataFrame(coverage_rows)

    # Category-level summary across all days
    summary_rows: list[dict] = []
    assigned_df = pd.DataFrame(all_assigned_rows)

    all_categories = sorted(assigned_df["attack_category"].unique())
    # Order: BENIGN first, then other categories by total count descending
    totals_series = assigned_df.groupby("attack_category")[["train", "validation", "test"]].sum()
    totals_series["total"] = totals_series.sum(axis=1)

    # Sort categories: BENIGN first, then descending total
    def sort_key(cat_name):
        return (0 if cat_name == "BENIGN" else 1, -totals_series.loc[cat_name, "total"])

    sorted_cats = sorted(all_categories, key=sort_key)

    for cat in sorted_cats:
        cat_sub = assigned_df[assigned_df["attack_category"] == cat]
        days_present = "|".join(sorted(cat_sub["dataset_day"].unique()))
        tr_tot = int(cat_sub["train"].sum())
        va_tot = int(cat_sub["validation"].sum())
        te_tot = int(cat_sub["test"].sum())

        summary_rows.append({
            "attack_category": cat,
            "days_present": days_present,
            "train_total": tr_tot,
            "validation_total": va_tot,
            "test_total": te_tot,
            "missing_from_train": tr_tot == 0,
            "missing_from_validation": va_tot == 0,
            "missing_from_test": te_tot == 0,
        })

    summary_df = pd.DataFrame(summary_rows)
    return coverage_df, summary_df


def analyze_global_split_category_coverage(
    master_df: pd.DataFrame, segments_df: pd.DataFrame
) -> pd.DataFrame:
    """
    Simulate global chronological 70/15/15 split across all 2,454 windows.
    Train: 1..1718, Validation: 1719..2086, Test: 2087..2454.
    """
    total_windows = len(master_df)
    train_size = int(round(total_windows * 0.70))
    val_size = int(round(total_windows * 0.15))
    train_end = train_size
    val_end = train_end + val_size

    splits = []
    for pos in master_df["global_position"]:
        if pos <= train_end:
            splits.append("TRAIN")
        elif pos <= val_end:
            splits.append("VALIDATION")
        else:
            splits.append("TEST")

    master_annotated = master_df.copy()
    master_annotated["global_split"] = splits

    coverage_rows = []
    all_categories = sorted(master_annotated[ATTACK_CATEGORY_COLUMN].unique())

    # Sort categories: BENIGN first, then descending total count
    cat_counts = master_annotated[ATTACK_CATEGORY_COLUMN].value_counts()
    sorted_cats = sorted(
        all_categories,
        key=lambda c: (0 if c == "BENIGN" else 1, -cat_counts[c])
    )

    for cat in sorted_cats:
        sub = master_annotated[master_annotated[ATTACK_CATEGORY_COLUMN] == cat]
        tr = int((sub["global_split"] == "TRAIN").sum())
        va = int((sub["global_split"] == "VALIDATION").sum())
        te = int((sub["global_split"] == "TEST").sum())

        coverage_rows.append({
            "attack_category": cat,
            "train_windows": tr,
            "validation_windows": va,
            "test_windows": te,
            "missing_from_train": tr == 0,
            "missing_from_validation": va == 0,
            "missing_from_test": te == 0,
        })

    return pd.DataFrame(coverage_rows)


def compare_split_strategy_risks(
    global_coverage_df: pd.DataFrame,
    per_day_summary_df: pd.DataFrame,
    per_day_boundaries_df: pd.DataFrame,
    segments_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Construct programmatic risk matrix comparing Global Chronological 70/15/15
    vs Per-Day Chronological 70/15/15.
    """
    # 1. Global metrics
    global_missing_train = int(global_coverage_df["missing_from_train"].sum())
    global_missing_val = int(global_coverage_df["missing_from_validation"].sum())
    global_missing_test = int(global_coverage_df["missing_from_test"].sum())

    # Global boundary intersections (Train=1718, Val=2086)
    # Check if any segment has global_start <= 1718 < global_end or global_start <= 2086 < global_end
    global_cuts = 0
    if not segments_df.empty:
        for _, seg in segments_df.iterrows():
            if seg["global_start_position"] <= 1718 < seg["global_end_position"]:
                global_cuts += 1
            if seg["global_start_position"] <= 2086 < seg["global_end_position"]:
                global_cuts += 1

    # 2. Per-Day metrics
    per_day_missing_train = int(per_day_summary_df["missing_from_train"].sum())
    per_day_missing_val = int(per_day_summary_df["missing_from_validation"].sum())
    per_day_missing_test = int(per_day_summary_df["missing_from_test"].sum())
    per_day_cuts = int(per_day_boundaries_df["boundary_inside_attack_segment"].sum())

    risk_rows = [
        {
            "strategy": "Global Chronological 70/15/15",
            "categories_missing_from_train": global_missing_train,
            "categories_missing_from_validation": global_missing_val,
            "categories_missing_from_test": global_missing_test,
            "boundaries_inside_attack_segments": global_cuts,
            "attack_segment_fragmentation_count": global_cuts,
            "temporal_order_preserved": True,
            "cross_day_continuity_assumed": True,
            "rare_category_isolation_risk": "High (ATTACK is 100% in Train; Infiltration, Bot, PortScan, DDoS are 0% in Train)",
            "potential_temporal_leakage_risk": "Low within days, but assumes non-existent cross-day continuum",
        },
        {
            "strategy": "Per-Day Chronological 70/15/15",
            "categories_missing_from_train": per_day_missing_train,
            "categories_missing_from_validation": per_day_missing_val,
            "categories_missing_from_test": per_day_missing_test,
            "boundaries_inside_attack_segments": per_day_cuts,
            "attack_segment_fragmentation_count": per_day_cuts,
            "temporal_order_preserved": True,
            "cross_day_continuity_assumed": False,
            "rare_category_isolation_risk": "High (ATTACK is 100% in Val; DDoS is 100% in Test; DoS, Bot, Web Attack are 100% in Train)",
            "potential_temporal_leakage_risk": "Medium (Intraday attack bursts are sliced across Train/Val boundaries)",
        },
    ]

    return pd.DataFrame(risk_rows)


def generate_attack_segment_summary_json(
    daily_dfs: dict[str, pd.DataFrame],
    segments_df: pd.DataFrame,
    gaps_df: pd.DataFrame,
    category_summary_df: pd.DataFrame,
    per_day_boundaries_df: pd.DataFrame,
    per_day_summary_df: pd.DataFrame,
    global_coverage_df: pd.DataFrame,
    risk_df: pd.DataFrame,
) -> dict:
    """
    Generate comprehensive JSON summary documenting all findings of Phase 3.1B.
    """
    total_wins = sum(len(df) for df in daily_dfs.values())
    total_atk_wins = int(segments_df["window_count"].sum()) if not segments_df.empty else 0
    total_benign_wins = int(gaps_df["window_count"].sum()) if not gaps_df.empty else 0

    per_day_metrics = {}
    for day_name, df in daily_dfs.items():
        day_segs = segments_df[segments_df["dataset_day"] == day_name] if not segments_df.empty else pd.DataFrame()
        day_gaps = gaps_df[gaps_df["dataset_day"] == day_name] if not gaps_df.empty else pd.DataFrame()
        per_day_metrics[day_name] = {
            "total_windows": len(df),
            "attack_windows": int(day_segs["window_count"].sum()) if not day_segs.empty else 0,
            "benign_windows": int(day_gaps["window_count"].sum()) if not day_gaps.empty else 0,
            "attack_segments": len(day_segs),
            "benign_gaps": len(day_gaps),
            "categories_present": sorted(df[ATTACK_CATEGORY_COLUMN].unique()),
        }

    cat_segment_metrics = {}
    if not category_summary_df.empty:
        for _, row in category_summary_df.iterrows():
            cat_segment_metrics[row["attack_category"]] = {
                "total_windows": int(row["total_windows"]),
                "number_of_segments": int(row["number_of_segments"]),
                "average_segment_length": float(row["average_segment_length"]),
                "min_segment_length": int(row["minimum_segment_length"]),
                "max_segment_length": int(row["maximum_segment_length"]),
                "days_present": row["dataset_days_present"],
            }

    global_missing_train = global_coverage_df[global_coverage_df["missing_from_train"]]["attack_category"].tolist()
    global_missing_val = global_coverage_df[global_coverage_df["missing_from_validation"]]["attack_category"].tolist()
    global_missing_test = global_coverage_df[global_coverage_df["missing_from_test"]]["attack_category"].tolist()

    per_day_missing_train = per_day_summary_df[per_day_summary_df["missing_from_train"]]["attack_category"].tolist()
    per_day_missing_val = per_day_summary_df[per_day_summary_df["missing_from_validation"]]["attack_category"].tolist()
    per_day_missing_test = per_day_summary_df[per_day_summary_df["missing_from_test"]]["attack_category"].tolist()

    summary = {
        "total_windows": total_wins,
        "total_attack_windows": total_atk_wins,
        "total_benign_windows": total_benign_wins,
        "total_attack_segments": len(segments_df),
        "total_benign_gaps": len(gaps_df),
        "rounding_policy": "train_size = round(N * 0.70), validation_size = round(N * 0.15), test_size = N - train_size - validation_size",
        "days_with_attacks": [d for d, m in per_day_metrics.items() if m["attack_segments"] > 0],
        "all_benign_days": [d for d, m in per_day_metrics.items() if m["attack_segments"] == 0],
        "per_day_metrics": per_day_metrics,
        "attack_category_segment_metrics": cat_segment_metrics,
        "global_split_summary": {
            "train_windows": 1718,
            "validation_windows": 368,
            "test_windows": 368,
            "categories_missing_from_train": global_missing_train,
            "categories_missing_from_validation": global_missing_val,
            "categories_missing_from_test": global_missing_test,
        },
        "per_day_split_summary": {
            "categories_missing_from_train": per_day_missing_train,
            "categories_missing_from_validation": per_day_missing_val,
            "categories_missing_from_test": per_day_missing_test,
            "boundaries_cutting_attack_segments": per_day_boundaries_df[
                per_day_boundaries_df["boundary_inside_attack_segment"]
            ][["dataset_day", "boundary_name", "segment_id", "attack_category"]].to_dict(orient="records"),
        },
        "split_strategy_comparison": risk_df.to_dict(orient="records"),
        "key_findings": [
            "Attack windows are highly clustered into 81 distinct temporal bursts separated by 86 BENIGN gaps.",
            "Attacks are extremely day-specific: Monday has no attacks; Tuesday has only Brute Force; Wednesday has DoS and Heartbleed; Thursday has Brute Force, Web Attack, and Infiltration; Friday has Bot, PortScan, and DDoS.",
            "A Global Chronological 70/15/15 split leaves 4 attack categories (Infiltration, Bot, PortScan, DDoS) completely absent from training.",
            "A Per-Day Chronological 70/15/15 split leaves 2 attack categories absent from training (ATTACK, DDoS), 4 absent from validation, and 6 absent from test.",
            "Both naive chronological splitting strategies fragment ongoing attack bursts across split boundaries.",
        ],
    }
    return summary


def save_artifacts(
    segments_df: pd.DataFrame,
    gaps_df: pd.DataFrame,
    cat_summary_df: pd.DataFrame,
    per_day_boundaries_df: pd.DataFrame,
    per_day_coverage_df: pd.DataFrame,
    per_day_summary_df: pd.DataFrame,
    global_coverage_df: pd.DataFrame,
    risk_df: pd.DataFrame,
    summary_dict: dict,
) -> None:
    """
    Save all 8 CSV tables and 1 JSON summary to data/model_inputs/metadata/.
    """
    METADATA_DIR.mkdir(parents=True, exist_ok=True)

    segments_df.to_csv(METADATA_DIR / ATTACK_SEGMENTS_CSV, index=False)
    gaps_df.to_csv(METADATA_DIR / BENIGN_GAPS_CSV, index=False)
    cat_summary_df.to_csv(METADATA_DIR / ATTACK_CATEGORY_SEGMENT_SUMMARY_CSV, index=False)
    per_day_boundaries_df.to_csv(METADATA_DIR / PER_DAY_SPLIT_BOUNDARIES_CSV, index=False)
    per_day_coverage_df.to_csv(METADATA_DIR / PER_DAY_SPLIT_CATEGORY_COVERAGE_CSV, index=False)
    per_day_summary_df.to_csv(METADATA_DIR / PER_DAY_SPLIT_CATEGORY_SUMMARY_CSV, index=False)
    global_coverage_df.to_csv(METADATA_DIR / GLOBAL_SPLIT_CATEGORY_COVERAGE_CSV, index=False)
    risk_df.to_csv(METADATA_DIR / SPLIT_STRATEGY_RISK_ANALYSIS_CSV, index=False)

    with open(METADATA_DIR / ATTACK_SEGMENT_SUMMARY_JSON, "w") as f:
        json.dump(summary_dict, f, indent=4)

    logger.info("Saved all Phase 3.1B metadata artifacts successfully.")


def main() -> None:
    """
    Execute the Phase 3.1B chronological attack segment analysis pipeline.
    """
    logger.info("Starting NexThreat Phase 3.1B Chronological Attack Segment Analysis")
    logger.info("============================================================")

    # 1. Load feature datasets independently
    daily_dfs = load_feature_datasets()

    # 2. Validate chronological data and label consistency
    validate_chronological_data(daily_dfs)

    # In-memory master dataframe for global analysis (NOT saved as new dataset)
    master_df = pd.concat(list(daily_dfs.values()), ignore_index=True)

    # 3. Analyze attack segments and 4. Analyze benign gaps per day
    all_segments: list[dict] = []
    all_gaps: list[dict] = []

    for day_name, df in daily_dfs.items():
        logger.info(f"Analyzing {day_name}...")
        day_segs = analyze_attack_segments(df, day_name)
        day_gaps = analyze_benign_gaps(df, day_name, day_segs)

        all_segments.extend(day_segs)
        all_gaps.extend(day_gaps)

        logger.info(f"  Attack segments found: {len(day_segs)}")
        logger.info(f"  BENIGN gaps found: {len(day_gaps)}")

    segments_df = pd.DataFrame(all_segments)
    gaps_df = pd.DataFrame(all_gaps)

    # 12. Accounting Integrity Verification
    total_atk_windows = int(segments_df["window_count"].sum())
    total_benign_windows = int(gaps_df["window_count"].sum())
    total_accounted = total_atk_windows + total_benign_windows

    if total_atk_windows != 515:
        raise ValueError(
            f"Attack accounting mismatch: expected 515, found {total_atk_windows}"
        )
    if total_benign_windows != 1939:
        raise ValueError(
            f"BENIGN accounting mismatch: expected 1939, found {total_benign_windows}"
        )
    if total_accounted != EXPECTED_TOTAL_WINDOWS:
        raise ValueError(
            f"Total accounting mismatch: expected {EXPECTED_TOTAL_WINDOWS}, found {total_accounted}"
        )
    logger.info(
        f"Accounting integrity verified: {total_atk_windows} attack + {total_benign_windows} benign = {total_accounted} total windows."
    )

    # 5. Attack Category Segment Summary
    cat_summary_df = analyze_category_segments(segments_df)
    logger.info("\n=== ATTACK CATEGORY SEGMENT SUMMARY ===")
    logger.info("\n" + cat_summary_df.to_string(index=False))

    # 6. Per-day split boundary analysis
    logger.info("\nAnalyzing hypothetical per-day 70/15/15 boundaries...")
    per_day_boundaries_df = analyze_per_day_split_boundaries(daily_dfs, segments_df)
    logger.info("\n=== PER-DAY SPLIT BOUNDARIES ===")
    logger.info("\n" + per_day_boundaries_df.to_string(index=False))

    # 7. Per-day category coverage
    per_day_coverage_df, per_day_summary_df = analyze_per_day_category_coverage(daily_dfs)
    logger.info("\n=== PER-DAY SPLIT CATEGORY SUMMARY ===")
    logger.info("\n" + per_day_summary_df.to_string(index=False))

    # 8. Global chronological split coverage
    logger.info("\nAnalyzing hypothetical global 70/15/15 boundaries...")
    global_coverage_df = analyze_global_split_category_coverage(master_df, segments_df)
    logger.info("\n=== GLOBAL SPLIT CATEGORY COVERAGE ===")
    logger.info("\n" + global_coverage_df.to_string(index=False))

    # 9. Split Strategy Risk Comparison
    logger.info("\nGenerating split strategy risk analysis...")
    risk_df = compare_split_strategy_risks(
        global_coverage_df, per_day_summary_df, per_day_boundaries_df, segments_df
    )
    logger.info("\n=== SPLIT STRATEGY RISK ANALYSIS ===")
    logger.info("\n" + risk_df.to_string(index=False))

    # 10. Generate JSON Summary
    summary_dict = generate_attack_segment_summary_json(
        daily_dfs,
        segments_df,
        gaps_df,
        cat_summary_df,
        per_day_boundaries_df,
        per_day_summary_df,
        global_coverage_df,
        risk_df,
    )

    # 11. Save all artifacts
    logger.info("\nSaving metadata artifacts...")
    save_artifacts(
        segments_df,
        gaps_df,
        cat_summary_df,
        per_day_boundaries_df,
        per_day_coverage_df,
        per_day_summary_df,
        global_coverage_df,
        risk_df,
        summary_dict,
    )

    logger.info("============================================================")
    logger.info("Phase 3.1B analysis completed successfully.")


if __name__ == "__main__":
    main()
