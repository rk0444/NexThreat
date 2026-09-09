"""
NexThreat Phase 3.2A — Split Manifest Generation Engine.

Responsible for ALL dataset split allocation decisions across Autoencoder,
XGBoost, and LSTM models. Operates in strict read-only mode over the master
chronological feature datasets, generating deterministic and auditable split
manifests in data/model_inputs/manifests/.
"""
import hashlib
import json
import logging
from pathlib import Path
import pandas as pd
import numpy as np

from src.dataset_preparation.config import (
    FEATURES_DIR,
    METADATA_DIR,
    MANIFESTS_DIR,
    FEATURE_FILES,
    EXPECTED_TOTAL_WINDOWS,
    EXPECTED_DAILY_COUNTS,
    WINDOW_ID_COLUMN,
    ATTACK_CATEGORY_COLUMN,
    IS_ATTACK_COLUMN,
    SOURCE_IS_ATTACK_COLUMN,
    DATASET_DAY_COLUMN,
    REQUIRED_COLUMNS,
    SPLIT_RATIOS,
    ATTACK_SEGMENTS_CSV,
    BENIGN_GAPS_CSV,
    AUTOENCODER_MODEL_NAME,
    XGBOOST_MODEL_NAME,
    LSTM_MODEL_NAME,
    TRAIN_SPLIT,
    VALIDATION_SPLIT,
    TEST_SPLIT,
    BUFFER_SPLIT,
    EXCLUDED_SPLIT,
    AUTOENCODER_MANIFEST_CSV,
    XGBOOST_MANIFEST_CSV,
    LSTM_MANIFEST_CSV,
    XGBOOST_REQUIRED_CLASSES,
    XGBOOST_EXCLUDED_CLASSES,
    LSTM_BOUNDARY_BUFFER,
    RANDOM_SEED,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def compute_source_hashes() -> dict[str, str]:
    """
    Compute cryptographic SHA-256 hashes for all 5 master feature files.
    """
    hashes = {}
    for day_name, filename in FEATURE_FILES.items():
        file_path = FEATURES_DIR / filename
        if not file_path.exists():
            raise FileNotFoundError(f"Source feature dataset not found: {file_path}")

        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        hashes[filename] = sha256.hexdigest()
    return hashes


def load_master_dataset() -> tuple[dict[str, pd.DataFrame], pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Load master chronological feature datasets and Phase 3.1 metadata artifacts in READ-ONLY mode.
    """
    daily_dfs: dict[str, pd.DataFrame] = {}
    global_pos = 1

    for day_name, filename in FEATURE_FILES.items():
        file_path = FEATURES_DIR / filename
        df = pd.read_csv(file_path, low_memory=False)

        if IS_ATTACK_COLUMN not in df.columns and SOURCE_IS_ATTACK_COLUMN in df.columns:
            df[IS_ATTACK_COLUMN] = df[SOURCE_IS_ATTACK_COLUMN]

        df[DATASET_DAY_COLUMN] = day_name
        df["day_position"] = range(1, len(df) + 1)
        df["global_position"] = range(global_pos, global_pos + len(df))
        global_pos += len(df)

        daily_dfs[day_name] = df

    master_df = pd.concat(list(daily_dfs.values()), ignore_index=True)
    if len(master_df) != EXPECTED_TOTAL_WINDOWS:
        raise ValueError(
            f"Master dataset window count mismatch: expected {EXPECTED_TOTAL_WINDOWS}, found {len(master_df)}"
        )

    segments_path = METADATA_DIR / ATTACK_SEGMENTS_CSV
    gaps_path = METADATA_DIR / BENIGN_GAPS_CSV

    if not segments_path.exists() or not gaps_path.exists():
        raise FileNotFoundError("Phase 3.1 metadata files missing.")

    segments_df = pd.read_csv(segments_path)
    gaps_df = pd.read_csv(gaps_path)

    # Attach segment_id to master_df
    master_df["segment_id"] = "BENIGN_GAP"
    for _, seg in segments_df.iterrows():
        g_start = int(seg["global_start_position"])
        g_end = int(seg["global_end_position"])
        seg_id = str(seg["segment_id"])
        master_df.loc[
            (master_df["global_position"] >= g_start) & (master_df["global_position"] <= g_end),
            "segment_id",
        ] = seg_id

    for _, gap in gaps_df.iterrows():
        g_start = int(gap["global_start_position"])
        g_end = int(gap["global_end_position"])
        gap_id = str(gap["gap_id"])
        master_df.loc[
            (master_df["global_position"] >= g_start) & (master_df["global_position"] <= g_end),
            "segment_id",
        ] = gap_id

    return daily_dfs, master_df, segments_df, gaps_df


def generate_autoencoder_manifest(
    master_df: pd.DataFrame,
    segments_df: pd.DataFrame,
    gaps_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Generate Autoencoder split manifest enforcing Level 3 Benign Purity Priority:
      - Training: 100% Monday pure benign (487w) + 70% of Tue-Fri benign gaps (~870w) = ~1,357 pure benign windows.
      - Attack contamination in Training = 0 (0.0%).
      - Validation & Test: Remaining 30% of benign gaps (~582w) + Category-stratified attack segments across all 8 classes.
    """
    logger.info("Generating Autoencoder Split Manifest...")
    manifest_rows = []

    # 1. Segment-level attack allocation (0 in Train; split across Val and Test)
    attack_segment_allocations: dict[str, str] = {}
    for cat, grp in segments_df.groupby("attack_category"):
        num_segs = len(grp)
        # Allocate roughly 50% Val / 50% Test for balanced anomaly evaluation
        val_count = max(1, num_segs // 2) if num_segs > 1 else (1 if cat != "DDoS" else 0)
        # For DDoS (1 segment), allocate to Test (or Val)
        if cat == "DDoS":
            val_count = 0

        for idx, (_, seg) in enumerate(grp.iterrows()):
            seg_id = seg["segment_id"]
            if idx < val_count:
                attack_segment_allocations[seg_id] = VALIDATION_SPLIT
            else:
                attack_segment_allocations[seg_id] = TEST_SPLIT

    # 2. Benign Gap Allocation
    # Monday is 100% Train
    # Tue-Fri gaps allocated ~70% Train, 15% Val, 15% Test
    gap_allocations: dict[int, str] = {}
    for _, gap in gaps_df.iterrows():
        day = gap["dataset_day"]
        g_start = int(gap["global_start_position"])
        g_end = int(gap["global_end_position"])
        g_len = int(gap["window_count"])

        if day == "Monday":
            for pos in range(g_start, g_end + 1):
                gap_allocations[pos] = TRAIN_SPLIT
        else:
            # Chronological 70/15/15 within each non-Monday gap
            tr_cut = int(round(g_len * 0.70))
            va_cut = int(round(g_len * 0.15))
            for idx, pos in enumerate(range(g_start, g_end + 1)):
                if idx < tr_cut:
                    gap_allocations[pos] = TRAIN_SPLIT
                elif idx < tr_cut + va_cut:
                    gap_allocations[pos] = VALIDATION_SPLIT
                else:
                    gap_allocations[pos] = TEST_SPLIT

    for _, row in master_df.iterrows():
        pos = int(row["global_position"])
        win_id = str(row[WINDOW_ID_COLUMN])
        day = str(row[DATASET_DAY_COLUMN])
        cat = str(row[ATTACK_CATEGORY_COLUMN])
        is_atk = int(row[IS_ATTACK_COLUMN])
        seg_id = str(row["segment_id"])

        if is_atk == 1:
            split_label = attack_segment_allocations.get(seg_id, TEST_SPLIT)
            reason = f"Anomaly evaluation partition ({split_label}) for threshold calibration"
        else:
            split_label = gap_allocations.get(pos, TRAIN_SPLIT)
            if split_label == TRAIN_SPLIT:
                reason = "Pure benign baseline training (Level 3 Purity)"
            else:
                reason = f"Unseen benign evaluation partition ({split_label})"

        manifest_rows.append({
            "global_position": pos,
            "window_id": win_id,
            "dataset_day": day,
            "attack_category": cat,
            "is_attack": is_atk,
            "split": split_label,
            "model": AUTOENCODER_MODEL_NAME,
            "segment_id": seg_id,
            "is_exception": False,
            "allocation_reason": reason,
            "notes": "Strict Level 3 Benign Purity (Zero attack contamination in Train)",
        })

    ae_manifest = pd.DataFrame(manifest_rows)
    logger.info(
        f"Autoencoder manifest generated: {len(ae_manifest)} windows "
        f"({(ae_manifest['split'] == TRAIN_SPLIT).sum()} train, "
        f"{(ae_manifest['split'] == VALIDATION_SPLIT).sum()} val, "
        f"{(ae_manifest['split'] == TEST_SPLIT).sum()} test)."
    )
    return ae_manifest


def generate_xgboost_manifest(
    master_df: pd.DataFrame,
    segments_df: pd.DataFrame,
    gaps_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Generate XGBoost split manifest enforcing Level 2 Preferred Segment Atomicity:
      - Mandatory complete major supervised class coverage (8/8 classes in Train).
      - Heartbleed (ATTACK) strictly excluded from supervised datasets.
      - Whole-segment allocation for multi-segment classes.
      - Explicit Model-Specific Supervised Sub-Segmentation Exception for DDoS (15w Train / 3w Val / 3w Test).
      - Whole-segment allocation for Web Attack: SEG_001 (21w Train) / SEG_002 (3w Test) (Val = 0w).
    """
    logger.info("Generating XGBoost Split Manifest...")
    manifest_rows = []

    # 1. Attack Segment Allocations
    # Brute Force (7 segs, 171w): Tue SEG_001..004 + Thu SEG_003 (167w) -> Train; Thu SEG_001 (2w) -> Val; Thu SEG_002 (2w) -> Test
    # Bot (16 segs, 163w): Fri SEG_001..011 (123w) -> Train; Fri SEG_012..014 (20w) -> Val; Fri SEG_015..016 (20w) -> Test
    # DoS (10 segs, 71w): Wed SEG_001..007 (61w) -> Train; Wed SEG_008..009 (7w) -> Val; Wed SEG_010 (3w) -> Test
    # Infiltration (25 segs, 27w): Thu SEG_006..023 (18w) -> Train; Thu SEG_024..027 (5w) -> Val; Thu SEG_028..030 (4w) -> Test
    # PortScan (9 segs, 27w): Fri SEG_017..022 (19w) -> Train; Fri SEG_023 (3w) -> Val; Fri SEG_024..025 (5w) -> Test
    # Web Attack (2 segs, 24w): Thu SEG_004 (21w) -> Train; Thu SEG_005 (3w) -> Test
    # Heartbleed / ATTACK (11 segs, 11w): Excluded from XGBoost
    # DDoS (1 seg, 21w): Handled via sub-segment exception (15/3/3)

    segment_level_split: dict[str, str] = {}
    for cat, grp in segments_df.groupby("attack_category"):
        if cat == "Brute Force":
            for _, seg in grp.iterrows():
                sid = seg["segment_id"]
                if sid == "Thursday_SEG_001":
                    segment_level_split[sid] = VALIDATION_SPLIT
                elif sid == "Thursday_SEG_002":
                    segment_level_split[sid] = TEST_SPLIT
                else:
                    segment_level_split[sid] = TRAIN_SPLIT
        elif cat == "Bot":
            for idx, (_, seg) in enumerate(grp.iterrows()):
                sid = seg["segment_id"]
                if idx < 11:
                    segment_level_split[sid] = TRAIN_SPLIT
                elif idx < 14:
                    segment_level_split[sid] = VALIDATION_SPLIT
                else:
                    segment_level_split[sid] = TEST_SPLIT
        elif cat == "DoS":
            for idx, (_, seg) in enumerate(grp.iterrows()):
                sid = seg["segment_id"]
                if idx < 7:
                    segment_level_split[sid] = TRAIN_SPLIT
                elif idx < 9:
                    segment_level_split[sid] = VALIDATION_SPLIT
                else:
                    segment_level_split[sid] = TEST_SPLIT
        elif cat == "Infiltration":
            for idx, (_, seg) in enumerate(grp.iterrows()):
                sid = seg["segment_id"]
                if idx < 18:
                    segment_level_split[sid] = TRAIN_SPLIT
                elif idx < 22:
                    segment_level_split[sid] = VALIDATION_SPLIT
                else:
                    segment_level_split[sid] = TEST_SPLIT
        elif cat == "PortScan":
            for idx, (_, seg) in enumerate(grp.iterrows()):
                sid = seg["segment_id"]
                if idx < 6:
                    segment_level_split[sid] = TRAIN_SPLIT
                elif idx < 7:
                    segment_level_split[sid] = VALIDATION_SPLIT
                else:
                    segment_level_split[sid] = TEST_SPLIT
        elif cat == "Web Attack":
            for idx, (_, seg) in enumerate(grp.iterrows()):
                sid = seg["segment_id"]
                if idx == 0:
                    segment_level_split[sid] = TRAIN_SPLIT
                else:
                    segment_level_split[sid] = TEST_SPLIT
        elif cat == "ATTACK":
            for _, seg in grp.iterrows():
                sid = seg["segment_id"]
                segment_level_split[sid] = EXCLUDED_SPLIT

    # 2. Benign Gap Allocations (~70% Train, 15% Val, 15% Test)
    gap_allocations: dict[int, str] = {}
    for _, gap in gaps_df.iterrows():
        g_start = int(gap["global_start_position"])
        g_end = int(gap["global_end_position"])
        g_len = int(gap["window_count"])

        tr_cut = int(round(g_len * 0.70))
        va_cut = int(round(g_len * 0.15))
        for idx, pos in enumerate(range(g_start, g_end + 1)):
            if idx < tr_cut:
                gap_allocations[pos] = TRAIN_SPLIT
            elif idx < tr_cut + va_cut:
                gap_allocations[pos] = VALIDATION_SPLIT
            else:
                gap_allocations[pos] = TEST_SPLIT

    # DDoS Sub-segmentation parameters (Friday_SEG_026: global 2388..2408)
    ddos_seg = segments_df[segments_df["attack_category"] == "DDoS"].iloc[0]
    ddos_start = int(ddos_seg["global_start_position"])
    ddos_end = int(ddos_seg["global_end_position"])

    for _, row in master_df.iterrows():
        pos = int(row["global_position"])
        win_id = str(row[WINDOW_ID_COLUMN])
        day = str(row[DATASET_DAY_COLUMN])
        cat = str(row[ATTACK_CATEGORY_COLUMN])
        is_atk = int(row[IS_ATTACK_COLUMN])
        seg_id = str(row["segment_id"])

        is_exception = False
        notes = "Level 2 Preferred Segment Atomicity"

        if cat == "DDoS":
            # Documented Exception: 15 Train / 3 Val / 3 Test
            offset = pos - ddos_start
            if offset < 15:
                split_label = TRAIN_SPLIT
            elif offset < 18:
                split_label = VALIDATION_SPLIT
            else:
                split_label = TEST_SPLIT
            is_exception = True
            reason = "Model-Specific Supervised Sub-Segmentation Exception"
            notes = "Explicit documented exception for single-segment DDoS (15w Train / 3w Val / 3w Test)"
        elif cat in XGBOOST_EXCLUDED_CLASSES or cat == "ATTACK":
            split_label = EXCLUDED_SPLIT
            reason = "Excluded from supervised multi-class XGBoost (11 single-window spikes)"
            notes = "Heartbleed evaluated in binary anomaly detection only"
        elif is_atk == 1:
            split_label = segment_level_split.get(seg_id, TRAIN_SPLIT)
            reason = f"Whole attack segment allocation ({split_label})"
        else:
            split_label = gap_allocations.get(pos, TRAIN_SPLIT)
            reason = f"Benign background traffic allocation ({split_label})"

        manifest_rows.append({
            "global_position": pos,
            "window_id": win_id,
            "dataset_day": day,
            "attack_category": cat,
            "is_attack": is_atk,
            "split": split_label,
            "model": XGBOOST_MODEL_NAME,
            "segment_id": seg_id,
            "is_exception": is_exception,
            "allocation_reason": reason,
            "notes": notes,
        })

    xgb_manifest = pd.DataFrame(manifest_rows)
    logger.info(
        f"XGBoost manifest generated: {len(xgb_manifest)} windows "
        f"({(xgb_manifest['split'] == TRAIN_SPLIT).sum()} train, "
        f"{(xgb_manifest['split'] == VALIDATION_SPLIT).sum()} val, "
        f"{(xgb_manifest['split'] == TEST_SPLIT).sum()} test, "
        f"{(xgb_manifest['split'] == EXCLUDED_SPLIT).sum()} excluded)."
    )
    return xgb_manifest


def generate_lstm_manifest(
    master_df: pd.DataFrame,
    segments_df: pd.DataFrame,
    gaps_df: pd.DataFrame,
    daily_dfs: dict[str, pd.DataFrame],
) -> pd.DataFrame:
    """
    Generate LSTM split manifest enforcing Level 1 Strict Segment Atomicity:
      - Continuous daily chronological blocks.
      - Zero attack segment slicing across partitions.
      - Mandatory 10-window boundary buffers at split transitions.
      - 1,586 Train windows / 100 Buffer windows / 432 Validation windows / 336 Test windows.
    """
    logger.info("Generating LSTM Split Manifest...")
    manifest_rows = []

    # Validated segment-atomic daily configurations
    lstm_daily_configs = {
        "Monday": {"train_end": 341, "buf1": (342, 351), "val": (352, 414), "buf2": (415, 424), "test": (425, 487)},
        "Tuesday": {"train_end": 306, "buf1": (307, 316), "val": (317, 420), "buf2": (421, 430), "test": (431, 488)},
        "Wednesday": {"train_end": 346, "buf1": (347, 356), "val": (357, 421), "buf2": (422, 431), "test": (432, 509)},
        "Thursday": {"train_end": 310, "buf1": (311, 320), "val": (321, 416), "buf2": (417, 426), "test": (427, 486)},
        "Friday": {"train_end": 283, "buf1": (284, 293), "val": (294, 397), "buf2": (398, 407), "test": (408, 484)},
    }

    for day_name, df in daily_dfs.items():
        cfg = lstm_daily_configs[day_name]
        t_end = cfg["train_end"]
        b1_s, b1_e = cfg["buf1"]
        v_s, v_e = cfg["val"]
        b2_s, b2_e = cfg["buf2"]
        te_s, te_e = cfg["test"]

        for _, row in df.iterrows():
            pos = int(row["global_position"])
            day_pos = int(row["day_position"])
            win_id = str(row[WINDOW_ID_COLUMN])
            cat = str(row[ATTACK_CATEGORY_COLUMN])
            is_atk = int(row[IS_ATTACK_COLUMN])

            # Lookup segment_id
            seg_match = master_df.loc[master_df["global_position"] == pos, "segment_id"]
            seg_id = seg_match.values[0] if not seg_match.empty else "UNKNOWN"

            is_buffer = False
            if day_pos <= t_end:
                split_label = TRAIN_SPLIT
                reason = "Continuous chronological train block"
            elif day_pos <= b1_e:
                split_label = BUFFER_SPLIT
                is_buffer = True
                reason = "10-window Train/Val boundary exclusion buffer"
            elif day_pos <= v_e:
                split_label = VALIDATION_SPLIT
                reason = "Continuous chronological validation block"
            elif day_pos <= b2_e:
                split_label = BUFFER_SPLIT
                is_buffer = True
                reason = "10-window Val/Test boundary exclusion buffer"
            else:
                split_label = TEST_SPLIT
                reason = "Continuous chronological test block"

            manifest_rows.append({
                "global_position": pos,
                "window_id": win_id,
                "dataset_day": day_name,
                "day_position": day_pos,
                "attack_category": cat,
                "is_attack": is_atk,
                "split": split_label,
                "model": LSTM_MODEL_NAME,
                "segment_id": seg_id,
                "is_buffer": is_buffer,
                "is_exception": False,
                "allocation_reason": reason,
                "notes": "Strict Level 1 Segment Atomicity & Sequence Boundary Isolation",
            })

    lstm_manifest = pd.DataFrame(manifest_rows)
    logger.info(
        f"LSTM manifest generated: {len(lstm_manifest)} windows "
        f"({(lstm_manifest['split'] == TRAIN_SPLIT).sum()} train, "
        f"{(lstm_manifest['split'] == BUFFER_SPLIT).sum()} buffer, "
        f"{(lstm_manifest['split'] == VALIDATION_SPLIT).sum()} val, "
        f"{(lstm_manifest['split'] == TEST_SPLIT).sum()} test)."
    )
    return lstm_manifest


def save_manifests(
    ae_manifest: pd.DataFrame,
    xgb_manifest: pd.DataFrame,
    lstm_manifest: pd.DataFrame,
) -> None:
    """
    Save all 3 split manifests to data/model_inputs/manifests/.
    """
    MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)

    ae_path = MANIFESTS_DIR / AUTOENCODER_MANIFEST_CSV
    xgb_path = MANIFESTS_DIR / XGBOOST_MANIFEST_CSV
    lstm_path = MANIFESTS_DIR / LSTM_MANIFEST_CSV

    ae_manifest.to_csv(ae_path, index=False)
    xgb_manifest.to_csv(xgb_path, index=False)
    lstm_manifest.to_csv(lstm_path, index=False)

    logger.info(f"Saved Autoencoder manifest to: {ae_path}")
    logger.info(f"Saved XGBoost manifest to: {xgb_path}")
    logger.info(f"Saved LSTM manifest to: {lstm_path}")


def main() -> None:
    """
    Execute Phase 3.2A Manifest Generation.
    """
    logger.info("================================================================================")
    logger.info("NexThreat Phase 3.2A — Split Manifest Generation Engine")
    logger.info("================================================================================")

    # 1. Compute source hashes
    source_hashes_before = compute_source_hashes()
    logger.info("Computed source dataset SHA-256 hashes (Read-Only Mode):")
    for f, h in source_hashes_before.items():
        logger.info(f"  {f}: {h}")

    # 2. Load master dataset in read-only mode
    daily_dfs, master_df, segments_df, gaps_df = load_master_dataset()

    # 3. Generate Autoencoder manifest
    ae_manifest = generate_autoencoder_manifest(master_df, segments_df, gaps_df)

    # 4. Generate XGBoost manifest
    xgb_manifest = generate_xgboost_manifest(master_df, segments_df, gaps_df)

    # 5. Generate LSTM manifest
    lstm_manifest = generate_lstm_manifest(master_df, segments_df, gaps_df, daily_dfs)

    # 6. Save manifests
    save_manifests(ae_manifest, xgb_manifest, lstm_manifest)

    # 7. Re-verify source hashes unchanged
    source_hashes_after = compute_source_hashes()
    assert source_hashes_before == source_hashes_after, "FATAL: Master dataset was modified during manifest generation!"
    logger.info("Source dataset immutability verified: SHA-256 hashes identical before and after.")

    logger.info("================================================================================")
    logger.info("Phase 3.2A manifest generation completed successfully.")
    logger.info("================================================================================")


if __name__ == "__main__":
    main()
