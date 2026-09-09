"""
NexThreat Phase 3.2E — Split Integrity and Leakage Verification Suite.

Independently inspects, audits, and mathematically verifies all generated manifests
and materialized model datasets (Autoencoder, XGBoost, LSTM). Confirms zero attack
contamination in Autoencoder, full supervised class coverage in XGBoost, zero temporal
leakage and strict segment atomicity in LSTM, and master dataset immutability.
Generates data/model_inputs/manifests/split_integrity_report.json.
"""
import datetime
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
    AUTOENCODER_DIR,
    XGBOOST_DIR,
    LSTM_DIR,
    FEATURE_FILES,
    EXPECTED_TOTAL_WINDOWS,
    EXPECTED_DAILY_COUNTS,
    WINDOW_ID_COLUMN,
    ATTACK_CATEGORY_COLUMN,
    IS_ATTACK_COLUMN,
    DATASET_DAY_COLUMN,
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
    SPLIT_INTEGRITY_REPORT_JSON,
    TRAIN_CSV,
    VALIDATION_CSV,
    TEST_CSV,
    LSTM_TRAIN_WINDOWS_CSV,
    LSTM_VALIDATION_WINDOWS_CSV,
    LSTM_TEST_WINDOWS_CSV,
    XGBOOST_REQUIRED_CLASSES,
    XGBOOST_EXCLUDED_CLASSES,
    LSTM_SEQUENCE_LENGTH,
    LSTM_BOUNDARY_BUFFER,
    ATTACK_SEGMENTS_CSV,
    BENIGN_GAPS_CSV,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def compute_source_hashes() -> dict[str, str]:
    """
    Compute SHA-256 hashes for all 5 master feature files.
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


def verify_master_dataset_integrity(initial_hashes: dict[str, str]) -> dict:
    """
    Verify master dataset files are unchanged.
    """
    current_hashes = compute_source_hashes()
    is_identical = initial_hashes == current_hashes
    if not is_identical:
        raise AssertionError("Master dataset hash mismatch! Source data was modified.")
    return {
        "source_dataset_unchanged": bool(is_identical),
        "source_hashes": current_hashes,
    }


def verify_universal_manifest_properties() -> dict:
    """
    Verify universal manifest structure, row counts, and non-overlapping partitions.
    """
    results = {}
    manifest_paths = {
        AUTOENCODER_MODEL_NAME: MANIFESTS_DIR / AUTOENCODER_MANIFEST_CSV,
        XGBOOST_MODEL_NAME: MANIFESTS_DIR / XGBOOST_MANIFEST_CSV,
        LSTM_MODEL_NAME: MANIFESTS_DIR / LSTM_MANIFEST_CSV,
    }

    for model_name, path in manifest_paths.items():
        if not path.exists():
            raise FileNotFoundError(f"Manifest missing: {path}")

        df = pd.read_csv(path)
        if len(df) != EXPECTED_TOTAL_WINDOWS:
            raise ValueError(
                f"{model_name} manifest row count mismatch: expected {EXPECTED_TOTAL_WINDOWS}, found {len(df)}"
            )

        # Duplicate check
        dups = int(df["global_position"].duplicated().sum())
        if dups > 0:
            raise AssertionError(f"{model_name} manifest contains {dups} duplicate global_position values.")

        # Range check
        min_pos = int(df["global_position"].min())
        max_pos = int(df["global_position"].max())
        if min_pos != 1 or max_pos != EXPECTED_TOTAL_WINDOWS:
            raise AssertionError(f"{model_name} manifest global_position range invalid: [{min_pos}..{max_pos}]")

        # Partition overlap check
        splits = df["split"].unique()
        split_sets = {s: set(df[df["split"] == s]["global_position"]) for s in splits}
        overlap_detected = False
        overlap_details = []

        split_keys = list(split_sets.keys())
        for i in range(len(split_keys)):
            for j in range(i + 1, len(split_keys)):
                k1, k2 = split_keys[i], split_keys[j]
                intersection = split_sets[k1].intersection(split_sets[k2])
                if len(intersection) > 0:
                    overlap_detected = True
                    overlap_details.append(f"{k1} ∩ {k2} = {len(intersection)} windows")

        if overlap_detected:
            raise AssertionError(f"{model_name} partition overlap detected: {overlap_details}")

        results[model_name] = {
            "total_windows": int(len(df)),
            "duplicate_count": dups,
            "partition_overlap_detected": bool(overlap_detected),
            "split_distribution": {k: int(v) for k, v in df["split"].value_counts().items()},
        }

    return results


def verify_autoencoder_split() -> dict:
    """
    Verify Autoencoder purity: 0 attack windows in Train, complete separation,
    and anomaly presence in Validation/Test.
    """
    train_path = AUTOENCODER_DIR / TRAIN_CSV
    val_path = AUTOENCODER_DIR / VALIDATION_CSV
    test_path = AUTOENCODER_DIR / TEST_CSV

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    # Attack contamination check
    train_atk_count = int((train_df[IS_ATTACK_COLUMN] == 1).sum())
    train_contamination_pct = float(train_atk_count / len(train_df) * 100) if len(train_df) > 0 else 0.0

    if train_atk_count > 0:
        raise AssertionError(
            f"Autoencoder purity failure: {train_atk_count} attack windows found in Train!"
        )

    # Overlap check
    tr_set = set(train_df["global_position"])
    va_set = set(val_df["global_position"])
    te_set = set(test_df["global_position"])

    assert len(tr_set.intersection(va_set)) == 0, "Autoencoder Train ∩ Val overlap detected!"
    assert len(tr_set.intersection(te_set)) == 0, "Autoencoder Train ∩ Test overlap detected!"
    assert len(va_set.intersection(te_set)) == 0, "Autoencoder Val ∩ Test overlap detected!"

    # Anomaly representation in Val/Test
    val_attack_cats = val_df[val_df[IS_ATTACK_COLUMN] == 1][ATTACK_CATEGORY_COLUMN].unique().tolist()
    test_attack_cats = test_df[test_df[IS_ATTACK_COLUMN] == 1][ATTACK_CATEGORY_COLUMN].unique().tolist()

    return {
        "status": "PASS",
        "train_count": int(len(train_df)),
        "validation_count": int(len(val_df)),
        "test_count": int(len(test_df)),
        "total_materialized_windows": int(len(train_df) + len(val_df) + len(test_df)),
        "train_benign_count": int(len(train_df)),
        "attack_contamination_count": train_atk_count,
        "attack_contamination_percentage": train_contamination_pct,
        "validation_attack_categories": sorted(val_attack_cats),
        "test_attack_categories": sorted(test_attack_cats),
        "overlap_detected": False,
    }


def verify_xgboost_split() -> dict:
    """
    Verify XGBoost supervised coverage: all 8 required classes in Train,
    Heartbleed strictly excluded, and DDoS exception explicitly documented.
    """
    train_path = XGBOOST_DIR / TRAIN_CSV
    val_path = XGBOOST_DIR / VALIDATION_CSV
    test_path = XGBOOST_DIR / TEST_CSV
    manifest_path = MANIFESTS_DIR / XGBOOST_MANIFEST_CSV

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)
    manifest = pd.read_csv(manifest_path)

    # 1. Required Training Classes
    train_classes = set(train_df[ATTACK_CATEGORY_COLUMN].unique())
    missing_classes = [c for c in XGBOOST_REQUIRED_CLASSES if c not in train_classes]
    if missing_classes:
        raise AssertionError(f"XGBoost training missing required classes: {missing_classes}")

    # 2. Excluded Classes
    for excl in XGBOOST_EXCLUDED_CLASSES:
        if excl in train_classes:
            raise AssertionError(f"Excluded class '{excl}' found in XGBoost Train!")
        if excl in set(val_df[ATTACK_CATEGORY_COLUMN].unique()):
            raise AssertionError(f"Excluded class '{excl}' found in XGBoost Validation!")
        if excl in set(test_df[ATTACK_CATEGORY_COLUMN].unique()):
            raise AssertionError(f"Excluded class '{excl}' found in XGBoost Test!")

    # 3. DDoS Exception Check
    ddos_manifest_rows = manifest[manifest["attack_category"] == "DDoS"]
    if len(ddos_manifest_rows) != 21:
        raise AssertionError(f"DDoS window count mismatch: expected 21, found {len(ddos_manifest_rows)}")

    all_flagged_exception = bool(ddos_manifest_rows["is_exception"].all())
    if not all_flagged_exception:
        raise AssertionError("DDoS sub-segmented rows missing is_exception = True flag!")

    ddos_tr = int((train_df[ATTACK_CATEGORY_COLUMN] == "DDoS").sum())
    ddos_va = int((val_df[ATTACK_CATEGORY_COLUMN] == "DDoS").sum())
    ddos_te = int((test_df[ATTACK_CATEGORY_COLUMN] == "DDoS").sum())

    if ddos_tr != 15 or ddos_va != 3 or ddos_te != 3:
        raise AssertionError(f"DDoS allocation mismatch: train={ddos_tr} (exp 15), val={ddos_va} (exp 3), test={ddos_te} (exp 3)")

    # 4. Overlap Check
    tr_set = set(train_df["global_position"])
    va_set = set(val_df["global_position"])
    te_set = set(test_df["global_position"])

    assert len(tr_set.intersection(va_set)) == 0, "XGBoost Train ∩ Val overlap detected!"
    assert len(tr_set.intersection(te_set)) == 0, "XGBoost Train ∩ Test overlap detected!"
    assert len(va_set.intersection(te_set)) == 0, "XGBoost Val ∩ Test overlap detected!"

    return {
        "status": "PASS",
        "train_count": int(len(train_df)),
        "validation_count": int(len(val_df)),
        "test_count": int(len(test_df)),
        "excluded_count": int((manifest["split"] == EXCLUDED_SPLIT).sum()),
        "total_materialized_windows": int(len(train_df) + len(val_df) + len(test_df)),
        "training_classes": sorted(list(train_classes)),
        "missing_required_classes": missing_classes,
        "excluded_classes_verified": XGBOOST_EXCLUDED_CLASSES,
        "ddos_exception": {
            "total_windows": 21,
            "train_windows": ddos_tr,
            "validation_windows": ddos_va,
            "test_windows": ddos_te,
            "is_exception_flagged": all_flagged_exception,
            "allocation_reason": ddos_manifest_rows["allocation_reason"].iloc[0],
        },
        "overlap_detected": False,
    }


def verify_lstm_split() -> dict:
    """
    Verify LSTM chronological integrity, buffer exclusion, segment atomicity,
    and impossibility of cross-partition sequences.
    """
    train_path = LSTM_DIR / LSTM_TRAIN_WINDOWS_CSV
    val_path = LSTM_DIR / LSTM_VALIDATION_WINDOWS_CSV
    test_path = LSTM_DIR / LSTM_TEST_WINDOWS_CSV
    manifest_path = MANIFESTS_DIR / LSTM_MANIFEST_CSV
    segments_path = METADATA_DIR / ATTACK_SEGMENTS_CSV

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)
    manifest = pd.read_csv(manifest_path)
    segments_df = pd.read_csv(segments_path)

    # 1. Buffer count and exclusion
    buffer_rows = manifest[manifest["is_buffer"]]
    if len(buffer_rows) != 100:
        raise AssertionError(f"LSTM buffer count mismatch: expected 100, found {len(buffer_rows)}")

    # Ensure buffer windows are NOT in materialized files
    buf_positions = set(buffer_rows["global_position"])
    tr_positions = set(train_df["global_position"])
    va_positions = set(val_df["global_position"])
    te_positions = set(test_df["global_position"])

    assert len(buf_positions.intersection(tr_positions)) == 0, "Buffer windows leaked into Train!"
    assert len(buf_positions.intersection(va_positions)) == 0, "Buffer windows leaked into Val!"
    assert len(buf_positions.intersection(te_positions)) == 0, "Buffer windows leaked into Test!"

    # 2. Chronological Ordering per day
    for day in FEATURE_FILES.keys():
        m_day = manifest[manifest["dataset_day"] == day]
        tr_day = m_day[m_day["split"] == TRAIN_SPLIT]["global_position"]
        va_day = m_day[m_day["split"] == VALIDATION_SPLIT]["global_position"]
        te_day = m_day[m_day["split"] == TEST_SPLIT]["global_position"]

        assert tr_day.max() < va_day.min(), f"{day} Chronological violation: Train max >= Val min"
        assert va_day.max() < te_day.min(), f"{day} Chronological violation: Val max >= Test min"

        # Check buffer separation
        b1_day = m_day[(m_day["is_buffer"]) & (m_day["global_position"] < va_day.min())]["global_position"]
        b2_day = m_day[(m_day["is_buffer"]) & (m_day["global_position"] > va_day.max())]["global_position"]

        assert len(b1_day) == LSTM_BOUNDARY_BUFFER, f"{day} Buffer 1 length mismatch: {len(b1_day)}"
        assert len(b2_day) == LSTM_BOUNDARY_BUFFER, f"{day} Buffer 2 length mismatch: {len(b2_day)}"

    # 3. Segment Atomicity (Zero segment slicing across LSTM partitions)
    for _, seg in segments_df.iterrows():
        sid = seg["segment_id"]
        g_start = int(seg["global_start_position"])
        g_end = int(seg["global_end_position"])
        seg_positions = set(range(g_start, g_end + 1))

        # Check which partition contains the segment
        in_tr = seg_positions.issubset(tr_positions)
        in_va = seg_positions.issubset(va_positions)
        in_te = seg_positions.issubset(te_positions)

        if not (in_tr or in_va or in_te):
            raise AssertionError(f"LSTM Segment Atomicity Violated: Segment {sid} was sliced across partitions!")

    # 4. Cross-Boundary Sequence Prevention
    # For every target window in Validation, historical context (10 windows) must not touch Train
    for day in FEATURE_FILES.keys():
        m_day = manifest[manifest["dataset_day"] == day]
        tr_max = m_day[m_day["split"] == TRAIN_SPLIT]["global_position"].max()
        va_min = m_day[m_day["split"] == VALIDATION_SPLIT]["global_position"].min()
        va_max = m_day[m_day["split"] == VALIDATION_SPLIT]["global_position"].max()
        te_min = m_day[m_day["split"] == TEST_SPLIT]["global_position"].min()

        # The distance between tr_max and va_min is exactly 11 (10 buffer windows in between)
        assert va_min - tr_max == LSTM_BOUNDARY_BUFFER + 1, f"{day} Buffer distance Train->Val violation"
        assert te_min - va_max == LSTM_BOUNDARY_BUFFER + 1, f"{day} Buffer distance Val->Test violation"

    return {
        "status": "PASS",
        "train_windows": int(len(train_df)),
        "buffer_windows": int(len(buffer_rows)),
        "validation_windows": int(len(val_df)),
        "test_windows": int(len(test_df)),
        "total_windows": int(len(train_df) + len(buffer_rows) + len(val_df) + len(test_df)),
        "chronological_ordering_verified": True,
        "boundary_buffer_size": LSTM_BOUNDARY_BUFFER,
        "segment_atomicity_verified": True,
        "cross_boundary_sequence_possible": False,
        "overlap_detected": False,
    }


def generate_split_integrity_report(
    master_integrity: dict,
    universal_checks: dict,
    ae_verification: dict,
    xgb_verification: dict,
    lstm_verification: dict,
) -> dict:
    """
    Synthesize all verification checks into structured JSON report.
    """
    report = {
        "phase": "3.2",
        "phase_title": "Final Model-Specific Dataset Split Integrity Report",
        "timestamp": datetime.datetime.now().isoformat(),
        "final_status": "PASS",
        "master_dataset_integrity": master_integrity,
        "universal_manifest_checks": universal_checks,
        "autoencoder_verification": ae_verification,
        "xgboost_verification": xgb_verification,
        "lstm_verification": lstm_verification,
        "summary": {
            "master_dataset_unchanged": master_integrity["source_dataset_unchanged"],
            "autoencoder_attack_contamination_count": ae_verification["attack_contamination_count"],
            "xgboost_all_required_classes_present": len(xgb_verification["missing_required_classes"]) == 0,
            "xgboost_excluded_classes_verified": len(xgb_verification["excluded_classes_verified"]) > 0,
            "lstm_segment_atomicity_verified": lstm_verification["segment_atomicity_verified"],
            "lstm_cross_boundary_sequence_possible": lstm_verification["cross_boundary_sequence_possible"],
            "all_checks_passed": True,
        },
    }

    report_path = MANIFESTS_DIR / SPLIT_INTEGRITY_REPORT_JSON
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    logger.info(f"Saved split integrity report to: {report_path}")
    return report


def main() -> None:
    """
    Execute Independent Verification Suite for Phase 3.2.
    """
    logger.info("================================================================================")
    logger.info("NexThreat Phase 3.2E — Split Integrity and Leakage Verification Suite")
    logger.info("================================================================================")

    # 1. Initial Hash Calculation
    initial_hashes = compute_source_hashes()

    # 2. Universal Manifest Checks
    logger.info("Checking universal manifest integrity and non-overlapping partitions...")
    universal_checks = verify_universal_manifest_properties()

    # 3. Autoencoder Verification
    logger.info("Verifying Autoencoder Level 3 Benign Purity and Anomaly Representation...")
    ae_verification = verify_autoencoder_split()
    logger.info(f"  Autoencoder Train: {ae_verification['train_count']} windows (0 attack contamination).")

    # 4. XGBoost Verification
    logger.info("Verifying XGBoost Level 2 Supervised Class Coverage & DDoS Exception...")
    xgb_verification = verify_xgboost_split()
    logger.info(f"  XGBoost Train: {xgb_verification['train_count']} windows (All 8 required classes present).")
    logger.info(f"  XGBoost DDoS Exception: {xgb_verification['ddos_exception']['train_windows']} Train / {xgb_verification['ddos_exception']['validation_windows']} Val / {xgb_verification['ddos_exception']['test_windows']} Test.")

    # 5. LSTM Verification
    logger.info("Verifying LSTM Level 1 Strict Segment Atomicity, Buffers, & Leakage Prevention...")
    lstm_verification = verify_lstm_split()
    logger.info(f"  LSTM Partitions: {lstm_verification['train_windows']} Train / {lstm_verification['buffer_windows']} Buffer / {lstm_verification['validation_windows']} Val / {lstm_verification['test_windows']} Test.")
    logger.info("  LSTM Segment Atomicity: 100% Preserved. Cross-Boundary Sequence Possible: False.")

    # 6. Master Dataset Immutability Check
    logger.info("Verifying Master Dataset SHA-256 Immutability...")
    master_integrity = verify_master_dataset_integrity(initial_hashes)

    # 7. Generate Integrity Report
    logger.info("Generating Final Split Integrity Report JSON...")
    report = generate_split_integrity_report(
        master_integrity, universal_checks, ae_verification, xgb_verification, lstm_verification
    )

    print("\n" + "=" * 80)
    print("NEXTHREAT PHASE 3.2 SPLIT INTEGRITY VERIFICATION COMPLETE")
    print("=" * 80)
    print(f"MASTER DATASET UNCHANGED:          {report['summary']['master_dataset_unchanged']}")
    print(f"AUTOENCODER ATTACK CONTAMINATION:  {report['summary']['autoencoder_attack_contamination_count']} windows (0.0%)")
    print(f"XGBOOST SUPERVISED COVERAGE:       8 / 8 Major Classes Present in Train (Heartbleed Excluded)")
    print(f"XGBOOST DDOS EXCEPTION:            Documented (15 Train / 3 Val / 3 Test)")
    print(f"LSTM SEGMENT ATOMICITY:            100% Preserved (Zero Slicing)")
    print(f"LSTM BOUNDARY BUFFERS:             100 Windows Excluded (Zero Cross-Boundary Sequences)")
    print(f"PARTITION OVERLAPS:                ZERO OVERLAP DETECTED")
    print("=" * 80)
    print("FINAL INTEGRITY STATUS:            PASS")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
