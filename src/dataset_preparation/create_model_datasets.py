"""
NexThreat Phase 3.2B/C/D — Model-Specific Dataset Materialization Engine.

Executes manifest instructions to physically separate Train / Validation / Test
datasets for Autoencoder, XGBoost, and LSTM models. Operates strictly from manifests
with ZERO independent split logic. Preserves master feature dataset immutability.
"""
import hashlib
import logging
from pathlib import Path
import pandas as pd

from src.dataset_preparation.config import (
    FEATURES_DIR,
    MANIFESTS_DIR,
    AUTOENCODER_DIR,
    XGBOOST_DIR,
    LSTM_DIR,
    FEATURE_FILES,
    EXPECTED_TOTAL_WINDOWS,
    IS_ATTACK_COLUMN,
    SOURCE_IS_ATTACK_COLUMN,
    DATASET_DAY_COLUMN,
    TRAIN_SPLIT,
    VALIDATION_SPLIT,
    TEST_SPLIT,
    AUTOENCODER_MANIFEST_CSV,
    XGBOOST_MANIFEST_CSV,
    LSTM_MANIFEST_CSV,
    TRAIN_CSV,
    VALIDATION_CSV,
    TEST_CSV,
    LSTM_TRAIN_WINDOWS_CSV,
    LSTM_VALIDATION_WINDOWS_CSV,
    LSTM_TEST_WINDOWS_CSV,
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


def load_master_feature_dataset() -> pd.DataFrame:
    """
    Load master chronological feature datasets into memory with global_position.
    """
    dfs = []
    global_pos = 1

    for day_name, filename in FEATURE_FILES.items():
        file_path = FEATURES_DIR / filename
        df = pd.read_csv(file_path, low_memory=False)

        if IS_ATTACK_COLUMN not in df.columns and SOURCE_IS_ATTACK_COLUMN in df.columns:
            df[IS_ATTACK_COLUMN] = df[SOURCE_IS_ATTACK_COLUMN]

        df[DATASET_DAY_COLUMN] = day_name
        df["global_position"] = range(global_pos, global_pos + len(df))
        global_pos += len(df)

        dfs.append(df)

    master_df = pd.concat(dfs, ignore_index=True)
    if len(master_df) != EXPECTED_TOTAL_WINDOWS:
        raise ValueError(
            f"Master dataset window count mismatch: expected {EXPECTED_TOTAL_WINDOWS}, found {len(master_df)}"
        )
    return master_df


def create_autoencoder_datasets(master_df: pd.DataFrame) -> None:
    """
    Materialize Autoencoder Train / Validation / Test datasets using manifest filtering.
    """
    manifest_path = MANIFESTS_DIR / AUTOENCODER_MANIFEST_CSV
    if not manifest_path.exists():
        raise FileNotFoundError(f"Autoencoder manifest missing: {manifest_path}")

    manifest = pd.read_csv(manifest_path)
    AUTOENCODER_DIR.mkdir(parents=True, exist_ok=True)

    train_positions = manifest[manifest["split"] == TRAIN_SPLIT]["global_position"].tolist()
    val_positions = manifest[manifest["split"] == VALIDATION_SPLIT]["global_position"].tolist()
    test_positions = manifest[manifest["split"] == TEST_SPLIT]["global_position"].tolist()

    train_df = master_df[master_df["global_position"].isin(train_positions)].copy()
    val_df = master_df[master_df["global_position"].isin(val_positions)].copy()
    test_df = master_df[master_df["global_position"].isin(test_positions)].copy()

    train_path = AUTOENCODER_DIR / TRAIN_CSV
    val_path = AUTOENCODER_DIR / VALIDATION_CSV
    test_path = AUTOENCODER_DIR / TEST_CSV

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    logger.info(f"Autoencoder datasets created in {AUTOENCODER_DIR}:")
    logger.info(f"  Train:      {len(train_df):,} windows -> {train_path.name}")
    logger.info(f"  Validation: {len(val_df):,} windows -> {val_path.name}")
    logger.info(f"  Test:       {len(test_df):,} windows -> {test_path.name}")


def create_xgboost_datasets(master_df: pd.DataFrame) -> None:
    """
    Materialize XGBoost Train / Validation / Test datasets using manifest filtering.
    """
    manifest_path = MANIFESTS_DIR / XGBOOST_MANIFEST_CSV
    if not manifest_path.exists():
        raise FileNotFoundError(f"XGBoost manifest missing: {manifest_path}")

    manifest = pd.read_csv(manifest_path)
    XGBOOST_DIR.mkdir(parents=True, exist_ok=True)

    train_positions = manifest[manifest["split"] == TRAIN_SPLIT]["global_position"].tolist()
    val_positions = manifest[manifest["split"] == VALIDATION_SPLIT]["global_position"].tolist()
    test_positions = manifest[manifest["split"] == TEST_SPLIT]["global_position"].tolist()

    train_df = master_df[master_df["global_position"].isin(train_positions)].copy()
    val_df = master_df[master_df["global_position"].isin(val_positions)].copy()
    test_df = master_df[master_df["global_position"].isin(test_positions)].copy()

    train_path = XGBOOST_DIR / TRAIN_CSV
    val_path = XGBOOST_DIR / VALIDATION_CSV
    test_path = XGBOOST_DIR / TEST_CSV

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    logger.info(f"XGBoost datasets created in {XGBOOST_DIR}:")
    logger.info(f"  Train:      {len(train_df):,} windows -> {train_path.name}")
    logger.info(f"  Validation: {len(val_df):,} windows -> {val_path.name}")
    logger.info(f"  Test:       {len(test_df):,} windows -> {test_path.name}")


def create_lstm_datasets(master_df: pd.DataFrame) -> None:
    """
    Materialize LSTM Train / Validation / Test temporal window partitions using manifest filtering.
    Boundary buffer windows are explicitly excluded from materialized output files.
    """
    manifest_path = MANIFESTS_DIR / LSTM_MANIFEST_CSV
    if not manifest_path.exists():
        raise FileNotFoundError(f"LSTM manifest missing: {manifest_path}")

    manifest = pd.read_csv(manifest_path)
    LSTM_DIR.mkdir(parents=True, exist_ok=True)

    train_positions = manifest[manifest["split"] == TRAIN_SPLIT]["global_position"].tolist()
    val_positions = manifest[manifest["split"] == VALIDATION_SPLIT]["global_position"].tolist()
    test_positions = manifest[manifest["split"] == TEST_SPLIT]["global_position"].tolist()

    train_df = master_df[master_df["global_position"].isin(train_positions)].copy()
    val_df = master_df[master_df["global_position"].isin(val_positions)].copy()
    test_df = master_df[master_df["global_position"].isin(test_positions)].copy()

    train_path = LSTM_DIR / LSTM_TRAIN_WINDOWS_CSV
    val_path = LSTM_DIR / LSTM_VALIDATION_WINDOWS_CSV
    test_path = LSTM_DIR / LSTM_TEST_WINDOWS_CSV

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    logger.info(f"LSTM temporal window partitions created in {LSTM_DIR}:")
    logger.info(f"  Train Windows:      {len(train_df):,} windows -> {train_path.name}")
    logger.info(f"  Validation Windows: {len(val_df):,} windows -> {val_path.name}")
    logger.info(f"  Test Windows:       {len(test_df):,} windows -> {test_path.name}")


def main() -> None:
    """
    Execute Phase 3.2B/C/D Dataset Materialization.
    """
    logger.info("================================================================================")
    logger.info("NexThreat Phase 3.2 — Model-Specific Dataset Materialization Engine")
    logger.info("================================================================================")

    # 1. Compute source hashes before
    source_hashes_before = compute_source_hashes()
    logger.info("Computed source dataset SHA-256 hashes (Before Dataset Materialization):")
    for f, h in source_hashes_before.items():
        logger.info(f"  {f}: {h}")

    # 2. Load Master Dataset (Read-Only)
    master_df = load_master_feature_dataset()

    # 3. Create Autoencoder Datasets
    create_autoencoder_datasets(master_df)

    # 4. Create XGBoost Datasets
    create_xgboost_datasets(master_df)

    # 5. Create LSTM Datasets
    create_lstm_datasets(master_df)

    # 6. Re-verify source hashes unchanged
    source_hashes_after = compute_source_hashes()
    assert source_hashes_before == source_hashes_after, "FATAL: Master dataset was modified during dataset creation!"
    logger.info("Source dataset immutability verified: SHA-256 hashes identical before and after.")

    logger.info("================================================================================")
    logger.info("Phase 3.2 dataset materialization completed successfully.")
    logger.info("================================================================================")


if __name__ == "__main__":
    main()
