"""
NexThreat Master Data Preprocessing Pipeline.
"""
import logging
from pathlib import Path
import pandas as pd
import numpy as np

from src.preprocessing.config import (
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    TIMESTAMP_FORMAT,
    DATASET_FILENAMES,
    CRITICAL_COLUMNS
)
from src.preprocessing.label_mapping import LABEL_MAPPING

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_dataset(filepath: Path) -> pd.DataFrame:
    """Load CSV dataset into a pandas DataFrame."""
    logger.info(f"Loading dataset from {filepath}")
    return pd.read_csv(filepath)

def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names."""
    df.columns = df.columns.str.strip()
    return df

def validate_required_columns(df: pd.DataFrame):
    """Validate that all critical columns exist in the DataFrame."""
    missing_cols = [col for col in CRITICAL_COLUMNS if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing critical columns in dataset: {missing_cols}")

def remove_duplicates(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Remove duplicate rows. Returns the deduped DataFrame and the count of removed rows."""
    initial_count = len(df)
    df = df.drop_duplicates()
    removed_count = initial_count - len(df)
    return df, removed_count

def parse_timestamp(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Parse Timestamp using configured format, removing invalid rows.
    Returns the DataFrame and the count of invalid timestamp rows removed."""
    initial_count = len(df)
    # Parse timestamp, coercing errors to NaT
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], format=TIMESTAMP_FORMAT, errors="coerce")
    
    # Remove rows with invalid timestamps (NaT)
    df_valid = df.dropna(subset=["Timestamp"]).copy()
    invalid_count = initial_count - len(df_valid)
    return df_valid, invalid_count

def replace_infinite_values(df: pd.DataFrame) -> pd.DataFrame:
    """Replace +inf and -inf values with NaN."""
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    return df

def handle_missing_values(df: pd.DataFrame) -> pd.DataFrame:
    """Handle missing values safely.
    Replaces numeric NaNs with 0, and non-numeric NaNs with 'Unknown' (excluding Timestamp).
    """
    # Fill numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)
    
    # Fill non-numeric columns (excluding datetime types to preserve them)
    non_numeric_cols = df.select_dtypes(exclude=[np.number, "datetime", "datetimetz"]).columns
    df[non_numeric_cols] = df[non_numeric_cols].fillna("Unknown")
    
    return df

def standardize_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Create original_label, attack_category, and is_attack columns."""
    df["original_label"] = df["Label"]
    
    stripped_labels = df["original_label"].astype(str).str.strip()
    
    # Check for unknown labels before mapping to report them clearly
    unknown_labels = set(stripped_labels) - set(LABEL_MAPPING.keys())
    if unknown_labels:
        raise ValueError(f"Unknown labels encountered in dataset: {unknown_labels}")
    
    # Map to standardized category
    df["attack_category"] = stripped_labels.map(LABEL_MAPPING)
    
    # Vectorized assignment for is_attack
    df["is_attack"] = (df["attack_category"] != "BENIGN").astype(int)
    
    return df

def validate_processed_dataset(df: pd.DataFrame):
    """Validate processed dataset to ensure it meets requirements."""
    if df.empty:
        raise ValueError("Validation failed: Dataset is empty after preprocessing.")
        
    if "Timestamp" not in df.columns:
        raise ValueError("Validation failed: Timestamp column is missing.")
        
    if df["Timestamp"].isnull().any():
        raise ValueError("Validation failed: Timestamp column contains null values.")
        
    if not df["Timestamp"].is_monotonic_increasing:
        raise ValueError("Validation failed: Dataset is not sorted chronologically.")
        
    missing_critical = [col for col in CRITICAL_COLUMNS if col not in df.columns]
    if missing_critical:
        raise ValueError(f"Validation failed: Missing critical columns {missing_critical}.")
        
    if df["attack_category"].isnull().any():
        raise ValueError("Validation failed: Unknown labels remain in the dataset.")

def save_processed_dataset(df: pd.DataFrame, filepath: Path):
    """Save the processed DataFrame to CSV."""
    logger.info(f"Saving processed dataset to {filepath}")
    filepath.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(filepath, index=False)

def preprocess_dataset(filename: str):
    """Execute the full preprocessing pipeline for a specific dataset."""
    raw_filepath = RAW_DATA_DIR / filename
    
    if not raw_filepath.exists():
        logger.warning(f"File not found: {raw_filepath}. Skipping.")
        return
        
    processed_filename = filename.replace(".csv", "_processed.csv")
    processed_filepath = PROCESSED_DATA_DIR / processed_filename
    
    logger.info(f"--- Starting preprocessing pipeline for {filename} ---")
    
    # 1. Load CSV
    df = load_dataset(raw_filepath)
    original_row_count = len(df)
    
    # 2. Strip whitespace from column names
    df = clean_column_names(df)
    
    # 3. Validate critical columns
    validate_required_columns(df)
    
    # 4. Remove duplicate rows
    df, duplicate_count = remove_duplicates(df)
    
    # 5. Parse Timestamp and remove rows with invalid timestamps
    df, invalid_timestamp_count = parse_timestamp(df)
    
    # 6. Sort chronologically
    df = df.sort_values(by="Timestamp").reset_index(drop=True)
    
    # 7. Replace +inf and -inf with NaN
    df = replace_infinite_values(df)
    
    # 8. Handle missing values safely
    df = handle_missing_values(df)
    
    # 9, 10, 11. Preserve original columns, create original_label, attack_category, is_attack
    df = standardize_labels(df)
    
    # 12. Validate processed dataset
    validate_processed_dataset(df)
    
    # 13. Save CSV into data/processed
    save_processed_dataset(df, processed_filepath)
    
    # Print validations/metrics
    final_row_count = len(df)
    logger.info(f"Metrics for {filename}:")
    logger.info(f"  Original row count: {original_row_count}")
    logger.info(f"  Duplicate rows removed: {duplicate_count}")
    logger.info(f"  Invalid timestamp rows removed: {invalid_timestamp_count}")
    logger.info(f"  Final row count: {final_row_count}")
    logger.info("  Attack Category Distribution:")
    category_counts = df["attack_category"].value_counts()
    for cat, count in category_counts.items():
        logger.info(f"    {cat}: {count}")
        
    logger.info(f"--- Completed preprocessing for {filename} ---\n")

def main():
    """Main function to run the pipeline over all datasets."""
    logger.info("Starting Master Data Preprocessing Pipeline...")
    for filename in DATASET_FILENAMES:
        try:
            preprocess_dataset(filename)
        except Exception as e:
            logger.error(f"Pipeline failed for {filename}: {e}", exc_info=True)
    logger.info("Master Data Preprocessing Pipeline finished.")

if __name__ == "__main__":
    main()
