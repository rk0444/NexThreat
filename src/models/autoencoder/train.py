"""
NexThreat Phase 4.2 — Autoencoder Model Training Pipeline.

Trains the unsupervised Autoencoder strictly on pure-BENIGN training features (X_train),
using X_validation strictly to monitor validation reconstruction loss and trigger
early stopping. Attack labels and test splits are never accessed during training.
"""
from __future__ import annotations

from datetime import datetime
import logging
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import tensorflow as tf
from tensorflow import keras

from src.models.config import (
    RANDOM_SEED,
    AUTOENCODER_INPUT_FILES,
    FEATURE_COUNT,
    FEATURE_DTYPE,
    to_project_relative,
)
from src.models.utils import (
    set_global_seed,
    ensure_directory,
    load_numpy_array,
    validate_numpy_array,
    save_json_report,
)
from src.models.autoencoder.config import (
    INPUT_DIM,
    BATCH_SIZE,
    MAX_EPOCHS,
    LEARNING_RATE,
    EARLY_STOPPING_MONITOR,
    EARLY_STOPPING_MODE,
    EARLY_STOPPING_PATIENCE,
    RESTORE_BEST_WEIGHTS,
    BEST_MODEL_PATH,
    FINAL_MODEL_PATH,
    TRAINING_REPORT_PATH,
    TRAINING_HISTORY_PATH,
    REQUIRED_AUTOENCODER_DIRS,
)
from src.models.autoencoder.model import build_autoencoder

logger = logging.getLogger("NexThreat.Models.Autoencoder.Train")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def train_autoencoder() -> Dict[str, Any]:
    """
    Execute end-to-end Autoencoder training.

    Returns
    -------
    Dict[str, Any]
        Training summary diagnostics.
    """
    logger.info("=" * 70)
    logger.info("NexThreat Phase 4.2 — Autoencoder Model Training")
    logger.info("=" * 70)

    start_time = datetime.now()

    # 1. Enforce global deterministic seed
    seed_report = set_global_seed(RANDOM_SEED)
    logger.info("Configured global seed=%d (TF Deterministic: %s)", RANDOM_SEED, seed_report["tensorflow"]["determinism_enabled"])

    # 2. Ensure all Autoencoder output directories exist
    for directory in REQUIRED_AUTOENCODER_DIRS:
        ensure_directory(directory)

    # 3. Load model-ready input datasets (strictly read-only from Phase 3.3)
    train_path = AUTOENCODER_INPUT_FILES["X_train"]
    val_path = AUTOENCODER_INPUT_FILES["X_validation"]

    logger.info("Loading training features from: %s", to_project_relative(train_path))
    X_train = load_numpy_array(train_path)

    logger.info("Loading validation features from: %s", to_project_relative(val_path))
    X_val = load_numpy_array(val_path)

    # 4. Validate input arrays
    train_valid, train_info = validate_numpy_array(
        X_train,
        expected_dtype=FEATURE_DTYPE,
        expected_ndim=2,
        expected_shape=(1511, FEATURE_COUNT),
        check_finite=True,
    )
    if not train_valid:
        raise ValueError(f"X_train validation failed: {train_info['errors']}")

    val_valid, val_info = validate_numpy_array(
        X_val,
        expected_dtype=FEATURE_DTYPE,
        expected_ndim=2,
        expected_shape=(535, FEATURE_COUNT),
        check_finite=True,
    )
    if not val_valid:
        raise ValueError(f"X_validation validation failed: {val_info['errors']}")

    logger.info(
        "Validated datasets: X_train=%s (%d samples), X_validation=%s (%d samples)",
        X_train.shape,
        len(X_train),
        X_val.shape,
        len(X_val),
    )

    # 5. Construct Autoencoder architecture
    model = build_autoencoder(
        input_dim=FEATURE_COUNT,
        learning_rate=LEARNING_RATE,
    )
    model.summary(print_fn=logger.info)

    # 6. Configure training callbacks
    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor=EARLY_STOPPING_MONITOR,
            mode=EARLY_STOPPING_MODE,
            patience=EARLY_STOPPING_PATIENCE,
            restore_best_weights=RESTORE_BEST_WEIGHTS,
            verbose=1,
        ),
        keras.callbacks.ModelCheckpoint(
            filepath=str(BEST_MODEL_PATH),
            monitor=EARLY_STOPPING_MONITOR,
            mode=EARLY_STOPPING_MODE,
            save_best_only=True,
            verbose=1,
        ),
    ]

    # 7. Unsupervised training: target is input itself (X_train -> X_train)
    logger.info(
        "Starting model fit: epochs=%d, batch_size=%d, patience=%d",
        MAX_EPOCHS,
        BATCH_SIZE,
        EARLY_STOPPING_PATIENCE,
    )

    history = model.fit(
        x=X_train,
        y=X_train,
        validation_data=(X_val, X_val),
        epochs=MAX_EPOCHS,
        batch_size=BATCH_SIZE,
        callbacks=callbacks,
        shuffle=True,
        verbose=1,
    )

    end_time = datetime.now()

    # 8. Save final model
    ensure_directory(FINAL_MODEL_PATH.parent)
    model.save(str(FINAL_MODEL_PATH))
    logger.info("Saved final model to: %s", to_project_relative(FINAL_MODEL_PATH))

    # 9. Extract and serialize training history
    history_dict = {
        "epoch": list(range(1, len(history.history["loss"]) + 1)),
        "loss": [float(v) for v in history.history["loss"]],
        "val_loss": [float(v) for v in history.history["val_loss"]],
    }
    save_json_report(history_dict, TRAINING_HISTORY_PATH)
    logger.info("Saved training history to: %s", to_project_relative(TRAINING_HISTORY_PATH))

    # 10. Extract metrics
    actual_epochs = len(history_dict["epoch"])
    val_losses = history_dict["val_loss"]
    best_epoch = int(np.argmin(val_losses) + 1)
    best_val_loss = float(np.min(val_losses))
    final_train_loss = float(history_dict["loss"][-1])
    final_val_loss = float(val_losses[-1])
    early_stopped = actual_epochs < MAX_EPOCHS

    training_report: Dict[str, Any] = {
        "phase": "4.2",
        "model": "autoencoder",
        "training_start": start_time.isoformat(),
        "training_end": end_time.isoformat(),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
        "random_seed": RANDOM_SEED,
        "training_sample_count": len(X_train),
        "validation_sample_count": len(X_val),
        "feature_count": FEATURE_COUNT,
        "batch_size": BATCH_SIZE,
        "maximum_epochs": MAX_EPOCHS,
        "actual_epochs": actual_epochs,
        "best_epoch": best_epoch,
        "best_validation_loss": best_val_loss,
        "final_training_loss": final_train_loss,
        "final_validation_loss": final_val_loss,
        "early_stopping_status": {
            "triggered": early_stopped,
            "patience": EARLY_STOPPING_PATIENCE,
            "restore_best_weights": RESTORE_BEST_WEIGHTS,
        },
        "saved_model_paths": {
            "best_model": to_project_relative(BEST_MODEL_PATH),
            "final_model": to_project_relative(FINAL_MODEL_PATH),
        },
    }

    save_json_report(training_report, TRAINING_REPORT_PATH)
    logger.info("Saved training report to: %s", to_project_relative(TRAINING_REPORT_PATH))

    logger.info("=" * 70)
    logger.info(
        "Autoencoder Training Complete: Best Epoch %d (Val Loss: %.6f)",
        best_epoch,
        best_val_loss,
    )
    logger.info("=" * 70)

    return training_report


if __name__ == "__main__":
    train_autoencoder()
