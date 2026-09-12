"""
NexThreat Phase 4.4 — LSTM Model Architecture & Deterministic Construction.

Implements the Keras sequence model architecture:
Input(10, 13) -> LSTM(units) -> Dropout(rate) -> Dense(units, relu) -> Dropout(rate) -> Dense(1, sigmoid)
with strict seed initialization and Adam optimizer compilation.
"""
from __future__ import annotations

import logging
import os
import random
from typing import Any, Dict, Optional, Tuple

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

from src.models.lstm.config import (
    INPUT_SHAPE,
    LOSS_FUNCTION,
    RANDOM_SEED,
)

logger = logging.getLogger("NexThreat.Models.LSTM.Model")


def set_deterministic_seeds(seed: int = RANDOM_SEED) -> None:
    """
    Set deterministic seeds across Python hash seed, Python random, NumPy,
    and TensorFlow runtime for reproducible execution.
    """
    os.environ["PYTHONHASHSEED"] = str(seed)
    os.environ["TF_DETERMINISTIC_OPS"] = "1"
    random.seed(seed)
    np.random.seed(seed)
    tf.random.set_seed(seed)
    try:
        tf.config.experimental.enable_op_determinism()
    except (AttributeError, RuntimeError) as e:
        logger.debug("Op determinism already set or unsupported: %s", e)
    logger.debug("Deterministic seeds set to %d across all runtimes.", seed)


def build_lstm_candidate(
    candidate_config: Dict[str, Any],
    input_shape: Tuple[int, int] = INPUT_SHAPE,
    model_name: Optional[str] = None,
) -> keras.Model:
    """
    Construct and compile a Keras LSTM candidate binary forecasting model.

    Parameters
    ----------
    candidate_config : Dict[str, Any]
        Candidate specification containing units, dropout rates, activations,
        and learning rate.
    input_shape : Tuple[int, int]
        Sequence input shape (default: (10, 13)).
    model_name : Optional[str]
        Optional name for the Keras model.

    Returns
    -------
    keras.Model
        Compiled Keras LSTM model.
    """
    lstm_units = candidate_config["lstm_units"]
    lstm_dropout = candidate_config["lstm_dropout"]
    dense_units = candidate_config["dense_units"]
    dense_activation = candidate_config["dense_activation"]
    dense_dropout = candidate_config["dense_dropout"]
    output_units = candidate_config["output_units"]
    output_activation = candidate_config["output_activation"]
    learning_rate = candidate_config["learning_rate"]

    name = model_name or candidate_config.get("name", "lstm_forecaster")

    logger.info(
        "Building %s: Input%s -> LSTM(%d) -> Dropout(%.2f) -> Dense(%d, %s) -> Dropout(%.2f) -> Dense(%d, %s)",
        name,
        input_shape,
        lstm_units,
        lstm_dropout,
        dense_units,
        dense_activation,
        dense_dropout,
        output_units,
        output_activation,
    )

    inputs = keras.Input(shape=input_shape, name="sequence_input", dtype=tf.float32)
    x = layers.LSTM(lstm_units, return_sequences=False, name="lstm_layer")(inputs)
    x = layers.Dropout(lstm_dropout, name="lstm_dropout")(x)
    x = layers.Dense(dense_units, activation=dense_activation, name="dense_hidden")(x)
    x = layers.Dropout(dense_dropout, name="dense_dropout")(x)
    outputs = layers.Dense(output_units, activation=output_activation, name="output_sigmoid")(x)

    model = keras.Model(inputs=inputs, outputs=outputs, name=name)

    optimizer = keras.optimizers.Adam(learning_rate=learning_rate)
    model.compile(
        optimizer=optimizer,
        loss=LOSS_FUNCTION,
        metrics=["accuracy"],
    )

    return model
