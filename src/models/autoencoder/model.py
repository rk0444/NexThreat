"""
NexThreat Phase 4.2 — Autoencoder Model Architecture.

Implements the deterministic symmetric neural network:
Input(13) -> Dense(32, ReLU) -> Dense(16, ReLU) -> Dense(8, ReLU)
          -> Dense(16, ReLU) -> Dense(32, ReLU) -> Dense(13, Linear)
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

from src.models.autoencoder.config import (
    INPUT_DIM,
    LATENT_DIM,
    HIDDEN_ACTIVATION,
    OUTPUT_ACTIVATION,
    LEARNING_RATE,
    LOSS_FUNCTION,
)

logger = logging.getLogger("NexThreat.Models.Autoencoder.Model")


def build_autoencoder(
    input_dim: int = INPUT_DIM,
    latent_dim: int = LATENT_DIM,
    learning_rate: float = LEARNING_RATE,
) -> keras.Model:
    """
    Construct and compile the NexThreat Autoencoder architecture.

    Parameters
    ----------
    input_dim : int
        Feature dimensionality (default: FEATURE_COUNT = 13).
    latent_dim : int
        Compressed bottleneck dimensionality (default: 8).
    learning_rate : float
        Adam optimizer learning rate (default: 0.001).

    Returns
    -------
    keras.Model
        Compiled Keras Autoencoder model ready for unsupervised training.
    """
    logger.info(
        "Building Autoencoder model: %d -> 32 -> 16 -> %d -> 16 -> 32 -> %d",
        input_dim,
        latent_dim,
        input_dim,
    )

    # Input Layer
    inputs = keras.Input(shape=(input_dim,), name="features_input", dtype=tf.float32)

    # Encoder
    x = layers.Dense(32, activation=HIDDEN_ACTIVATION, name="encoder_dense_1")(inputs)
    x = layers.Dense(16, activation=HIDDEN_ACTIVATION, name="encoder_dense_2")(x)
    bottleneck = layers.Dense(latent_dim, activation=HIDDEN_ACTIVATION, name="bottleneck_latent")(x)

    # Decoder
    x = layers.Dense(16, activation=HIDDEN_ACTIVATION, name="decoder_dense_1")(bottleneck)
    x = layers.Dense(32, activation=HIDDEN_ACTIVATION, name="decoder_dense_2")(x)
    outputs = layers.Dense(input_dim, activation=OUTPUT_ACTIVATION, name="reconstruction_output")(x)

    # Full Autoencoder Model
    autoencoder = keras.Model(inputs=inputs, outputs=outputs, name="nexthreat_autoencoder")

    optimizer = keras.optimizers.Adam(learning_rate=learning_rate)
    autoencoder.compile(
        optimizer=optimizer,
        loss=LOSS_FUNCTION,
        metrics=["mse"],
    )

    return autoencoder
