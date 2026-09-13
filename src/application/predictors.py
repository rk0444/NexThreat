"""
NexThreat Phase 5.2 — Independent Read-Only Model Predictors.

Implements single authoritative, pure NumPy forward passes for Autoencoder
and LSTM (extracted from frozen .keras HDF5 weights) and a Booster wrapper
for XGBoost, strictly preserving Phase 4.5 / 4.7 verified behavior.
Zero Keras fallback, zero retraining, zero scaler refitting.
"""
from __future__ import annotations

import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import zipfile

import h5py
import joblib
import numpy as np
import xgboost as xgb

from src.application.config import (
    AUTOENCODER_FINAL_MODEL_PATH,
    AUTOENCODER_SCALER_PATH,
    AUTOENCODER_THRESHOLD,
    XGBOOST_MODEL_PATH,
    XGBOOST_INDEX_TO_CLASS,
    CANONICAL_FEATURE_COLUMNS,
    LSTM_FINAL_MODEL_PATH,
    LSTM_RUNTIME_SCALER_PATH,
    LSTM_THRESHOLD,
)
from src.application.exceptions import ModelExecutionError


class AutoencoderPredictor:
    """Pure NumPy forward pass for the frozen Phase 4.2 Autoencoder."""

    def __init__(
        self,
        model_path: Path = AUTOENCODER_FINAL_MODEL_PATH,
        scaler_path: Path = AUTOENCODER_SCALER_PATH,
        threshold: float = AUTOENCODER_THRESHOLD,
    ):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.threshold = float(threshold)

        if not self.scaler_path.exists():
            raise ModelExecutionError(f"Missing Autoencoder scaler artifact: {self.scaler_path}")
        if not self.model_path.exists():
            raise ModelExecutionError(f"Missing Autoencoder model artifact: {self.model_path}")

        try:
            self.scaler = joblib.load(self.scaler_path)
            with zipfile.ZipFile(self.model_path, "r") as z:
                with h5py.File(io.BytesIO(z.read("model.weights.h5")), "r") as f:
                    self.weights = [
                        np.array(f["layers"][f"dense{s}"]["vars"]["0"], dtype=np.float32)
                        for s in ["", "_1", "_2", "_3", "_4", "_5"]
                    ]
                    self.biases = [
                        np.array(f["layers"][f"dense{s}"]["vars"]["1"], dtype=np.float32)
                        for s in ["", "_1", "_2", "_3", "_4", "_5"]
                    ]
        except Exception as e:
            raise ModelExecutionError(f"Failed to load Autoencoder weights or scaler: {e}") from e

    def predict_sample(self, X_raw: np.ndarray) -> Tuple[float, int]:
        """
        Scale 13 features and calculate reconstruction MSE and discrete anomaly decision.
        Decision Rule: MSE > 0.003207791231673312
        Returns: (reconstruction_mse, is_anomaly)
        """
        try:
            X_2d = X_raw.reshape(1, -1)
            X_scaled = self.scaler.transform(X_2d).astype(np.float32)
            h = X_scaled
            for i in range(5):
                h = np.maximum(0.0, h @ self.weights[i] + self.biases[i])
            X_hat = h @ self.weights[5] + self.biases[5]
            mse = float(np.mean((X_hat - X_scaled) ** 2))
            is_anomaly = 1 if mse > self.threshold else 0
            return mse, is_anomaly
        except Exception as e:
            raise ModelExecutionError(f"Autoencoder inference execution failed: {e}") from e


class XGBoostPredictor:
    """Wrapper for the frozen Phase 4.3 XGBoost Booster."""

    def __init__(
        self,
        model_path: Path = XGBOOST_MODEL_PATH,
        class_mapping: Optional[Dict[int, str]] = None,
    ):
        self.model_path = model_path
        self.class_mapping = class_mapping or XGBOOST_INDEX_TO_CLASS

        if not self.model_path.exists():
            raise ModelExecutionError(f"Missing XGBoost model artifact: {self.model_path}")

        try:
            self.booster = xgb.Booster()
            self.booster.load_model(str(self.model_path))
        except Exception as e:
            raise ModelExecutionError(f"Failed to load XGBoost booster: {e}") from e

    def predict_sample(self, X_raw: np.ndarray) -> Tuple[int, str, int, List[float]]:
        """
        Predict 8-class probabilities, predicted class index, canonical class name, and binary attack decision.
        Features are passed unscaled.
        Binary Decision: class_index != 0
        Returns: (predicted_class_index, predicted_class_name, is_attack, class_probabilities)
        """
        try:
            X_2d = X_raw.reshape(1, -1)
            dmatrix = xgb.DMatrix(X_2d, feature_names=CANONICAL_FEATURE_COLUMNS)
            probs = self.booster.predict(dmatrix)[0]  # (8,)
            class_idx = int(np.argmax(probs))
            class_name = self.class_mapping.get(class_idx, f"UNKNOWN_{class_idx}")
            is_attack = 1 if class_idx != 0 else 0
            return class_idx, class_name, is_attack, [float(p) for p in probs]
        except Exception as e:
            raise ModelExecutionError(f"XGBoost inference execution failed: {e}") from e


class LSTMPredictor:
    """Pure NumPy forward pass for the frozen Phase 4.4 LSTM."""

    def __init__(
        self,
        model_path: Path = LSTM_FINAL_MODEL_PATH,
        scaler_path: Path = LSTM_RUNTIME_SCALER_PATH,
        threshold: float = LSTM_THRESHOLD,
    ):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.threshold = float(threshold)

        if not self.scaler_path.exists():
            raise ModelExecutionError(f"Missing LSTM scaler artifact: {self.scaler_path}")
        if not self.model_path.exists():
            raise ModelExecutionError(f"Missing LSTM model artifact: {self.model_path}")

        try:
            self.scaler = joblib.load(self.scaler_path)
            with zipfile.ZipFile(self.model_path, "r") as z:
                with h5py.File(io.BytesIO(z.read("model.weights.h5")), "r") as f:
                    self.kernel = np.array(f["layers"]["lstm"]["cell"]["vars"]["0"], dtype=np.float32)
                    self.recurrent_kernel = np.array(f["layers"]["lstm"]["cell"]["vars"]["1"], dtype=np.float32)
                    self.bias = np.array(f["layers"]["lstm"]["cell"]["vars"]["2"], dtype=np.float32)
                    self.dense_w = np.array(f["layers"]["dense"]["vars"]["0"], dtype=np.float32)
                    self.dense_b = np.array(f["layers"]["dense"]["vars"]["1"], dtype=np.float32)
                    self.dense_1_w = np.array(f["layers"]["dense_1"]["vars"]["0"], dtype=np.float32)
                    self.dense_1_b = np.array(f["layers"]["dense_1"]["vars"]["1"], dtype=np.float32)
        except Exception as e:
            raise ModelExecutionError(f"Failed to load LSTM weights or scaler: {e}") from e

    @staticmethod
    def _sigmoid(x: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(x, -30.0, 30.0)))

    def predict_sequence(self, lookback_10x13: np.ndarray) -> Tuple[float, int]:
        """
        Scale single 10x13 historical sequence and compute future attack forecast probability.
        Decision Rule: probability >= 0.3000
        Returns: (forecast_probability, forecast_decision)
        """
        try:
            if lookback_10x13.shape != (10, 13):
                raise ValueError(f"Expected lookback shape (10, 13), got {lookback_10x13.shape}")

            seq_scaled = self.scaler.transform(lookback_10x13).astype(np.float32)
            h = np.zeros(32, dtype=np.float32)
            c = np.zeros(32, dtype=np.float32)
            for t in range(10):
                xt = seq_scaled[t]
                z = xt @ self.kernel + h @ self.recurrent_kernel + self.bias
                zi, zf, zc, zo = np.split(z, 4)
                i = self._sigmoid(zi)
                f = self._sigmoid(zf)
                c_cand = np.tanh(zc)
                o = self._sigmoid(zo)
                c = f * c + i * c_cand
                h = o * np.tanh(c)

            d = np.maximum(0.0, h @ self.dense_w + self.dense_b)
            prob = float(self._sigmoid(d @ self.dense_1_w + self.dense_1_b)[0])
            decision = 1 if prob >= self.threshold else 0
            return prob, decision
        except Exception as e:
            raise ModelExecutionError(f"LSTM inference execution failed: {e}") from e
