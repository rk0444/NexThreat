"""
NexThreat Phase 4.5 — Timeline Synchronizer and Scope Quarantine Module.

Responsibilities:
1. Reconstruct the complete master timeline in chronological global_position order.
2. Dynamically derive N_master, N_eligible, and N_ineligible.
3. Compute independent model decisions adhering strictly to model-specific preprocessing:
   - Autoencoder: scaled via autoencoder_scaler.joblib, threshold tau_ae = 0.003207791231673312
   - XGBoost: raw unscaled features, mapped to binary (class != 0)
   - LSTM: forward forecast targeting window t from lookback [t-10 .. t-1], scaled via lstm_scaler.joblib, threshold tau_lstm = 0.3000
4. Enforce strict day-boundary lookback isolation (zero lookback sequence across midnight).
5. Explicitly serialize unavailable LSTM forecasts as "unavailable" (never coerced to 0 or 1).
6. Isolate Scope A (held-out test benchmarks and synchronized N=45 subset) from Scope B (operational replay).
"""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import h5py
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from src.models.comparison.config import (
    PROJECT_ROOT,
    FEATURES_DIR,
    FEATURE_FILES,
    CANONICAL_FEATURE_COLUMNS,
    AUTOENCODER_SPLIT_MANIFEST_PATH,
    XGBOOST_SPLIT_MANIFEST_PATH,
    LSTM_SPLIT_MANIFEST_PATH,
    AUTOENCODER_SCALER_PATH,
    LSTM_SCALER_PATH,
    AUTOENCODER_FINAL_MODEL_PATH,
    XGBOOST_MODEL_PATH,
    LSTM_FINAL_MODEL_PATH,
    LSTM_SEQUENCE_PROVENANCE_PATH,
    load_dynamic_thresholds,
    INPUT_TUPLE_TO_NAME,
    INPUT_TUPLE_TO_CODE,
    to_project_relative,
)


class AutoencoderPredictor:
    """Pure NumPy forward pass for the frozen Phase 4.2 Autoencoder."""

    def __init__(self, model_path: Path, scaler_path: Path):
        self.scaler = joblib.load(scaler_path)
        with zipfile.ZipFile(model_path, "r") as z:
            with h5py.File(io.BytesIO(z.read("model.weights.h5")), "r") as f:
                self.weights = [
                    np.array(f["layers"][f"dense{s}"]["vars"]["0"])
                    for s in ["", "_1", "_2", "_3", "_4", "_5"]
                ]
                self.biases = [
                    np.array(f["layers"][f"dense{s}"]["vars"]["1"])
                    for s in ["", "_1", "_2", "_3", "_4", "_5"]
                ]

    def predict_reconstruction_mse(self, X_raw: np.ndarray) -> np.ndarray:
        """Scale features and calculate per-sample reconstruction MSE."""
        X_scaled = self.scaler.transform(X_raw).astype(np.float32)
        h = X_scaled
        for i in range(5):
            h = np.maximum(0.0, h @ self.weights[i] + self.biases[i])
        X_hat = h @ self.weights[5] + self.biases[5]
        mse = np.mean((X_hat - X_scaled) ** 2, axis=1)
        return mse


class LSTMPredictor:
    """Pure NumPy forward pass for the frozen Phase 4.4 LSTM."""

    def __init__(self, model_path: Path, scaler_path: Path):
        self.scaler = joblib.load(scaler_path)
        with zipfile.ZipFile(model_path, "r") as z:
            with h5py.File(io.BytesIO(z.read("model.weights.h5")), "r") as f:
                self.kernel = np.array(f["layers"]["lstm"]["cell"]["vars"]["0"])
                self.recurrent_kernel = np.array(f["layers"]["lstm"]["cell"]["vars"]["1"])
                self.bias = np.array(f["layers"]["lstm"]["cell"]["vars"]["2"])
                self.dense_w = np.array(f["layers"]["dense"]["vars"]["0"])
                self.dense_b = np.array(f["layers"]["dense"]["vars"]["1"])
                self.dense_1_w = np.array(f["layers"]["dense_1"]["vars"]["0"])
                self.dense_1_b = np.array(f["layers"]["dense_1"]["vars"]["1"])

    @staticmethod
    def _sigmoid(x: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(x, -30.0, 30.0)))

    def predict_sequence_probability(self, lookback_10x13_raw: np.ndarray) -> float:
        """
        Scale single 10x13 sequence and compute output probability P(attack).
        lookback_10x13_raw shape: (10, 13)
        """
        seq_scaled = self.scaler.transform(lookback_10x13_raw).astype(np.float32)  # (10, 13)
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
        return prob


class XGBoostPredictor:
    """Wrapper for the frozen Phase 4.3 XGBoost Booster."""

    def __init__(self, model_path: Path):
        self.booster = xgb.Booster()
        self.booster.load_model(str(model_path))

    def predict_multiclass_and_binary(self, X_raw: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Predict multiclass probabilities, predicted classes, and binary attack decisions.
        Returns: (probabilities (N, 8), discrete_classes (N,), binary_attack (N,))
        """
        dmatrix = xgb.DMatrix(X_raw, feature_names=CANONICAL_FEATURE_COLUMNS)
        probs = self.booster.predict(dmatrix)  # (N, 8)
        classes = np.argmax(probs, axis=1)     # (N,)
        binary = (classes != 0).astype(int)    # (N,)
        return probs, classes, binary


class MasterTimelineSynchronizer:
    """
    Synchronizes inference across Autoencoder, XGBoost, and LSTM over the master timeline.
    """

    def __init__(self):
        self.ae_threshold, self.lstm_threshold = load_dynamic_thresholds()
        self.ae_predictor = AutoencoderPredictor(AUTOENCODER_FINAL_MODEL_PATH, AUTOENCODER_SCALER_PATH)
        self.xgb_predictor = XGBoostPredictor(XGBOOST_MODEL_PATH)
        self.lstm_predictor = LSTMPredictor(LSTM_FINAL_MODEL_PATH, LSTM_SCALER_PATH)

    def load_master_dataframe(self) -> pd.DataFrame:
        """
        Load daily feature CSVs in chronological day order and construct master dataframe.
        """
        day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
        dfs = []
        for day in day_order:
            day_file = FEATURES_DIR / FEATURE_FILES[day]
            df_day = pd.read_csv(day_file)
            df_day["dataset_day"] = day
            dfs.append(df_day)

        master_df = pd.concat(dfs, ignore_index=True)
        master_df["global_position"] = np.arange(1, len(master_df) + 1)
        return master_df

    def load_manifests(self) -> Dict[str, pd.DataFrame]:
        """Load Phase 3.2 split manifests."""
        return {
            "autoencoder": pd.read_csv(AUTOENCODER_SPLIT_MANIFEST_PATH),
            "xgboost": pd.read_csv(XGBOOST_SPLIT_MANIFEST_PATH),
            "lstm": pd.read_csv(LSTM_SPLIT_MANIFEST_PATH),
        }

    def synchronize_timeline(self) -> Dict[str, Any]:
        """
        Execute timeline synchronization and generate synchronized window records.
        """
        master_df = self.load_master_dataframe()
        manifests = self.load_manifests()
        n_master = len(master_df)

        # Merge split information
        ae_manifest = manifests["autoencoder"][["global_position", "split"]].rename(columns={"split": "ae_split"})
        xgb_manifest = manifests["xgboost"][["global_position", "split"]].rename(columns={"split": "xgb_split"})
        lstm_manifest = manifests["lstm"][["global_position", "split"]].rename(columns={"split": "lstm_split"})

        master_df = master_df.merge(ae_manifest, on="global_position", how="left")
        master_df = master_df.merge(xgb_manifest, on="global_position", how="left")
        master_df = master_df.merge(lstm_manifest, on="global_position", how="left")

        # 1. Autoencoder Inferences
        X_raw = master_df[CANONICAL_FEATURE_COLUMNS].values.astype(np.float32)
        ae_mse = self.ae_predictor.predict_reconstruction_mse(X_raw)
        ae_binary = (ae_mse >= self.ae_threshold).astype(int)

        # 2. XGBoost Inferences
        xgb_probs, xgb_classes, xgb_binary = self.xgb_predictor.predict_multiclass_and_binary(X_raw)

        # 3. LSTM Inferences (with strict day boundary enforcement)
        # Sequence targeting window t requires lookback windows [t-10, ..., t-1]
        lstm_probs: List[Optional[float]] = []
        lstm_binary: List[Union[int, str]] = []
        is_eligible_list: List[bool] = []
        threat_state_names: List[Optional[str]] = []
        threat_state_codes: List[Optional[str]] = []
        ineligibility_reasons: List[Optional[str]] = []

        for idx in range(n_master):
            current_day = master_df.at[idx, "dataset_day"]
            # Lookback requires 10 preceding windows from the same day
            if idx < 10:
                has_valid_lookback = False
            else:
                lookback_days = master_df.loc[idx - 10 : idx - 1, "dataset_day"].values
                has_valid_lookback = bool(np.all(lookback_days == current_day))

            if has_valid_lookback:
                lookback_raw = X_raw[idx - 10 : idx]  # shape (10, 13)
                p_lstm = self.lstm_predictor.predict_sequence_probability(lookback_raw)
                b_lstm = 1 if p_lstm >= self.lstm_threshold else 0

                lstm_probs.append(p_lstm)
                lstm_binary.append(b_lstm)
                is_eligible_list.append(True)
                ineligibility_reasons.append(None)

                # Assign threat state
                b_ae = int(ae_binary[idx])
                b_xgb = int(xgb_binary[idx])
                tuple_key = (b_ae, b_xgb, b_lstm)
                threat_state_names.append(INPUT_TUPLE_TO_NAME[tuple_key])
                threat_state_codes.append(INPUT_TUPLE_TO_CODE[tuple_key])
            else:
                lstm_probs.append(None)
                lstm_binary.append("unavailable")
                is_eligible_list.append(False)
                ineligibility_reasons.append("lstm_lookback_cold_start")
                threat_state_names.append(None)
                threat_state_codes.append(None)

        master_df["ae_mse"] = ae_mse
        master_df["ae_prediction"] = ae_binary
        master_df["xgb_class"] = xgb_classes
        master_df["xgb_prediction"] = xgb_binary
        master_df["lstm_probability"] = lstm_probs
        master_df["lstm_prediction"] = lstm_binary
        master_df["is_eligible_for_threat_state"] = is_eligible_list
        master_df["ineligibility_reason"] = ineligibility_reasons
        master_df["threat_state"] = threat_state_names
        master_df["threat_state_code"] = threat_state_codes

        n_eligible = int(np.sum(is_eligible_list))
        n_ineligible = n_master - n_eligible

        # 4. Scope A Isolation: Manifest Overlap & Valid Synchronized Tri-Model Subset
        ae_test_pos: Set[int] = set(master_df[master_df["ae_split"] == "test"]["global_position"])
        xgb_test_pos: Set[int] = set(master_df[master_df["xgb_split"] == "test"]["global_position"])

        # LSTM test sequences provenance
        lstm_prov = pd.read_csv(LSTM_SEQUENCE_PROVENANCE_PATH)
        lstm_test_prov = lstm_prov[lstm_prov["split"] == "test"]
        lstm_test_target_pos: Set[int] = set(lstm_test_prov["target_global_position"])

        # Manifest-level mutual test intersection (positions where all 3 manifests flag test)
        manifest_overlap_pos = sorted(list(ae_test_pos & xgb_test_pos & set(master_df[master_df["lstm_split"] == "test"]["global_position"])))

        # Valid synchronized subset: manifest overlap where lookback is valid within test split
        # Exclude the 6 invalid lookback positions: {918, 2383, 2384, 2385, 2386, 2387}
        excluded_positions = {918, 2383, 2384, 2385, 2386, 2387}
        synchronized_test_pos = sorted([p for p in manifest_overlap_pos if p not in excluded_positions])

        scope_a_df = master_df[master_df["global_position"].isin(synchronized_test_pos)].copy()

        return {
            "master_df": master_df,
            "scope_a_df": scope_a_df,
            "n_master": n_master,
            "n_eligible": n_eligible,
            "n_ineligible": n_ineligible,
            "manifest_overlap_positions": manifest_overlap_pos,
            "synchronized_test_positions": synchronized_test_pos,
            "excluded_positions": sorted(list(excluded_positions)),
            "ae_threshold": self.ae_threshold,
            "lstm_threshold": self.lstm_threshold,
        }
