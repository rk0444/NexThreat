"""
NexThreat Phase 4.1 — Model Infrastructure Utilities.

Provides reusable utilities for:
1. Deterministic global seed management (Python, NumPy, TensorFlow lazy/optional).
2. Canonical directory creation and path resolution.
3. Robust NumPy array loading and dtype-aware validation.
4. JSON report serialization and deserialization.
5. System environment and hardware introspection.
"""
from __future__ import annotations

from datetime import datetime
import json
import logging
import os
from pathlib import Path
import platform
import random
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

from src.models.config import (
    PROJECT_ROOT,
    RANDOM_SEED,
    ENABLE_DETERMINISTIC_OPERATIONS,
    REQUIRED_DIRECTORIES,
    to_project_relative,
)

logger = logging.getLogger("NexThreat.Models.Utils")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


# ============================================================
# CUSTOM JSON ENCODER FOR SCIENTIFIC TYPES
# ============================================================

class ScientificJSONEncoder(json.JSONEncoder):
    """
    JSON Encoder supporting Path, NumPy scalar types, arrays, and datetime.
    """
    def default(self, o: Any) -> Any:
        if isinstance(o, Path):
            return to_project_relative(o)
        if isinstance(o, (np.integer, np.int64, np.int32)):
            return int(o)
        if isinstance(o, (np.floating, np.float32, np.float64)):
            return float(o)
        if isinstance(o, np.ndarray):
            return o.tolist()
        if isinstance(o, (datetime,)):
            return o.isoformat()
        return super().default(o)


# ============================================================
# REPRODUCIBILITY & SEED MANAGEMENT (Refinements 2 & 3)
# ============================================================

def set_global_seed(seed: int = RANDOM_SEED) -> Dict[str, Any]:
    """
    Configure global deterministic seeds across Python, NumPy, and optional TensorFlow.

    Execution order:
    1. Configure relevant environment variables (PYTHONHASHSEED, TF_DETERMINISTIC_OPS).
    2. Seed Python standard random.
    3. Seed NumPy random.
    4. Attempt TensorFlow import safely (lazy import; PyTorch is excluded).
    5. If TensorFlow exists:
       - Set TensorFlow random seed.
       - Enable deterministic operations where supported.
    6. Continue without failure if TensorFlow is unavailable.

    Parameters
    ----------
    seed : int
        Integer seed value (default: RANDOM_SEED = 42).

    Returns
    -------
    Dict[str, Any]
        Diagnostic status dictionary describing configured seeds.
    """
    # 1. Environment variables
    os.environ["PYTHONHASHSEED"] = str(seed)
    if ENABLE_DETERMINISTIC_OPERATIONS:
        os.environ["TF_DETERMINISTIC_OPS"] = "1"
        os.environ["TF_CUDNN_DETERMINISTIC"] = "1"

    # 2. Python random
    random.seed(seed)

    # 3. NumPy random
    np.random.seed(seed)

    # 4 & 5. Safe lazy TensorFlow import
    tf_status: Dict[str, Any] = {
        "available": False,
        "version": None,
        "seed_configured": False,
        "determinism_enabled": False,
        "note": "TensorFlow not installed (optional dependency)",
    }

    try:
        import tensorflow as tf  # type: ignore
        tf_status["available"] = True
        tf_status["version"] = tf.__version__
        tf.random.set_seed(seed)
        tf_status["seed_configured"] = True

        if ENABLE_DETERMINISTIC_OPERATIONS:
            try:
                tf.config.experimental.enable_op_determinism()
                tf_status["determinism_enabled"] = True
                tf_status["note"] = "TensorFlow seeded with op determinism enabled"
            except Exception as det_err:
                tf_status["determinism_enabled"] = False
                tf_status["note"] = f"TensorFlow seeded (determinism warning: {det_err})"
        else:
            tf_status["note"] = "TensorFlow seeded (op determinism disabled by config)"

        logger.info("TensorFlow %s seeded successfully with seed=%d.", tf.__version__, seed)
    except ImportError:
        logger.info("TensorFlow is not installed. Skipping TensorFlow seeding.")
    except Exception as e:
        tf_status["note"] = f"TensorFlow import/seed notice: {e}"
        logger.warning("TensorFlow seeding encountered non-fatal note: %s", e)

    seed_report = {
        "seed": seed,
        "python_random_seeded": True,
        "numpy_random_seeded": True,
        "pytorch_handled": False,  # Explicitly False per Refinement 2
        "tensorflow": tf_status,
        "env_vars": {
            "PYTHONHASHSEED": os.environ.get("PYTHONHASHSEED"),
            "TF_DETERMINISTIC_OPS": os.environ.get("TF_DETERMINISTIC_OPS"),
            "TF_CUDNN_DETERMINISTIC": os.environ.get("TF_CUDNN_DETERMINISTIC"),
        },
    }
    return seed_report


# ============================================================
# DIRECTORY MANAGEMENT (Refinements 1 & 6)
# ============================================================

def ensure_directory(path: Union[Path, str]) -> Path:
    """
    Ensure a directory exists, creating parents as needed.

    Parameters
    ----------
    path : Union[Path, str]
        Path to directory.

    Returns
    -------
    Path
        Resolved directory Path.
    """
    p = Path(path).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def initialize_model_directories() -> List[Path]:
    """
    Initialize all canonical model and report directories defined in REQUIRED_DIRECTORIES.
    Does not hardcode directory counts or lists (Refinements 1 & 6).

    Returns
    -------
    List[Path]
        List of initialized directory Paths.
    """
    logger.info("Initializing canonical model infrastructure directories...")
    created_or_verified: List[Path] = []

    for directory in REQUIRED_DIRECTORIES:
        ensured = ensure_directory(directory)
        created_or_verified.append(ensured)
        logger.debug("Ensured directory: %s", to_project_relative(ensured))

    logger.info("Successfully initialized %d canonical directories.", len(created_or_verified))
    return created_or_verified


# ============================================================
# ARRAY LOADING & VALIDATION (Refinement 5)
# ============================================================

def load_numpy_array(path: Union[Path, str], mmap_mode: Optional[str] = None) -> np.ndarray:
    """
    Load a NumPy array from disk with validation.

    Parameters
    ----------
    path : Union[Path, str]
        Path to .npy file.
    mmap_mode : Optional[str]
        Memory map mode (e.g. 'r' for read-only memory mapping large arrays).

    Returns
    -------
    np.ndarray
        Loaded NumPy array.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"NumPy array file not found: {p}")
    return np.load(p, mmap_mode=mmap_mode)


def validate_numpy_array(
    arr: np.ndarray,
    expected_dtype: Optional[Union[np.dtype, type]] = None,
    expected_ndim: Optional[int] = None,
    expected_shape: Optional[Tuple[Optional[int], ...]] = None,
    check_finite: bool = True,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Validate a NumPy array against structural, type, and finiteness requirements.

    Dtype-aware finiteness handling (Refinement 5):
    - Floating-point arrays (e.g. float32, float64):
      * Checked for NaN and Infinity.
      * Validation fails if NaN or Inf is found.
    - Integer arrays (e.g. int64, int32 labels):
      * Does NOT call np.isnan() or np.isinf().
      * NaN/Inf checks are treated as not applicable.
    - Other types:
      * Validated against expected_dtype.

    Parameters
    ----------
    arr : np.ndarray
        Array to inspect.
    expected_dtype : Optional[Union[np.dtype, type]]
        Expected numpy dtype (e.g. np.float32 or np.int64).
    expected_ndim : Optional[int]
        Expected number of dimensions (e.g. 2 for tabular, 3 for sequence).
    expected_shape : Optional[Tuple[Optional[int], ...]]
        Expected shape tuple. None in any position allows any dimension size.
    check_finite : bool
        Whether to perform finiteness checks where applicable.

    Returns
    -------
    Tuple[bool, Dict[str, Any]]
        (passed, diagnostic_info_dict)
    """
    errors: List[str] = []

    if not isinstance(arr, np.ndarray):
        return False, {"error": f"Input is not a numpy.ndarray: {type(arr)}"}

    # 1. Non-empty check
    if arr.size == 0:
        errors.append("Array is empty (size == 0)")

    # 2. Dtype check
    dtype_match = True
    if expected_dtype is not None:
        expected_dt = np.dtype(expected_dtype)
        if arr.dtype != expected_dt:
            dtype_match = False
            errors.append(f"Dtype mismatch: expected {expected_dt}, got {arr.dtype}")

    # 3. Ndim check
    ndim_match = True
    if expected_ndim is not None:
        if arr.ndim != expected_ndim:
            ndim_match = False
            errors.append(f"Ndim mismatch: expected {expected_ndim}, got {arr.ndim}")

    # 4. Shape check
    shape_match = True
    if expected_shape is not None:
        if len(arr.shape) != len(expected_shape):
            shape_match = False
            errors.append(f"Shape length mismatch: expected rank {len(expected_shape)}, got {len(arr.shape)}")
        else:
            for i, (exp_dim, actual_dim) in enumerate(zip(expected_shape, arr.shape)):
                if exp_dim is not None and exp_dim != actual_dim:
                    shape_match = False
                    errors.append(f"Dimension {i} mismatch: expected {exp_dim}, got {actual_dim}")

    # 5. Dtype-aware finiteness check (Refinement 5)
    has_nan: Optional[bool] = None
    has_inf: Optional[bool] = None
    finite_applicable = False
    is_finite = True

    if check_finite and arr.size > 0:
        if np.issubdtype(arr.dtype, np.floating):
            finite_applicable = True
            has_nan = bool(np.isnan(arr).any())
            has_inf = bool(np.isinf(arr).any())
            if has_nan:
                errors.append("Array contains NaN values")
            if has_inf:
                errors.append("Array contains Infinite values")
            is_finite = not (has_nan or has_inf)
        elif np.issubdtype(arr.dtype, np.integer):
            # Integer arrays: NaN/Inf checks not applicable, do not call np.isnan/isinf
            finite_applicable = False
            has_nan = None
            has_inf = None
            is_finite = True
        else:
            # Non-float, non-integer numeric or object array
            finite_applicable = False
            if not dtype_match:
                errors.append(f"Unsupported non-numeric array dtype: {arr.dtype}")

    passed = len(errors) == 0

    info: Dict[str, Any] = {
        "shape": list(arr.shape),
        "dtype": str(arr.dtype),
        "ndim": int(arr.ndim),
        "size": int(arr.size),
        "finite_applicable": finite_applicable,
        "has_nan": has_nan,
        "has_inf": has_inf,
        "is_finite": is_finite,
        "passed": passed,
        "errors": errors,
    }

    return passed, info


# ============================================================
# REPORT SERIALIZATION & DESERIALIZATION (Refinement 7)
# ============================================================

def save_json_report(
    data: Dict[str, Any],
    file_path: Union[Path, str],
    indent: int = 4,
) -> Path:
    """
    Serialize data dictionary to JSON with support for scientific types.

    Parameters
    ----------
    data : Dict[str, Any]
        Dictionary to serialize.
    file_path : Union[Path, str]
        Destination file path.
    indent : int
        JSON indentation spaces.

    Returns
    -------
    Path
        Destination Path object.
    """
    p = Path(file_path).resolve()
    ensure_directory(p.parent)

    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, cls=ScientificJSONEncoder)

    logger.debug("Saved JSON report to: %s", to_project_relative(p))
    return p


def load_json_report(file_path: Union[Path, str]) -> Dict[str, Any]:
    """
    Load and parse a JSON report file.

    Parameters
    ----------
    file_path : Union[Path, str]
        Path to JSON file.

    Returns
    -------
    Dict[str, Any]
        Parsed JSON dictionary.
    """
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"JSON report file not found: {p}")

    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


# ============================================================
# SYSTEM & HARDWARE INTROSPECTION
# ============================================================

def get_system_environment_info() -> Dict[str, Any]:
    """
    Collect comprehensive system environment, Python runtime, and installed
    package details for infrastructure audit and reproducibility tracking.

    Returns
    -------
    Dict[str, Any]
        Environment diagnostic dictionary.
    """
    # Core packages
    packages: Dict[str, Optional[str]] = {}
    for pkg_name in ["numpy", "pandas", "sklearn", "joblib", "scipy"]:
        try:
            mod = __import__(pkg_name)
            packages[pkg_name] = getattr(mod, "__version__", "unknown")
        except ImportError:
            packages[pkg_name] = None

    # TensorFlow (optional)
    tf_info: Dict[str, Any] = {"installed": False, "version": None, "gpu_devices": []}
    try:
        import tensorflow as tf  # type: ignore
        tf_info["installed"] = True
        tf_info["version"] = tf.__version__
        try:
            gpus = tf.config.list_physical_devices("GPU")
            tf_info["gpu_devices"] = [str(g) for g in gpus]
        except Exception:
            pass
    except ImportError:
        pass

    # PyTorch check: strictly for audit documentation confirming it is NOT used
    pytorch_installed = False
    try:
        import torch  # type: ignore # noqa
        pytorch_installed = True
    except ImportError:
        pass

    return {
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "packages": packages,
        "tensorflow": tf_info,
        "pytorch_in_architecture": False,
        "pytorch_detected_in_env": pytorch_installed,
    }


# ============================================================
# CLI ENTRYPOINT (Refinement 9)
# ============================================================

def main() -> None:
    """
    CLI command to initialize directories and seed environment:
    python -m src.models.utils
    """
    logger.info("=" * 70)
    logger.info("NexThreat Phase 4.1 — Infrastructure Initialization")
    logger.info("=" * 70)

    # 1. Set global seed
    seed_report = set_global_seed(RANDOM_SEED)
    logger.info("Configured global seed=%d (TensorFlow available: %s)", RANDOM_SEED, seed_report["tensorflow"]["available"])

    # 2. Initialize directories
    dirs = initialize_model_directories()
    logger.info("Initialized %d canonical directories.", len(dirs))

    # 3. Environment info
    env_info = get_system_environment_info()
    logger.info(
        "Environment: Python %s on %s (%d CPU cores)",
        env_info["python_version"],
        env_info["system"],
        env_info["cpu_count"] or 1,
    )

    logger.info("=" * 70)
    logger.info("Phase 4.1 Infrastructure Initialization Complete.")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
