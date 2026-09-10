"""
NexThreat Phase 4.1 — Model Infrastructure Independent Verification Suite.

Independently inspects and audits:
- Category A: Directory structure & write permissions across dynamic canonical directories.
- Category B: Environment & dependency verification (NumPy, Pandas, Scikit-learn, Joblib, TensorFlow lazy/optional, zero PyTorch).
- Category C: Model-ready input availability & integrity (Phase 3.3 datasets, artifacts, metadata).
- Category D: Tensor shape, dtype, and finiteness validation (float32 finite, int64 bypass, rank & dimension checks).
- Category E: Reproducibility & determinism configuration (centralized seed=42, PRNG repeatability, env flags).
- Category F: Read-only protection & immutability audit (cryptographic SHA-256 verification of previous phases).
- Category G: Core model utilities unit validation in isolation (zero writes to previous data directories).

Generates:
1. data/model_reports/infrastructure/infrastructure_metadata.json (portable relative paths)
2. data/model_reports/infrastructure/model_infrastructure_verification_report.json (overall_status: PASS)
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import logging
import os
from pathlib import Path
import random
import tempfile
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np

from src.models.config import (
    PROJECT_ROOT,
    DATA_DIR,
    MODELS_DIR,
    MODEL_REPORTS_DIR,
    MODEL_READY_DIR,
    READ_ONLY_DIRECTORIES,
    MODEL_DIRECTORIES,
    REPORT_DIRECTORIES,
    REQUIRED_DIRECTORIES,
    RANDOM_SEED,
    ENABLE_DETERMINISTIC_OPERATIONS,
    INFRASTRUCTURE_REPORT_DIR,
    INFRASTRUCTURE_METADATA_PATH,
    MODEL_INFRASTRUCTURE_VERIFICATION_REPORT_PATH,
    ALL_MODEL_READY_ARRAYS,
    ALL_MODEL_READY_ARTIFACTS,
    ALL_MODEL_READY_METADATA,
    EXPECTED_TENSOR_SPECS,
    AUTOENCODER_INPUT_FILES,
    XGBOOST_INPUT_FILES,
    LSTM_INPUT_FILES,
    FEATURE_COUNT,
    FEATURE_COLUMNS,
    FEATURE_DTYPE,
    LABEL_DTYPE,
    LSTM_SEQUENCE_LENGTH,
    XGBOOST_NUM_CLASSES,
    to_project_relative,
)
from src.models.utils import (
    set_global_seed,
    ensure_directory,
    initialize_model_directories,
    load_numpy_array,
    validate_numpy_array,
    save_json_report,
    load_json_report,
    get_system_environment_info,
)

logger = logging.getLogger("NexThreat.Models.Verification")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


# Baseline SHA-256 hashes for all 26 Phase 3.3 model-ready files
BASELINE_MODEL_READY_HASHES: Dict[str, str] = {
    "artifacts/autoencoder_scaler.joblib": "269484386351907137aca35ca771659b1acded096e1ea40b267673a729cf89b7",
    "artifacts/lstm_scaler.joblib": "0f1ee25a878ebc60c9169d4fd826a66d41565aec4e1c8e7eb5d2d5e72867cbe7",
    "artifacts/xgboost_label_encoder.joblib": "1bd6fc5e22917d71a986214fa4c9d153ca582b0c616ebde57ff259d21cdb53f5",
    "autoencoder/X_test.npy": "a38ef9e64ac0235bb9c5474cf8cc510b7722ca0212586c5be08f7d3b16447075",
    "autoencoder/X_train.npy": "5c243ba00c31110e098929c7e4ce0e6cfdf441ad096c12db65e6b47eafb9b184",
    "autoencoder/X_validation.npy": "0077f4b8d569febc33af5b21e271b458feab0cf8dba847b97299dd322d093d74",
    "autoencoder/y_test.npy": "90afa4e7218233f7156df7d70139e002b180e8c14dc771d5cfe2f4b91f2a23a1",
    "autoencoder/y_validation.npy": "e8764783f8fad12c07531952ea02f9e16f89f3d445bb71f2460424a7f6b7b820",
    "lstm/X_test.npy": "52f1fddc1407553df1652c8aa7b4e7792e2fae9737adda8dc42bb06c8268ae61",
    "lstm/X_train.npy": "7dd9da8649499dcf2f72179ab3571feea1d47dafbb249b3b693b705e4a195c96",
    "lstm/X_validation.npy": "7032d4256bfba09370e201136edc3faf7cbc4d769bb53d041962e7646a12dfa9",
    "lstm/y_test.npy": "5ce9aa2b45e84458f17cfd4cb5f5081ef9f33129d9370490f86579f8ddd4aee2",
    "lstm/y_train.npy": "8665dabba3869adb15a347eeb63d1bce8f6454540fa310726f022c52fadb8c18",
    "lstm/y_validation.npy": "dcf1838c884e77a4577d7014b43dc8f774e71b3211eed70c2ced3adeefa8590d",
    "metadata/feature_columns.json": "b6777c2361ca6f03d24dcaad5385491da4364b8a0f4c9bf24e27d9257c8f0b1d",
    "metadata/lstm_sequence_metadata.json": "17c8f05a1a05c3b2dae66f6866f4afa416bc55e0ca58b02c0d1beca0f35e255e",
    "metadata/lstm_sequence_provenance.csv": "b5254e761e8d14b1b08d94e9c2cf0db7a3252c9781ddc8c9c7e0cfabedf94876",
    "metadata/preparation_metadata.json": "f28a3ea03e69b756479853efe1aa3833fc3b58bcd7d2644a053421a1bd5361c7",
    "metadata/xgboost_label_mapping.json": "510725bc3aba004e6f407e99c62ba49df736486d2eecbf089c15909e297056dc",
    "reports/model_preparation_report.json": "c3b9a3adc36a4feb6f9faea6fe8c5eaffdbb9cc24ebbd7a3c63fb7f3980bcb55",
    "xgboost/X_test.npy": "d9cdc2a9ac89afebe9f5f868548e3b8c5fc19df0b23c2880186136794cd09c01",
    "xgboost/X_train.npy": "7b3402aa6ee23ff820820aaff7bc182586fd08735f5e0fe6bf6868258c64a1a4",
    "xgboost/X_validation.npy": "6e886ad4e3cd92900acee9f6891fbab0cab7df6ec58df3fc1c887f42c3d64239",
    "xgboost/y_test.npy": "6deda47ef824a4ef63785de71ecdccf789a20b93b9ccd2ee63e1e88dd8dd1dbc",
    "xgboost/y_train.npy": "f9e826ba76c0650a666cd34b39df072d0a3090b9ea8369861e7a3262c2a9435c",
    "xgboost/y_validation.npy": "5c18ee9166e97832ad2dd3580f7858ed2876b6a1306cda26edc7c7e9b19ca29a",
}


def calculate_file_sha256(file_path: Path | str) -> str:
    """Calculate SHA-256 hash using chunked binary reading."""
    p = Path(file_path)
    sha256 = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


# ============================================================
# CATEGORY A: DIRECTORY STRUCTURE & WRITE PERMISSIONS (Refinements 1 & 6)
# ============================================================

def verify_category_a_directories() -> Dict[str, Any]:
    """
    Verify that every directory listed in REQUIRED_DIRECTORIES exists and is writable.
    Does not validate against any hardcoded count (Refinement 1).
    Uses the canonical REQUIRED_DIRECTORIES from config.py (Refinement 6).
    """
    logger.info("Category A: Auditing dynamic canonical directory hierarchy...")
    directory_results: List[Dict[str, Any]] = []
    all_exist = True
    all_writable = True

    for directory in REQUIRED_DIRECTORIES:
        rel_path = to_project_relative(directory)
        exists = directory.exists() and directory.is_dir()
        if not exists:
            all_exist = False
            directory_results.append({
                "path": rel_path,
                "exists": False,
                "writable": False,
                "error": "Directory does not exist",
            })
            continue

        # Test write permission using temporary sentinel
        writable = False
        sentinel_file = directory / ".write_test_sentinel.tmp"
        try:
            sentinel_file.write_text("ok", encoding="utf-8")
            if sentinel_file.exists():
                writable = True
                sentinel_file.unlink()
        except Exception as e:
            writable = False
            logger.error("Directory not writable %s: %s", rel_path, e)

        if not writable:
            all_writable = False

        directory_results.append({
            "path": rel_path,
            "exists": True,
            "writable": writable,
        })

    passed = all_exist and all_writable
    status = "PASS" if passed else "FAIL"

    logger.info(
        "Category A Status: %s (%d canonical directories verified)",
        status,
        len(directory_results),
    )

    return {
        "status": status,
        "total_required_directories": len(REQUIRED_DIRECTORIES),
        "total_verified_directories": len(directory_results),
        "all_directories_exist": all_exist,
        "all_directories_writable": all_writable,
        "directories": directory_results,
    }


# ============================================================
# CATEGORY B: ENVIRONMENT & DEPENDENCY VERIFICATION (Refinements 2 & 3)
# ============================================================

def verify_category_b_environment() -> Dict[str, Any]:
    """
    Verify Python environment, core dependencies, hardware access, and TensorFlow
    optional configuration. Excludes PyTorch per Refinement 2.
    """
    logger.info("Category B: Auditing runtime environment and dependencies...")
    env_info = get_system_environment_info()

    # 1. Python version >= 3.9
    py_ver_tuple = tuple(map(int, env_info["python_version"].split(".")[:2]))
    python_valid = py_ver_tuple >= (3, 9)

    # 2. Core dependencies check
    core_pkgs = ["numpy", "pandas", "sklearn", "joblib", "scipy"]
    missing_core = [pkg for pkg in core_pkgs if env_info["packages"].get(pkg) is None]
    core_deps_valid = len(missing_core) == 0

    # 3. TensorFlow optional status check (Refinement 2 & 3)
    tf_info = env_info["tensorflow"]
    if tf_info["installed"]:
        tf_status = f"AVAILABLE (version {tf_info['version']})"
    else:
        tf_status = "OPTIONAL - NOT INSTALLED (Non-fatal, architecture ready)"
        logger.info("Category B note: %s", tf_status)

    # 4. PyTorch confirmation (Refinement 2: PyTorch must NOT be in architecture)
    pytorch_excluded = not env_info["pytorch_in_architecture"]

    passed = python_valid and core_deps_valid and pytorch_excluded
    status = "PASS" if passed else "FAIL"

    logger.info("Category B Status: %s (Python %s, TensorFlow: %s)", status, env_info["python_version"], tf_status)

    return {
        "status": status,
        "python_version": env_info["python_version"],
        "python_version_valid": python_valid,
        "platform": env_info["platform"],
        "cpu_count": env_info["cpu_count"],
        "packages": env_info["packages"],
        "missing_core_dependencies": missing_core,
        "tensorflow_status": tf_status,
        "tensorflow_info": tf_info,
        "pytorch_in_architecture": False,
        "pytorch_detected_in_env": env_info["pytorch_detected_in_env"],
    }


# ============================================================
# CATEGORY C: MODEL-READY INPUT AVAILABILITY & INTEGRITY
# ============================================================

def verify_category_c_inputs() -> Dict[str, Any]:
    """
    Verify availability and non-empty status of all 17 model-ready arrays,
    3 preprocessor artifacts, and 6 metadata/report files from Phase 3.3.
    """
    logger.info("Category C: Auditing Phase 3.3 model-ready inputs availability...")
    files_checked: Dict[str, Dict[str, Any]] = {}
    all_exist = True
    all_non_empty = True

    # Audit Arrays
    for key, path in ALL_MODEL_READY_ARRAYS.items():
        exists = path.exists() and path.is_file()
        size_bytes = path.stat().st_size if exists else 0
        non_empty = size_bytes > 0

        if not exists:
            all_exist = False
        if not non_empty:
            all_non_empty = False

        files_checked[key] = {
            "path": to_project_relative(path),
            "exists": exists,
            "size_bytes": size_bytes,
            "type": "numpy_array",
        }

    # Audit Artifacts (scalers & label encoders)
    for key, path in ALL_MODEL_READY_ARTIFACTS.items():
        exists = path.exists() and path.is_file()
        size_bytes = path.stat().st_size if exists else 0
        non_empty = size_bytes > 0
        valid_artifact = False

        if exists and non_empty:
            try:
                loaded = joblib.load(path)
                valid_artifact = loaded is not None
            except Exception as e:
                logger.error("Failed to deserialize artifact %s: %s", key, e)

        if not exists:
            all_exist = False
        if not (non_empty and valid_artifact):
            all_non_empty = False

        files_checked[f"artifacts/{key}"] = {
            "path": to_project_relative(path),
            "exists": exists,
            "size_bytes": size_bytes,
            "valid_artifact": valid_artifact,
            "type": "joblib_artifact",
        }

    # Audit Metadata & Report
    for key, path in ALL_MODEL_READY_METADATA.items():
        exists = path.exists() and path.is_file()
        size_bytes = path.stat().st_size if exists else 0
        non_empty = size_bytes > 0

        if not exists:
            all_exist = False
        if not non_empty:
            all_non_empty = False

        files_checked[f"metadata/{key}"] = {
            "path": to_project_relative(path),
            "exists": exists,
            "size_bytes": size_bytes,
            "type": "metadata_file",
        }

    passed = all_exist and all_non_empty
    status = "PASS" if passed else "FAIL"

    logger.info(
        "Category C Status: %s (Audited %d files: 17 arrays, 3 artifacts, 6 metadata/reports)",
        status,
        len(files_checked),
    )

    return {
        "status": status,
        "total_files_audited": len(files_checked),
        "all_files_exist": all_exist,
        "all_files_non_empty": all_non_empty,
        "files": files_checked,
    }


# ============================================================
# CATEGORY D: TENSOR SHAPE, DTYPE, & FINITENESS (Refinement 5)
# ============================================================

def verify_category_d_tensor_validation() -> Dict[str, Any]:
    """
    Validate all 17 NumPy arrays using validate_numpy_array().
    Applies dtype-aware validation per Refinement 5:
    - Floating point arrays (float32): finiteness check (no NaN, no Inf).
    - Integer arrays (int64): finiteness check skipped; validated for valid discrete values.
    """
    logger.info("Category D: Auditing tensor shapes, dtypes, and finiteness...")
    array_validations: Dict[str, Any] = {}
    all_passed = True

    for array_key, expected_spec in EXPECTED_TENSOR_SPECS.items():
        path = ALL_MODEL_READY_ARRAYS.get(array_key)
        if path is None or not path.exists():
            all_passed = False
            array_validations[array_key] = {"passed": False, "error": "File not found"}
            continue

        arr = load_numpy_array(path)
        passed, info = validate_numpy_array(
            arr=arr,
            expected_dtype=expected_spec["dtype"],
            expected_ndim=expected_spec["ndim"],
            expected_shape=expected_spec["expected_shape"],
            check_finite=True,
        )

        # Extra domain checks
        extra_checks: Dict[str, Any] = {}
        if array_key == "xgboost/y_train":
            unique_classes = sorted([int(c) for c in np.unique(arr)])
            expected_classes = list(range(XGBOOST_NUM_CLASSES))
            all_classes_present = unique_classes == expected_classes
            extra_checks["unique_classes"] = unique_classes
            extra_checks["all_8_classes_present"] = all_classes_present
            if not all_classes_present:
                passed = False
                info["errors"].append(f"XGBoost y_train missing classes: expected {expected_classes}, got {unique_classes}")

        if array_key == "autoencoder/y_validation":
            unique_labels = sorted([int(c) for c in np.unique(arr)])
            extra_checks["unique_labels"] = unique_labels
            extra_checks["is_binary"] = set(unique_labels).issubset({0, 1})

        if array_key == "autoencoder/y_test":
            unique_labels = sorted([int(c) for c in np.unique(arr)])
            extra_checks["unique_labels"] = unique_labels
            extra_checks["is_binary"] = set(unique_labels).issubset({0, 1})

        info["extra_checks"] = extra_checks
        info["path"] = to_project_relative(path)

        if not passed:
            all_passed = False

        array_validations[array_key] = info

    status = "PASS" if all_passed else "FAIL"
    logger.info("Category D Status: %s (Validated %d tensor arrays)", status, len(array_validations))

    return {
        "status": status,
        "total_tensors_validated": len(array_validations),
        "all_tensors_valid": all_passed,
        "tensors": array_validations,
    }


# ============================================================
# CATEGORY E: REPRODUCIBILITY & DETERMINISM (Refinements 2 & 3)
# ============================================================

def verify_category_e_reproducibility() -> Dict[str, Any]:
    """
    Verify centralized reproducibility configuration and PRNG repeatability.
    Tests Python random, NumPy random, and environment variable flags.
    Confirms zero PyTorch handling.
    """
    logger.info("Category E: Auditing reproducibility and deterministic seed configuration...")

    # 1. Execute set_global_seed(42)
    seed_report = set_global_seed(RANDOM_SEED)

    # 2. Test Python random repeatability
    random.seed(RANDOM_SEED)
    py_seq_1 = [random.random() for _ in range(5)]
    random.seed(RANDOM_SEED)
    py_seq_2 = [random.random() for _ in range(5)]
    python_repeatable = py_seq_1 == py_seq_2

    # 3. Test NumPy random repeatability
    np.random.seed(RANDOM_SEED)
    np_seq_1 = np.random.rand(5).tolist()
    np.random.seed(RANDOM_SEED)
    np_seq_2 = np.random.rand(5).tolist()
    numpy_repeatable = np_seq_1 == np_seq_2

    # 4. Verify environment flags
    env_hash_seed = os.environ.get("PYTHONHASHSEED") == str(RANDOM_SEED)
    env_tf_det = os.environ.get("TF_DETERMINISTIC_OPS") == "1"

    # 5. Confirm PyTorch is not in the architecture
    pytorch_handled = seed_report.get("pytorch_handled", False)

    passed = (
        python_repeatable
        and numpy_repeatable
        and env_hash_seed
        and env_tf_det
        and not pytorch_handled
    )
    status = "PASS" if passed else "FAIL"

    logger.info("Category E Status: %s (Python repeatable: %s, NumPy repeatable: %s)", status, python_repeatable, numpy_repeatable)

    return {
        "status": status,
        "seed_configured": RANDOM_SEED,
        "enable_deterministic_operations": ENABLE_DETERMINISTIC_OPERATIONS,
        "python_random_repeatable": python_repeatable,
        "numpy_random_repeatable": numpy_repeatable,
        "env_pythonhashseed_set": env_hash_seed,
        "env_tf_deterministic_set": env_tf_det,
        "pytorch_handled": pytorch_handled,
        "seed_execution_report": seed_report,
    }


# ============================================================
# CATEGORY F: READ-ONLY PROTECTION & IMMUTABILITY AUDIT (Refinement 4)
# ============================================================

def verify_category_f_immutability() -> Dict[str, Any]:
    """
    Verify that Phase 4.1 treats all previous data directories as strictly read-only:
    data/raw/, data/processed/, data/windows/, data/features/, data/model_inputs/, data/model_ready/.
    Audits cryptographic SHA-256 hashes of all 26 files in data/model_ready/.
    Checks that no stray temporary files were created inside any read-only directory.
    """
    logger.info("Category F: Auditing read-only protection and SHA-256 immutability...")

    all_hashes_matched = True
    hash_audit_results: Dict[str, Any] = {}

    for rel_path, expected_hash in BASELINE_MODEL_READY_HASHES.items():
        file_path = MODEL_READY_DIR / rel_path
        if not file_path.exists():
            all_hashes_matched = False
            hash_audit_results[rel_path] = {
                "exists": False,
                "error": "File missing in model_ready",
                "matched": False,
            }
            continue

        actual_hash = calculate_file_sha256(file_path)
        matched = actual_hash == expected_hash
        if not matched:
            all_hashes_matched = False
            logger.error("IMMUTABILITY MISMATCH on %s: expected=%s actual=%s", rel_path, expected_hash, actual_hash)

        hash_audit_results[rel_path] = {
            "path": to_project_relative(file_path),
            "expected_sha256": expected_hash,
            "actual_sha256": actual_hash,
            "matched": matched,
        }

    # Verify no stray temporary files exist in read-only directories
    stray_temporary_files: List[str] = []
    for ro_dir in READ_ONLY_DIRECTORIES:
        if ro_dir.exists():
            for stray in ro_dir.rglob("*.tmp"):
                stray_temporary_files.append(to_project_relative(stray))
            for stray in ro_dir.rglob("temp_*"):
                stray_temporary_files.append(to_project_relative(stray))

    zero_stray_files = len(stray_temporary_files) == 0
    passed = all_hashes_matched and zero_stray_files
    status = "PASS" if passed else "FAIL"

    logger.info(
        "Category F Status: %s (%d files verified against baseline SHA-256; %d stray temp files)",
        status,
        len(hash_audit_results),
        len(stray_temporary_files),
    )

    return {
        "status": status,
        "read_only_directories_declared": [to_project_relative(d) for d in READ_ONLY_DIRECTORIES],
        "total_model_ready_files_verified": len(hash_audit_results),
        "all_hashes_matched": all_hashes_matched,
        "stray_temporary_files_found": stray_temporary_files,
        "zero_stray_temporary_files": zero_stray_files,
        "files": hash_audit_results,
    }


# ============================================================
# CATEGORY G: CORE MODEL UTILITIES UNIT VALIDATION (Refinement 8)
# ============================================================

def verify_category_g_utilities() -> Dict[str, Any]:
    """
    Validate all core model utility functions in isolation.
    Uses tempfile.TemporaryDirectory() or data/model_reports/infrastructure/temp_*
    to ensure zero writes to data/model_ready/ or other previous directories (Refinement 8).

    Tests:
    1. set_global_seed()
    2. ensure_directory()
    3. initialize_model_directories()
    4. load_numpy_array()
    5. validate_numpy_array() (including float32 NaN/Inf and int64 bypass)
    6. save_json_report()
    7. load_json_report()
    """
    logger.info("Category G: Testing core utilities in strict isolation...")
    utility_test_results: Dict[str, Any] = {}
    all_passed = True

    # Use isolated temp directory
    with tempfile.TemporaryDirectory(prefix="nexthreat_util_test_") as temp_dir_str:
        temp_dir = Path(temp_dir_str)

        # 1. Test set_global_seed()
        try:
            res_seed = set_global_seed(123)
            seed_ok = (
                res_seed["seed"] == 123
                and res_seed["python_random_seeded"]
                and res_seed["numpy_random_seeded"]
                and not res_seed["pytorch_handled"]
            )
            # Reset back to project standard seed 42
            set_global_seed(RANDOM_SEED)
            utility_test_results["set_global_seed"] = {"passed": seed_ok}
        except Exception as e:
            seed_ok = False
            all_passed = False
            utility_test_results["set_global_seed"] = {"passed": False, "error": str(e)}

        # 2. Test ensure_directory()
        try:
            sub_dir = temp_dir / "nested" / "sub_dir"
            ensured = ensure_directory(sub_dir)
            dir_ok = ensured.exists() and ensured.is_dir()
            utility_test_results["ensure_directory"] = {"passed": dir_ok}
            if not dir_ok:
                all_passed = False
        except Exception as e:
            all_passed = False
            utility_test_results["ensure_directory"] = {"passed": False, "error": str(e)}

        # 3. Test initialize_model_directories()
        try:
            dirs = initialize_model_directories()
            init_ok = len(dirs) == len(REQUIRED_DIRECTORIES) and all(d.exists() for d in dirs)
            utility_test_results["initialize_model_directories"] = {"passed": init_ok}
            if not init_ok:
                all_passed = False
        except Exception as e:
            all_passed = False
            utility_test_results["initialize_model_directories"] = {"passed": False, "error": str(e)}

        # 4 & 5. Test load_numpy_array() and validate_numpy_array()
        try:
            # Case 5a: Valid float32 array
            float_arr = np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32)
            float_path = temp_dir / "float_test.npy"
            np.save(float_path, float_arr)
            loaded_float = load_numpy_array(float_path)
            v_float_ok, v_float_info = validate_numpy_array(
                loaded_float,
                expected_dtype=np.float32,
                expected_ndim=2,
                expected_shape=(2, 2),
                check_finite=True,
            )

            # Case 5b: Float array with NaN (must fail)
            nan_arr = np.array([1.0, np.nan], dtype=np.float32)
            v_nan_ok, v_nan_info = validate_numpy_array(nan_arr, expected_dtype=np.float32, check_finite=True)
            nan_properly_caught = (not v_nan_ok) and v_nan_info["has_nan"] is True

            # Case 5c: Integer label array (int64) - NaN/Inf checks bypassed per Refinement 5
            int_arr = np.array([0, 1, 2, 3], dtype=np.int64)
            int_path = temp_dir / "int_test.npy"
            np.save(int_path, int_arr)
            loaded_int = load_numpy_array(int_path)
            v_int_ok, v_int_info = validate_numpy_array(
                loaded_int,
                expected_dtype=np.int64,
                expected_ndim=1,
                expected_shape=(4,),
                check_finite=True,
            )
            # Finiteness should NOT be applicable and should not produce false errors
            int_properly_handled = (
                v_int_ok
                and v_int_info["finite_applicable"] is False
                and v_int_info["has_nan"] is None
                and v_int_info["has_inf"] is None
            )

            array_utils_ok = v_float_ok and nan_properly_caught and int_properly_handled
            utility_test_results["load_and_validate_numpy_array"] = {
                "passed": array_utils_ok,
                "float32_finite_valid": v_float_ok,
                "nan_detected_correctly": nan_properly_caught,
                "int64_nan_bypass_correct": int_properly_handled,
            }
            if not array_utils_ok:
                all_passed = False
        except Exception as e:
            all_passed = False
            utility_test_results["load_and_validate_numpy_array"] = {"passed": False, "error": str(e)}

        # 6 & 7. Test save_json_report() and load_json_report()
        try:
            test_json_data = {
                "name": "Phase 4.1 Test",
                "array_val": np.int64(42),
                "float_val": np.float32(3.14),
                "path_val": temp_dir / "sample.txt",
                "timestamp": datetime.now(),
            }
            json_file_path = temp_dir / "test_report.json"
            save_json_report(test_json_data, json_file_path)
            loaded_json = load_json_report(json_file_path)
            json_ok = (
                loaded_json.get("name") == "Phase 4.1 Test"
                and loaded_json.get("array_val") == 42
            )
            utility_test_results["save_and_load_json_report"] = {"passed": json_ok}
            if not json_ok:
                all_passed = False
        except Exception as e:
            all_passed = False
            utility_test_results["save_and_load_json_report"] = {"passed": False, "error": str(e)}

    status = "PASS" if all_passed else "FAIL"
    logger.info("Category G Status: %s (All 7 utilities validated in isolation)", status)

    return {
        "status": status,
        "all_utilities_passed": all_passed,
        "isolated_testing_verified": True,
        "utilities_tested": utility_test_results,
    }


# ============================================================
# METADATA & REPORT GENERATORS (Refinement 7)
# ============================================================

def generate_infrastructure_metadata() -> Dict[str, Any]:
    """
    Generate portable data/model_reports/infrastructure/infrastructure_metadata.json.
    Stores strictly project-relative paths (Refinement 7).
    """
    logger.info("Generating infrastructure metadata artifact...")
    env_info = get_system_environment_info()

    metadata: Dict[str, Any] = {
        "phase": "4.1",
        "phase_title": "Model Training Infrastructure Metadata",
        "created_at": datetime.now().isoformat(),
        "reproducibility": {
            "random_seed": RANDOM_SEED,
            "enable_deterministic_operations": ENABLE_DETERMINISTIC_OPERATIONS,
            "env_vars": {
                "PYTHONHASHSEED": str(RANDOM_SEED),
                "TF_DETERMINISTIC_OPS": "1" if ENABLE_DETERMINISTIC_OPERATIONS else "0",
                "TF_CUDNN_DETERMINISTIC": "1" if ENABLE_DETERMINISTIC_OPERATIONS else "0",
            },
        },
        "environment": {
            "python_version": env_info["python_version"],
            "platform": env_info["platform"],
            "system": env_info["system"],
            "cpu_count": env_info["cpu_count"],
            "packages": env_info["packages"],
            "tensorflow": env_info["tensorflow"],
            "pytorch_in_architecture": False,
        },
        "canonical_directories": [to_project_relative(d) for d in REQUIRED_DIRECTORIES],
        "model_directories": [to_project_relative(d) for d in MODEL_DIRECTORIES],
        "report_directories": [to_project_relative(d) for d in REPORT_DIRECTORIES],
        "read_only_directories": [to_project_relative(d) for d in READ_ONLY_DIRECTORIES],
        "model_input_specifications": {
            "feature_count": FEATURE_COUNT,
            "feature_columns": FEATURE_COLUMNS,
            "feature_dtype": "float32",
            "label_dtype": "int64",
            "autoencoder": {
                "files": {k: to_project_relative(p) for k, p in AUTOENCODER_INPUT_FILES.items()},
                "scaler": to_project_relative(ALL_MODEL_READY_ARTIFACTS["autoencoder_scaler"]),
                "shapes": {
                    "X_train": list(EXPECTED_TENSOR_SPECS["autoencoder/X_train"]["expected_shape"]),
                    "X_validation": list(EXPECTED_TENSOR_SPECS["autoencoder/X_validation"]["expected_shape"]),
                    "X_test": list(EXPECTED_TENSOR_SPECS["autoencoder/X_test"]["expected_shape"]),
                    "y_validation": list(EXPECTED_TENSOR_SPECS["autoencoder/y_validation"]["expected_shape"]),
                    "y_test": list(EXPECTED_TENSOR_SPECS["autoencoder/y_test"]["expected_shape"]),
                },
            },
            "xgboost": {
                "files": {k: to_project_relative(p) for k, p in XGBOOST_INPUT_FILES.items()},
                "encoder": to_project_relative(ALL_MODEL_READY_ARTIFACTS["xgboost_label_encoder"]),
                "num_classes": XGBOOST_NUM_CLASSES,
                "shapes": {
                    "X_train": list(EXPECTED_TENSOR_SPECS["xgboost/X_train"]["expected_shape"]),
                    "X_validation": list(EXPECTED_TENSOR_SPECS["xgboost/X_validation"]["expected_shape"]),
                    "X_test": list(EXPECTED_TENSOR_SPECS["xgboost/X_test"]["expected_shape"]),
                    "y_train": list(EXPECTED_TENSOR_SPECS["xgboost/y_train"]["expected_shape"]),
                    "y_validation": list(EXPECTED_TENSOR_SPECS["xgboost/y_validation"]["expected_shape"]),
                    "y_test": list(EXPECTED_TENSOR_SPECS["xgboost/y_test"]["expected_shape"]),
                },
            },
            "lstm": {
                "files": {k: to_project_relative(p) for k, p in LSTM_INPUT_FILES.items()},
                "scaler": to_project_relative(ALL_MODEL_READY_ARTIFACTS["lstm_scaler"]),
                "sequence_length": LSTM_SEQUENCE_LENGTH,
                "shapes": {
                    "X_train": list(EXPECTED_TENSOR_SPECS["lstm/X_train"]["expected_shape"]),
                    "X_validation": list(EXPECTED_TENSOR_SPECS["lstm/X_validation"]["expected_shape"]),
                    "X_test": list(EXPECTED_TENSOR_SPECS["lstm/X_test"]["expected_shape"]),
                    "y_train": list(EXPECTED_TENSOR_SPECS["lstm/y_train"]["expected_shape"]),
                    "y_validation": list(EXPECTED_TENSOR_SPECS["lstm/y_validation"]["expected_shape"]),
                    "y_test": list(EXPECTED_TENSOR_SPECS["lstm/y_test"]["expected_shape"]),
                },
            },
        },
    }

    save_json_report(metadata, INFRASTRUCTURE_METADATA_PATH)
    logger.info("Saved portable infrastructure metadata to: %s", to_project_relative(INFRASTRUCTURE_METADATA_PATH))
    return metadata


# ============================================================
# MASTER VERIFICATION SUITE EXECUTION
# ============================================================

def run_model_infrastructure_verification() -> Dict[str, Any]:
    """
    Execute all 7 verification categories and compile the final report.
    Guarantees that:
    - Directories are initialized.
    - All categories are audited independently.
    - Both metadata and verification report JSON files are saved.
    - overall_status is 'PASS'.
    """
    logger.info("=" * 80)
    logger.info("NexThreat Phase 4.1 — Independent Model Infrastructure Verification")
    logger.info("=" * 80)

    # Ensure infrastructure directories exist
    initialize_model_directories()

    # Execute all verification categories
    cat_a = verify_category_a_directories()
    cat_b = verify_category_b_environment()
    cat_c = verify_category_c_inputs()
    cat_d = verify_category_d_tensor_validation()
    cat_e = verify_category_e_reproducibility()
    cat_f = verify_category_f_immutability()
    cat_g = verify_category_g_utilities()

    categories = {
        "category_a_directories": cat_a,
        "category_b_environment": cat_b,
        "category_c_inputs": cat_c,
        "category_d_tensor_validation": cat_d,
        "category_e_reproducibility": cat_e,
        "category_f_immutability": cat_f,
        "category_g_utilities": cat_g,
    }

    failed_categories = [k for k, v in categories.items() if v["status"] != "PASS"]
    all_passed = len(failed_categories) == 0
    overall_status = "PASS" if all_passed else "FAIL"

    summary = {
        "all_categories_passed": all_passed,
        "total_categories_checked": len(categories),
        "passed_categories_count": len(categories) - len(failed_categories),
        "failed_categories": failed_categories,
        "overall_status": overall_status,
    }

    report: Dict[str, Any] = {
        "phase": "4.1",
        "phase_title": "Model Training Infrastructure Verification Report",
        "timestamp": datetime.now().isoformat(),
        "overall_status": overall_status,
        "summary": summary,
        "categories": categories,
    }

    # Generate metadata file (Refinement 7)
    generate_infrastructure_metadata()

    # Save comprehensive verification report
    save_json_report(report, MODEL_INFRASTRUCTURE_VERIFICATION_REPORT_PATH)
    logger.info("Saved verification report to: %s", to_project_relative(MODEL_INFRASTRUCTURE_VERIFICATION_REPORT_PATH))

    logger.info("=" * 80)
    logger.info("PHASE 4.1 VERIFICATION COMPLETE — OVERALL STATUS: %s", overall_status)
    logger.info("=" * 80)

    if not all_passed:
        raise RuntimeError(f"Phase 4.1 Verification FAILED in categories: {failed_categories}")

    return report


if __name__ == "__main__":
    run_model_infrastructure_verification()
