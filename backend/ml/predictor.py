"""
Prediction service — loads the active model and performs inference.
Applies the saved preprocessing pipeline (no leakage).
Caches the active model in memory to avoid reloading on every request.
"""
import os
import json
import time

import joblib
import numpy as np
import pandas as pd

from backend.ml.preprocessor import NIDSPreprocessor
from backend.ml.attack_taxonomy import normalize_label
from backend.utils.severity import assign_severity
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# In-memory cache of the active model
_cached_version: str = None
_cached_model = None
_cached_preprocessor: NIDSPreprocessor = None
_cached_classes: list = None


def _load_model(model_dir: str):
    """Load model + preprocessor from disk."""
    global _cached_model, _cached_preprocessor, _cached_classes, _cached_version

    if _cached_version == model_dir and _cached_model is not None:
        return  # Already cached

    logger.info(f"Loading model from {model_dir}")
    model_path = os.path.join(model_dir, "model.pkl")
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")

    _cached_model = joblib.load(model_path)
    _cached_preprocessor = NIDSPreprocessor.load(model_dir)

    label_config_path = os.path.join(model_dir, "label_config.json")
    if os.path.exists(label_config_path):
        with open(label_config_path) as f:
            cfg = json.load(f)
        _cached_classes = cfg.get("classes", [])
    else:
        _cached_classes = []

    _cached_version = model_dir
    logger.info(f"Model loaded. Classes: {_cached_classes}")


def predict_single(features: dict, model_dir: str, model_version: str = "unknown") -> dict:
    """
    Predict a single network flow record.
    features: dict of {feature_name: value}
    Returns full prediction result.
    """
    _load_model(model_dir)

    # Build DataFrame from features
    df = pd.DataFrame([features])

    t_start = time.time()
    X = _cached_preprocessor.transform(df)
    pred_label = _cached_model.predict(X)[0]
    pred_time = round(time.time() - t_start, 4)

    # Normalize label
    attack_type, _ = normalize_label(pred_label)

    # Confidence / probability
    confidence = 1.0
    probabilities = {}
    if hasattr(_cached_model, "predict_proba"):
        probs = _cached_model.predict_proba(X)[0]
        classes = _cached_model.classes_
        probabilities = {str(c): round(float(p), 4) for c, p in zip(classes, probs)}
        confidence = round(float(np.max(probs)), 4)

    # Severity
    severity = assign_severity(attack_type, confidence)
    is_intrusion = attack_type != "BENIGN"

    return {
        "prediction": attack_type,
        "raw_prediction": str(pred_label),
        "status": "Intrusion Detected" if is_intrusion else "Normal Traffic",
        "is_intrusion": is_intrusion,
        "confidence": confidence,
        "probabilities": probabilities,
        "severity": severity,
        "model_version": model_version,
        "prediction_time": pred_time,
    }


def predict_batch(df: pd.DataFrame, model_dir: str, model_version: str = "unknown") -> list:
    """
    Predict an entire DataFrame of network flow records.
    Returns list of prediction result dicts.
    """
    _load_model(model_dir)

    X = _cached_preprocessor.transform(df)
    preds = _cached_model.predict(X)

    probabilities_all = None
    if hasattr(_cached_model, "predict_proba"):
        probabilities_all = _cached_model.predict_proba(X)

    results = []
    for i, pred in enumerate(preds):
        attack_type, _ = normalize_label(str(pred))
        confidence = 1.0
        probs = {}
        if probabilities_all is not None:
            row_probs = probabilities_all[i]
            classes = _cached_model.classes_
            probs = {str(c): round(float(p), 4) for c, p in zip(classes, row_probs)}
            confidence = round(float(np.max(row_probs)), 4)

        severity = assign_severity(attack_type, confidence)
        is_intrusion = attack_type != "BENIGN"

        result = {
            "prediction": attack_type,
            "raw_prediction": str(pred),
            "status": "Intrusion Detected" if is_intrusion else "Normal Traffic",
            "is_intrusion": is_intrusion,
            "confidence": confidence,
            "severity": severity,
            "model_version": model_version,
        }
        results.append(result)

    return results


def invalidate_cache():
    """Force a model reload on next prediction."""
    global _cached_version, _cached_model, _cached_preprocessor, _cached_classes
    _cached_version = None
    _cached_model = None
    _cached_preprocessor = None
    _cached_classes = None
    logger.info("Model cache invalidated.")
