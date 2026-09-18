"""
Training pipeline for NIDS models.
Supports Random Forest (primary), Logistic Regression, Decision Tree, SVM.
Each training run saves: model.pkl + preprocessor artifacts + metadata.json
"""
import os
import json
import time
import uuid
from datetime import datetime

import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split

from backend.ml.preprocessor import NIDSPreprocessor
from backend.ml.evaluator import evaluate_model, get_feature_importance
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Supported model types
MODEL_TYPES = {
    "random_forest": {
        "label": "Random Forest",
        "class": RandomForestClassifier,
        "params": {
            "n_estimators": 100,
            "max_depth": 20,
            "min_samples_split": 5,
            "n_jobs": -1,
            "random_state": 42,
            "class_weight": "balanced",
        },
    },
    "logistic_regression": {
        "label": "Logistic Regression",
        "class": LogisticRegression,
        "params": {
            "max_iter": 1000,
            "random_state": 42,
            "class_weight": "balanced",
            "n_jobs": -1,
        },
    },
    "decision_tree": {
        "label": "Decision Tree",
        "class": DecisionTreeClassifier,
        "params": {
            "max_depth": 20,
            "random_state": 42,
            "class_weight": "balanced",
        },
    },
    "svm": {
        "label": "Support Vector Machine",
        "class": SVC,
        "params": {
            "kernel": "rbf",
            "probability": True,
            "random_state": 42,
            "class_weight": "balanced",
        },
    },
}


def train_model(
    csv_path: str,
    model_type: str = "random_forest",
    test_size: float = 0.2,
    model_base_dir: str = "models",
    dataset_name: str = "unknown",
    trained_by: str = "system",
    max_rows: int = 100000,
) -> dict:
    """
    Full training pipeline.
    Returns model metadata dict (to be saved in MongoDB).
    Raises on any failure.
    """
    if model_type not in MODEL_TYPES:
        raise ValueError(f"Unknown model type: {model_type}. Choose from {list(MODEL_TYPES)}")

    model_id = str(uuid.uuid4())[:8]
    version = f"{model_type[:2].upper()}-v{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    model_dir = os.path.join(model_base_dir, version)
    os.makedirs(model_dir, exist_ok=True)

    logger.info(f"Starting training: {model_type} | version={version} | dataset={dataset_name}")

    # ── 1. Load dataset ────────────────────────────────────────────────────────
    df = pd.read_csv(csv_path, nrows=max_rows, low_memory=False)
    total_rows = len(df)
    logger.info(f"Loaded {total_rows} rows from {csv_path}")

    if total_rows < 100:
        raise ValueError(f"Dataset too small: {total_rows} rows. Minimum 100 required.")

    # ── 2. Preprocess ──────────────────────────────────────────────────────────
    preprocessor = NIDSPreprocessor()
    X, y, feature_names = preprocessor.fit_transform(df)

    # ── 3. Train/test split ────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )
    logger.info(f"Split: {len(X_train)} train / {len(X_test)} test")

    # ── 4. Build & train model ─────────────────────────────────────────────────
    cfg = MODEL_TYPES[model_type]
    clf = cfg["class"](**cfg["params"])

    train_start = time.time()
    clf.fit(X_train, y_train)
    train_time = round(time.time() - train_start, 2)
    logger.info(f"Training completed in {train_time}s")

    # ── 5. Evaluate ────────────────────────────────────────────────────────────
    pred_start = time.time()
    metrics = evaluate_model(clf, X_test, y_test)
    pred_time = round(time.time() - pred_start, 2)
    metrics["training_time"] = train_time
    metrics["prediction_time"] = pred_time

    # Feature importance
    importance = get_feature_importance(clf, feature_names)

    # ── 6. Save artifacts ──────────────────────────────────────────────────────
    joblib.dump(clf, os.path.join(model_dir, "model.pkl"))
    preprocessor.save(model_dir)

    # Class labels
    classes = sorted(list(set(y)))
    label_config = {"classes": classes, "feature_names": feature_names}
    with open(os.path.join(model_dir, "label_config.json"), "w") as f:
        json.dump(label_config, f, indent=2)

    # Metadata
    metadata = {
        "model_id": model_id,
        "version": version,
        "model_type": model_type,
        "model_label": cfg["label"],
        "model_dir": model_dir,
        "dataset_name": dataset_name,
        "training_date": datetime.utcnow().isoformat(),
        "feature_count": len(feature_names),
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "total_samples": total_rows,
        "classes": classes,
        "metrics": metrics,
        "feature_importance": importance[:20],  # top 20
        "trained_by": trained_by,
        "status": "TRAINED",
    }
    with open(os.path.join(model_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2, default=str)

    logger.info(
        f"Model saved to {model_dir} | "
        f"Accuracy={metrics['accuracy']:.4f} | F1={metrics['f1_weighted']:.4f}"
    )
    return metadata


def compare_models(
    csv_path: str,
    model_base_dir: str = "models",
    dataset_name: str = "unknown",
    max_rows: int = 50000,
) -> list:
    """
    Train all model types on the same split and return comparison results.
    Does NOT save models — comparison only.
    """
    df = pd.read_csv(csv_path, nrows=max_rows, low_memory=False)
    preprocessor = NIDSPreprocessor()
    X, y, feature_names = preprocessor.fit_transform(df)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    results = []
    for mtype, cfg in MODEL_TYPES.items():
        logger.info(f"Comparing model: {mtype}")
        try:
            clf = cfg["class"](**cfg["params"])
            t_start = time.time()
            clf.fit(X_train, y_train)
            train_time = round(time.time() - t_start, 2)
            p_start = time.time()
            metrics = evaluate_model(clf, X_test, y_test)
            pred_time = round(time.time() - p_start, 2)
            results.append({
                "model_type": mtype,
                "model_label": cfg["label"],
                "accuracy": metrics["accuracy"],
                "precision": metrics["precision_weighted"],
                "recall": metrics["recall_weighted"],
                "f1_weighted": metrics["f1_weighted"],
                "f1_macro": metrics["f1_macro"],
                "training_time": train_time,
                "prediction_time": pred_time,
                "roc_auc": metrics.get("roc_auc"),
                "status": "success",
            })
        except Exception as e:
            logger.error(f"Model comparison failed for {mtype}: {e}")
            results.append({
                "model_type": mtype,
                "model_label": cfg["label"],
                "status": "failed",
                "error": str(e),
            })
    return results
