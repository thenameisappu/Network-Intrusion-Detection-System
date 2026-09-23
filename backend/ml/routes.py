"""ML/Model routes — /models/*, /predict/*"""
import os
import threading
from flask import Blueprint, request, g, current_app
from werkzeug.utils import secure_filename

from backend.ml.trainer import train_model, compare_models, MODEL_TYPES
from backend.ml.predictor import predict_single, predict_batch, invalidate_cache
from backend.ml.feature_config import FEATURE_NAMES
from backend.database.repositories.model_repo import ModelRepository
from backend.database.repositories.dataset_repo import DatasetRepository
from backend.database.repositories.detection_repo import DetectionRepository
from backend.database.repositories.alert_repo import AlertRepository
from backend.database.repositories.audit_repo import AuditRepository
from backend.utils.response import success_response, error_response
from backend.utils.decorators import login_required, admin_required
from backend.utils.severity import assign_severity
from backend.utils.logger import get_logger
import pandas as pd

ml_bp = Blueprint("ml", __name__)
logger = get_logger(__name__)


# ── Model management ───────────────────────────────────────────────────────────

@ml_bp.route("/models", methods=["GET"])
@login_required
def list_models():
    repo = ModelRepository()
    models = repo.list_all()
    return success_response("Models retrieved.", data={"models": models})


@ml_bp.route("/models/active", methods=["GET"])
@login_required
def get_active_model():
    repo = ModelRepository()
    model = repo.find_active()
    if not model:
        return error_response("No active model found.", "NO_ACTIVE_MODEL", status_code=404)
    return success_response("Active model.", data=model)


@ml_bp.route("/models/<model_id>", methods=["GET"])
@login_required
def get_model(model_id: str):
    repo = ModelRepository()
    model = repo.find_by_id(model_id)
    if not model:
        return error_response("Model not found.", "NOT_FOUND", status_code=404)
    return success_response("Model details.", data=model)


@ml_bp.route("/models/<model_id>/activate", methods=["POST"])
@admin_required
def activate_model(model_id: str):
    model_repo = ModelRepository()
    model = model_repo.find_by_id(model_id)
    if not model:
        return error_response("Model not found.", "NOT_FOUND", status_code=404)
    if model["status"] == "FAILED":
        return error_response("Cannot activate a FAILED model.", "INVALID_STATUS")

    model_repo.set_active(model_id)
    invalidate_cache()  # Clear cached model

    AuditRepository().log(
        "MODEL_ACTIVATED", user_id=g.current_user["id"],
        username=g.current_user["username"],
        details={"model_id": model_id, "version": model.get("version")},
    )
    return success_response("Model activated.", data={"model_id": model_id, "version": model.get("version")})


@ml_bp.route("/models/<model_id>", methods=["DELETE"])
@admin_required
def delete_model(model_id: str):
    model_repo = ModelRepository()
    model = model_repo.find_by_id(model_id)
    if not model:
        return error_response("Model not found.", "NOT_FOUND", status_code=404)
    if model["status"] == "ACTIVE":
        return error_response("Cannot delete the active model. Activate another model first.", "ACTIVE_MODEL")

    import shutil
    model_dir = model.get("model_dir")
    if model_dir and os.path.exists(model_dir):
        shutil.rmtree(model_dir, ignore_errors=True)
    model_repo.delete(model_id)
    return success_response("Model deleted.")


# ── Training ───────────────────────────────────────────────────────────────────

@ml_bp.route("/models/train", methods=["POST"])
@admin_required
def train():
    data = request.get_json(silent=True) or {}
    dataset_id = data.get("dataset_id")
    model_type = data.get("model_type", "random_forest")
    test_size = float(data.get("test_size", 0.2))

    if not dataset_id:
        return error_response("dataset_id is required.", "MISSING_FIELD")
    if model_type not in MODEL_TYPES:
        return error_response(f"Invalid model_type. Choose from: {list(MODEL_TYPES.keys())}", "INVALID_MODEL_TYPE")

    ds_repo = DatasetRepository()
    dataset = ds_repo.find_by_id(dataset_id)
    if not dataset:
        return error_response("Dataset not found.", "NOT_FOUND", status_code=404)

    filepath = dataset.get("filepath")
    if not filepath or not os.path.exists(filepath):
        return error_response("Dataset file not found on disk.", "FILE_NOT_FOUND", status_code=404)

    model_base_dir = current_app.config["MODEL_PATH"]

    # Run training synchronously (async with status tracking for large datasets)
    try:
        metadata = train_model(
            csv_path=filepath,
            model_type=model_type,
            test_size=test_size,
            model_base_dir=model_base_dir,
            dataset_name=dataset.get("name", "unknown"),
            trained_by=g.current_user["username"],
        )
    except Exception as e:
        logger.error(f"Training failed: {e}")
        return error_response(f"Training failed: {str(e)}", "TRAINING_FAILED", status_code=500)

    model_repo = ModelRepository()
    model_db_id = model_repo.create(metadata)

    AuditRepository().log(
        "MODEL_TRAINED",
        user_id=g.current_user["id"], username=g.current_user["username"],
        details={"model_db_id": model_db_id, "version": metadata.get("version"),
                 "model_type": model_type, "accuracy": metadata["metrics"]["accuracy"]},
    )

    return success_response("Model trained successfully.", data={
        "model_db_id": model_db_id,
        "version": metadata["version"],
        "metrics": metadata["metrics"],
        "feature_count": metadata["feature_count"],
    }, status_code=201)


@ml_bp.route("/models/evaluate/<model_id>", methods=["POST"])
@admin_required
def evaluate_model_endpoint(model_id: str):
    """Re-evaluate an existing model on a dataset."""
    data = request.get_json(silent=True) or {}
    dataset_id = data.get("dataset_id")
    if not dataset_id:
        return error_response("dataset_id is required.", "MISSING_FIELD")

    model_repo = ModelRepository()
    ds_repo = DatasetRepository()
    model = model_repo.find_by_id(model_id)
    dataset = ds_repo.find_by_id(dataset_id)

    if not model:
        return error_response("Model not found.", "NOT_FOUND", status_code=404)
    if not dataset:
        return error_response("Dataset not found.", "NOT_FOUND", status_code=404)

    return success_response("Evaluation metrics.", data={
        "metrics": model.get("metrics", {}),
        "feature_importance": model.get("feature_importance", []),
    })


@ml_bp.route("/models/compare", methods=["POST"])
@admin_required
def compare():
    data = request.get_json(silent=True) or {}
    dataset_id = data.get("dataset_id")
    if not dataset_id:
        return error_response("dataset_id is required.", "MISSING_FIELD")

    ds_repo = DatasetRepository()
    dataset = ds_repo.find_by_id(dataset_id)
    if not dataset:
        return error_response("Dataset not found.", "NOT_FOUND", status_code=404)

    filepath = dataset.get("filepath")
    if not filepath or not os.path.exists(filepath):
        return error_response("Dataset file not found on disk.", "FILE_NOT_FOUND", status_code=404)

    try:
        results = compare_models(
            csv_path=filepath,
            model_base_dir=current_app.config["MODEL_PATH"],
            dataset_name=dataset.get("name", "unknown"),
        )
    except Exception as e:
        return error_response(f"Comparison failed: {str(e)}", "COMPARISON_FAILED", status_code=500)

    return success_response("Model comparison complete.", data={"results": results})


@ml_bp.route("/models/types", methods=["GET"])
@login_required
def model_types():
    types = [{"type": k, "label": v["label"]} for k, v in MODEL_TYPES.items()]
    return success_response("Available model types.", data={"types": types})


# ── Prediction ─────────────────────────────────────────────────────────────────

@ml_bp.route("/predict", methods=["POST"])
@login_required
def predict():
    data = request.get_json(silent=True) or {}
    features = data.get("features")
    if not features or not isinstance(features, dict):
        return error_response("'features' dict is required.", "MISSING_FEATURES")

    model_repo = ModelRepository()
    active_model = model_repo.find_active()
    if not active_model:
        return error_response("No active model. Please train and activate a model first.", "NO_ACTIVE_MODEL", status_code=404)

    model_dir = active_model.get("model_dir")
    if not model_dir or not os.path.exists(model_dir):
        return error_response("Active model files not found on disk.", "MODEL_FILES_MISSING", status_code=500)

    try:
        result = predict_single(
            features=features,
            model_dir=model_dir,
            model_version=active_model.get("version", "unknown"),
        )
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return error_response(f"Prediction failed: {str(e)}", "PREDICTION_FAILED", status_code=500)

    # Extract optional metadata
    source_ip = data.get("source_ip", "unknown")
    destination_ip = data.get("destination_ip", "unknown")
    source_port = int(data.get("source_port", 0))
    destination_port = int(data.get("destination_port", 0))
    protocol = data.get("protocol", "unknown")

    # Store detection
    detection_doc = {
        "source_ip": source_ip, "destination_ip": destination_ip,
        "source_port": source_port, "destination_port": destination_port,
        "protocol": protocol,
        "prediction": result["prediction"],
        "confidence": result["confidence"],
        "severity": result["severity"],
        "is_intrusion": result["is_intrusion"],
        "model_version": result["model_version"],
        "features": {k: v for k, v in list(features.items())[:10]},  # Sample only
    }
    det_repo = DetectionRepository()
    detection_id = det_repo.create(detection_doc)

    # Generate alert if intrusion detected
    if result["is_intrusion"]:
        alert_repo = AlertRepository()
        alert_repo.create({
            "detection_id": detection_id,
            "source_ip": source_ip, "destination_ip": destination_ip,
            "source_port": source_port, "destination_port": destination_port,
            "protocol": protocol,
            "attack_type": result["prediction"],
            "severity": result["severity"],
            "confidence": result["confidence"],
            "model_version": result["model_version"],
        })

    result["detection_id"] = detection_id
    return success_response("Prediction complete.", data=result)


@ml_bp.route("/predict/batch", methods=["POST"])
@login_required
def batch_predict():
    if "file" not in request.files:
        return error_response("No file provided.", "MISSING_FILE")

    file = request.files["file"]
    if not file.filename.endswith(".csv"):
        return error_response("Only CSV files are allowed.", "INVALID_FILE_TYPE")

    model_repo = ModelRepository()
    active_model = model_repo.find_active()
    if not active_model:
        return error_response("No active model.", "NO_ACTIVE_MODEL", status_code=404)

    model_dir = active_model.get("model_dir")
    if not model_dir or not os.path.exists(model_dir):
        return error_response("Model files not found.", "MODEL_FILES_MISSING", status_code=500)

    upload_dir = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)
    safe_name = secure_filename(file.filename)
    tmp_path = os.path.join(upload_dir, f"batch_{safe_name}")
    file.save(tmp_path)

    try:
        df = pd.read_csv(tmp_path, low_memory=False)
        results = predict_batch(df, model_dir, active_model.get("version", "unknown"))
    except Exception as e:
        logger.error(f"Batch prediction failed: {e}")
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return error_response(f"Batch prediction failed: {str(e)}", "PREDICTION_FAILED", status_code=500)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    # Build detection docs + stats
    det_repo = DetectionRepository()
    alert_repo = AlertRepository()
    detections = []
    total = len(results)
    intrusions = 0
    attack_counts = {}
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for i, r in enumerate(results):
        doc = {
            "source_ip": str(df.iloc[i].get("Source IP", df.iloc[i].get("source_ip", "batch"))),
            "destination_ip": str(df.iloc[i].get("Destination IP", df.iloc[i].get("destination_ip", "batch"))),
            "source_port": int(df.iloc[i].get("Source Port", df.iloc[i].get("source_port", 0)) or 0),
            "destination_port": int(df.iloc[i].get("Destination Port", df.iloc[i].get("destination_port", 0)) or 0),
            "protocol": str(df.iloc[i].get("Protocol", df.iloc[i].get("protocol", "unknown"))),
            "prediction": r["prediction"],
            "confidence": r["confidence"],
            "severity": r["severity"],
            "is_intrusion": r["is_intrusion"],
            "model_version": r["model_version"],
            "batch": True,
        }
        detections.append(doc)

        if r["is_intrusion"]:
            intrusions += 1
            attack_counts[r["prediction"]] = attack_counts.get(r["prediction"], 0) + 1
        sev = r["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1

    inserted = det_repo.insert_many(detections)

    # Create alerts for intrusions
    intrusion_detections = [d for d in detections if d["is_intrusion"]]
    for det in intrusion_detections[:100]:  # Cap at 100 alerts per batch
        alert_repo.create({
            "source_ip": det["source_ip"], "destination_ip": det["destination_ip"],
            "source_port": det.get("source_port"), "destination_port": det.get("destination_port"),
            "protocol": det.get("protocol"),
            "attack_type": det["prediction"],
            "severity": det["severity"],
            "confidence": det["confidence"],
            "model_version": det["model_version"],
        })

    # Prepare downloadable summary
    summary_rows = []
    for i, r in enumerate(results):
        row = {
            "row_index": i + 1,
            "prediction": r["prediction"],
            "is_intrusion": r["is_intrusion"],
            "confidence": r["confidence"],
            "severity": r["severity"],
        }
        summary_rows.append(row)

    return success_response("Batch prediction complete.", data={
        "total_records": total,
        "normal_records": total - intrusions,
        "intrusion_records": intrusions,
        "attack_categories": attack_counts,
        "severity_distribution": severity_counts,
        "records_stored": inserted,
        "results_preview": summary_rows[:50],
    })


@ml_bp.route("/features", methods=["GET"])
@login_required
def get_features():
    """Return the list of expected feature names for the prediction form."""
    return success_response("Feature names.", data={"features": FEATURE_NAMES})
