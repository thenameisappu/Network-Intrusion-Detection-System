"""Dataset routes — /datasets/*"""
import os
from flask import Blueprint, request, g, current_app
from werkzeug.utils import secure_filename
from backend.datasets.validator import validate_dataset
from backend.database.repositories.dataset_repo import DatasetRepository
from backend.database.repositories.audit_repo import AuditRepository
from backend.utils.response import success_response, error_response
from backend.utils.decorators import login_required, admin_required
from backend.utils.logger import get_logger

dataset_bp = Blueprint("datasets", __name__, url_prefix="/datasets")
logger = get_logger(__name__)


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() == "csv"


@dataset_bp.route("", methods=["GET"])
@login_required
def list_datasets():
    repo = DatasetRepository()
    datasets = repo.list_all()
    return success_response("Datasets retrieved.", data={"datasets": datasets})


@dataset_bp.route("/upload", methods=["POST"])
@login_required
def upload_dataset():
    if "file" not in request.files:
        return error_response("No file provided.", "MISSING_FILE")

    file = request.files["file"]
    if not file.filename:
        return error_response("Empty filename.", "EMPTY_FILENAME")
    if not _allowed_file(file.filename):
        return error_response("Only CSV files are allowed.", "INVALID_FILE_TYPE")

    upload_dir = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)

    safe_name = secure_filename(file.filename)
    filepath = os.path.join(upload_dir, safe_name)

    # Path traversal protection
    abs_upload = os.path.abspath(upload_dir)
    abs_target = os.path.abspath(filepath)
    if not abs_target.startswith(abs_upload):
        return error_response("Invalid file path.", "PATH_TRAVERSAL")

    file.save(filepath)
    logger.info(f"Dataset uploaded: {safe_name} by {g.current_user['username']}")

    # Validate immediately
    validation = validate_dataset(filepath)
    if not validation["valid"]:
        os.remove(filepath)
        return error_response(
            "Dataset validation failed.",
            "INVALID_DATASET",
            details={"errors": validation["errors"], "warnings": validation["warnings"]},
        )

    # Save metadata to DB
    repo = DatasetRepository()
    audit = AuditRepository()
    dataset_id = repo.create({
        "name": safe_name,
        "filename": safe_name,
        "filepath": filepath,
        "uploaded_by": g.current_user["id"],
        "uploader": g.current_user["username"],
        "validation": validation,
        "stats": validation.get("stats", {}),
        "status": "VALIDATED",
    })
    audit.log("DATASET_UPLOADED", user_id=g.current_user["id"],
              username=g.current_user["username"],
              details={"dataset_id": dataset_id, "filename": safe_name})

    return success_response("Dataset uploaded and validated.", data={
        "dataset_id": dataset_id,
        "filename": safe_name,
        "stats": validation.get("stats", {}),
        "warnings": validation.get("warnings", []),
    }, status_code=201)


@dataset_bp.route("/<dataset_id>", methods=["GET"])
@login_required
def get_dataset(dataset_id: str):
    repo = DatasetRepository()
    dataset = repo.find_by_id(dataset_id)
    if not dataset:
        return error_response("Dataset not found.", "NOT_FOUND", status_code=404)
    return success_response("Dataset details.", data=dataset)


@dataset_bp.route("/<dataset_id>", methods=["DELETE"])
@admin_required
def delete_dataset(dataset_id: str):
    repo = DatasetRepository()
    dataset = repo.find_by_id(dataset_id)
    if not dataset:
        return error_response("Dataset not found.", "NOT_FOUND", status_code=404)

    filepath = dataset.get("filepath")
    if filepath and os.path.exists(filepath):
        os.remove(filepath)

    repo.delete(dataset_id)
    return success_response("Dataset deleted.")


@dataset_bp.route("/<dataset_id>/validate", methods=["POST"])
@login_required
def revalidate_dataset(dataset_id: str):
    repo = DatasetRepository()
    dataset = repo.find_by_id(dataset_id)
    if not dataset:
        return error_response("Dataset not found.", "NOT_FOUND", status_code=404)

    filepath = dataset.get("filepath")
    if not filepath or not os.path.exists(filepath):
        return error_response("Dataset file not found on disk.", "FILE_NOT_FOUND", status_code=404)

    validation = validate_dataset(filepath)
    repo.update(dataset_id, {"validation": validation, "stats": validation.get("stats", {})})
    return success_response("Validation complete.", data=validation)
