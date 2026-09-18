"""Detection routes — /detections/*"""
from flask import Blueprint, request
from backend.database.repositories.detection_repo import DetectionRepository
from backend.utils.response import success_response, error_response
from backend.utils.decorators import login_required

detections_bp = Blueprint("detections", __name__, url_prefix="/detections")


@detections_bp.route("", methods=["GET"])
@login_required
def list_detections():
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 20)), 100)
    prediction = request.args.get("prediction")
    severity = request.args.get("severity")
    status = request.args.get("status")
    search = request.args.get("search")

    filters = {}
    if prediction:
        filters["prediction"] = prediction
    if severity:
        filters["severity"] = severity
    if status:
        filters["status"] = status
    if search:
        filters["$or"] = [
            {"source_ip": {"$regex": search, "$options": "i"}},
            {"destination_ip": {"$regex": search, "$options": "i"}},
            {"prediction": {"$regex": search, "$options": "i"}},
        ]

    repo = DetectionRepository()
    result = repo.list_paginated(page=page, per_page=per_page, filters=filters)
    return success_response("Detections retrieved.", data=result)


@detections_bp.route("/<detection_id>", methods=["GET"])
@login_required
def get_detection(detection_id: str):
    repo = DetectionRepository()
    detection = repo.find_by_id(detection_id)
    if not detection:
        return error_response("Detection not found.", "NOT_FOUND", status_code=404)
    return success_response("Detection details.", data=detection)
