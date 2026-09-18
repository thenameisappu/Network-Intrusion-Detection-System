"""Admin routes — /admin/*"""
from flask import Blueprint, request, g
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.audit_repo import AuditRepository
from backend.database.repositories.detection_repo import DetectionRepository
from backend.database.repositories.alert_repo import AlertRepository
from backend.database.repositories.model_repo import ModelRepository
from backend.database.repositories.dataset_repo import DatasetRepository
from backend.utils.response import success_response, error_response
from backend.utils.decorators import admin_required
from backend.utils.logger import get_logger

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
logger = get_logger(__name__)


@admin_bp.route("/users", methods=["GET"])
@admin_required
def list_users():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    repo = UserRepository()
    result = repo.list_all(page=page, per_page=per_page)
    return success_response("Users retrieved.", data=result)


@admin_bp.route("/users/<user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id: str):
    if user_id == g.current_user["id"]:
        return error_response("Cannot delete your own account.", "SELF_DELETE")
    repo = UserRepository()
    user = repo.find_by_id(user_id)
    if not user:
        return error_response("User not found.", "NOT_FOUND", status_code=404)
    repo.delete(user_id)
    AuditRepository().log("USER_DELETED", user_id=g.current_user["id"],
                          username=g.current_user["username"],
                          details={"deleted_user": user["username"]})
    return success_response("User deleted.")


@admin_bp.route("/users/<user_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_user_active(user_id: str):
    repo = UserRepository()
    user = repo.find_by_id(user_id)
    if not user:
        return error_response("User not found.", "NOT_FOUND", status_code=404)
    new_status = not user.get("is_active", True)
    repo.update(user_id, {"is_active": new_status})
    return success_response(f"User {'activated' if new_status else 'deactivated'}.")


@admin_bp.route("/audit-logs", methods=["GET"])
@admin_required
def audit_logs():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    event = request.args.get("event")
    filters = {}
    if event:
        filters["event"] = event
    repo = AuditRepository()
    result = repo.list_paginated(page=page, per_page=per_page, filters=filters)
    return success_response("Audit logs retrieved.", data=result)


@admin_bp.route("/system-stats", methods=["GET"])
@admin_required
def system_stats():
    return success_response("System statistics.", data={
        "users": UserRepository().count(),
        "datasets": DatasetRepository().count(),
        "models": ModelRepository().count(),
        "detections": DetectionRepository().count_total(),
        "alerts": AlertRepository().count_active(),
    })


@admin_bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    from backend.database.connection import get_db
    db = get_db()
    if request.method == "GET":
        settings_doc = db.system_settings.find_one({"key": "main"}) or {}
        settings_doc.pop("_id", None)
        return success_response("Settings retrieved.", data=settings_doc)
    else:
        data = request.get_json(silent=True) or {}
        db.system_settings.update_one(
            {"key": "main"}, {"$set": data}, upsert=True
        )
        return success_response("Settings updated.")
