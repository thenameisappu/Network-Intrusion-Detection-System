"""Alert routes — /alerts/*"""
from flask import Blueprint, request, g
from backend.database.repositories.alert_repo import AlertRepository
from backend.database.repositories.audit_repo import AuditRepository
from backend.database.repositories.base import _now
from backend.utils.response import success_response, error_response
from backend.utils.decorators import login_required

alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")


@alerts_bp.route("", methods=["GET"])
@login_required
def list_alerts():
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 20)), 100)
    status = request.args.get("status")
    severity = request.args.get("severity")
    attack_type = request.args.get("attack_type")

    filters = {}
    if status:
        filters["status"] = status
    if severity:
        filters["severity"] = severity
    if attack_type:
        filters["attack_type"] = attack_type

    repo = AlertRepository()
    result = repo.list_paginated(page=page, per_page=per_page, filters=filters)
    return success_response("Alerts retrieved.", data=result)


@alerts_bp.route("/<alert_id>", methods=["GET"])
@login_required
def get_alert(alert_id: str):
    repo = AlertRepository()
    alert = repo.find_by_id(alert_id)
    if not alert:
        return error_response("Alert not found.", "NOT_FOUND", status_code=404)
    return success_response("Alert details.", data=alert)


@alerts_bp.route("/<alert_id>/acknowledge", methods=["POST"])
@login_required
def acknowledge_alert(alert_id: str):
    repo = AlertRepository()
    alert = repo.find_by_id(alert_id)
    if not alert:
        return error_response("Alert not found.", "NOT_FOUND", status_code=404)

    repo.update_status(alert_id, "ACKNOWLEDGED", {
        "acknowledged_by": g.current_user["username"],
        "acknowledged_at": _now(),
    })
    AuditRepository().log("ALERT_ACKNOWLEDGED", user_id=g.current_user["id"],
                          username=g.current_user["username"],
                          details={"alert_id": alert_id})
    return success_response("Alert acknowledged.")


@alerts_bp.route("/<alert_id>/resolve", methods=["POST"])
@login_required
def resolve_alert(alert_id: str):
    data = request.get_json(silent=True) or {}
    note = data.get("note", "")

    repo = AlertRepository()
    alert = repo.find_by_id(alert_id)
    if not alert:
        return error_response("Alert not found.", "NOT_FOUND", status_code=404)

    repo.update_status(alert_id, "RESOLVED", {
        "resolved_by": g.current_user["username"],
        "resolved_at": _now(),
    })
    if note:
        repo.add_note(alert_id, {"text": note, "author": g.current_user["username"]})

    AuditRepository().log("ALERT_RESOLVED", user_id=g.current_user["id"],
                          username=g.current_user["username"],
                          details={"alert_id": alert_id, "note": note})
    return success_response("Alert resolved.")


@alerts_bp.route("/<alert_id>/notes", methods=["POST"])
@login_required
def add_note(alert_id: str):
    data = request.get_json(silent=True) or {}
    note_text = (data.get("note") or "").strip()
    if not note_text:
        return error_response("Note text is required.", "MISSING_FIELD")

    repo = AlertRepository()
    alert = repo.find_by_id(alert_id)
    if not alert:
        return error_response("Alert not found.", "NOT_FOUND", status_code=404)

    repo.add_note(alert_id, {"text": note_text, "author": g.current_user["username"]})
    return success_response("Note added.")


@alerts_bp.route("/summary", methods=["GET"])
@login_required
def alert_summary():
    repo = AlertRepository()
    severity_counts = repo.count_by_severity()
    status_counts = repo.count_by_status()
    return success_response("Alert summary.", data={
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "total_active": repo.count_active(),
    })
