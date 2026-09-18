"""Analytics routes — /analytics/*"""
from flask import Blueprint, request
from backend.database.repositories.detection_repo import DetectionRepository
from backend.database.repositories.alert_repo import AlertRepository
from backend.utils.response import success_response, error_response
from backend.utils.decorators import login_required

analytics_bp = Blueprint("analytics", __name__, url_prefix="/analytics")


@analytics_bp.route("/attacks", methods=["GET"])
@login_required
def attack_distribution():
    repo = DetectionRepository()
    dist = repo.count_by_field("prediction")
    result = [{"label": d["_id"] or "Unknown", "count": d["count"]} for d in dist]
    return success_response("Attack distribution.", data={"distribution": result})


@analytics_bp.route("/severity", methods=["GET"])
@login_required
def severity_distribution():
    repo = DetectionRepository()
    dist = repo.count_by_field("severity")
    result = [{"label": d["_id"] or "Unknown", "count": d["count"]} for d in dist]
    return success_response("Severity distribution.", data={"distribution": result})


@analytics_bp.route("/protocols", methods=["GET"])
@login_required
def protocol_distribution():
    repo = DetectionRepository()
    dist = repo.count_by_field("protocol")
    result = [{"label": str(d["_id"]) if d["_id"] is not None else "Unknown", "count": d["count"]} for d in dist]
    return success_response("Protocol distribution.", data={"distribution": result})


@analytics_bp.route("/trends", methods=["GET"])
@login_required
def attack_trends():
    days = int(request.args.get("days", 7))
    repo = DetectionRepository()
    daily = repo.attack_trend_daily(days=days)
    hourly = repo.trend_by_hour(hours=24)
    return success_response("Attack trends.", data={
        "daily": daily,
        "hourly": hourly,
    })


@analytics_bp.route("/top-ips", methods=["GET"])
@login_required
def top_ips():
    limit = int(request.args.get("limit", 10))
    repo = DetectionRepository()
    src = repo.top_ips("source_ip", limit=limit)
    dst = repo.top_ips("destination_ip", limit=limit)
    return success_response("Top IPs.", data={
        "source_ips": [{"ip": d["_id"], "count": d["count"]} for d in src],
        "destination_ips": [{"ip": d["_id"], "count": d["count"]} for d in dst],
    })


@analytics_bp.route("/overview", methods=["GET"])
@login_required
def overview():
    det_repo = DetectionRepository()
    alert_repo = AlertRepository()
    total = det_repo.count_total()
    intrusions = det_repo.count_intrusions()
    normal = det_repo.count_normal()
    attack_dist = det_repo.count_by_field("prediction")
    severity_dist = det_repo.count_by_field("severity")
    return success_response("Analytics overview.", data={
        "total": total,
        "intrusions": intrusions,
        "normal": normal,
        "detection_rate": round(intrusions / total * 100, 2) if total > 0 else 0,
        "attack_distribution": [{"label": d["_id"] or "Unknown", "count": d["count"]} for d in attack_dist],
        "severity_distribution": [{"label": d["_id"] or "Unknown", "count": d["count"]} for d in severity_dist],
        "alert_severity": alert_repo.count_by_severity(),
    })
