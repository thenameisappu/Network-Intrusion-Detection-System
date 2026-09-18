"""Dashboard routes — /dashboard/*"""
from flask import Blueprint
from backend.dashboard.service import DashboardService
from backend.utils.response import success_response, error_response
from backend.utils.decorators import login_required

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")
_service = DashboardService()


@dashboard_bp.route("/summary", methods=["GET"])
@login_required
def summary():
    try:
        data = _service.get_summary()
        return success_response("Dashboard summary.", data=data)
    except Exception as e:
        return error_response(str(e), "DASHBOARD_ERROR", status_code=500)


@dashboard_bp.route("/trends", methods=["GET"])
@login_required
def trends():
    try:
        data = _service.get_trends()
        return success_response("Traffic trends.", data=data)
    except Exception as e:
        return error_response(str(e), "DASHBOARD_ERROR", status_code=500)


@dashboard_bp.route("/top-ips", methods=["GET"])
@login_required
def top_ips():
    try:
        data = _service.get_top_ips()
        return success_response("Top IPs.", data=data)
    except Exception as e:
        return error_response(str(e), "DASHBOARD_ERROR", status_code=500)
