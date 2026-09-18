"""Reports routes — /reports/*"""
import io
import csv
import json
from datetime import datetime
from flask import Blueprint, request, g, send_file, jsonify
from backend.database.repositories.detection_repo import DetectionRepository
from backend.database.repositories.alert_repo import AlertRepository
from backend.database.repositories.model_repo import ModelRepository
from backend.utils.response import success_response, error_response
from backend.utils.decorators import login_required
from backend.utils.logger import get_logger

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")
logger = get_logger(__name__)


def _generate_report_data() -> dict:
    det_repo = DetectionRepository()
    alert_repo = AlertRepository()
    model_repo = ModelRepository()

    total = det_repo.count_total()
    intrusions = det_repo.count_intrusions()
    active_model = model_repo.find_active()
    attack_dist = det_repo.count_by_field("prediction")
    severity_dist = det_repo.count_by_field("severity")
    recent = det_repo.recent(limit=50)

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "total_traffic": total,
        "total_intrusions": intrusions,
        "normal_traffic": total - intrusions,
        "detection_rate": round(intrusions / total * 100, 2) if total > 0 else 0,
        "attack_categories": {d["_id"]: d["count"] for d in attack_dist if d["_id"]},
        "severity_distribution": {d["_id"]: d["count"] for d in severity_dist if d["_id"]},
        "active_model": {
            "version": active_model.get("version") if active_model else "N/A",
            "model_type": active_model.get("model_type") if active_model else "N/A",
            "accuracy": active_model.get("metrics", {}).get("accuracy") if active_model else None,
        },
        "recent_incidents": recent,
        "alert_summary": alert_repo.count_by_severity(),
    }


@reports_bp.route("/generate", methods=["POST"])
@login_required
def generate_report():
    data = request.get_json(silent=True) or {}
    fmt = data.get("format", "json").lower()

    if fmt not in ("json", "csv", "pdf"):
        return error_response("Format must be json, csv, or pdf.", "INVALID_FORMAT")

    report = _generate_report_data()

    if fmt == "json":
        buf = io.BytesIO(json.dumps(report, indent=2, default=str).encode())
        return send_file(
            buf, mimetype="application/json",
            as_attachment=True,
            download_name=f"nids_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
        )

    elif fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["NIDS Security Report"])
        writer.writerow(["Generated At", report["generated_at"]])
        writer.writerow([])
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Total Traffic", report["total_traffic"]])
        writer.writerow(["Total Intrusions", report["total_intrusions"]])
        writer.writerow(["Normal Traffic", report["normal_traffic"]])
        writer.writerow(["Detection Rate (%)", report["detection_rate"]])
        writer.writerow(["Active Model", report["active_model"]["version"]])
        writer.writerow([])
        writer.writerow(["Attack Category", "Count"])
        for cat, cnt in report["attack_categories"].items():
            writer.writerow([cat, cnt])
        writer.writerow([])
        writer.writerow(["Severity", "Count"])
        for sev, cnt in report["severity_distribution"].items():
            writer.writerow([sev, cnt])
        writer.writerow([])
        writer.writerow(["Recent Incidents"])
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Prediction", "Severity", "Confidence"])
        for inc in report["recent_incidents"]:
            writer.writerow([
                inc.get("timestamp", ""), inc.get("source_ip", ""),
                inc.get("destination_ip", ""), inc.get("prediction", ""),
                inc.get("severity", ""), inc.get("confidence", ""),
            ])

        bytes_buf = io.BytesIO(buf.getvalue().encode())
        return send_file(
            bytes_buf, mimetype="text/csv",
            as_attachment=True,
            download_name=f"nids_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
        )

    elif fmt == "pdf":
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors

            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            story.append(Paragraph("NIDS Security Report", styles["Title"]))
            story.append(Paragraph(f"Generated: {report['generated_at']}", styles["Normal"]))
            story.append(Spacer(1, 12))

            story.append(Paragraph("Summary Statistics", styles["Heading2"]))
            summary_data = [
                ["Metric", "Value"],
                ["Total Traffic", str(report["total_traffic"])],
                ["Total Intrusions", str(report["total_intrusions"])],
                ["Normal Traffic", str(report["normal_traffic"])],
                ["Detection Rate", f"{report['detection_rate']}%"],
                ["Active Model", report["active_model"]["version"]],
                ["Model Accuracy", f"{report['active_model'].get('accuracy', 'N/A')}"],
            ]
            t = Table(summary_data, colWidths=[250, 250])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ]))
            story.append(t)
            story.append(Spacer(1, 12))

            story.append(Paragraph("Attack Distribution", styles["Heading2"]))
            atk_data = [["Attack Category", "Count"]] + [
                [k, str(v)] for k, v in report["attack_categories"].items()
            ]
            if len(atk_data) > 1:
                t2 = Table(atk_data, colWidths=[250, 250])
                t2.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                story.append(t2)

            doc.build(story)
            buf.seek(0)
            return send_file(
                buf, mimetype="application/pdf",
                as_attachment=True,
                download_name=f"nids_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf",
            )
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return error_response(f"PDF generation failed: {str(e)}", "PDF_ERROR", status_code=500)


@reports_bp.route("/preview", methods=["GET"])
@login_required
def preview_report():
    report = _generate_report_data()
    # Remove large data from preview
    report.pop("recent_incidents", None)
    return success_response("Report preview.", data=report)
