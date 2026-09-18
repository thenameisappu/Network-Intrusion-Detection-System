"""Dashboard service — aggregates real statistics from the database."""
from backend.database.repositories.detection_repo import DetectionRepository
from backend.database.repositories.alert_repo import AlertRepository
from backend.database.repositories.model_repo import ModelRepository
from backend.database.repositories.dataset_repo import DatasetRepository
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class DashboardService:
    def __init__(self):
        self._detections = DetectionRepository()
        self._alerts = AlertRepository()
        self._models = ModelRepository()
        self._datasets = DatasetRepository()

    def get_summary(self) -> dict:
        total = self._detections.count_total()
        intrusions = self._detections.count_intrusions()
        normal = self._detections.count_normal()
        detection_rate = round((intrusions / total * 100), 2) if total > 0 else 0

        severity_counts = self._alerts.count_by_severity()
        active_alerts = self._alerts.count_active()
        active_model = self._models.find_active()

        attack_dist = self._detections.count_by_field("prediction")
        attack_dist_clean = [
            {"label": d["_id"] or "Unknown", "count": d["count"]}
            for d in attack_dist if d["_id"] != "BENIGN"
        ]

        recent = self._detections.recent(limit=10)
        return {
            "total_traffic": total,
            "normal_traffic": normal,
            "intrusion_count": intrusions,
            "detection_rate": detection_rate,
            "active_alerts": active_alerts,
            "severity_counts": {
                "CRITICAL": severity_counts.get("CRITICAL", 0),
                "HIGH": severity_counts.get("HIGH", 0),
                "MEDIUM": severity_counts.get("MEDIUM", 0),
                "LOW": severity_counts.get("LOW", 0),
            },
            "attack_distribution": attack_dist_clean,
            "recent_detections": recent,
            "active_model": {
                "version": active_model.get("version") if active_model else None,
                "model_type": active_model.get("model_type") if active_model else None,
                "accuracy": active_model.get("metrics", {}).get("accuracy") if active_model else None,
            } if active_model else None,
            "total_datasets": self._datasets.count(),
            "total_models": self._models.count(),
        }

    def get_trends(self) -> dict:
        hourly = self._detections.trend_by_hour(hours=24)
        daily_attacks = self._detections.attack_trend_daily(days=7)
        protocol_dist = self._detections.count_by_field("protocol")
        return {
            "hourly_traffic": hourly,
            "daily_attacks": daily_attacks,
            "protocol_distribution": [
                {"label": d["_id"] or "Unknown", "count": d["count"]}
                for d in protocol_dist
            ],
        }

    def get_top_ips(self) -> dict:
        src = self._detections.top_ips("source_ip", limit=10)
        dst = self._detections.top_ips("destination_ip", limit=10)
        return {
            "top_source_ips": [{"ip": d["_id"], "count": d["count"]} for d in src],
            "top_destination_ips": [{"ip": d["_id"], "count": d["count"]} for d in dst],
        }
