"""Alert repository — manages security alert lifecycle."""
from datetime import datetime
from backend.database.connection import get_db
from backend.database.repositories.base import _serialize, _now, id_query
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class AlertRepository:
    def __init__(self):
        self._col = get_db()["alerts"]

    def create(self, alert: dict) -> str:
        alert.setdefault("timestamp", _now())
        alert.setdefault("status", "ACTIVE")
        alert.setdefault("notes", [])
        alert.setdefault("occurrences", 1)
        result = self._col.insert_one(alert)
        return str(result.inserted_id)

    def create_or_aggregate(self, alert: dict, window_seconds: float = 60.0) -> tuple:
        """
        Create a new alert or aggregate with an existing recent alert with identical fingerprint.
        Returns: (alert_id, is_new_alert: bool)
        """
        src = alert.get("source_ip")
        dst = alert.get("destination_ip")
        attack = alert.get("attack_type")

        # Search for recent active alert with same fingerprint
        query = {
            "source_ip": src,
            "destination_ip": dst,
            "attack_type": attack,
            "status": "ACTIVE",
        }
        cursor = self._col.find(query).sort("timestamp", -1).limit(1)
        existing = list(cursor)

        if existing:
            doc = existing[0]
            doc_id = str(doc.get("_id"))
            now_iso = _now()
            occ = doc.get("occurrences", 1) + 1
            self._col.update_one(
                id_query(doc_id),
                {"$set": {
                    "occurrences": occ,
                    "confidence": max(doc.get("confidence", 0), alert.get("confidence", 0)),
                    "last_seen": now_iso,
                    "updated_at": now_iso,
                }}
            )
            return doc_id, False

        # If not existing recently, create new
        alert["occurrences"] = 1
        new_id = self.create(alert)
        return new_id, True

    def find_by_id(self, alert_id: str) -> dict:
        try:
            doc = self._col.find_one(id_query(alert_id))
            return _serialize(doc)
        except Exception:
            return None

    def list_paginated(self, page: int = 1, per_page: int = 20, filters: dict = None) -> dict:
        query = filters or {}
        skip = (page - 1) * per_page
        total = self._col.count_documents(query)
        cursor = self._col.find(query).sort("timestamp", -1).skip(skip).limit(per_page)
        items = [_serialize(d) for d in cursor]
        return {
            "alerts": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, (total + per_page - 1) // per_page),
        }

    def update_status(self, alert_id: str, status: str, extra: dict = None) -> bool:
        update = {"status": status, "updated_at": _now()}
        if extra:
            for k, v in extra.items():
                if isinstance(v, datetime):
                    extra[k] = v.isoformat()
            update.update(extra)
        result = self._col.update_one(id_query(alert_id), {"$set": update})
        return result.modified_count > 0

    def add_note(self, alert_id: str, note: dict) -> bool:
        note["timestamp"] = _now()
        result = self._col.update_one(
            id_query(alert_id),
            {"$push": {"notes": note}, "$set": {"updated_at": _now()}},
        )
        return result.modified_count > 0

    def count_by_severity(self) -> dict:
        pipeline = [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
        result = {}
        for doc in self._col.aggregate(pipeline):
            result[doc["_id"]] = doc["count"]
        return result

    def count_active(self) -> int:
        return self._col.count_documents({"status": "ACTIVE"})

    def count_by_status(self) -> dict:
        pipeline = [{"$group": {"_id": "$status", "count": {"$sum": 1}}}]
        result = {}
        for doc in self._col.aggregate(pipeline):
            result[doc["_id"]] = doc["count"]
        return result
