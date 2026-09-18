"""Alert repository — manages security alert lifecycle."""
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
        result = self._col.insert_one(alert)
        return str(result.inserted_id)

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
            # Serialize any datetime values in extra
            for k, v in extra.items():
                from datetime import datetime
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
