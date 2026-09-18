"""Detection repository — stores every ML prediction result."""
from datetime import datetime
from backend.database.connection import get_db, is_using_tinydb
from backend.database.repositories.base import _serialize, _now, id_query
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class DetectionRepository:
    def __init__(self):
        self._col = get_db()["detections"]

    def create(self, detection: dict) -> str:
        detection.setdefault("timestamp", _now())
        detection.setdefault("status", "NEW")
        result = self._col.insert_one(detection)
        return str(result.inserted_id)

    def insert_many(self, detections: list) -> int:
        for d in detections:
            d.setdefault("timestamp", _now())
            d.setdefault("status", "NEW")
        if not detections:
            return 0
        result = self._col.insert_many(detections)
        return len(result.inserted_ids)

    def find_by_id(self, detection_id: str) -> dict:
        try:
            doc = self._col.find_one(id_query(detection_id))
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
            "detections": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, (total + per_page - 1) // per_page),
        }

    def count_by_field(self, field: str) -> list:
        pipeline = [
            {"$group": {"_id": f"${field}", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        return list(self._col.aggregate(pipeline))

    def count_intrusions(self) -> int:
        return self._col.count_documents({"prediction": {"$ne": "BENIGN"}})

    def count_normal(self) -> int:
        return self._col.count_documents({"prediction": "BENIGN"})

    def count_total(self) -> int:
        return self._col.count_documents({})

    def recent(self, limit: int = 10) -> list:
        cursor = self._col.find().sort("timestamp", -1).limit(limit)
        return [_serialize(d) for d in cursor]

    def trend_by_hour(self, hours: int = 24) -> list:
        """Return hourly traffic trend — simplified for TinyDB compatibility."""
        if is_using_tinydb():
            # Simplified: just return count by recent detections
            all_docs = list(self._col.find())
            return _simple_hourly_trend(all_docs, hours)
        from datetime import timedelta
        since = datetime.utcnow() - timedelta(hours=hours)
        pipeline = [
            {"$match": {"timestamp": {"$gte": since}}},
            {
                "$group": {
                    "_id": {
                        "hour": {"$hour": "$timestamp"},
                        "day": {"$dayOfMonth": "$timestamp"},
                    },
                    "total": {"$sum": 1},
                    "intrusions": {
                        "$sum": {"$cond": [{"$ne": ["$prediction", "BENIGN"]}, 1, 0]}
                    },
                }
            },
            {"$sort": {"_id.day": 1, "_id.hour": 1}},
        ]
        return list(self._col.aggregate(pipeline))

    def top_ips(self, field: str = "source_ip", limit: int = 10) -> list:
        pipeline = [
            {"$match": {field: {"$exists": True, "$ne": None}}},
            {"$group": {"_id": f"${field}", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": limit},
        ]
        return list(self._col.aggregate(pipeline))

    def attack_trend_daily(self, days: int = 7) -> list:
        if is_using_tinydb():
            all_docs = list(self._col.find())
            return _simple_daily_trend(all_docs, days)
        from datetime import timedelta
        since = datetime.utcnow() - timedelta(days=days)
        pipeline = [
            {"$match": {"timestamp": {"$gte": since}, "prediction": {"$ne": "BENIGN"}}},
            {
                "$group": {
                    "_id": {
                        "year": {"$year": "$timestamp"},
                        "month": {"$month": "$timestamp"},
                        "day": {"$dayOfMonth": "$timestamp"},
                        "attack": "$prediction",
                    },
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"_id.year": 1, "_id.month": 1, "_id.day": 1}},
        ]
        return list(self._col.aggregate(pipeline))


def _simple_hourly_trend(docs: list, hours: int) -> list:
    """Aggregate docs by hour for TinyDB fallback."""
    from collections import defaultdict
    from datetime import timedelta
    since = datetime.utcnow() - timedelta(hours=hours)
    counts = defaultdict(lambda: {"total": 0, "intrusions": 0})
    for d in docs:
        ts = d.get("timestamp")
        if not ts:
            continue
        try:
            if isinstance(ts, str):
                dt = datetime.fromisoformat(ts)
            else:
                dt = ts
            if dt < since:
                continue
            key = (dt.day, dt.hour)
            counts[key]["total"] += 1
            if d.get("prediction") != "BENIGN":
                counts[key]["intrusions"] += 1
        except Exception:
            pass
    return [
        {"_id": {"day": k[0], "hour": k[1]}, "total": v["total"], "intrusions": v["intrusions"]}
        for k, v in sorted(counts.items())
    ]


def _simple_daily_trend(docs: list, days: int) -> list:
    """Aggregate docs by day/attack for TinyDB fallback."""
    from collections import defaultdict
    from datetime import timedelta
    since = datetime.utcnow() - timedelta(days=days)
    counts = defaultdict(int)
    for d in docs:
        ts = d.get("timestamp")
        prediction = d.get("prediction", "")
        if not ts or prediction == "BENIGN":
            continue
        try:
            if isinstance(ts, str):
                dt = datetime.fromisoformat(ts)
            else:
                dt = ts
            if dt < since:
                continue
            counts[(dt.year, dt.month, dt.day, prediction)] += 1
        except Exception:
            pass
    return [
        {"_id": {"year": k[0], "month": k[1], "day": k[2], "attack": k[3]}, "count": v}
        for k, v in sorted(counts.items())
    ]
