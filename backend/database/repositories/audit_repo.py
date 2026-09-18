"""Audit log repository — immutable append-only security event log."""
from datetime import datetime
from bson import ObjectId
from backend.database.connection import get_db
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def _serialize(doc) -> dict:
    if doc is None:
        return None
    doc["id"] = str(doc.pop("_id"))
    if "timestamp" in doc and hasattr(doc["timestamp"], "isoformat"):
        doc["timestamp"] = doc["timestamp"].isoformat()
    return doc


class AuditRepository:
    def __init__(self):
        self._col = get_db()["audit_logs"]

    def log(
        self,
        event: str,
        user_id: str = None,
        username: str = None,
        details: dict = None,
        ip_address: str = None,
    ) -> str:
        entry = {
            "timestamp": datetime.utcnow(),
            "event": event,
            "user_id": user_id,
            "username": username,
            "details": details or {},
            "ip_address": ip_address,
        }
        result = self._col.insert_one(entry)
        return str(result.inserted_id)

    def list_paginated(self, page: int = 1, per_page: int = 20, filters: dict = None) -> dict:
        query = filters or {}
        skip = (page - 1) * per_page
        total = self._col.count_documents(query)
        cursor = self._col.find(query).sort("timestamp", -1).skip(skip).limit(per_page)
        items = [_serialize(d) for d in cursor]
        return {
            "logs": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, (total + per_page - 1) // per_page),
        }
