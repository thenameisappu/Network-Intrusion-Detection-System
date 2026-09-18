"""Model metadata repository — tracks all trained model versions."""
from datetime import datetime
from bson import ObjectId
from backend.database.connection import get_db
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def _serialize(doc) -> dict:
    if doc is None:
        return None
    doc["id"] = str(doc.pop("_id"))
    for field in ("created_at", "updated_at"):
        if field in doc and hasattr(doc[field], "isoformat"):
            doc[field] = doc[field].isoformat()
    return doc


class ModelRepository:
    def __init__(self):
        self._col = get_db()["models"]

    def create(self, model_data: dict) -> str:
        model_data["created_at"] = datetime.utcnow()
        model_data["updated_at"] = datetime.utcnow()
        model_data.setdefault("status", "TRAINED")
        result = self._col.insert_one(model_data)
        return str(result.inserted_id)

    def find_by_id(self, model_id: str) -> dict:
        try:
            doc = self._col.find_one({"_id": ObjectId(model_id)})
            return _serialize(doc)
        except Exception:
            return None

    def find_active(self) -> dict:
        doc = self._col.find_one({"status": "ACTIVE"})
        return _serialize(doc)

    def list_all(self) -> list:
        cursor = self._col.find().sort("created_at", -1)
        return [_serialize(d) for d in cursor]

    def set_active(self, model_id: str) -> bool:
        """Deactivate all, then activate the specified model."""
        self._col.update_many(
            {"status": "ACTIVE"}, {"$set": {"status": "ARCHIVED", "updated_at": datetime.utcnow()}}
        )
        result = self._col.update_one(
            {"_id": ObjectId(model_id)},
            {"$set": {"status": "ACTIVE", "updated_at": datetime.utcnow()}},
        )
        return result.modified_count > 0

    def update_status(self, model_id: str, status: str) -> bool:
        result = self._col.update_one(
            {"_id": ObjectId(model_id)},
            {"$set": {"status": status, "updated_at": datetime.utcnow()}},
        )
        return result.modified_count > 0

    def delete(self, model_id: str) -> bool:
        result = self._col.delete_one({"_id": ObjectId(model_id)})
        return result.deleted_count > 0

    def count(self) -> int:
        return self._col.count_documents({})
