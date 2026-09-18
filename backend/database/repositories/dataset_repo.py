"""Dataset metadata repository."""
from datetime import datetime
from bson import ObjectId
from backend.database.connection import get_db
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def _serialize(doc) -> dict:
    if doc is None:
        return None
    doc["id"] = str(doc.pop("_id"))
    for field in ("uploaded_at", "updated_at"):
        if field in doc and hasattr(doc[field], "isoformat"):
            doc[field] = doc[field].isoformat()
    return doc


class DatasetRepository:
    def __init__(self):
        self._col = get_db()["datasets"]

    def create(self, dataset_data: dict) -> str:
        dataset_data["uploaded_at"] = datetime.utcnow()
        dataset_data["updated_at"] = datetime.utcnow()
        result = self._col.insert_one(dataset_data)
        return str(result.inserted_id)

    def find_by_id(self, dataset_id: str) -> dict:
        try:
            doc = self._col.find_one({"_id": ObjectId(dataset_id)})
            return _serialize(doc)
        except Exception:
            return None

    def list_all(self) -> list:
        cursor = self._col.find().sort("uploaded_at", -1)
        return [_serialize(d) for d in cursor]

    def update(self, dataset_id: str, data: dict) -> bool:
        data["updated_at"] = datetime.utcnow()
        result = self._col.update_one({"_id": ObjectId(dataset_id)}, {"$set": data})
        return result.modified_count > 0

    def delete(self, dataset_id: str) -> bool:
        result = self._col.delete_one({"_id": ObjectId(dataset_id)})
        return result.deleted_count > 0

    def count(self) -> int:
        return self._col.count_documents({})
