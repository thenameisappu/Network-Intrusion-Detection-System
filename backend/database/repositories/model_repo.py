"""Model metadata repository — tracks all trained model versions."""
from backend.database.connection import get_db
from backend.database.repositories.base import _serialize, _now, id_query
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class ModelRepository:
    def __init__(self):
        self._col = get_db()["models"]

    def create(self, model_data: dict) -> str:
        model_data["created_at"] = _now()
        model_data["updated_at"] = _now()
        model_data.setdefault("status", "TRAINED")
        result = self._col.insert_one(model_data)
        return str(result.inserted_id)

    def _model_query(self, model_id: str) -> dict:
        try:
            return {"$or": [{"_id": str(model_id)}, {"model_id": str(model_id)}]}
        except Exception:
            return {"_id": str(model_id)}

    def find_by_id(self, model_id: str) -> dict:
        try:
            doc = self._col.find_one(self._model_query(model_id))
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
        """Deactivate all models, then activate the specified one."""
        self._col.update_many(
            {"status": "ACTIVE"},
            {"$set": {"status": "ARCHIVED", "updated_at": _now()}}
        )
        result = self._col.update_one(
            self._model_query(model_id),
            {"$set": {"status": "ACTIVE", "updated_at": _now()}},
        )
        return result.modified_count > 0

    def update_status(self, model_id: str, status: str) -> bool:
        result = self._col.update_one(
            id_query(model_id),
            {"$set": {"status": status, "updated_at": _now()}},
        )
        return result.modified_count > 0

    def update(self, model_id: str, data: dict) -> bool:
        data["updated_at"] = _now()
        result = self._col.update_one(id_query(model_id), {"$set": data})
        return result.modified_count > 0

    def delete(self, model_id: str) -> bool:
        result = self._col.delete_one(id_query(model_id))
        return result.deleted_count > 0

    def count(self) -> int:
        return self._col.count_documents({})
