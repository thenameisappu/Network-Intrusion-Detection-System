"""User repository — all user database operations."""
from backend.database.connection import get_db
from backend.database.repositories.base import _serialize, _now, id_query
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class UserRepository:
    def __init__(self):
        self._col = get_db()["users"]

    def find_by_username(self, username: str) -> dict:
        doc = self._col.find_one({"username": username})
        return _serialize(doc)

    def find_by_email(self, email: str) -> dict:
        doc = self._col.find_one({"email": email})
        return _serialize(doc)

    def find_by_id(self, user_id: str) -> dict:
        try:
            doc = self._col.find_one(id_query(user_id))
            return _serialize(doc)
        except Exception:
            return None

    def create(self, user_data: dict) -> str:
        user_data["created_at"] = _now()
        user_data["updated_at"] = _now()
        result = self._col.insert_one(user_data)
        return str(result.inserted_id)

    def update(self, user_id: str, update_data: dict) -> bool:
        update_data["updated_at"] = _now()
        result = self._col.update_one(id_query(user_id), {"$set": update_data})
        return result.modified_count > 0

    def list_all(self, page: int = 1, per_page: int = 20) -> dict:
        skip = (page - 1) * per_page
        total = self._col.count_documents({})
        cursor = list(self._col.find({}).skip(skip).limit(per_page))
        users = []
        for d in cursor:
            s = _serialize(d)
            s.pop("password_hash", None)  # Strip password hash
            users.append(s)
        pages = max(1, (total + per_page - 1) // per_page)
        return {"users": users, "total": total, "page": page, "per_page": per_page, "pages": pages}

    def delete(self, user_id: str) -> bool:
        result = self._col.delete_one(id_query(user_id))
        return result.deleted_count > 0

    def count(self) -> int:
        return self._col.count_documents({})
