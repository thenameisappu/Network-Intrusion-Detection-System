"""
MongoDB connection with automatic TinyDB fallback.
- Tries MongoDB first (localhost:27017 by default).
- If MongoDB is unavailable, transparently switches to TinyDB (JSON file-based).
- All repository code uses the same interface regardless of backend.
- TinyDB is NOT thread-safe: a global lock serialises all TinyDB access.
"""
import threading
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.database import Database
from backend.utils.logger import get_logger

logger = get_logger(__name__)

_client: MongoClient = None
_db: Database = None
_using_tinydb: bool = False
_tinydb_instance = None
_tinydb_lock = threading.Lock()  # Serialise all TinyDB access — it is NOT thread-safe


def init_db(app) -> None:
    """Initialize database connection — MongoDB preferred, TinyDB fallback."""
    global _client, _db, _using_tinydb, _tinydb_instance

    uri = app.config["MONGODB_URI"]
    db_name = app.config["MONGODB_DB"]

    # Try MongoDB
    try:
        _client = MongoClient(uri, serverSelectionTimeoutMS=3000)
        _client.admin.command("ping")
        _db = _client[db_name]
        _create_indexes(_db)
        _using_tinydb = False
        logger.info(f"[OK] Connected to MongoDB - database: {db_name}")
        return
    except Exception as e:
        logger.warning(f"MongoDB unavailable ({e}). Falling back to TinyDB.")

    # TinyDB fallback
    try:
        import os
        from tinydb import TinyDB
        db_path = os.path.join("dataset", "nids_db.json")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        _tinydb_instance = TinyDB(db_path)
        _using_tinydb = True
        logger.info(f"[OK] Using TinyDB fallback - data stored in {db_path}")
        logger.warning("[WARN] TinyDB is for development/demo only. "
                       "Install MongoDB for production use.")
    except Exception as e2:
        logger.error(f"TinyDB fallback also failed: {e2}")
        raise RuntimeError(
            "Could not connect to any database. "
            "Please install MongoDB or ensure TinyDB is installed."
        )


def get_db():
    """Return the database handle (MongoDB Database or TinyDB proxy)."""
    if _using_tinydb:
        return TinyDBProxy(_tinydb_instance)
    if _db is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    return _db


def is_using_tinydb() -> bool:
    return _using_tinydb


def _create_indexes(db: Database) -> None:
    """Create indexes for MongoDB collections."""
    try:
        db.detections.create_index([("timestamp", DESCENDING)])
        db.detections.create_index([("prediction", ASCENDING)])
        db.detections.create_index([("severity", ASCENDING)])
        db.detections.create_index([("source_ip", ASCENDING)])
        db.detections.create_index([("destination_ip", ASCENDING)])
        db.detections.create_index([("status", ASCENDING)])
        db.alerts.create_index([("timestamp", DESCENDING)])
        db.alerts.create_index([("severity", ASCENDING)])
        db.alerts.create_index([("status", ASCENDING)])
        db.users.create_index([("username", ASCENDING)], unique=True)
        db.users.create_index([("email", ASCENDING)], unique=True)
        db.models.create_index([("status", ASCENDING)])
        db.models.create_index([("created_at", DESCENDING)])
        db.datasets.create_index([("uploaded_at", DESCENDING)])
        db.audit_logs.create_index([("timestamp", DESCENDING)])
        logger.info("MongoDB indexes created/verified.")
    except Exception as e:
        logger.warning(f"Index creation failed (non-fatal): {e}")


class TinyDBCollection:
    """Minimal MongoDB-compatible wrapper around a TinyDB table."""
    def __init__(self, table):
        self._table = table
        self._unique_fields = {}

    def _make_id(self):
        import uuid
        return str(uuid.uuid4())

    def insert_one(self, doc: dict):
        with _tinydb_lock:
            doc = dict(doc)
            if "_id" not in doc:
                doc["_id"] = self._make_id()
            self._table.insert(doc)
            class Result:
                inserted_id = doc["_id"]
            return Result()

    def insert_many(self, docs: list):
        with _tinydb_lock:
            ids = []
            for doc in docs:
                doc = dict(doc)
                if "_id" not in doc:
                    doc["_id"] = self._make_id()
                ids.append(doc["_id"])
                self._table.insert(doc)
            class Result:
                inserted_ids = ids
            return Result()

    def find_one(self, query: dict = None, projection: dict = None):
        with _tinydb_lock:
            results = self._find_unlocked(query or {})
            return next(iter(results), None)

    def find(self, query: dict = None, projection: dict = None):
        with _tinydb_lock:
            return _TinyDBCursor(self._find_unlocked(query or {}))

    def _find_unlocked(self, query: dict):
        all_docs = self._table.all()
        if not query:
            return list(all_docs)
        return [d for d in all_docs if self._matches(d, query)]

    def count_documents(self, query: dict = None) -> int:
        with _tinydb_lock:
            return len(self._find_unlocked(query or {}))

    def update_one(self, query: dict, update: dict, upsert: bool = False):
        with _tinydb_lock:
            return self._update_one_unlocked(query, update, upsert)

    def _update_one_unlocked(self, query: dict, update: dict, upsert: bool = False):
        docs = self._find_unlocked(query)
        if docs:
            doc = docs[0]
            set_data = update.get("$set", {})
            push_data = update.get("$push", {})
            updated = dict(doc)
            updated.update(set_data)
            for k, v in push_data.items():
                if k not in updated:
                    updated[k] = []
                updated[k].append(v)
            from tinydb import Query
            q = Query()
            self._table.update(updated, q._id == doc["_id"])
            class Result:
                modified_count = 1
            return Result()
        elif upsert:
            doc = {}
            for k, v in query.items():
                if not k.startswith("$"):
                    doc[k] = v
            doc.update(update.get("$set", {}))
            doc["_id"] = self._make_id()
            self._table.insert(doc)
            class Result:
                modified_count = 0
                upserted_id = doc["_id"]
            return Result()
        class Result:
            modified_count = 0
        return Result()

    def update_many(self, query: dict, update: dict):
        with _tinydb_lock:
            docs = self._find_unlocked(query)
            count = 0
            for doc in docs:
                set_data = update.get("$set", {})
                updated = dict(doc)
                updated.update(set_data)
                from tinydb import Query
                q = Query()
                self._table.update(updated, q._id == doc["_id"])
                count += 1
            class Result:
                modified_count = count
            return Result()

    def delete_one(self, query: dict):
        with _tinydb_lock:
            docs = self._find_unlocked(query)
            if docs:
                from tinydb import Query
                q = Query()
                self._table.remove(q._id == docs[0]["_id"])
                class Result:
                    deleted_count = 1
                return Result()
            class Result:
                deleted_count = 0
            return Result()

    def aggregate(self, pipeline: list):
        with _tinydb_lock:
            docs = list(self._table.all())
        for stage in pipeline:
            if "$match" in stage:
                docs = [d for d in docs if self._matches(d, stage["$match"])]
            elif "$group" in stage:
                docs = self._group(docs, stage["$group"])
            elif "$sort" in stage:
                for field, order in reversed(list(stage["$sort"].items())):
                    docs.sort(key=lambda d: d.get(field, 0), reverse=(order == -1))
            elif "$limit" in stage:
                docs = docs[:stage["$limit"]]
        return iter(docs)

    def create_index(self, *args, **kwargs):
        pass  # No-op for TinyDB

    def _matches(self, doc: dict, query: dict) -> bool:
        for key, value in query.items():
            if key == "$or":
                if not any(self._matches(doc, sub) for sub in value):
                    return False
            elif key == "$and":
                if not all(self._matches(doc, sub) for sub in value):
                    return False
            elif isinstance(value, dict):
                doc_val = doc.get(key)
                for op, op_val in value.items():
                    if op == "$ne" and doc_val == op_val:
                        return False
                    elif op == "$gte" and (doc_val is None or doc_val < op_val):
                        return False
                    elif op == "$lte" and (doc_val is None or doc_val > op_val):
                        return False
                    elif op == "$in" and doc_val not in op_val:
                        return False
                    elif op == "$exists":
                        if op_val and key not in doc:
                            return False
                        if not op_val and key in doc:
                            return False
                    elif op == "$regex":
                        import re
                        flags = 0
                        if value.get("$options") == "i":
                            flags = re.IGNORECASE
                        if doc_val is None or not re.search(op_val, str(doc_val), flags):
                            return False
            else:
                if doc.get(key) != value:
                    return False
        return True

    def _group(self, docs: list, group_spec: dict) -> list:
        from collections import defaultdict
        id_spec = group_spec.get("_id")
        groups = defaultdict(list)
        for doc in docs:
            if isinstance(id_spec, str) and id_spec.startswith("$"):
                key = doc.get(id_spec[1:])
            elif isinstance(id_spec, dict):
                key = tuple(
                    doc.get(v[1:]) if isinstance(v, str) and v.startswith("$") else v
                    for v in id_spec.values()
                )
            else:
                key = id_spec
            groups[key].append(doc)

        result = []
        for key, group_docs in groups.items():
            row = {"_id": key}
            for out_field, agg in group_spec.items():
                if out_field == "_id":
                    continue
                if isinstance(agg, dict):
                    if "$sum" in agg:
                        spec = agg["$sum"]
                        if spec == 1:
                            row[out_field] = len(group_docs)
                        elif isinstance(spec, dict) and "$cond" in spec:
                            cond = spec["$cond"]
                            row[out_field] = sum(
                                1 for d in group_docs if self._matches(d, {cond[0]["$ne"][0].lstrip("$"): {"$ne": cond[0]["$ne"][1]}})
                            )
                        elif isinstance(spec, str) and spec.startswith("$"):
                            row[out_field] = sum(d.get(spec[1:], 0) or 0 for d in group_docs)
                    elif "$count" in agg:
                        row[out_field] = len(group_docs)
            result.append(row)
        return result


class _TinyDBCursor:
    def __init__(self, docs: list):
        self._docs = docs

    def sort(self, key_or_list, direction=None):
        if isinstance(key_or_list, str):
            self._docs.sort(key=lambda d: d.get(key_or_list) or 0, reverse=(direction == -1))
        elif isinstance(key_or_list, list):
            for field, order in reversed(key_or_list):
                self._docs.sort(key=lambda d: d.get(field) or 0, reverse=(order == -1))
        return self

    def skip(self, n: int):
        self._docs = self._docs[n:]
        return self

    def limit(self, n: int):
        if n > 0:
            self._docs = self._docs[:n]
        return self

    def __iter__(self):
        return iter(self._docs)

    def __next__(self):
        return next(iter(self._docs))


class TinyDBProxy:
    """Provides MongoDB-style collection access for TinyDB."""
    def __init__(self, db):
        self._db = db
        self._collections = {}

    def __getitem__(self, name: str) -> TinyDBCollection:
        if name not in self._collections:
            self._collections[name] = TinyDBCollection(self._db.table(name))
        return self._collections[name]

    def __getattr__(self, name: str) -> TinyDBCollection:
        if name.startswith("_"):
            raise AttributeError(name)
        return self[name]
