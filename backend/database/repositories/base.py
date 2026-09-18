"""
Database serialization helpers.
Handles MongoDB ObjectId and datetime objects for both MongoDB and TinyDB compatibility.
"""
from datetime import datetime
from backend.database.connection import is_using_tinydb


def _to_id(id_val):
    """Convert value to the appropriate ID format."""
    if is_using_tinydb():
        return str(id_val) if id_val else None
    try:
        from bson import ObjectId
        return ObjectId(str(id_val))
    except Exception:
        return id_val


def _now() -> str:
    """Return current UTC time as ISO string (for TinyDB) or datetime (for MongoDB)."""
    now = datetime.utcnow()
    if is_using_tinydb():
        return now.isoformat()
    return now


def _make_id():
    """Generate a new ID appropriate for the active database backend."""
    if is_using_tinydb():
        import uuid
        return str(uuid.uuid4())
    from bson import ObjectId
    return ObjectId()


def _serialize(doc) -> dict:
    """Convert a database document to a plain dict with 'id' key."""
    if doc is None:
        return None
    doc = dict(doc)
    # Convert _id to id
    if "_id" in doc:
        doc["id"] = str(doc.pop("_id"))
    # Convert datetime objects to ISO strings for JSON serialisation
    for k, v in doc.items():
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc


def build_query(field: str, value):
    """Return a simple equality query."""
    return {field: value}


def id_query(user_id: str) -> dict:
    """Return a query for _id field using the correct type."""
    if is_using_tinydb():
        return {"_id": str(user_id)}
    try:
        from bson import ObjectId
        return {"_id": ObjectId(user_id)}
    except Exception:
        return {"_id": str(user_id)}
