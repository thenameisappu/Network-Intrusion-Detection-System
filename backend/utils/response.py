"""
Utility: Standardised JSON response helpers.
All API endpoints must use these helpers to maintain consistency.
"""
from flask import jsonify
from typing import Any, Optional


def success_response(message: str, data: Any = None, status_code: int = 200):
    payload = {"success": True, "message": message}
    if data is not None:
        payload["data"] = data
    return jsonify(payload), status_code


def error_response(
    message: str,
    code: str = "ERROR",
    details: Optional[Any] = None,
    status_code: int = 400,
):
    payload = {
        "success": False,
        "message": message,
        "error": {"code": code},
    }
    if details is not None:
        payload["error"]["details"] = details
    return jsonify(payload), status_code
