"""
Auth decorators for protecting API routes.
Provides role-based access control (admin vs analyst/user).
"""
from functools import wraps
from flask import g
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from backend.utils.response import error_response
from backend.database.repositories.user_repo import UserRepository


def login_required(fn):
    """Require valid JWT for any role."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = UserRepository().find_by_id(user_id)
            if not user:
                return error_response("User not found", "UNAUTHORIZED", status_code=401)
            g.current_user = user
            return fn(*args, **kwargs)
        except Exception as e:
            return error_response("Authentication required", "UNAUTHORIZED", status_code=401)
    return wrapper


def admin_required(fn):
    """Require valid JWT AND admin role."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
            claims = get_jwt()
            if claims.get("role") != "admin":
                return error_response("Admin access required", "FORBIDDEN", status_code=403)
            user_id = get_jwt_identity()
            user = UserRepository().find_by_id(user_id)
            if not user:
                return error_response("User not found", "UNAUTHORIZED", status_code=401)
            g.current_user = user
            return fn(*args, **kwargs)
        except Exception:
            return error_response("Authentication required", "UNAUTHORIZED", status_code=401)
    return wrapper
