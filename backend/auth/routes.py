"""Auth routes — /auth/*"""
from flask import Blueprint, request, g
from flask_jwt_extended import get_jwt_identity
from backend.auth.service import AuthService
from backend.utils.response import success_response, error_response
from backend.utils.decorators import login_required, admin_required
from backend.database.repositories.user_repo import UserRepository

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
_service = AuthService()


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return error_response("Username and password are required.", "MISSING_FIELDS")
    try:
        result = _service.login(username, password, ip=request.remote_addr)
        return success_response("Login successful.", data=result)
    except ValueError as e:
        return error_response(str(e), "INVALID_CREDENTIALS", status_code=401)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    return success_response("Logged out successfully.")


@auth_bp.route("/me", methods=["GET"])
@login_required
def me():
    user = g.current_user
    return success_response("User profile.", data={
        "id": user["id"],
        "username": user["username"],
        "email": user.get("email", ""),
        "role": user.get("role", "analyst"),
        "full_name": user.get("full_name", ""),
    })


@auth_bp.route("/register", methods=["POST"])
@admin_required
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    full_name = data.get("full_name", "")
    role = data.get("role", "analyst")

    if not username or not email or not password:
        return error_response("Username, email, and password are required.", "MISSING_FIELDS")
    if role not in ("admin", "analyst"):
        return error_response("Role must be 'admin' or 'analyst'.", "INVALID_ROLE")

    try:
        result = _service.register(username, email, password, full_name, role)
        return success_response("User created successfully.", data=result, status_code=201)
    except ValueError as e:
        return error_response(str(e), "DUPLICATE_USER")


@auth_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json(silent=True) or {}
    old = data.get("old_password", "")
    new = data.get("new_password", "")
    if not old or not new:
        return error_response("old_password and new_password are required.", "MISSING_FIELDS")
    if len(new) < 8:
        return error_response("New password must be at least 8 characters.", "WEAK_PASSWORD")
    try:
        _service.change_password(g.current_user["id"], old, new)
        return success_response("Password changed successfully.")
    except ValueError as e:
        return error_response(str(e), "INVALID_PASSWORD")
