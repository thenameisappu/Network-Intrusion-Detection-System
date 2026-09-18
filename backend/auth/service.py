"""Auth service — user management, login, registration."""
import bcrypt
from flask_jwt_extended import create_access_token
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.audit_repo import AuditRepository
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class AuthService:
    def __init__(self):
        self._users = UserRepository()
        self._audit = AuditRepository()

    def login(self, username: str, password: str, ip: str = None) -> dict:
        user = self._users.find_by_username(username)
        if not user:
            self._audit.log("LOGIN_FAILED", username=username, ip_address=ip,
                            details={"reason": "user_not_found"})
            raise ValueError("Invalid username or password.")

        if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            self._audit.log("LOGIN_FAILED", user_id=user["id"], username=username,
                            ip_address=ip, details={"reason": "wrong_password"})
            raise ValueError("Invalid username or password.")

        additional_claims = {"role": user.get("role", "analyst"), "username": user["username"]}
        token = create_access_token(identity=user["id"], additional_claims=additional_claims)

        self._audit.log("LOGIN_SUCCESS", user_id=user["id"], username=username, ip_address=ip)
        logger.info(f"User logged in: {username}")

        return {
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user.get("email", ""),
                "role": user.get("role", "analyst"),
                "full_name": user.get("full_name", ""),
            },
        }

    def register(self, username: str, email: str, password: str,
                 full_name: str = "", role: str = "analyst") -> dict:
        if self._users.find_by_username(username):
            raise ValueError(f"Username '{username}' already exists.")
        if self._users.find_by_email(email):
            raise ValueError(f"Email '{email}' already registered.")

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user_data = {
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "full_name": full_name,
            "role": role,
            "is_active": True,
        }
        user_id = self._users.create(user_data)
        self._audit.log("USER_CREATED", user_id=user_id, username=username,
                        details={"role": role})
        logger.info(f"New user created: {username} ({role})")
        return {"id": user_id, "username": username, "role": role}

    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        user = self._users.find_by_id(user_id)
        if not user:
            raise ValueError("User not found.")
        if not bcrypt.checkpw(old_password.encode(), user["password_hash"].encode()):
            raise ValueError("Current password is incorrect.")
        new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        self._users.update(user_id, {"password_hash": new_hash})
        self._audit.log("PASSWORD_CHANGED", user_id=user_id, username=user["username"])
        return True
