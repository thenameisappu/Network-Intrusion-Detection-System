"""
Seed script — creates the admin user and default system settings.
Run this ONCE before starting the application:
    python scripts/seed_db.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bcrypt
from dotenv import load_dotenv
load_dotenv()

from backend.database.connection import init_db
from backend.database.repositories.user_repo import UserRepository
from backend.database.connection import get_db

# Mock Flask app for init_db
class MockApp:
    config = {
        "MONGODB_URI": os.getenv("MONGODB_URI", "mongodb://localhost:27017/"),
        "MONGODB_DB": os.getenv("MONGODB_DB", "nids_db"),
    }

print("Connecting to MongoDB...")
init_db(MockApp())
print("Connected.")

repo = UserRepository()

# Create admin user
admin_username = "admin"
existing = repo.find_by_username(admin_username)
if existing:
    print(f"Admin user '{admin_username}' already exists. Skipping creation.")
else:
    password = "Admin@123"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_id = repo.create({
        "username": admin_username,
        "email": "admin@nids.local",
        "password_hash": password_hash,
        "full_name": "System Administrator",
        "role": "admin",
        "is_active": True,
    })
    print(f"[OK] Admin user created: username=admin, password=Admin@123 (id={user_id})")

# Create analyst demo user
analyst_username = "analyst"
existing_analyst = repo.find_by_username(analyst_username)
if existing_analyst:
    print(f"Analyst user '{analyst_username}' already exists. Skipping.")
else:
    analyst_hash = bcrypt.hashpw(b"Analyst@123", bcrypt.gensalt()).decode()
    analyst_id = repo.create({
        "username": analyst_username,
        "email": "analyst@nids.local",
        "password_hash": analyst_hash,
        "full_name": "Security Analyst",
        "role": "analyst",
        "is_active": True,
    })
    print(f"[OK] Analyst user created: username=analyst, password=Analyst@123 (id={analyst_id})")

# System settings
db = get_db()
db.system_settings.update_one(
    {"key": "main"},
    {"$set": {
        "key": "main",
        "system_name": "AI-Based Network Intrusion Detection System",
        "version": "1.0.0",
        "alert_threshold_confidence": 0.7,
        "max_batch_size": 10000,
        "retention_days": 90,
        "simulation_enabled": True,
    }},
    upsert=True,
)
print("[OK] System settings initialised.")
print("\nSetup complete! You can now start the backend:")
print("  python backend/app.py")
print("\nDefault credentials:")
print("  Admin   - username: admin    | password: Admin@123")
print("  Analyst - username: analyst  | password: Analyst@123")
