import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Local database path
DATABASE_PATH = str(
    BASE_DIR / "database" / "campus_safety.db"
)

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "campus-safety-secret-key-change-this"
)

DEFAULT_MANAGER_USERNAME = os.getenv(
    "MANAGER_USERNAME",
    "manager"
)

DEFAULT_MANAGER_PASSWORD = os.getenv(
    "MANAGER_PASSWORD",
    "manager123"
)