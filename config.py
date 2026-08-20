import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = "/tmp/campus_safety.db"

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key-for-production")

# Default manager login.
# Change these values before real deployment.
DEFAULT_MANAGER_USERNAME = os.getenv("MANAGER_USERNAME", "ADMIN")
DEFAULT_MANAGER_PASSWORD = os.getenv("MANAGER_PASSWORD", "PASSWORD")
