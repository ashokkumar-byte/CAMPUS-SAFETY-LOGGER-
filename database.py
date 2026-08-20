import sqlite3
import os
from werkzeug.security import generate_password_hash
from config import DATABASE_PATH, DEFAULT_MANAGER_USERNAME, DEFAULT_MANAGER_PASSWORD

def get_db():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    db = sqlite3.connect(DATABASE_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reported_by INTEGER NOT NULL,
            incident_type TEXT NOT NULL,
            location TEXT NOT NULL,
            description TEXT NOT NULL,
            priority TEXT NOT NULL DEFAULT 'Medium',
            status TEXT NOT NULL DEFAULT 'Pending',
            llm_summary TEXT,
            llm_recommendation TEXT,
            manager_remarks TEXT,
            assigned_to INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (reported_by) REFERENCES users(id),
            FOREIGN KEY (assigned_to) REFERENCES users(id)
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS incident_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            updated_by INTEGER NOT NULL,
            old_status TEXT,
            new_status TEXT,
            remarks TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id),
            FOREIGN KEY (updated_by) REFERENCES users(id)
        )
    """)

    # Create the requested ADMIN account automatically.
    admin = db.execute(
        "SELECT id FROM users WHERE username = ?",
        (DEFAULT_MANAGER_USERNAME,)
    ).fetchone()

    from datetime import datetime
    if not admin:
        db.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
            (
                DEFAULT_MANAGER_USERNAME,
                generate_password_hash(DEFAULT_MANAGER_PASSWORD),
                datetime.now().isoformat(timespec="seconds")
            )
        )
    else:
        db.execute(
            "UPDATE users SET password_hash = ?, role = 'admin' WHERE username = ?",
            (generate_password_hash(DEFAULT_MANAGER_PASSWORD), DEFAULT_MANAGER_USERNAME)
        )

    db.commit()
    db.close()
