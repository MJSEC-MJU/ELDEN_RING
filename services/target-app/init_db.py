"""
Initialize SQLite database with sample user data for SQL Injection demo.
"""

import sqlite3
import os

DB_PATH = os.environ.get("DB_PATH", "/app/data/users.db")


def init_database():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)

    sample_users = [
        ("admin", "admin1234", "admin"),
        ("user1", "password1", "user"),
        ("user2", "password2", "user"),
        ("demo", "demo1234", "user"),
    ]

    for username, password, role in sample_users:
        try:
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, password, role),
            )
        except sqlite3.IntegrityError:
            pass  # already exists

    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH} with {len(sample_users)} users")


if __name__ == "__main__":
    init_database()
