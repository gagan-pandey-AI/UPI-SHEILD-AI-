import sqlite3

conn = sqlite3.connect("database.db")

cursor = conn.cursor()

# Users Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    photo TEXT DEFAULT 'default png'
)
""")

# Scan History Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    message TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)
    REFERENCES users(id)
)
""")

conn.commit()

conn.close()

print("Database Created Successfully!")