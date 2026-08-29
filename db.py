"""SQLite persistence for the local MySmartMed research prototype."""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "mysmartmed.db"

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS User_Details (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE CHECK(length(username) BETWEEN 3 AND 48),
    password_hash TEXT NOT NULL,
    password_salt BLOB NOT NULL,
    contact_number TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS Patient_Details (
    patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES User_Details(user_id) ON DELETE CASCADE,
    name TEXT NOT NULL, dob TEXT, gender TEXT, contact_number TEXT, family_email TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS Doctor_Details (
    doctor_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES User_Details(user_id) ON DELETE CASCADE,
    name TEXT NOT NULL, hospital TEXT, specialisation TEXT, contact_number TEXT
);
CREATE TABLE IF NOT EXISTS Visit_Details (
    visit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL REFERENCES Patient_Details(patient_id) ON DELETE CASCADE,
    doctor_id INTEGER NOT NULL REFERENCES Doctor_Details(doctor_id) ON DELETE RESTRICT,
    visit_date TEXT NOT NULL, next_visit_date TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS Medicine_Details (
    medicine_id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL REFERENCES Patient_Details(patient_id) ON DELETE CASCADE,
    name TEXT NOT NULL, dosage TEXT, frequency TEXT, time_of_day TEXT NOT NULL,
    start_date TEXT, end_date TEXT, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
);
CREATE TABLE IF NOT EXISTS Refill_Details (
    refill_id INTEGER PRIMARY KEY AUTOINCREMENT,
    medicine_id INTEGER NOT NULL UNIQUE REFERENCES Medicine_Details(medicine_id) ON DELETE CASCADE,
    total_qty TEXT NOT NULL, remaining_qty TEXT NOT NULL, threshold TEXT NOT NULL,
    last_refill_date TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS Compliance_Log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    medicine_id INTEGER NOT NULL REFERENCES Medicine_Details(medicine_id) ON DELETE CASCADE,
    scheduled_time TEXT NOT NULL,
    status TEXT NOT NULL,
    logged_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(medicine_id, scheduled_time)
);
CREATE INDEX IF NOT EXISTS idx_patients_user ON Patient_Details(user_id);
CREATE INDEX IF NOT EXISTS idx_doctors_user ON Doctor_Details(user_id);
CREATE INDEX IF NOT EXISTS idx_medicines_patient ON Medicine_Details(patient_id);
CREATE INDEX IF NOT EXISTS idx_compliance_medicine_time ON Compliance_Log(medicine_id, scheduled_time);
"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Initialized database at {DB_PATH}")
