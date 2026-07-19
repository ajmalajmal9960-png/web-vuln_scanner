"""
database.py
Lightweight SQLite persistence layer for scan history.
Swap DB_PATH / get_connection() for a MySQL connector (e.g. mysql-connector-python)
if you want to use MySQL instead -- see README "Using MySQL instead of SQLite".
"""

import sqlite3
import json
from datetime import datetime

DB_PATH = "scans.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'live',
            summary TEXT NOT NULL,
            results TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def save_scan(url, results, mode="live"):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (url, scanned_at, mode, summary, results) VALUES (?, ?, ?, ?, ?)",
        (
            url,
            datetime.utcnow().isoformat(),
            mode,
            json.dumps(results["summary"]),
            json.dumps(results["findings"]),
        ),
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def get_all_scans():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, url, scanned_at, mode, summary FROM scans ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return [
        {"id": r[0], "url": r[1], "scanned_at": r[2], "mode": r[3], "summary": json.loads(r[4])}
        for r in rows
    ]


def get_scan(scan_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, url, scanned_at, mode, summary, results FROM scans WHERE id = ?",
        (scan_id,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "url": row[1],
        "scanned_at": row[2],
        "mode": row[3],
        "summary": json.loads(row[4]),
        "findings": json.loads(row[5]),
    }
