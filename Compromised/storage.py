"""SQLite persistence for incidents, alerts, feedback and custom IOC watchlists.

Everything the investigation dashboard shows lives here, so detections survive
server restarts (unlike the browser-local history kept in the UI).
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

# tests can point this at a temporary file to stay isolated from live data
DB_PATH = Path(os.environ.get("PHISHGUARD_DB")
               or Path(__file__).parent / "data" / "phishguard.db")
_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn, _lock:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id          TEXT PRIMARY KEY,
                kind        TEXT NOT NULL,               -- email | activity | takeover
                created_at  TEXT NOT NULL,
                title       TEXT NOT NULL,
                score       INTEGER NOT NULL,
                verdict     TEXT NOT NULL,
                payload     TEXT NOT NULL,               -- full report JSON
                inputs      TEXT,                        -- original user inputs
                feedback    TEXT,                        -- NULL | 'tp' | 'fp'
                feedback_at TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id  TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                severity     TEXT NOT NULL,              -- critical | high | medium
                title        TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'new' -- new | acknowledged | resolved
            );

            CREATE TABLE IF NOT EXISTS custom_iocs (
                indicator TEXT PRIMARY KEY,
                type      TEXT NOT NULL,
                note      TEXT,
                added_at  TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            """
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _row_to_dict(row: sqlite3.Row, include_payload: bool = False) -> dict:
    d = {
        "id": row["id"],
        "kind": row["kind"],
        "created_at": row["created_at"],
        "title": row["title"],
        "score": row["score"],
        "verdict": row["verdict"],
        "feedback": row["feedback"],
    }
    if include_payload:
        d["report"] = json.loads(row["payload"])
        d["inputs"] = json.loads(row["inputs"] or "null")
    return d


# ------------------------------- incidents ---------------------------------

def save_incident(incident_id: str, kind: str, title: str, score: int,
                  verdict: str, report: dict, inputs: dict | None = None) -> None:
    with _connect() as conn, _lock:
        conn.execute(
            """INSERT OR REPLACE INTO incidents
               (id, kind, created_at, title, score, verdict, payload, inputs)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (incident_id, kind, _now(), title[:300], score, verdict,
             json.dumps(report), json.dumps(inputs or {})),
        )


def list_incidents(limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_incident(incident_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    return _row_to_dict(row, include_payload=True) if row else None


def set_feedback(incident_id: str, label: str) -> dict | None:
    """label: 'tp' (true positive) or 'fp' (false positive)."""
    if label not in ("tp", "fp"):
        return None
    with _connect() as conn, _lock:
        conn.execute(
            "UPDATE incidents SET feedback = ?, feedback_at = ? WHERE id = ?",
            (label, _now(), incident_id),
        )
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    return _row_to_dict(row) if row else None


# -------------------------------- alerts -----------------------------------

def create_alert(incident_id: str, severity: str, title: str) -> int:
    with _connect() as conn, _lock:
        cur = conn.execute(
            "INSERT INTO alerts (incident_id, created_at, severity, title) VALUES (?, ?, ?, ?)",
            (incident_id, _now(), severity, title[:300]),
        )
        return int(cur.lastrowid)


def list_alerts(limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def update_alert(alert_id: int, status: str) -> dict | None:
    if status not in ("new", "acknowledged", "resolved"):
        return None
    with _connect() as conn, _lock:
        conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return dict(row) if row else None


def has_open_alert(incident_id: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM alerts WHERE incident_id = ? AND status != 'resolved' LIMIT 1",
            (incident_id,),
        ).fetchone()
    return row is not None


# ------------------------------ custom IOCs --------------------------------

def add_custom_ioc(indicator: str, ioc_type: str, note: str = "") -> None:
    with _connect() as conn, _lock:
        conn.execute(
            "INSERT OR REPLACE INTO custom_iocs (indicator, type, note, added_at) VALUES (?, ?, ?, ?)",
            (indicator.lower().strip(), ioc_type, note, _now()),
        )


def list_custom_iocs() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM custom_iocs ORDER BY added_at DESC").fetchall()
    return [dict(r) for r in rows]


def custom_ioc_set() -> set[str]:
    with _connect() as conn:
        rows = conn.execute("SELECT indicator FROM custom_iocs").fetchall()
    return {r["indicator"] for r in rows}


# --------------------------------- stats -----------------------------------

def stats() -> dict:
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
        by_verdict = {
            r["verdict"]: r["c"]
            for r in conn.execute(
                "SELECT verdict, COUNT(*) c FROM incidents WHERE kind='email' GROUP BY verdict"
            )
        }
        by_kind = {
            r["kind"]: r["c"]
            for r in conn.execute("SELECT kind, COUNT(*) c FROM incidents GROUP BY kind")
        }
        avg = conn.execute(
            "SELECT AVG(score) a FROM incidents WHERE kind='email'"
        ).fetchone()["a"]
        open_alerts = conn.execute(
            "SELECT COUNT(*) c FROM alerts WHERE status != 'resolved'"
        ).fetchone()["c"]
        alert_counts = {
            r["status"]: r["c"]
            for r in conn.execute("SELECT status, COUNT(*) c FROM alerts GROUP BY status")
        }
        fb = conn.execute(
            "SELECT COUNT(*) c, SUM(CASE WHEN feedback='tp' THEN 1 ELSE 0 END) tp, "
            "SUM(CASE WHEN feedback='fp' THEN 1 ELSE 0 END) fp "
            "FROM incidents WHERE feedback IS NOT NULL"
        ).fetchone()
    judged = fb["c"] or 0
    tp = fb["tp"] or 0
    return {
        "total_incidents": total,
        "by_verdict": by_verdict,
        "by_kind": by_kind,
        "avg_score": round(avg or 0, 1),
        "open_alerts": open_alerts,
        "alert_counts": alert_counts,
        "feedback": {
            "judged": judged,
            "true_positives": tp,
            "false_positives": fb["fp"] or 0,
            "accuracy": round(100 * tp / judged, 1) if judged else None,
        },
    }
