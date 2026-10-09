"""SQLite access layer (parameterised queries only)."""
import sqlite3
from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL, pw_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
  is_active INTEGER NOT NULL DEFAULT 1, totp_secret_enc BLOB, totp_pending_enc BLOB, totp_enabled INTEGER NOT NULL DEFAULT 0,
  totp_last_step INTEGER NOT NULL DEFAULT 0, failed_count INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, pw_changed_at INTEGER NOT NULL, last_login_at INTEGER);
CREATE TABLE IF NOT EXISTS backup_codes(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL, used_at INTEGER);
CREATE INDEX IF NOT EXISTS ix_backup_user ON backup_codes(user_id, code_hash);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  dev_hash TEXT NOT NULL UNIQUE, label TEXT, ip TEXT, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  trusted_until INTEGER);
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_id INTEGER,
  created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  ip TEXT, ua TEXT, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS challenges(
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind TEXT NOT NULL,
  code_hash TEXT, attempts INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL, next_url TEXT,
  used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS reset_tokens(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS files(
  id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  orig_name TEXT, safe_name TEXT NOT NULL, mime TEXT, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
  wrapped_key BLOB NOT NULL, scan_engine TEXT, scan_status TEXT, created_at INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_files_owner ON files(owner_id, sha256);
CREATE TABLE IF NOT EXISTS shares(
  id INTEGER PRIMARY KEY, file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  creator_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE, parent_share_id INTEGER,
  token_hash TEXT NOT NULL UNIQUE, permission TEXT NOT NULL DEFAULT 'viewer' CHECK(permission IN ('viewer','collaborator')),
  allow_download INTEGER NOT NULL DEFAULT 0, allow_reshare INTEGER NOT NULL DEFAULT 0, expires_at INTEGER,
  max_downloads INTEGER, download_count INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_shares_file ON shares(file_id);
CREATE INDEX IF NOT EXISTS ix_shares_recipient ON shares(recipient_id);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, user_id INTEGER, action TEXT NOT NULL, object TEXT, ip TEXT, ua TEXT,
  detail TEXT, severity TEXT NOT NULL DEFAULT 'info', prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_audit_user ON audit(user_id, ts);
CREATE INDEX IF NOT EXISTS ix_audit_action ON audit(action, ts);
CREATE INDEX IF NOT EXISTS ix_audit_object ON audit(object);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, user_id INTEGER, kind TEXT NOT NULL, severity TEXT NOT NULL,
  detail TEXT, ip TEXT, resolved INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS attempts(key TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_attempts ON attempts(key, ts);
"""


def connect(path):
    conn = sqlite3.connect(path, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(path):
    conn = connect(path)
    conn.executescript(SCHEMA)
    conn.close()


def one(sql, args=()):
    return get_db().execute(sql, args).fetchone()


def many(sql, args=()):
    return get_db().execute(sql, args).fetchall()


def run(sql, args=()):
    """Execute a write; returns the cursor (rowcount / lastrowid)."""
    return get_db().execute(sql, args)
