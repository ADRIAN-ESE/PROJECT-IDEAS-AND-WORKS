"""
Minimal Cyber Awareness App — Flask Backend
Serves the SPA frontend and provides REST API endpoints.
"""

from flask import Flask, jsonify, request, render_template, send_from_directory, session, Response
from flask_cors import CORS
from email.message import EmailMessage
import base64
import csv
import io
import logging
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import smtplib
import sqlite3
import struct
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

from quiz_data import get_topics, get_questions, get_all_questions
from phishing_data import get_phishing_examples, get_phishing_by_id


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "cyberaware.db")


def _parse_bool(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587") or "587")
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()
SMTP_FROM = os.environ.get("SMTP_FROM", "").strip() or SMTP_USERNAME
SMTP_USE_TLS = _parse_bool("SMTP_USE_TLS", True)
SMTP_USE_SSL = _parse_bool("SMTP_USE_SSL", False)

CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")
APP_ENV = os.environ.get("APP_ENV", "development").strip().lower()


def _parse_positive_int(name, default):
    raw = os.environ.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer.") from exc
    if value < 1:
        raise RuntimeError(f"{name} must be a positive integer.")
    return value


def _validate_runtime_settings(app_env, secret_key, cookie_secure, debug):
    if app_env == "production":
        if not secret_key or len(secret_key) < 32:
            raise RuntimeError("Production requires a SECRET_KEY of at least 32 characters.")
        if not cookie_secure:
            raise RuntimeError("SESSION_COOKIE_SECURE must be enabled in production.")
        if debug:
            raise RuntimeError("FLASK_DEBUG must be disabled in production.")


SESSION_LIFETIME_HOURS = _parse_positive_int("SESSION_LIFETIME_HOURS", 24)
MAX_REQUESTS_PER_MINUTE = _parse_positive_int("MAX_REQUESTS_PER_MINUTE", 300)
QUIZ_TIME_LIMIT_MINUTES = {
    "beginner": 10,
    "intermediate": 15,
    "advanced": 20,
}
COMPREHENSIVE_EXAM_QUESTION_MIX = {
    "beginner": 2,
    "intermediate": 2,
    "advanced": 1,
}
COMPREHENSIVE_EXAM_TIME_LIMIT_MINUTES = 60
COMPREHENSIVE_EXAM_PASS_PERCENT = 70
_trusted_proxy_cidrs = []
for _network in os.environ.get("TRUSTED_PROXY_CIDRS", "").split(","):
    _network = _network.strip()
    if _network:
        try:
            _trusted_proxy_cidrs.append(ipaddress.ip_network(_network, strict=False))
        except ValueError as exc:
            raise RuntimeError(f"Invalid TRUSTED_PROXY_CIDRS entry: {_network}") from exc

_secret_key = os.environ.get("SECRET_KEY")
_cookie_secure = _parse_bool("SESSION_COOKIE_SECURE", APP_ENV == "production")
_debug = _parse_bool("FLASK_DEBUG", False)
_validate_runtime_settings(APP_ENV, _secret_key, _cookie_secure, _debug)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cyberaware")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = _secret_key or secrets.token_urlsafe(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = _cookie_secure
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=SESSION_LIFETIME_HOURS)
app.config["JSON_SORT_KEYS"] = False

_cors_origins = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]
CORS(
    app,
    resources={r"/api/*": {"origins": _cors_origins or "*"}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)


def _is_trusted_proxy(address, trusted_networks):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in trusted_networks)


def _resolve_client_identifier(remote_addr, forwarded_for=None, trusted_networks=()):
    if not remote_addr:
        return "unknown"
    if not forwarded_for or not _is_trusted_proxy(remote_addr, trusted_networks):
        return remote_addr

    try:
        chain = [ipaddress.ip_address(value.strip()) for value in forwarded_for.split(",")]
        peer = ipaddress.ip_address(remote_addr)
    except ValueError:
        return remote_addr

    for address in reversed(chain):
        if not any(address in network for network in trusted_networks):
            return str(address)
    return str(chain[0]) if chain else str(peer)


def _client_identifier():
    return _resolve_client_identifier(
        request.remote_addr,
        request.headers.get("X-Forwarded-For"),
        _trusted_proxy_cidrs,
    )


def _check_rate_limit(identifier, per_minute=MAX_REQUESTS_PER_MINUTE):
    current_window = int(time.time() // 60)
    client_key = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
    with get_db() as db:
        db.execute(
            "DELETE FROM rate_limit_windows WHERE window_start < ?",
            (current_window - 1,),
        )
        db.execute(
            """
            INSERT INTO rate_limit_windows (client_key, window_start, request_count)
            VALUES (?, ?, 1)
            ON CONFLICT (client_key, window_start)
            DO UPDATE SET request_count = request_count + 1
            """,
            (client_key, current_window),
        )
        request_count = db.execute(
            "SELECT request_count FROM rate_limit_windows "
            "WHERE client_key = ? AND window_start = ?",
            (client_key, current_window),
        ).fetchone()["request_count"]
    return request_count <= per_minute


@app.before_request
def _global_rate_limit_and_security_headers():
    ident = _client_identifier()
    if not _check_rate_limit(ident):
        logger.warning("Rate limit exceeded for %s on %s", ident, request.path)
        return jsonify({"error": "Too many requests. Slow down and try again later."}), 429
    if request.method == "OPTIONS":
        return None


@app.after_request
def _apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if app.config.get("SESSION_COOKIE_SECURE"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers["Content-Security-Policy"] = csp
    return response


@app.errorhandler(400)
def _bad_request(error):
    return jsonify({"error": getattr(error, "description", "Bad request.")}), 400


@app.errorhandler(404)
def _not_found(error):
    return jsonify({"error": "Not found."}), 404


@app.errorhandler(405)
def _method_not_allowed(error):
    return jsonify({"error": "Method not allowed."}), 405


@app.errorhandler(500)
def _server_error(error):
    logger.exception("Unhandled server error on %s %s", request.method, request.path)
    return jsonify({"error": "Internal server error."}), 500


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _utc_datetime(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def _is_expired(iso_expires):
    when = _utc_datetime(iso_expires)
    if when is None:
        return True
    return when < datetime.now(timezone.utc)


def validate_password_strength(password):
    """Return (is_valid, [feedback_messages])."""
    feedback = []
    if not isinstance(password, str):
        return False, ["Password must be a string."]
    if len(password) < 10:
        feedback.append("Password must be at least 10 characters.")
    if not re.search(r"[a-z]", password):
        feedback.append("Password must include at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        feedback.append("Password must include at least one uppercase letter.")
    if not re.search(r"\d", password):
        feedback.append("Password must include at least one number.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        feedback.append("Password must include at least one symbol.")
    if re.search(r"(.)\1{3,}", password):
        feedback.append("Password contains too many repeated characters.")
    if password.lower() in COMMON_PASSWORDS:
        feedback.insert(0, "This password is too common — choose a different one.")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf|zxcv)", password.lower()):
        feedback.append("Password contains an obvious sequential pattern.")
    return (not feedback, feedback)


def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                email_verified INTEGER NOT NULL DEFAULT 0,
                verification_code TEXT,
                verification_expires TEXT,
                two_factor_enabled INTEGER NOT NULL DEFAULT 0,
                two_factor_secret TEXT,
                backup_codes TEXT,
                password_reset_code TEXT,
                password_reset_expires TEXT,
                failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                last_login_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_progress (
                user_id INTEGER PRIMARY KEY,
                streak INTEGER NOT NULL DEFAULT 0,
                last_active TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS quiz_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                topic TEXT NOT NULL,
                topic_name TEXT NOT NULL,
                score INTEGER NOT NULL,
                total INTEGER NOT NULL,
                percent INTEGER NOT NULL,
                date TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS phishing_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                example_id TEXT NOT NULL,
                found INTEGER NOT NULL,
                total INTEGER NOT NULL,
                date TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS progress_reset_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
                requested_at TEXT NOT NULL,
                resolved_at TEXT,
                reviewed_by INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (reviewed_by) REFERENCES users (id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS quiz_attempts (
                attempt_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                topic TEXT NOT NULL,
                question_ids TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS comprehensive_exam_attempts (
                attempt_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                question_refs TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS comprehensive_exam_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                score INTEGER NOT NULL,
                total INTEGER NOT NULL,
                percent INTEGER NOT NULL,
                proficiency_level TEXT NOT NULL,
                passed INTEGER NOT NULL,
                date TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS rate_limit_windows (
                client_key TEXT NOT NULL,
                window_start INTEGER NOT NULL,
                request_count INTEGER NOT NULL,
                PRIMARY KEY (client_key, window_start)
            );
            CREATE INDEX IF NOT EXISTS idx_rate_limit_window_start
                ON rate_limit_windows(window_start);
            CREATE INDEX IF NOT EXISTS idx_quiz_results_user ON quiz_results(user_id);
            CREATE INDEX IF NOT EXISTS idx_quiz_results_topic ON quiz_results(topic);
            CREATE INDEX IF NOT EXISTS idx_phishing_results_user ON phishing_results(user_id);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        """)

    with get_db() as db:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        migrations = [
            ("email_verified", "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0"),
            ("approved", "ALTER TABLE users ADD COLUMN approved INTEGER NOT NULL DEFAULT 1"),
            ("progressive_2fa_required", "ALTER TABLE users ADD COLUMN progressive_2fa_required INTEGER NOT NULL DEFAULT 0"),
            ("verification_code", "ALTER TABLE users ADD COLUMN verification_code TEXT"),
            ("verification_expires", "ALTER TABLE users ADD COLUMN verification_expires TEXT"),
            ("two_factor_enabled", "ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0"),
            ("two_factor_secret", "ALTER TABLE users ADD COLUMN two_factor_secret TEXT"),
            ("backup_codes", "ALTER TABLE users ADD COLUMN backup_codes TEXT"),
            ("password_reset_code", "ALTER TABLE users ADD COLUMN password_reset_code TEXT"),
            ("password_reset_expires", "ALTER TABLE users ADD COLUMN password_reset_expires TEXT"),
            ("failed_login_attempts", "ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0"),
            ("locked_until", "ALTER TABLE users ADD COLUMN locked_until TEXT"),
            ("last_login_at", "ALTER TABLE users ADD COLUMN last_login_at TEXT"),
        ]
        for column_name, ddl in migrations:
            if column_name not in columns:
                try:
                    db.execute(ddl)
                except sqlite3.OperationalError:
                    pass


def serialize_user(user):
    user = dict(user) if hasattr(user, "keys") else user
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "email_verified": bool(user.get("email_verified", 0)),
        "approved": bool(user.get("approved", 1)),
        "progressive_2fa_required": bool(user.get("progressive_2fa_required", 0)),
        "two_factor_enabled": bool(user.get("two_factor_enabled", 0)),
        "quizzes_completed": int(user.get("quizzes_completed", 0)),
        "created_at": user.get("created_at"),
        "last_login_at": user.get("last_login_at"),
    }


def generate_verification_code():
    return str(secrets.randbelow(900000) + 100000)


def generate_totp_secret():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(alphabet) for _ in range(32))


def generate_totp(secret, time_step=30, t=None):
    if t is None:
        t = int(time.time())
    counter = int(t // time_step)
    clean_secret = secret.strip().replace(" ", "").upper()
    missing_padding = len(clean_secret) % 8
    if missing_padding != 0:
        clean_secret += "=" * (8 - missing_padding)
    try:
        key = base64.b32decode(clean_secret, casefold=True)
    except (ValueError, TypeError):
        raise ValueError("Invalid TOTP secret format.")
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[19] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset+4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def verify_totp(secret, code, window=1):
    if not secret or not code:
        return False
    clean_code = str(code).strip()
    current_t = int(time.time())
    for offset in range(-window, window + 1):
        test_t = current_t + (offset * 30)
        try:
            if generate_totp(secret, t=test_t) == clean_code:
                return True
        except Exception:
            continue
    return False


def normalize_int(value, field_name, *, minimum=0, maximum=None):
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer.")
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{field_name} must be an integer.")
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{field_name} must be an integer.")
    if parsed < minimum or (maximum is not None and parsed > maximum):
        raise ValueError(f"{field_name} is outside the allowed range.")
    return parsed


def _send_email(recipient, subject, body_text):
    if not all((SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM)):
        raise RuntimeError("SMTP is not configured. Set SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, and SMTP_FROM.")
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = SMTP_FROM
    message["To"] = recipient
    message.set_content(body_text)

    if SMTP_USE_SSL:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(message)
        return
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
        smtp.ehlo()
        if SMTP_USE_TLS:
            smtp.starttls()
            smtp.ehlo()
        smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp.send_message(message)


def send_password_reset_email(recipient, code):
    _send_email(
        recipient,
        "Reset your CyberAware password",
        "Your CyberAware password reset code is: " + code +
        "\n\nThis code expires in 30 minutes. If you did not request a password reset, you can safely ignore this email.",
    )


def _record_successful_login(db, user_id):
    db.execute(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
        (utc_now(), user_id),
    )


def _record_failed_login(db, user_row):
    user_id = user_row["id"]
    attempts = (user_row["failed_login_attempts"] or 0) + 1
    if attempts >= 10:
        locked_until = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(timespec="seconds")
        db.execute(
            "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
            (attempts, locked_until, user_id),
        )
        logger.warning("Account locked for user %s due to failed attempts.", user_row["username"])
        return
    db.execute("UPDATE users SET failed_login_attempts = ? WHERE id = ?", (attempts, user_id))


def _account_locked(user_row):
    if not user_row:
        return False
    locked_until = user_row["locked_until"]
    if not locked_until:
        return False
    if not _is_expired(locked_until):
        return True
    return False


def logged_in_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as db:
        row = db.execute(
            """
            SELECT id, username, email, role, email_verified, approved, progressive_2fa_required,
                   two_factor_enabled, locked_until,
                   (SELECT COUNT(*) FROM quiz_results WHERE user_id = users.id) AS quizzes_completed
            FROM users WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
    if not row:
        session.clear()
        return None
    if _account_locked(row):
        session.clear()
        return None
    return row


def login_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        if not logged_in_user():
            return jsonify({"error": "Authentication required."}), 401
        return handler(*args, **kwargs)
    return wrapped


def _training_access_error(user):
    if user["role"] != "admin" and not user["approved"]:
        return jsonify({
            "error": "Your account is waiting for administrator approval.",
            "code": "approval_required",
        }), 403
    if user["role"] != "admin" and user["progressive_2fa_required"] \
            and user["quizzes_completed"] >= 2 and not user["two_factor_enabled"]:
        return jsonify({
            "error": "Set up two-factor authentication to continue training.",
            "code": "two_factor_setup_required",
        }), 403
    return None


def training_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        user = logged_in_user()
        if not user:
            return jsonify({"error": "Please sign in to access the training modules."}), 401
        access_error = _training_access_error(user)
        if access_error:
            return access_error
        return handler(*args, **kwargs)
    return wrapped


def admin_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        user = logged_in_user()
        if not user:
            return jsonify({"error": "Authentication required."}), 401
        if user["role"] != "admin":
            return jsonify({"error": "Administrator access required."}), 403
        return handler(*args, **kwargs)
    return wrapped


def update_activity(db, user_id):
    today = datetime.now(timezone.utc).date().isoformat()
    row = db.execute("SELECT streak, last_active FROM user_progress WHERE user_id = ?", (user_id,)).fetchone()
    if not row:
        db.execute("INSERT INTO user_progress (user_id, streak, last_active) VALUES (?, 1, ?)", (user_id, today))
        return
    if row["last_active"] == today:
        return
    yesterday = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()
    streak = row["streak"] + 1 if row["last_active"] == yesterday else 1
    db.execute("UPDATE user_progress SET streak = ?, last_active = ? WHERE user_id = ?", (streak, today, user_id))


init_db()

# ---------------------------------------------------------------------------
# Common weak passwords (small local dictionary for demo)
# ---------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "111111", "12345678", "iloveyou", "admin", "welcome", "monkey",
    "login", "princess", "dragon", "passw0rd", "master", "hello",
    "freedom", "whatever", "qazwsx", "trustno1", "jordan", "harley",
    "1234", "robert", "matthew", "jordan23", "letmein", "shadow"
}

LEARNING_RESOURCES = {
    "phishing": [
        {
            "title": "UK NCSC — Top Tips for Staying Secure Online",
            "url": "https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online",
            "description": "Practical steps for spotting phishing, securing accounts, updating devices, and protecting personal data.",
            "type": "Official learning guide",
            "difficulty": "Beginner"
        },
        {
            "title": "Stop Think Fraud — Recognise and Report Fraud",
            "url": "https://stopthinkfraud.campaign.gov.uk/",
            "description": "Learn how to recognize common fraud and scams and find guidance on what to do if targeted.",
            "type": "Public awareness guide",
            "difficulty": "Beginner"
        },
        {
            "title": "Cisco — What Is Phishing?",
            "url": "https://www.cisco.com/site/us/en/learn/topics/security/what-is-phishing.html",
            "description": "Learn how phishing works, common attack types, and ways to recognize suspicious messages.",
            "type": "Learning guide",
            "difficulty": "Beginner"
        },
        {
            "title": "Google — Avoid and Report Phishing",
            "url": "https://support.google.com/mail/answer/8253",
            "description": "Practical advice for recognizing suspicious messages and avoiding unsafe links or attachments.",
            "type": "Learning guide",
            "difficulty": "Beginner"
        },
        {
            "title": "IBM — What Is Phishing?",
            "url": "https://www.ibm.com/think/topics/phishing",
            "description": "A detailed overview of phishing tactics, warning signs, and prevention.",
            "type": "Learning article",
            "difficulty": "Beginner"
        }
    ],
    "passwords": [
        {
            "title": "UK NCSC — Use a Strong and Separate Password for Your Email",
            "url": "https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online/use-a-strong-and-separate-password-for-email",
            "description": "Understand why your email account needs a unique, strong password and how two-step verification adds protection.",
            "type": "Official learning guide",
            "difficulty": "Beginner"
        },
        {
            "title": "Google Account — Security Recommendations",
            "url": "https://support.google.com/accounts/answer/46526",
            "description": "Review practical steps for strengthening account security, including password protection.",
            "type": "Learning guide",
            "difficulty": "Beginner"
        },
        {
            "title": "Have I Been Pwned — Pwned Passwords",
            "url": "https://haveibeenpwned.com/Passwords",
            "description": "Learn whether a password has appeared in known data breaches; avoid reusing exposed passwords.",
            "type": "Security tool",
            "difficulty": "Beginner"
        },
        {
            "title": "IBM — Identity and Access Management",
            "url": "https://www.ibm.com/think/topics/identity-access-management",
            "description": "Understand how authentication and access controls help protect accounts and information.",
            "type": "Learning article",
            "difficulty": "Intermediate"
        }
    ],
    "social-engineering": [
        {
            "title": "Stop Think Fraud — Recognise and Report Fraud",
            "url": "https://stopthinkfraud.campaign.gov.uk/",
            "description": "See practical guidance for recognizing fraud tactics and deciding what to do next.",
            "type": "Public awareness guide",
            "difficulty": "Beginner"
        },
        {
            "title": "IBM — What Is Social Engineering?",
            "url": "https://www.ibm.com/think/topics/social-engineering",
            "description": "Learn how attackers use psychological manipulation and how common tactics work.",
            "type": "Learning article",
            "difficulty": "Beginner"
        },
        {
            "title": "Cisco — What Is Social Engineering?",
            "url": "https://www.cisco.com/site/us/en/learn/topics/security/what-is-social-engineering.html",
            "description": "Explore common social engineering attacks and ways to recognize them.",
            "type": "Learning guide",
            "difficulty": "Beginner"
        },
        {
            "title": "Google — Avoid and Report Phishing",
            "url": "https://support.google.com/mail/answer/8253",
            "description": "Use practical checks to identify deceptive messages and suspicious links.",
            "type": "Learning guide",
            "difficulty": "Beginner"
        }
    ],
    "data-protection": [
        {
            "title": "IBM — What Is Data Security?",
            "url": "https://www.ibm.com/think/topics/data-security",
            "description": "Learn how organizations protect sensitive information from unauthorized access and loss.",
            "type": "Learning article",
            "difficulty": "Intermediate"
        },
        {
            "title": "IBM — What Is Data Privacy?",
            "url": "https://www.ibm.com/think/topics/data-privacy",
            "description": "An introduction to personal data, privacy principles, and data protection laws.",
            "type": "Learning article",
            "difficulty": "Intermediate"
        },
        {
            "title": "Electronic Frontier Foundation — Privacy",
            "url": "https://www.eff.org/issues/privacy",
            "description": "Explore digital privacy principles and the impact of privacy protections on people.",
            "type": "Learning resource",
            "difficulty": "Intermediate"
        }
    ],
    "safe-browsing": [
        {
            "title": "UK NCSC — Top Tips for Staying Secure Online",
            "url": "https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online",
            "description": "Follow simple guidance on suspicious messages, account security, software updates, and backups.",
            "type": "Official learning guide",
            "difficulty": "Beginner"
        },
        {
            "title": "Google Safety Center",
            "url": "https://safety.google/",
            "description": "Learn how online threats such as phishing, malware, and scams are identified and blocked.",
            "type": "Learning resource",
            "difficulty": "Beginner"
        },
        {
            "title": "Mozilla — Firefox Privacy",
            "url": "https://www.mozilla.org/en-US/privacy/firefox/",
            "description": "Understand browser privacy features and how Firefox handles browsing data.",
            "type": "Learning resource",
            "difficulty": "Beginner"
        },
        {
            "title": "Firefox — Private Browsing",
            "url": "https://www.firefox.com/en-US/features/private-browsing/",
            "description": "Learn what private browsing does and what it does not hide while you browse.",
            "type": "Learning guide",
            "difficulty": "Beginner"
        }
    ],
    "wifi-security": [
        {
            "title": "IBM — What Is Network Security?",
            "url": "https://www.ibm.com/think/topics/network-security",
            "description": "Learn network security fundamentals, including safeguards for wireless connections.",
            "type": "Learning article",
            "difficulty": "Beginner"
        },
        {
            "title": "Apple — Recommended Settings for Wi-Fi Routers",
            "url": "https://support.apple.com/en-us/102766",
            "description": "Review recommended security settings for wireless routers and access points.",
            "type": "Learning guide",
            "difficulty": "Intermediate"
        },
        {
            "title": "Apple — Private Wi-Fi Addresses",
            "url": "https://support.apple.com/en-us/102509",
            "description": "Learn how private Wi-Fi addresses can help protect a device's identity on wireless networks.",
            "type": "Learning guide",
            "difficulty": "Beginner"
        }
    ],
    "device-security": [
        {
            "title": "IBM — What Is Endpoint Security?",
            "url": "https://www.ibm.com/think/topics/endpoint-security",
            "description": "Learn how computers and mobile devices are protected against cyber threats.",
            "type": "Learning article",
            "difficulty": "Intermediate"
        },
        {
            "title": "IBM — What Is Cybersecurity?",
            "url": "https://www.ibm.com/think/topics/cybersecurity",
            "description": "A broad introduction to cybersecurity threats and the practices used to reduce risk.",
            "type": "Learning article",
            "difficulty": "Beginner"
        },
        {
            "title": "Google Safety Center",
            "url": "https://safety.google/",
            "description": "Learn about built-in protections against common online security threats.",
            "type": "Learning resource",
            "difficulty": "Beginner"
        }
    ],
    "incident-response": [
        {
            "title": "IBM — What Is Incident Response?",
            "url": "https://www.ibm.com/think/topics/incident-response",
            "description": "Understand incident response teams, plans, and the steps used to handle security events.",
            "type": "Learning article",
            "difficulty": "Intermediate"
        },
        {
            "title": "SANS — Information Security White Papers",
            "url": "https://www.sans.org/white-papers/",
            "description": "Browse security research and practical learning materials on incident handling and response.",
            "type": "Learning library",
            "difficulty": "Intermediate"
        },
        {
            "title": "IBM — What Is Cybersecurity?",
            "url": "https://www.ibm.com/think/topics/cybersecurity",
            "description": "Learn about common cyber threats and the security practices used to manage them.",
            "type": "Learning article",
            "difficulty": "Intermediate"
        }
    ],
    "cyber-law": [
        {
            "title": "Electronic Frontier Foundation — Privacy",
            "url": "https://www.eff.org/issues/privacy",
            "description": "Explore digital privacy rights and the policy questions raised by new technologies.",
            "type": "Learning resource",
            "difficulty": "Intermediate"
        },
        {
            "title": "IBM — What Is Data Privacy?",
            "url": "https://www.ibm.com/think/topics/data-privacy",
            "description": "Learn about privacy principles and how data protection laws affect information handling.",
            "type": "Learning article",
            "difficulty": "Intermediate"
        },
        {
            "title": "ISACA — COBIT Governance Framework",
            "url": "https://www.isaca.org/resources/cobit",
            "description": "An introduction to governance and management of enterprise information and technology.",
            "type": "Learning resource",
            "difficulty": "Intermediate"
        }
    ],
    "governance": [
        {
            "title": "ISACA — COBIT Governance Framework",
            "url": "https://www.isaca.org/resources/cobit",
            "description": "Learn how COBIT supports governance and management of enterprise information and technology.",
            "type": "Learning resource",
            "difficulty": "Intermediate"
        },
        {
            "title": "TechTarget — Cybersecurity Framework Overview",
            "url": "https://www.techtarget.com/cybersecurity/definition/NIST-Cybersecurity-Framework",
            "description": "Study how cybersecurity frameworks help organizations manage and reduce security risk.",
            "type": "Learning article",
            "difficulty": "Intermediate"
        },
        {
            "title": "IBM — Governance, Risk, and Compliance",
            "url": "https://www.ibm.com/think/topics/grc",
            "description": "Learn how governance, risk management, and compliance work together in organizations.",
            "type": "Learning article",
            "difficulty": "Intermediate"
        }
    ],
    "cyber-threat-management": [
        {
            "title": "IBM — Cyber Threat Intelligence",
            "url": "https://www.ibm.com/think/topics/cyber-threat-intelligence",
            "description": "Understand how threat intelligence is collected, assessed, and used to inform defensive decisions.",
            "type": "Learning article",
            "difficulty": "Intermediate"
        },
        {
            "title": "IBM — What Is Incident Response?",
            "url": "https://www.ibm.com/think/topics/incident-response",
            "description": "Explore incident response planning, coordination, containment, and recovery.",
            "type": "Learning article",
            "difficulty": "Advanced"
        },
        {
            "title": "IBM — Vulnerability Management",
            "url": "https://www.ibm.com/think/topics/vulnerability-management",
            "description": "Learn how to identify, prioritize, remediate, and track vulnerabilities across an environment.",
            "type": "Learning article",
            "difficulty": "Intermediate"
        }
    ]
}


# ---------------------------------------------------------------------------
# Routes — Frontend
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    question_count = sum(len(questions) for questions in get_all_questions().values())
    return render_template(
        "index.html",
        topic_count=len(get_topics()),
        question_count=question_count,
    )


@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory("static", path)


# ---------------------------------------------------------------------------
# API — Topics & Quiz
# ---------------------------------------------------------------------------

@app.route("/api/topics")
def api_topics():
    return jsonify(get_topics())


@app.route("/api/learning")
@training_required
def api_learning():
    topic_id = request.args.get("topic", "").strip()
    if topic_id:
        resources = LEARNING_RESOURCES.get(topic_id, [])
        return jsonify({"topic": topic_id, "resources": resources})
    return jsonify({"topics": list(LEARNING_RESOURCES.keys())})


@app.route("/api/quiz/<topic_id>")
@training_required
def api_quiz(topic_id):
    difficulty = request.args.get("difficulty")
    limit = request.args.get("limit", type=int)
    questions = get_questions(topic_id, difficulty=difficulty, limit=limit)
    if not questions:
        return jsonify({"error": "Topic not found or no questions"}), 404

    if difficulty in QUIZ_TIME_LIMIT_MINUTES:
        time_limit_minutes = QUIZ_TIME_LIMIT_MINUTES[difficulty]
    else:
        time_limit_minutes = round(
            sum(QUIZ_TIME_LIMIT_MINUTES[question["difficulty"]] for question in questions)
            / len(questions)
        )

    user = logged_in_user()
    attempt_id = secrets.token_urlsafe(32)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=time_limit_minutes)
    ).isoformat(timespec="seconds")
    question_ids = [question["id"] for question in questions]
    with get_db() as db:
        db.execute(
            "DELETE FROM quiz_attempts WHERE user_id = ? AND (expires_at <= ? OR used_at IS NOT NULL)",
            (user["id"], utc_now()),
        )
        db.execute(
            "INSERT INTO quiz_attempts (attempt_id, user_id, topic, question_ids, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (attempt_id, user["id"], topic_id, json.dumps(question_ids), expires_at),
        )

    return jsonify({
        "topic": topic_id,
        "count": len(questions),
        "attempt_id": attempt_id,
        "expires_at": expires_at,
        "time_limit_minutes": time_limit_minutes,
        "time_limit_seconds": time_limit_minutes * 60,
        "questions": [
            {
                key: question[key]
                for key in ("id", "difficulty", "question", "options")
            }
            for question in questions
        ],
    })


def _proficiency_level(percent):
    if percent >= 90:
        return "Advanced"
    if percent >= 75:
        return "Proficient"
    if percent >= 60:
        return "Developing"
    return "Foundation"


def _missing_exam_prerequisite_topics(db, user_id):
    completed_topics = {
        row["topic"]
        for row in db.execute(
            "SELECT DISTINCT topic FROM quiz_results WHERE user_id = ?",
            (user_id,),
        ).fetchall()
    }
    return [
        topic
        for topic in get_topics()
        if topic["id"] not in completed_topics
    ]


def _exam_prerequisite_error(missing_topics):
    if not missing_topics:
        return None
    return jsonify({
        "error": "Complete a quiz in every topic before starting the comprehensive exam.",
        "code": "quizzes_required",
        "missing_topics": [topic["name"] for topic in missing_topics],
    }), 403


@app.route("/api/exam", methods=["GET"])
@training_required
def api_comprehensive_exam():
    user = logged_in_user()
    with get_db() as db:
        missing_topics = _missing_exam_prerequisite_topics(db, user["id"])
    prerequisite_error = _exam_prerequisite_error(missing_topics)
    if prerequisite_error:
        return prerequisite_error

    exam_questions = []
    question_refs = []
    randomizer = secrets.SystemRandom()

    for topic in get_topics():
        topic_questions = get_questions(topic["id"])
        selected_questions = []
        for difficulty, count in COMPREHENSIVE_EXAM_QUESTION_MIX.items():
            candidates = [
                question
                for question in topic_questions
                if question["difficulty"] == difficulty
            ]
            if len(candidates) < count:
                logger.error(
                    "Topic %s has too few %s questions for the comprehensive exam.",
                    topic["id"],
                    difficulty,
                )
                return jsonify({"error": "The comprehensive exam is not available right now."}), 503
            selected_questions.extend(randomizer.sample(candidates, count))

        for question in selected_questions:
            question_ref = f"{topic['id']}:{question['id']}"
            question_refs.append({"topic": topic["id"], "question_id": question["id"]})
            exam_questions.append({
                "id": question_ref,
                "topic": topic["id"],
                "topic_name": topic["name"],
                "difficulty": question["difficulty"],
                "question": question["question"],
                "options": question["options"],
            })

    attempt_id = secrets.token_urlsafe(32)
    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(minutes=COMPREHENSIVE_EXAM_TIME_LIMIT_MINUTES)
    ).isoformat(timespec="seconds")
    with get_db() as db:
        db.execute(
            "INSERT INTO comprehensive_exam_attempts "
            "(attempt_id, user_id, question_refs, expires_at) VALUES (?, ?, ?, ?)",
            (attempt_id, user["id"], json.dumps(question_refs), expires_at),
        )

    return jsonify({
        "attempt_id": attempt_id,
        "count": len(exam_questions),
        "time_limit_minutes": COMPREHENSIVE_EXAM_TIME_LIMIT_MINUTES,
        "time_limit_seconds": COMPREHENSIVE_EXAM_TIME_LIMIT_MINUTES * 60,
        "expires_at": expires_at,
        "pass_percent": COMPREHENSIVE_EXAM_PASS_PERCENT,
        "questions": exam_questions,
    })


@app.route("/api/exam/submit", methods=["POST"])
@training_required
def submit_comprehensive_exam():
    user = logged_in_user()
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "An exam attempt and answers are required."}), 400
    attempt_id = data.get("attempt_id")
    answers = data.get("answers")
    if not isinstance(attempt_id, str) or not attempt_id.strip() or not isinstance(answers, list):
        return jsonify({"error": "An exam attempt and answers are required."}), 400

    with get_db() as db:
        prerequisite_error = _exam_prerequisite_error(
            _missing_exam_prerequisite_topics(db, user["id"])
        )
        if prerequisite_error:
            return prerequisite_error

        attempt = db.execute(
            "SELECT question_refs, expires_at, used_at "
            "FROM comprehensive_exam_attempts WHERE attempt_id = ? AND user_id = ?",
            (attempt_id, user["id"]),
        ).fetchone()
        if not attempt:
            return jsonify({"error": "Exam attempt not found."}), 404
        if attempt["used_at"]:
            return jsonify({"error": "This exam attempt has already been submitted."}), 409
        if _is_expired(attempt["expires_at"]):
            return jsonify({"error": "This exam attempt has expired. Start a new exam."}), 410

        question_refs = json.loads(attempt["question_refs"])
        if len(answers) != len(question_refs):
            return jsonify({"error": "Submit one answer for every exam question."}), 400

        submitted = {}
        try:
            for answer in answers:
                if not isinstance(answer, dict):
                    raise ValueError("Each answer must include a question ID and option.")
                question_id = answer.get("question_id")
                if not isinstance(question_id, str) or question_id in submitted:
                    raise ValueError("Answers must contain each exam question exactly once.")
                submitted[question_id] = normalize_int(
                    answer.get("selected"),
                    "selected option",
                    minimum=-1,
                )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        questions_by_ref = {}
        for reference in question_refs:
            question = next(
                (
                    question
                    for question in get_questions(reference["topic"])
                    if question["id"] == reference["question_id"]
                ),
                None,
            )
            if question is None:
                logger.error("Comprehensive exam attempt %s contains an unknown question.", attempt_id)
                return jsonify({"error": "Exam attempt is no longer valid."}), 409
            questions_by_ref[f"{reference['topic']}:{question['id']}"] = question

        if set(submitted) != set(questions_by_ref):
            return jsonify({"error": "Answers do not match this exam attempt."}), 400

        results = []
        score = 0
        for question_ref, question in questions_by_ref.items():
            selected = submitted[question_ref]
            if selected >= len(question["options"]):
                return jsonify({"error": "Selected option is outside the available choices."}), 400
            is_correct = selected == question["correct"]
            score += int(is_correct)
            topic_id = question_ref.split(":", 1)[0]
            topic_name = next(
                topic["name"] for topic in get_topics() if topic["id"] == topic_id
            )
            results.append({
                "question_id": question_ref,
                "topic": topic_id,
                "topic_name": topic_name,
                "selected": selected,
                "correct": question["correct"],
                "is_correct": is_correct,
                "explanation": question["explanation"],
                "source": question.get("source"),
                "source_label": question.get("source_label"),
            })

        total = len(question_refs)
        percent = round((score / total) * 100)
        proficiency_level = _proficiency_level(percent)
        passed = percent >= COMPREHENSIVE_EXAM_PASS_PERCENT
        consumed = db.execute(
            "UPDATE comprehensive_exam_attempts SET used_at = ? "
            "WHERE attempt_id = ? AND user_id = ? AND used_at IS NULL",
            (utc_now(), attempt_id, user["id"]),
        )
        if consumed.rowcount != 1:
            return jsonify({"error": "This exam attempt has already been submitted."}), 409
        completed_at = utc_now()
        db.execute(
            "INSERT INTO comprehensive_exam_results "
            "(user_id, score, total, percent, proficiency_level, passed, date) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user["id"], score, total, percent, proficiency_level, int(passed), completed_at),
        )
        update_activity(db, user["id"])

    return jsonify({
        "saved": True,
        "score": score,
        "total": total,
        "percent": percent,
        "passed": passed,
        "pass_percent": COMPREHENSIVE_EXAM_PASS_PERCENT,
        "proficiency_level": proficiency_level,
        "date": completed_at,
        "results": results,
    })


@app.route("/api/quiz")
@training_required
def api_all_quiz():
    return jsonify({
        topic: [
            {
                key: question[key]
                for key in ("id", "difficulty", "question", "options")
            }
            for question in questions
        ]
        for topic, questions in get_all_questions().items()
    })


# ---------------------------------------------------------------------------
# API — Phishing
# ---------------------------------------------------------------------------

@app.route("/api/phishing-examples")
@training_required
def api_phishing():
    difficulty = request.args.get("difficulty")
    examples = get_phishing_examples(difficulty=difficulty)
    return jsonify(examples)


@app.route("/api/phishing-examples/<example_id>")
@training_required
def api_phishing_one(example_id):
    example = get_phishing_by_id(example_id)
    if not example:
        return jsonify({"error": "Example not found"}), 404
    return jsonify(example)


# ---------------------------------------------------------------------------
# API — Authentication & User Progress
# ---------------------------------------------------------------------------

@app.route("/api/auth/me")
def auth_me():
    user = logged_in_user()
    if not user:
        return jsonify({"authenticated": False}), 401
    return jsonify({"authenticated": True, "user": serialize_user(user)})


@app.route("/api/challenges")
@training_required
def api_challenges():
    user = logged_in_user()
    challenges = [
        {"id": "daily-quiz", "title": "Daily Quiz Sprint", "description": "Complete one quiz challenge with at least 70%.", "reward": 150, "difficulty": "Medium"},
        {"id": "phish-run", "title": "Phish Hunter", "description": "Finish three phishing simulations without missing red flags.", "reward": 250, "difficulty": "High"},
        {"id": "password-reset", "title": "Password Hardening", "description": "Assess and improve two passwords using the checker.", "reward": 180, "difficulty": "Medium"},
        {"id": "awareness-streak", "title": "Awareness Streak", "description": "Return for three learning sessions in a row.", "reward": 300, "difficulty": "High"}
    ]

    if user:
        with get_db() as db:
            quiz_count = db.execute("SELECT COUNT(*) AS total FROM quiz_results WHERE user_id = ?", (user["id"],)).fetchone()["total"]
            phishing_count = db.execute("SELECT COUNT(*) AS total FROM phishing_results WHERE user_id = ?", (user["id"],)).fetchone()["total"]
            streak = db.execute("SELECT streak FROM user_progress WHERE user_id = ?", (user["id"],)).fetchone()
            streak_value = streak["streak"] if streak else 0

        challenges[0]["completed"] = quiz_count >= 1
        challenges[1]["completed"] = phishing_count >= 3
        challenges[2]["completed"] = False
        challenges[3]["completed"] = streak_value >= 3
    else:
        for challenge in challenges:
            challenge["completed"] = False

    return jsonify({"challenges": challenges})


@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
        return jsonify({"error": "Username must be 3-40 letters, numbers, dots, dashes, or underscores."}), 400
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"error": "Enter a valid email address."}), 400
    pw_valid, pw_feedback = validate_password_strength(password)
    if not pw_valid:
        return jsonify({"error": "Password is too weak.", "details": pw_feedback}), 400

    with get_db() as db:
        count = db.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
        role = "admin" if count == 0 else "user"
        approved = int(role == "admin")
        try:
            cursor = db.execute(
                "INSERT INTO users (username, email, password_hash, role, email_verified, approved, progressive_2fa_required, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (username, email, generate_password_hash(password), role, 0, approved, int(role == "user"), utc_now())
            )
        except sqlite3.IntegrityError:
            return jsonify({"error": "That username or email is already registered."}), 409
        user = db.execute(
            """
            SELECT id, username, email, role, email_verified, approved, progressive_2fa_required, two_factor_enabled,
                   0 AS quizzes_completed
            FROM users WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()

    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    logger.info("Registered user %s (%s)", user["username"], user["email"])
    return jsonify({
        "user": serialize_user(user),
        "message": (
            "Administrator account created successfully."
            if approved
            else "Account created. An administrator must approve it before you can start training."
        )
    }), 201


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    identifier = str(data.get("identifier", "")).strip().lower()
    password = data.get("password", "")
    with get_db() as db:
        user = db.execute(
            """
            SELECT id, username, email, password_hash, role, email_verified, approved,
                   progressive_2fa_required, two_factor_enabled,
                   locked_until, failed_login_attempts,
                   (SELECT COUNT(*) FROM quiz_results WHERE user_id = users.id) AS quizzes_completed
            FROM users WHERE lower(username) = ? OR email = ?
            """,
            (identifier, identifier)
        ).fetchone()

        if not user:
            logger.info("Failed login attempt for unknown identifier %s", identifier)
            return jsonify({"error": "Invalid username/email or password."}), 401

        if _account_locked(user):
            logger.warning("Blocked login for locked user %s", user["username"])
            return jsonify({"error": "Account is temporarily locked due to too many failed attempts. Try again later."}), 423

        if not isinstance(password, str) or not check_password_hash(user["password_hash"], password):
            _record_failed_login(db, user)
            return jsonify({"error": "Invalid username/email or password."}), 401

        if user["role"] != "admin" and not user["approved"]:
            return jsonify({
                "error": "Your account is waiting for administrator approval.",
                "code": "approval_required",
            }), 403

        if user["two_factor_enabled"]:
            _record_successful_login(db, user["id"])
            session.clear()
            session["2fa_pending_user_id"] = user["id"]
            return jsonify({
                "two_factor_required": True,
                "message": "Two-factor authentication code required.",
                "username": user["username"]
            })

        _record_successful_login(db, user["id"])

    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    logger.info("Successful login for user %s", user["username"])
    return jsonify({
        "user": serialize_user(user),
        "message": "Signed in successfully.",
        "email_verified": bool(user["email_verified"]),
        "approved": bool(user["approved"]),
        "quizzes_completed": int(user["quizzes_completed"]),
    })


@app.route("/api/auth/login/2fa", methods=["POST"])
def auth_login_2fa():
    user_id = session.get("2fa_pending_user_id")
    if not user_id:
        return jsonify({"error": "No pending two-factor authentication session."}), 400

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip().replace(" ", "").replace("-", "")
    if not code:
        return jsonify({"error": "Two-factor authentication code is required."}), 400

    with get_db() as db:
        user = db.execute(
            """
            SELECT id, username, email, role, email_verified, approved, progressive_2fa_required,
                   two_factor_enabled, two_factor_secret,
                   backup_codes,
                   (SELECT COUNT(*) FROM quiz_results WHERE user_id = users.id) AS quizzes_completed
            FROM users WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if not user or not user["two_factor_enabled"]:
            return jsonify({"error": "Two-factor authentication is not active."}), 400

        if verify_totp(user["two_factor_secret"], code):
            _record_successful_login(db, user["id"])
            session.pop("2fa_pending_user_id", None)
            session.permanent = True
            session["user_id"] = user["id"]
            logger.info("Successful 2FA login for user %s", user["username"])
            return jsonify({
                "user": serialize_user(user),
                "message": "Signed in successfully with 2FA.",
                "email_verified": bool(user["email_verified"])
            })

        code_hash = hashlib.sha256(code.lower().encode()).hexdigest()
        try:
            stored_hashes = json.loads(user["backup_codes"] or "[]")
        except Exception:
            stored_hashes = []

        if code_hash in stored_hashes:
            stored_hashes.remove(code_hash)
            db.execute("UPDATE users SET backup_codes = ? WHERE id = ?", (json.dumps(stored_hashes), user["id"]))
            _record_successful_login(db, user["id"])
            session.pop("2fa_pending_user_id", None)
            session.permanent = True
            session["user_id"] = user["id"]
            logger.info("Successful backup-code login for user %s", user["username"])
            return jsonify({
                "user": serialize_user(user),
                "message": "Signed in with a backup code. Note that this backup code is now used.",
                "email_verified": bool(user["email_verified"])
            })

        return jsonify({"error": "Invalid authenticator code or backup code."}), 401


@app.route("/api/auth/2fa/setup", methods=["POST"])
@login_required
def auth_2fa_setup():
    user = logged_in_user()
    secret = generate_totp_secret()
    otpauth_url = f"otpauth://totp/CyberAware:{user['username']}?secret={secret}&issuer=CyberAware&algorithm=SHA1&digits=6&period=30"
    return jsonify({
        "secret": secret,
        "otpauth_url": otpauth_url
    })


@app.route("/api/auth/2fa/enable", methods=["POST"])
@login_required
def auth_2fa_enable():
    user = logged_in_user()
    data = request.get_json(silent=True) or {}
    secret = str(data.get("secret", "")).strip().replace(" ", "").upper()
    code = str(data.get("code", "")).strip().replace(" ", "").replace("-", "")

    if not secret or not code:
        return jsonify({"error": "Secret and verification code are required."}), 400

    if not verify_totp(secret, code):
        return jsonify({"error": "Invalid verification code. Please check your authenticator app time and try again."}), 400

    # Generate 6 backup codes
    backup_codes = [secrets.token_hex(4).upper() for _ in range(6)]
    backup_hashes = [hashlib.sha256(c.lower().encode()).hexdigest() for c in backup_codes]

    with get_db() as db:
        db.execute(
            "UPDATE users SET two_factor_enabled = 1, two_factor_secret = ?, backup_codes = ? WHERE id = ?",
            (secret, json.dumps(backup_hashes), user["id"])
        )
        updated = db.execute(
            """
            SELECT id, username, email, role, email_verified, approved, progressive_2fa_required, two_factor_enabled,
                   (SELECT COUNT(*) FROM quiz_results WHERE user_id = users.id) AS quizzes_completed
            FROM users WHERE id = ?
            """,
            (user["id"],),
        ).fetchone()

    return jsonify({
        "user": serialize_user(updated),
        "backup_codes": backup_codes,
        "message": "Two-factor authentication has been enabled successfully. Save your backup codes safely!"
    })


@app.route("/api/auth/2fa/disable", methods=["POST"])
@login_required
def auth_2fa_disable():
    user = logged_in_user()
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    code = str(data.get("code", "")).strip().replace(" ", "").replace("-", "")

    with get_db() as db:
        full_user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        if not full_user:
            return jsonify({"error": "User not found."}), 404

        # Validate by password or current TOTP
        authenticated = False
        if password and check_password_hash(full_user["password_hash"], password):
            authenticated = True
        elif code and full_user["two_factor_secret"] and verify_totp(full_user["two_factor_secret"], code):
            authenticated = True

        if not authenticated:
            return jsonify({"error": "Enter your account password or current 2FA code to disable 2FA."}), 400

        db.execute("UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL, backup_codes = NULL WHERE id = ?", (user["id"],))
        updated = db.execute(
            """
            SELECT id, username, email, role, email_verified, approved, progressive_2fa_required, two_factor_enabled,
                   (SELECT COUNT(*) FROM quiz_results WHERE user_id = users.id) AS quizzes_completed
            FROM users WHERE id = ?
            """,
            (user["id"],),
        ).fetchone()

    return jsonify({
        "user": serialize_user(updated),
        "message": "Two-factor authentication has been disabled."
    })


@app.route("/api/certificate")
@training_required
def api_certificate():
    user = logged_in_user()
    with get_db() as db:
        quizzes = [dict(row) for row in db.execute(
            "SELECT topic, topic_name, score, total, percent, date FROM quiz_results WHERE user_id = ? ORDER BY id DESC",
            (user["id"],)
        )]
        phishing = [dict(row) for row in db.execute(
            "SELECT example_id, found, total, date FROM phishing_results WHERE user_id = ?",
            (user["id"],)
        )]
        exam = db.execute(
            "SELECT id, score, total, percent, proficiency_level, date "
            "FROM comprehensive_exam_results WHERE user_id = ? AND passed = 1 "
            "ORDER BY percent DESC, id DESC LIMIT 1",
            (user["id"],),
        ).fetchone()
        user_row = db.execute("SELECT created_at FROM users WHERE id = ?", (user["id"],)).fetchone()

    if not exam:
        return jsonify({
            "error": "Pass the all-topics comprehensive exam to earn your certificate.",
            "code": "comprehensive_exam_required",
        }), 403

    total_quizzes = len(quizzes)
    avg_score = exam["percent"]
    unique_topics = len({q["topic"] for q in quizzes})
    phish_completed = len(phishing)

    created_at = user_row["created_at"] if user_row else "2026-01-01"
    cert_raw = f"{user['id']}:{user['username']}:{created_at}"
    cert_id = "CYBER-" + hashlib.sha256(cert_raw.encode()).hexdigest()[:10].upper()

    return jsonify({
        "cert_id": f"{cert_id}-{exam['id']:06d}",
        "username": user["username"],
        "email": user["email"],
        "issue_date": exam["date"].split("T")[0],
        "avg_score": avg_score,
        "exam_score": exam["percent"],
        "proficiency_level": exam["proficiency_level"],
        "quizzes_taken": total_quizzes,
        "topics_covered": unique_topics,
        "phishing_simulations": phish_completed,
        "badge_title": exam["proficiency_level"],
        "verified": True
    })


@app.route("/api/progress/report")
@training_required
def api_progress_report():
    user = logged_in_user()
    with get_db() as db:
        quizzes = [dict(row) for row in db.execute(
            "SELECT topic, topic_name, score, total, percent, date FROM quiz_results WHERE user_id = ? ORDER BY id DESC",
            (user["id"],)
        )]
        phishing = [dict(row) for row in db.execute(
            "SELECT example_id, found, total, date FROM phishing_results WHERE user_id = ? ORDER BY id DESC",
            (user["id"],)
        )]
        meta = db.execute("SELECT streak, last_active FROM user_progress WHERE user_id = ?", (user["id"],)).fetchone()

    topic_summary = {}
    for q in quizzes:
        t = q["topic"]
        if t not in topic_summary:
            topic_summary[t] = {"name": q["topic_name"], "attempts": 0, "scores": []}
        topic_summary[t]["attempts"] += 1
        topic_summary[t]["scores"].append(q["percent"])

    topics_list = []
    for t, data in topic_summary.items():
        avg = round(sum(data["scores"]) / len(data["scores"]), 1)
        topics_list.append({
            "topic": t,
            "name": data["name"],
            "attempts": data["attempts"],
            "avg_score": avg,
            "status": "Proficient" if avg >= 80 else ("Competent" if avg >= 60 else "Needs Review")
        })

    total_quizzes = len(quizzes)
    overall_avg = round(sum(q["percent"] for q in quizzes) / total_quizzes, 1) if total_quizzes else 0

    return jsonify({
        "generated_at": utc_now(),
        "user": serialize_user(user),
        "metrics": {
            "total_quizzes": total_quizzes,
            "average_score": overall_avg,
            "phishing_completed": len(phishing),
            "current_streak": meta["streak"] if meta else 0,
            "last_active": meta["last_active"] if meta else None
        },
        "topics": topics_list,
        "recent_quizzes": quizzes[:10],
        "recent_phishing": phishing[:10]
    })


@app.route("/api/auth/password/reset-request", methods=["POST"])
def password_reset_request():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"error": "Enter a valid email address."}), 400

    with get_db() as db:
        user = db.execute("SELECT id, email FROM users WHERE lower(email) = ?", (email,)).fetchone()
        if not user:
            time.sleep(0.5)
            return jsonify({"message": "If an account with that email exists, a password reset link has been sent."})
        code = generate_verification_code()
        expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(timespec="seconds")
        db.execute(
            "UPDATE users SET password_reset_code = ?, password_reset_expires = ? WHERE id = ?",
            (code, expires, user["id"]),
        )

    try:
        send_password_reset_email(email, code)
    except (OSError, smtplib.SMTPException, RuntimeError) as error:
        logger.warning("Could not send password reset email to %s: %s", email, error)
        return jsonify({"error": "Unable to send password reset email. Try again later."}), 503

    return jsonify({"message": "If an account with that email exists, a password reset code has been sent."})


@app.route("/api/auth/password/reset-confirm", methods=["POST"])
def password_reset_confirm():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    code = str(data.get("code", "")).strip()
    new_password = data.get("new_password", "")

    if not email or not code:
        return jsonify({"error": "Email and reset code are required."}), 400

    pw_valid, pw_feedback = validate_password_strength(new_password)
    if not pw_valid:
        return jsonify({"error": "New password is too weak.", "details": pw_feedback}), 400

    with get_db() as db:
        user = db.execute(
            "SELECT id, password_reset_code, password_reset_expires, password_hash FROM users WHERE lower(email) = ?",
            (email,),
        ).fetchone()
        if not user or not user["password_reset_code"] or user["password_reset_code"] != code:
            return jsonify({"error": "Invalid reset code or email."}), 400
        if _is_expired(user["password_reset_expires"]):
            return jsonify({"error": "Reset code has expired. Request a new one."}), 410
        if check_password_hash(user["password_hash"], new_password):
            return jsonify({"error": "New password cannot match your current password."}), 400

        db.execute(
            "UPDATE users SET password_hash = ?, password_reset_code = NULL, password_reset_expires = NULL, failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
            (generate_password_hash(new_password), user["id"]),
        )
    logger.info("Password reset completed for email %s", email)
    return jsonify({"message": "Password reset successfully. You can now sign in with your new password."})


@app.route("/api/auth/password/change", methods=["POST"])
@login_required
def auth_change_password():
    user = logged_in_user()
    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not isinstance(current_password, str) or not isinstance(new_password, str):
        return jsonify({"error": "Passwords must be strings."}), 400

    with get_db() as db:
        full_user = db.execute(
            "SELECT id, password_hash, two_factor_enabled, two_factor_secret FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
        if not full_user or not check_password_hash(full_user["password_hash"], current_password):
            return jsonify({"error": "Current password is incorrect."}), 401

        if full_user["two_factor_enabled"]:
            code = str(data.get("two_factor_code") or data.get("code") or "").strip()
            if not code or not verify_totp(full_user["two_factor_secret"], code):
                return jsonify({"error": "Valid 2FA code required to change password."}), 401

    pw_valid, pw_feedback = validate_password_strength(new_password)
    if not pw_valid:
        return jsonify({"error": "New password is too weak.", "details": pw_feedback}), 400
    if check_password_hash(full_user["password_hash"], new_password):
        return jsonify({"error": "New password cannot match your current password."}), 400

    with get_db() as db:
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), user["id"]))
    logger.info("Password changed for user %s", user["username"])
    return jsonify({"message": "Password updated successfully."})


@app.route("/api/auth/account", methods=["DELETE"])
@login_required
def auth_delete_account():
    user = logged_in_user()
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not isinstance(password, str) or not password:
        return jsonify({"error": "Current password is required to delete your account."}), 400

    with get_db() as db:
        full_user = db.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
        if not full_user or not check_password_hash(full_user["password_hash"], password):
            return jsonify({"error": "Password confirmation is incorrect."}), 401

        db.execute("DELETE FROM user_progress WHERE user_id = ?", (user["id"],))
        db.execute("DELETE FROM quiz_results WHERE user_id = ?", (user["id"],))
        db.execute("DELETE FROM phishing_results WHERE user_id = ?", (user["id"],))
        db.execute("DELETE FROM users WHERE id = ?", (user["id"],))

    session.clear()
    logger.info("Account deleted for user %s", user["username"])
    return jsonify({"message": "Your account and associated progress have been permanently deleted."})


@app.route("/api/export/progress.csv")
@training_required
def export_progress_csv():
    user = logged_in_user()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["category", "topic", "topic_name", "example_id", "score", "found_flags", "total_flags", "percent", "date"])

    with get_db() as db:
        quizzes = db.execute(
            "SELECT topic, topic_name, score, total, percent, date FROM quiz_results WHERE user_id = ? ORDER BY date DESC",
            (user["id"],),
        ).fetchall()
        for q in quizzes:
            writer.writerow(["quiz", q["topic"], q["topic_name"], "", q["score"], "", q["total"], q["percent"], q["date"]])

        phishing = db.execute(
            "SELECT example_id, found, total, date FROM phishing_results WHERE user_id = ? ORDER BY date DESC",
            (user["id"],),
        ).fetchall()
        for p in phishing:
            writer.writerow(["phishing", "", "", p["example_id"], "", p["found"], p["total"], "", p["date"]])

    output = buf.getvalue()
    buf.close()
    filename = f"cyberaware-progress-{user['username']}-{utc_now().split('T')[0]}.csv"
    logger.info("Progress CSV exported for user %s", user["username"])
    return Response(
        output,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""},
    )


@app.route("/api/admin/export/users.csv")
@admin_required
def admin_export_users_csv():
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "username", "email", "role", "email_verified",
        "two_factor_enabled", "created_at", "last_login_at",
        "quizzes_taken", "phishing_done", "avg_score"
    ])
    with get_db() as db:
        rows = db.execute(
            """
            SELECT u.id, u.username, u.email, u.role, u.email_verified,
                   u.two_factor_enabled, u.created_at, u.last_login_at,
                   (SELECT COUNT(*) FROM quiz_results q WHERE q.user_id = u.id) AS quizzes_taken,
                   (SELECT COUNT(*) FROM phishing_results p WHERE p.user_id = u.id) AS phishing_done,
                   (SELECT ROUND(COALESCE(AVG(q2.percent), 0), 1) FROM quiz_results q2 WHERE q2.user_id = u.id) AS avg_score
            FROM users u
            ORDER BY u.id ASC
            """
        ).fetchall()
        for row in rows:
            writer.writerow([
                row["id"], row["username"], row["email"], row["role"],
                bool(row["email_verified"]), bool(row["two_factor_enabled"]),
                row["created_at"], row["last_login_at"],
                row["quizzes_taken"], row["phishing_done"], row["avg_score"],
            ])
    output = buf.getvalue()
    buf.close()
    filename = f"cyberaware-users-{utc_now().split('T')[0]}.csv"
    logger.info("Admin user CSV exported.")
    return Response(
        output,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""},
    )


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"message": "Signed out successfully."})


@app.route("/api/progress")
@training_required
def get_progress():
    user = logged_in_user()
    with get_db() as db:
        quizzes = [dict(row) for row in db.execute(
            "SELECT topic, topic_name, score, total, percent, date FROM quiz_results WHERE user_id = ? ORDER BY id DESC LIMIT 50",
            (user["id"],)
        )]
        phishing = [dict(row) for row in db.execute(
            "SELECT example_id AS id, found, total, date FROM phishing_results WHERE user_id = ? ORDER BY id DESC LIMIT 30",
            (user["id"],)
        )]
        exams = [dict(row) for row in db.execute(
            "SELECT score, total, percent, proficiency_level, passed, date "
            "FROM comprehensive_exam_results WHERE user_id = ? ORDER BY id DESC LIMIT 50",
            (user["id"],)
        )]
        meta = db.execute("SELECT streak, last_active FROM user_progress WHERE user_id = ?", (user["id"],)).fetchone()
    return jsonify({
        "quizzes": quizzes,
        "phishing": phishing,
        "exams": exams,
        "streak": meta["streak"] if meta else 0,
        "lastActive": meta["last_active"] if meta else None,
        "achievements": {}
    })


@app.route("/api/leaderboard")
def leaderboard():
    with get_db() as db:
        rows = db.execute(
            """
            SELECT
                u.username,
                COUNT(q.id) AS quizzes_taken,
                ROUND(COALESCE(AVG(q.percent), 0), 1) AS avg_score,
                MAX(q.percent) AS best_score,
                COALESCE((SELECT COUNT(*) FROM phishing_results p WHERE p.user_id = u.id), 0) AS phish_done
            FROM users u
            LEFT JOIN quiz_results q ON q.user_id = u.id
            GROUP BY u.id, u.username
            ORDER BY avg_score DESC, best_score DESC, quizzes_taken DESC, phish_done DESC, u.username ASC
            LIMIT 10
            """
        ).fetchall()

    leaderboard_data = []
    for index, row in enumerate(rows, start=1):
        avg_score = float(row["avg_score"] or 0)
        quizzes_taken = int(row["quizzes_taken"] or 0)
        phish_done = int(row["phish_done"] or 0)
        best_score = float(row["best_score"] or 0)
        points = int(round((avg_score * 10) + (quizzes_taken * 15) + (phish_done * 20) + (best_score * 0.5)))

        leaderboard_data.append({
            "rank": index,
            "username": row["username"],
            "avg_score": avg_score,
            "quizzes_taken": quizzes_taken,
            "best_score": best_score,
            "phish_done": phish_done,
            "points": points
        })

    return jsonify({"leaderboard": leaderboard_data, "generated_at": utc_now()})


@app.route("/api/progress/quiz", methods=["POST"])
@training_required
def save_quiz_progress():
    user = logged_in_user()
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "A quiz attempt and answers are required."}), 400
    attempt_id = data.get("attempt_id")
    answers = data.get("answers")
    if not isinstance(attempt_id, str) or not attempt_id.strip() or not isinstance(answers, list):
        return jsonify({"error": "A quiz attempt and answers are required."}), 400

    with get_db() as db:
        attempt = db.execute(
            "SELECT topic, question_ids, expires_at, used_at FROM quiz_attempts "
            "WHERE attempt_id = ? AND user_id = ?",
            (attempt_id, user["id"]),
        ).fetchone()
        if not attempt:
            return jsonify({"error": "Quiz attempt not found."}), 404
        if attempt["used_at"]:
            return jsonify({"error": "This quiz attempt has already been submitted."}), 409
        if _is_expired(attempt["expires_at"]):
            return jsonify({"error": "This quiz attempt has expired. Start a new quiz."}), 410

        question_ids = json.loads(attempt["question_ids"])
        if len(answers) != len(question_ids):
            return jsonify({"error": "Submit one answer for every question."}), 400

        submitted = {}
        try:
            for answer in answers:
                if not isinstance(answer, dict):
                    raise ValueError("Each answer must include a question ID and option.")
                question_id = answer.get("question_id")
                if not isinstance(question_id, str) or question_id in submitted:
                    raise ValueError("Answers must contain each quiz question exactly once.")
                selected = normalize_int(
                    answer.get("selected"),
                    "selected option",
                    minimum=-1,
                )
                submitted[question_id] = selected
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        if set(submitted) != set(question_ids):
            return jsonify({"error": "Answers do not match this quiz attempt."}), 400

        questions = {question["id"]: question for question in get_questions(attempt["topic"])}
        if any(question_id not in questions for question_id in question_ids):
            logger.error("Quiz attempt %s contains unknown question IDs.", attempt_id)
            return jsonify({"error": "Quiz attempt is no longer valid."}), 409

        results = []
        score = 0
        topic_resources = LEARNING_RESOURCES.get(attempt["topic"], [])
        related_resource = topic_resources[0] if topic_resources else None
        for question_id in question_ids:
            question = questions[question_id]
            selected = submitted[question_id]
            if selected >= len(question["options"]):
                return jsonify({"error": "Selected option is outside the available choices."}), 400
            is_correct = selected == question["correct"]
            score += int(is_correct)
            source = question.get("source")
            source_label = question.get("source_label")
            source_is_related = False
            if not source and related_resource:
                source = related_resource["url"]
                source_label = related_resource["title"]
                source_is_related = True
            result = {
                "question_id": question_id,
                "selected": selected,
                "correct": question["correct"],
                "is_correct": is_correct,
                "explanation": question["explanation"],
                "source": source,
                "source_label": source_label,
                "source_is_related": source_is_related,
            }
            results.append(result)

        total = len(question_ids)
        percent = round((score / total) * 100)
        consumed = db.execute(
            "UPDATE quiz_attempts SET used_at = ? "
            "WHERE attempt_id = ? AND user_id = ? AND used_at IS NULL",
            (utc_now(), attempt_id, user["id"]),
        )
        if consumed.rowcount != 1:
            return jsonify({"error": "This quiz attempt has already been submitted."}), 409

        topic_name = next(
            (topic["name"] for topic in get_topics() if topic["id"] == attempt["topic"]),
            attempt["topic"],
        )
        db.execute(
            "INSERT INTO quiz_results (user_id, topic, topic_name, score, total, percent, date) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user["id"], attempt["topic"], topic_name, score, total, percent, utc_now()),
        )
        update_activity(db, user["id"])
        quizzes_completed = db.execute(
            "SELECT COUNT(*) AS total FROM quiz_results WHERE user_id = ?",
            (user["id"],),
        ).fetchone()["total"]
    return jsonify({
        "saved": True,
        "score": score,
        "total": total,
        "percent": percent,
        "results": results,
        "quizzes_completed": quizzes_completed,
    })


@app.route("/api/progress/phishing", methods=["POST"])
@training_required
def save_phishing_progress():
    user = logged_in_user()
    data = request.get_json(silent=True) or {}
    try:
        example_id = str(data["id"]).strip()
        found = normalize_int(data["found"], "found", minimum=0)
        total = normalize_int(data["total"], "total", minimum=1)
    except (KeyError, ValueError):
        return jsonify({"error": "Incomplete phishing result."}), 400

    if not example_id:
        return jsonify({"error": "Example ID is required."}), 400
    if found > total:
        return jsonify({"error": "Found cannot exceed the total number of flags."}), 400

    with get_db() as db:
        db.execute(
            "INSERT INTO phishing_results (user_id, example_id, found, total, date) VALUES (?, ?, ?, ?, ?)",
            (user["id"], example_id, found, total, utc_now())
        )
        update_activity(db, user["id"])
    return jsonify({"saved": True})


@app.route("/api/progress", methods=["DELETE"])
@login_required
def reset_progress():
    user = logged_in_user()
    with get_db() as db:
        if user["role"] == "admin":
            _delete_user_progress(db, user["id"])
            return jsonify({"reset": True})

        existing = db.execute(
            "SELECT id, status FROM progress_reset_requests WHERE user_id = ?",
            (user["id"],),
        ).fetchone()
        if existing and existing["status"] == "pending":
            return jsonify({
                "error": "A progress reset request is already waiting for administrator approval.",
                "status": "pending",
            }), 409

        requested_at = utc_now()
        if existing:
            db.execute(
                "UPDATE progress_reset_requests SET status = 'pending', requested_at = ?, "
                "resolved_at = NULL, reviewed_by = NULL WHERE id = ?",
                (requested_at, existing["id"]),
            )
        else:
            db.execute(
                "INSERT INTO progress_reset_requests (user_id, status, requested_at) "
                "VALUES (?, 'pending', ?)",
                (user["id"], requested_at),
            )
    return jsonify({
        "requested": True,
        "status": "pending",
        "message": "Your progress reset request was sent to an administrator for approval.",
    }), 202


def _delete_user_progress(db, user_id):
    db.execute("DELETE FROM quiz_results WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM phishing_results WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM user_progress WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM comprehensive_exam_results WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM comprehensive_exam_attempts WHERE user_id = ?", (user_id,))


@app.route("/api/progress/reset-request")
@login_required
def get_progress_reset_request():
    user = logged_in_user()
    with get_db() as db:
        row = db.execute(
            "SELECT status, requested_at, resolved_at FROM progress_reset_requests "
            "WHERE user_id = ?",
            (user["id"],),
        ).fetchone()
    return jsonify({"request": dict(row) if row else None})


@app.route("/api/admin/progress-reset-requests/<int:request_id>", methods=["POST"])
@admin_required
def admin_resolve_progress_reset_request(request_id):
    admin = logged_in_user()
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get("action") not in {"approve", "reject"}:
        return jsonify({"error": "Choose whether to approve or reject the reset request."}), 400

    action = data["action"]
    status = "approved" if action == "approve" else "rejected"
    with get_db() as db:
        reset_request = db.execute(
            "SELECT user_id FROM progress_reset_requests WHERE id = ? AND status = 'pending'",
            (request_id,),
        ).fetchone()
        if not reset_request:
            return jsonify({"error": "Pending progress reset request not found."}), 404

        update = db.execute(
            "UPDATE progress_reset_requests SET status = ?, resolved_at = ?, reviewed_by = ? "
            "WHERE id = ? AND status = 'pending'",
            (status, utc_now(), admin["id"], request_id),
        )
        if update.rowcount != 1:
            return jsonify({"error": "Pending progress reset request not found."}), 404
        if action == "approve":
            _delete_user_progress(db, reset_request["user_id"])

    logger.info(
        "Admin %s marked progress reset request %s as %s.",
        admin["id"],
        request_id,
        status,
    )
    return jsonify({
        "status": status,
        "message": (
            "Progress reset approved and completed."
            if action == "approve"
            else "Progress reset request rejected."
        ),
    })


@app.route("/api/admin/summary")
@admin_required
def admin_summary():
    with get_db() as db:
        users = db.execute("SELECT id, username, email, role, approved, created_at FROM users ORDER BY id").fetchall()
        quiz_count = db.execute("SELECT COUNT(*) AS total FROM quiz_results").fetchone()["total"]
        phishing_count = db.execute("SELECT COUNT(*) AS total FROM phishing_results").fetchone()["total"]
        average_score = db.execute("SELECT COALESCE(AVG(percent), 0) AS average FROM quiz_results").fetchone()["average"]
        active_users = db.execute("SELECT COUNT(DISTINCT user_id) AS total FROM quiz_results").fetchone()["total"]
        leaderboard_rows = db.execute(
            """
            SELECT u.username, ROUND(COALESCE(AVG(q.percent), 0), 1) AS avg_score, COUNT(q.id) AS quizzes_taken, MAX(q.percent) AS best_score
            FROM users u
            LEFT JOIN quiz_results q ON q.user_id = u.id
            GROUP BY u.id, u.username
            ORDER BY avg_score DESC, best_score DESC, quizzes_taken DESC, u.username ASC
            LIMIT 5
            """
        ).fetchall()
        pending_approvals = db.execute(
            "SELECT COUNT(*) AS total FROM users WHERE role = 'user' AND approved = 0"
        ).fetchone()["total"]
        reset_requests = [
            dict(row)
            for row in db.execute(
                "SELECT r.id, r.requested_at, u.username, u.email "
                "FROM progress_reset_requests r JOIN users u ON u.id = r.user_id "
                "WHERE r.status = 'pending' ORDER BY r.requested_at, r.id"
            )
        ]

    leaderboard = []
    for row in leaderboard_rows:
        avg_score = float(row["avg_score"] or 0)
        quizzes_taken = int(row["quizzes_taken"] or 0)
        best_score = float(row["best_score"] or 0)
        points = int(round((avg_score * 10) + (quizzes_taken * 15) + (best_score * 0.5)))
        leaderboard.append({
            "username": row["username"],
            "avg_score": avg_score,
            "quizzes_taken": quizzes_taken,
            "best_score": best_score,
            "points": points
        })

    return jsonify({
        "users": [dict(user) for user in users],
        "quiz_attempts": quiz_count,
        "phishing_attempts": phishing_count,
        "average_score": round(float(average_score or 0), 1),
        "active_users": active_users,
        "pending_approvals": pending_approvals,
        "progress_reset_requests": reset_requests,
        "leaderboard": leaderboard
    })


@app.route("/api/admin/users/<int:user_id>/approve", methods=["POST"])
@admin_required
def admin_approve_user(user_id):
    with get_db() as db:
        user = db.execute(
            "SELECT username, role, approved FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not user:
            return jsonify({"error": "User not found."}), 404
        if user["role"] != "user":
            return jsonify({"error": "Administrator accounts do not need approval."}), 403
        if user["approved"]:
            return jsonify({"error": "User is already approved."}), 409

        db.execute("UPDATE users SET approved = 1 WHERE id = ?", (user_id,))

    logger.info("Admin approved user %s (id=%s)", user["username"], user_id)
    return jsonify({"message": f"{user['username']} is approved and can now sign in."})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def admin_delete_user(user_id):
    with get_db() as db:
        user = db.execute(
            "SELECT username, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not user:
            return jsonify({"error": "User not found."}), 404
        if user["role"] != "user":
            return jsonify({"error": "Administrator accounts cannot be removed here."}), 403

        db.execute("DELETE FROM user_progress WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM quiz_results WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM phishing_results WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))

    logger.info("Admin removed user %s (id=%s)", user["username"], user_id)
    return jsonify({"message": "User and associated progress removed."})


@app.route("/api/admin/users/batch", methods=["DELETE"])
@admin_required
def admin_delete_users_batch():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("user_ids"), list):
        return jsonify({"error": "Provide a list of user IDs to remove."}), 400

    raw_user_ids = data["user_ids"]
    if not raw_user_ids:
        return jsonify({"error": "Select at least one user to remove."}), 400

    user_ids = set()
    for user_id in raw_user_ids:
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 1:
            return jsonify({"error": "User IDs must be positive integers."}), 400
        user_ids.add(user_id)

    placeholders = ",".join("?" for _ in user_ids)
    with get_db() as db:
        users = db.execute(
            f"SELECT id, username, role FROM users WHERE id IN ({placeholders})",
            tuple(user_ids),
        ).fetchall()
        if len(users) != len(user_ids):
            return jsonify({"error": "One or more selected users no longer exist."}), 404
        if any(user["role"] != "user" for user in users):
            return jsonify({"error": "Administrator accounts cannot be removed here."}), 403

        db.execute(
            f"DELETE FROM users WHERE id IN ({placeholders})",
            tuple(user_ids),
        )

    usernames = [user["username"] for user in users]
    logger.info("Admin batch removed %s users: %s", len(usernames), ", ".join(usernames))
    return jsonify({
        "deleted_count": len(usernames),
        "message": f"{len(usernames)} user account(s) and associated progress removed.",
    })


@app.route("/api/admin/reset-users", methods=["POST"])
@admin_required
def admin_reset_users():
    with get_db() as db:
        db.execute(
            "DELETE FROM user_progress WHERE user_id NOT IN (SELECT id FROM users WHERE role = 'admin')"
        )
        db.execute(
            "DELETE FROM quiz_results WHERE user_id NOT IN (SELECT id FROM users WHERE role = 'admin')"
        )
        db.execute(
            "DELETE FROM phishing_results WHERE user_id NOT IN (SELECT id FROM users WHERE role = 'admin')"
        )
        db.execute("DELETE FROM users WHERE role != 'admin'")

    logger.info("Admin reset: all non-admin users and progress were removed.")
    return jsonify({"message": "All non-admin users and associated progress were removed."})


# ---------------------------------------------------------------------------
# API — Password Strength
# ---------------------------------------------------------------------------

def estimate_crack_time(entropy_bits):
    """Rough estimate assuming 10 billion guesses/second (powerful attacker)."""
    if entropy_bits <= 0:
        return "instant"
    guesses = 2 ** entropy_bits
    seconds = guesses / 1e10
    if seconds < 1:
        return "instant"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        return f"{seconds/60:.0f} minutes"
    if seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    if seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    if seconds < 31536000 * 100:
        return f"{seconds/31536000:.1f} years"
    return "centuries+"


def analyze_password(password: str) -> dict:
    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    charset = 0
    if has_lower:
        charset += 26
    if has_upper:
        charset += 26
    if has_digit:
        charset += 10
    if has_symbol:
        charset += 32  # approximate

    entropy = length * math.log2(charset) if charset > 0 else 0

    # Penalties
    score = 0
    feedback = []

    if length >= 12:
        score += 25
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 5
    else:
        feedback.append("Use at least 12 characters for better security.")

    if has_lower and has_upper:
        score += 20
    else:
        feedback.append("Mix uppercase and lowercase letters.")

    if has_digit:
        score += 15
    else:
        feedback.append("Add numbers.")

    if has_symbol:
        score += 20
    else:
        feedback.append("Add symbols (!@#$%^&* etc.).")

    if length >= 16:
        score += 10

    # Common password check
    is_common = password.lower() in COMMON_PASSWORDS
    if is_common:
        score = min(score, 15)
        feedback.insert(0, "This is a very common password — avoid it completely.")

    # Repeated characters / sequences
    if re.search(r"(.)\1{2,}", password):
        score = max(0, score - 10)
        feedback.append("Avoid repeating the same character many times.")

    if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde)", password.lower()):
        score = max(0, score - 10)
        feedback.append("Avoid sequential characters.")

    score = max(0, min(100, score))

    if score >= 80:
        strength = "Excellent"
        strength_class = "excellent"
    elif score >= 60:
        strength = "Strong"
        strength_class = "strong"
    elif score >= 40:
        strength = "Fair"
        strength_class = "fair"
    elif score >= 20:
        strength = "Weak"
        strength_class = "weak"
    else:
        strength = "Very Weak"
        strength_class = "very-weak"

    if not feedback and score >= 80:
        feedback.append("Great password! Consider using a password manager to store it.")

    return {
        "score": score,
        "strength": strength,
        "strength_class": strength_class,
        "entropy_bits": round(entropy, 1),
        "crack_time": estimate_crack_time(entropy),
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "is_common": is_common,
        "feedback": feedback
    }


@app.route("/api/check-password", methods=["POST"])
def api_check_password():
    user = logged_in_user()
    if user:
        access_error = _training_access_error(user)
        if access_error:
            return access_error
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not isinstance(password, str):
        return jsonify({"error": "Password must be a string"}), 400
    # Never log the password
    result = analyze_password(password)
    return jsonify(result)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    return jsonify({"status": "healthy", "service": "Minimal Cyber Awareness"})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5002"))
    debug = _debug
    app.run(host="0.0.0.0", port=port, debug=debug)
