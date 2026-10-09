"""Cross-cutting security services: audit log, detection, throttling, mail, sessions, CSRF, auth guards."""
import re
import secrets
import smtplib
import threading
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from functools import wraps

from flask import abort, current_app, flash, g, jsonify, redirect, request, url_for

import crypto
from db import many, one, run

now = lambda: int(time.time())  # noqa: E731
_audit_lock = threading.Lock()


def client_ip():
    return request.remote_addr or "0.0.0.0"


def user_agent():
    return (request.headers.get("User-Agent") or "")[:300]


def keyring():
    return current_app.extensions["keyring"]


# ------------------------------------------------------------------ audit + detection
def audit(action, user_id=None, obj=None, detail="", severity="info", ip=None):
    """Append a tamper-evident (HMAC-chained) audit record, then run detection rules."""
    ip = ip or (client_ip() if request else None)
    ua = user_agent() if request else None
    key = keyring().get("audit")
    ts = now()
    with _audit_lock:
        prev = one("SELECT hash FROM audit ORDER BY id DESC LIMIT 1")
        prev_hash = prev["hash"] if prev else "0" * 64
        payload = "|".join(str(x) for x in (prev_hash, ts, user_id, action, obj, ip, detail, severity))
        run("INSERT INTO audit(ts,user_id,action,object,ip,ua,detail,severity,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (ts, user_id, action, obj, ip, ua, detail[:500], severity, prev_hash, crypto.hmac_hex(key, payload)))
    _detect(action, user_id, ip)


def verify_audit_chain():
    key, prev_hash, count = keyring().get("audit"), "0" * 64, 0
    for r in many("SELECT * FROM audit ORDER BY id"):
        payload = "|".join(str(x) for x in (prev_hash, r["ts"], r["user_id"], r["action"], r["object"], r["ip"], r["detail"], r["severity"]))
        if r["prev_hash"] != prev_hash or r["hash"] != crypto.hmac_hex(key, payload):
            return False, r["id"]
        prev_hash, count = r["hash"], count + 1
    return True, count


def raise_alert(kind, detail, user_id=None, ip=None, severity="warning", dedupe_seconds=600):
    ip = ip or client_ip()
    dup = one("SELECT 1 FROM alerts WHERE kind=? AND IFNULL(ip,'')=? AND IFNULL(user_id,0)=? AND ts>? AND resolved=0",
              (kind, ip, user_id or 0, now() - dedupe_seconds))
    if not dup:
        run("INSERT INTO alerts(ts,user_id,kind,severity,detail,ip) VALUES(?,?,?,?,?,?)",
            (now(), user_id, kind, severity, detail[:300], ip))


def _detect(action, user_id, ip):
    t = now()
    if action in ("login_failed", "2fa_failed"):
        by_ip = one("SELECT COUNT(*) c, COUNT(DISTINCT IFNULL(user_id,-1)) u FROM audit WHERE action IN ('login_failed','2fa_failed') AND ip=? AND ts>?", (ip, t - 600))
        if by_ip["c"] >= 8 and by_ip["u"] >= 3:
            raise_alert("password_spraying", f"{by_ip['c']} failed attempts against {by_ip['u']} accounts from one address in 10 minutes", ip=ip, severity="critical")
        elif by_ip["c"] >= 10:
            raise_alert("repeated_failures_ip", f"{by_ip['c']} failed sign-in or 2FA attempts from one address in 10 minutes", ip=ip)
        if user_id:
            by_user = one("SELECT COUNT(*) c FROM audit WHERE action IN ('login_failed','2fa_failed') AND user_id=? AND ts>?", (user_id, t - 900))["c"]
            if by_user >= 5:
                raise_alert("bruteforce_account", f"{by_user} failed attempts on this account in 15 minutes", user_id=user_id, ip=ip)
    elif action == "download" and user_id:
        c = one("SELECT COUNT(*) c FROM audit WHERE action='download' AND user_id=? AND ts>?", (user_id, t - 300))["c"]
        if c >= 20:
            raise_alert("mass_download", f"{c} downloads in 5 minutes", user_id=user_id, ip=ip)
    elif action in ("integrity_failure", "malware_blocked"):
        raise_alert(action, "See audit log for the file concerned", user_id=user_id, ip=ip, severity="critical", dedupe_seconds=0)


# ------------------------------------------------------------------ throttling / lockout
def record_attempt(key):
    run("INSERT INTO attempts(key,ts) VALUES(?,?)", (key, now()))


def count_attempts(key, window):
    run("DELETE FROM attempts WHERE ts<?", (now() - 86400,))
    return one("SELECT COUNT(*) c FROM attempts WHERE key=? AND ts>?", (key, now() - window))["c"]


def register_failure(user):
    """Escalating lockout after repeated wrong passwords / codes."""
    cfg = current_app.config
    n = user["failed_count"] + 1
    lock = 0
    if n % cfg["MAX_FAILED"] == 0:
        lock = now() + min(900 * 2 ** (n // cfg["MAX_FAILED"] - 1), 86400)
    run("UPDATE users SET failed_count=?, locked_until=MAX(locked_until,?) WHERE id=?", (n, lock, user["id"]))
    if lock:
        audit("account_locked", user["id"], detail=f"locked after {n} consecutive failures", severity="warning")
        send_mail(user["email"], "Your account was temporarily locked",
                  "We saw several failed sign-in or verification attempts on your account, so it is locked for a while.\n"
                  "If this wasn't you, change your password once you can sign in.")


# ------------------------------------------------------------------ mail
def send_mail(to, subject, body):
    cfg = current_app.config
    if cfg.get("SMTP_HOST"):
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = cfg["MAIL_FROM"], to, subject
        msg.set_content(body)
        try:
            with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=15) as s:
                s.starttls()
                if cfg.get("SMTP_USER"):
                    s.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
                s.send_message(msg)
            return
        except Exception:  # fall through to the outbox so flows never dead-end
            current_app.logger.exception("SMTP send failed; writing to outbox")
    with open(cfg["INSTANCE_DIR"] / "outbox.log", "a", encoding="utf-8") as fh:
        fh.write(f"--- {datetime.now(timezone.utc).isoformat()} to={to} subject={subject}\n{body}\n\n")
    current_app.logger.info("DEV MAIL to=%s subject=%s\n%s", to, subject, body)


def base_url():
    return (current_app.config.get("BASE_URL") or request.host_url).rstrip("/")


# ------------------------------------------------------------------ cookies
def queue_cookie(name, value, max_age=None):
    g.setdefault("cookies", []).append((name, value, max_age))


def apply_cookies(resp):
    for name, value, max_age in g.get("cookies", []):
        if value is None:
            resp.delete_cookie(name)
        else:
            resp.set_cookie(name, value, max_age=max_age, httponly=True, samesite="Lax",
                            secure=current_app.config["COOKIE_SECURE"], path="/")
    return resp


def ua_label(ua):
    browser = next((n for p, n in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"), ("Safari/", "Safari")) if p in ua), "Browser")
    os_ = next((n for p, n in (("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iOS"), ("iPad", "iPadOS"), ("Mac OS", "macOS"), ("Linux", "Linux")) if p in ua), "unknown OS")
    return f"{browser} on {os_}"


# ------------------------------------------------------------------ devices & sessions
def current_device(user_id):
    tok = request.cookies.get("did")
    if not tok:
        return None
    return one("SELECT * FROM devices WHERE dev_hash=? AND user_id=?", (crypto.token_hash(tok), user_id))


def ensure_device(user_id, trust_days=None):
    """Register (or refresh) this browser as a verified device. Returns the device row id."""
    dev, t = current_device(user_id), now()
    trusted = t + trust_days * 86400 if trust_days else None
    if dev:
        run("UPDATE devices SET last_seen=?, ip=?, trusted_until=COALESCE(?,trusted_until) WHERE id=?", (t, client_ip(), trusted, dev["id"]))
        return dev["id"]
    tok = crypto.new_token()
    cur = run("INSERT INTO devices(user_id,dev_hash,label,ip,first_seen,last_seen,trusted_until) VALUES(?,?,?,?,?,?,?)",
              (user_id, crypto.token_hash(tok), ua_label(user_agent()), client_ip(), t, t, trusted))
    queue_cookie("did", tok, max_age=400 * 86400)
    return cur.lastrowid


def create_session(user_id, device_id):
    tok, t = crypto.new_token(), now()
    run("INSERT INTO sessions(id,user_id,device_id,created_at,last_seen,expires_at,ip,ua) VALUES(?,?,?,?,?,?,?,?)",
        (crypto.token_hash(tok), user_id, device_id, t, t, t + current_app.config["SESSION_ABSOLUTE_SECONDS"], client_ip(), user_agent()))
    queue_cookie("sid", tok)
    return tok


def load_session():
    g.user = g.session = None
    tok = request.cookies.get("sid")
    if not tok:
        return
    sid, t, cfg = crypto.token_hash(tok), now(), current_app.config
    s = one("SELECT * FROM sessions WHERE id=? AND revoked=0", (sid,))
    if not s:
        return
    if s["expires_at"] < t or t - s["last_seen"] > cfg["SESSION_IDLE_SECONDS"]:
        run("UPDATE sessions SET revoked=1 WHERE id=?", (sid,))
        return
    u = one("SELECT * FROM users WHERE id=? AND is_active=1", (s["user_id"],))
    if not u:
        return
    if t - s["last_seen"] > 60:
        run("UPDATE sessions SET last_seen=? WHERE id=?", (t, sid))
    g.user, g.session = u, s


def revoke_user_sessions(user_id, except_id=None):
    run("UPDATE sessions SET revoked=1 WHERE user_id=? AND id!=?", (user_id, except_id or ""))


# ------------------------------------------------------------------ CSRF (double-submit cookie)
def init_csrf():
    g.csrf = request.cookies.get("csrf") or secrets.token_urlsafe(32)
    if "csrf" not in request.cookies:
        queue_cookie("csrf", g.csrf)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
        if not secrets.compare_digest(sent, request.cookies.get("csrf", "\0")):
            audit("csrf_rejected", g.user["id"] if g.get("user") else None, detail=request.path, severity="warning")
            abort(400, "Your form expired. Reload the page and try again.")


# ------------------------------------------------------------------ guards
def wants_json():
    return request.path.startswith("/api/")


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not g.user:
            if wants_json():
                return jsonify(error="Sign in required."), 401
            return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))
        return fn(*a, **kw)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if g.user["role"] != "admin":
            audit("admin_denied", g.user["id"], detail=request.path, severity="warning")
            abort(403)
        if not g.user["totp_enabled"]:
            flash("Administrators must enable two-factor authentication before using the admin area.", "warn")
            return redirect(url_for("auth.setup_2fa"))
        return fn(*a, **kw)
    return wrapper


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return None


# ------------------------------------------------------------------ validation helpers
_COMMON = {"password1234", "passwordpassword", "123456789012", "qwertyuiopas", "letmein12345", "iloveyou1234",
           "administrator", "welcome12345", "changeme1234", "correcthorsebatterystaple"}


def password_problem(pw, username="", email=""):
    if len(pw) < 12:
        return "Use at least 12 characters."
    if len(pw) > 128:
        return "Use at most 128 characters."
    low = pw.lower()
    if low in _COMMON or len(set(low)) < 5:
        return "That password is too easy to guess."
    if username and username.lower() in low:
        return "Your password shouldn't contain your username."
    if email and email.split("@")[0].lower() in low and len(email.split("@")[0]) > 3:
        return "Your password shouldn't contain your email name."
    return None


USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
