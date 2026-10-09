"""Accounts, sign-in, 2FA, password management, sessions/devices, profile, activity."""
import re
import sqlite3

from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from flask import current_app

import core
import crypto
import qr
from core import audit, client_ip, login_required, now, queue_cookie
from db import many, one, run

bp = Blueprint("auth", __name__)


def _hash_pw(pw):
    return generate_password_hash(pw, method="scrypt")


def _backup_hash(code):
    return crypto.hmac_hex(core.keyring().get("backup"), crypto.normalize_code(code))


def _issue_backup_codes(user_id):
    codes = crypto.new_backup_codes()
    run("DELETE FROM backup_codes WHERE user_id=?", (user_id,))
    for c in codes:
        run("INSERT INTO backup_codes(user_id,code_hash) VALUES(?,?)", (user_id, _backup_hash(c)))
    return [crypto.format_backup(c) for c in codes]


def _user_secret(user, pending=False):
    blob = user["totp_pending_enc" if pending else "totp_secret_enc"]
    return crypto.unseal(core.keyring().get("totp"), blob, f"totp:{user['id']}".encode()).decode() if blob else None


def check_second_factor(user, raw):
    """Verify a TOTP code or single-use backup code. Returns 'totp', 'backup' or None."""
    code = crypto.normalize_code(raw or "")
    if re.fullmatch(r"\d{6}", code):
        secret = _user_secret(user)
        step = crypto.verify_totp(secret, code, user["totp_last_step"]) if secret else None
        if step and run("UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step<?", (step, user["id"], step)).rowcount:
            return "totp"
        return None
    if re.fullmatch(r"[A-Z0-9]{8}", code):
        if run("UPDATE backup_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL",
               (now(), user["id"], _backup_hash(code))).rowcount:
            left = one("SELECT COUNT(*) c FROM backup_codes WHERE user_id=? AND used_at IS NULL", (user["id"],))["c"]
            audit("backup_code_used", user["id"], detail=f"{left} codes left", severity="warning")
            if left <= 2:
                core.raise_alert("backup_codes_low", f"Only {left} backup codes left", user_id=user["id"], severity="info")
            return "backup"
    return None


def _password_and_code_ok(user, password, code):
    return check_password_hash(user["pw_hash"], password or "") and (check_second_factor(user, code) is not None)


# ---------------------------------------------------------------- register / login / logout
@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("files.dashboard"))
    form, errors = request.form, []
    if request.method == "POST":
        ip = client_ip()
        username, email = form.get("username", "").strip(), form.get("email", "").strip().lower()
        display = (form.get("display_name", "").strip() or username)[:60]
        pw = form.get("password", "")
        if core.count_attempts(f"reg:{ip}", 3600) >= 10:
            errors.append("Too many sign-ups from this address. Try again later.")
        if not core.USERNAME_RE.match(username):
            errors.append("Username must be 3–32 characters: letters, numbers, dot, dash or underscore.")
        if not core.EMAIL_RE.match(email):
            errors.append("Enter a valid email address.")
        if pw != form.get("password2", ""):
            errors.append("The two passwords don't match.")
        problem = core.password_problem(pw, username, email)
        if problem:
            errors.append(problem)
        if not errors:
            core.record_attempt(f"reg:{ip}")
            t = now()
            try:
                cur = run("INSERT INTO users(username,email,display_name,pw_hash,created_at,pw_changed_at) VALUES(?,?,?,?,?,?)",
                          (username, email, display, _hash_pw(pw), t, t))
            except sqlite3.IntegrityError:
                errors.append("That username or email is already registered.")
            else:
                audit("register", cur.lastrowid, detail=f"username={username}")
                flash("Account created. Sign in to continue.", "ok")
                return redirect(url_for("auth.login"))
    return render_template("register.html", errors=errors, form=form)


def _start_challenge(user, kind, next_url):
    tok, code = crypto.new_token(), None
    if kind == "device_email":
        import secrets
        code = f"{secrets.randbelow(10 ** 8):08d}"
        core.send_mail(user["email"], "Verify your new device",
                       f"Someone signed in to SecureShare from a device we haven't seen before.\n\nVerification code: {code}\n\n"
                       f"Device: {core.ua_label(core.user_agent())} ({client_ip()})\nThe code expires in 10 minutes. "
                       "If this wasn't you, change your password.")
    run("INSERT INTO challenges(id,user_id,kind,code_hash,expires_at,next_url) VALUES(?,?,?,?,?,?)",
        (crypto.token_hash(tok), user["id"], kind, crypto.hmac_hex(core.keyring().get("challenge"), code) if code else None,
         now() + 600, next_url))
    queue_cookie("chal", tok, max_age=600)


def _complete_login(user, next_url=None, trust_days=None, via="password"):
    prior_ips = {r["ip"] for r in many("SELECT DISTINCT ip FROM sessions WHERE user_id=?", (user["id"],))}
    new_device = core.current_device(user["id"]) is None
    device_id = core.ensure_device(user["id"], trust_days)
    run("UPDATE users SET failed_count=0, locked_until=0, last_login_at=? WHERE id=?", (now(), user["id"]))
    core.create_session(user["id"], device_id)
    audit("login_success", user["id"], detail=f"via={via}; device={core.ua_label(core.user_agent())}")
    if prior_ips and client_ip() not in prior_ips:
        core.raise_alert("new_ip_login", f"Sign-in from a new address ({client_ip()})", user_id=user["id"], severity="info", dedupe_seconds=3600)
    if new_device and prior_ips:
        audit("new_device_verified", user["id"], detail=core.ua_label(core.user_agent()), severity="warning")
    run("UPDATE challenges SET used=1 WHERE user_id=?", (user["id"],))
    queue_cookie("chal", None)
    return redirect(core.safe_next(next_url) or url_for("files.dashboard"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("files.dashboard"))
    next_url, error = core.safe_next(request.values.get("next")), None
    if request.method == "POST":
        ip, ident, pw = client_ip(), request.form.get("username", "").strip(), request.form.get("password", "")
        generic = "Sign-in failed. Check your details, or wait a while if you've tried several times."
        if core.count_attempts(f"fail:{ip}", 900) >= 30:
            audit("login_throttled", detail=f"ip={ip}", severity="warning")
            return render_template("login.html", error="Too many attempts from this address. Try again in a few minutes.", next=next_url), 429
        user = one("SELECT * FROM users WHERE username=? OR email=?", (ident, ident.lower()))
        locked = bool(user and user["locked_until"] > now())
        good = check_password_hash(user["pw_hash"] if user else current_app.extensions["dummy_hash"], pw)
        if not (user and good and user["is_active"]) or locked:
            core.record_attempt(f"fail:{ip}")
            if user and not locked:
                core.register_failure(user)
            audit("login_blocked_locked" if locked else "login_failed", user["id"] if user else None,
                  detail=f"identifier={ident[:64]}", severity="warning")
            return render_template("login.html", error=generic, next=next_url), 401
        dev = core.current_device(user["id"])
        if user["totp_enabled"]:
            need = None if (dev and dev["trusted_until"] and dev["trusted_until"] > now()) else "totp"
        elif dev or not one("SELECT 1 FROM devices WHERE user_id=?", (user["id"],)):
            need = None
        else:
            need = "device_email"
        if need:
            _start_challenge(user, need, next_url)
            return redirect(url_for("auth.verify"))
        return _complete_login(user, next_url)
    return render_template("login.html", error=error, next=next_url)


def _load_challenge():
    tok = request.cookies.get("chal")
    if not tok:
        return None
    return one("SELECT * FROM challenges WHERE id=? AND used=0 AND expires_at>? AND attempts<5", (crypto.token_hash(tok), now()))


@bp.route("/login/verify", methods=["GET", "POST"])
def verify():
    ch = _load_challenge()
    if not ch:
        flash("That verification expired. Sign in again.", "warn")
        return redirect(url_for("auth.login"))
    user = one("SELECT * FROM users WHERE id=? AND is_active=1", (ch["user_id"],))
    error = None
    if request.method == "POST" and user:
        code, ok = request.form.get("code", ""), False
        if ch["kind"] == "totp":
            ok = check_second_factor(user, code) is not None
        else:
            import hmac
            ok = hmac.compare_digest(crypto.hmac_hex(core.keyring().get("challenge"), code.strip()), ch["code_hash"] or "")
        if ok and user["locked_until"] <= now():
            remember = ch["kind"] == "totp" and request.form.get("remember") == "1"
            return _complete_login(user, ch["next_url"], current_app.config["TRUST_DEVICE_DAYS"] if remember else None,
                                   via="2fa" if ch["kind"] == "totp" else "device_email")
        run("UPDATE challenges SET attempts=attempts+1 WHERE id=?", (ch["id"],))
        core.record_attempt(f"fail:{client_ip()}")
        core.register_failure(user)
        audit("2fa_failed" if ch["kind"] == "totp" else "device_code_failed", user["id"], severity="warning")
        if ch["attempts"] + 1 >= 5:
            flash("Too many incorrect codes. Sign in again to get a fresh attempt.", "error")
            queue_cookie("chal", None)
            return redirect(url_for("auth.login"))
        error = "That code didn't work. Check the code and try again."
    return render_template("verify.html", kind=ch["kind"], error=error, left=5 - ch["attempts"])


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    run("UPDATE sessions SET revoked=1 WHERE id=?", (g.session["id"],))
    audit("logout", g.user["id"])
    queue_cookie("sid", None)
    flash("You're signed out.", "ok")
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------- forgot / reset password
@bp.route("/forgot", methods=["GET", "POST"])
def forgot():
    sent = False
    if request.method == "POST":
        ip, ident = client_ip(), request.form.get("identifier", "").strip()
        sent = True
        if core.count_attempts(f"reset:{ip}", 3600) < 5:
            core.record_attempt(f"reset:{ip}")
            user = one("SELECT * FROM users WHERE (username=? OR email=?) AND is_active=1", (ident, ident.lower()))
            if user and core.count_attempts(f"reset-user:{user['id']}", 3600) < 3:
                core.record_attempt(f"reset-user:{user['id']}")
                tok = crypto.new_token()
                run("INSERT INTO reset_tokens(token_hash,user_id,expires_at) VALUES(?,?,?)", (crypto.token_hash(tok), user["id"], now() + 1800))
                core.send_mail(user["email"], "Reset your SecureShare password",
                               f"Use this link within 30 minutes to choose a new password:\n\n{core.base_url()}/reset/{tok}\n\n"
                               "If you didn't ask for this, ignore this email — your password is unchanged.")
                audit("password_reset_requested", user["id"])
    return render_template("forgot.html", sent=sent)


@bp.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    row = one("SELECT * FROM reset_tokens WHERE token_hash=? AND used=0 AND expires_at>?", (crypto.token_hash(token), now()))
    user = one("SELECT * FROM users WHERE id=? AND is_active=1", (row["user_id"],)) if row else None
    if not user:
        return render_template("reset.html", invalid=True), 400
    error = None
    if request.method == "POST":
        pw = request.form.get("password", "")
        error = core.password_problem(pw, user["username"], user["email"]) or (None if pw == request.form.get("password2", "") else "The two passwords don't match.")
        if not error and run("UPDATE reset_tokens SET used=1 WHERE token_hash=? AND used=0", (row["token_hash"],)).rowcount:
            run("UPDATE users SET pw_hash=?, pw_changed_at=?, failed_count=0, locked_until=0 WHERE id=?", (_hash_pw(pw), now(), user["id"]))
            core.revoke_user_sessions(user["id"])
            run("UPDATE devices SET trusted_until=NULL WHERE user_id=?", (user["id"],))
            audit("password_reset_completed", user["id"], severity="warning")
            core.send_mail(user["email"], "Your password was changed", "Your SecureShare password was just reset and all sessions were signed out.")
            flash("Password updated. Sign in with your new password.", "ok")
            return redirect(url_for("auth.login"))
    return render_template("reset.html", invalid=False, error=error)


# ---------------------------------------------------------------- security centre
@bp.route("/security")
@login_required
def security():
    u = g.user
    sessions = many("SELECT s.*, d.label FROM sessions s LEFT JOIN devices d ON d.id=s.device_id WHERE s.user_id=? AND s.revoked=0 AND s.expires_at>? ORDER BY s.last_seen DESC", (u["id"], now()))
    devices = many("SELECT * FROM devices WHERE user_id=? ORDER BY last_seen DESC", (u["id"],))
    codes_left = one("SELECT COUNT(*) c FROM backup_codes WHERE user_id=? AND used_at IS NULL", (u["id"],))["c"]
    return render_template("security.html", sessions=sessions, devices=devices, codes_left=codes_left)


@bp.route("/security/password", methods=["POST"])
@login_required
def change_password():
    u, f = g.user, request.form
    if not check_password_hash(u["pw_hash"], f.get("current", "")):
        audit("password_change_failed", u["id"], severity="warning")
        flash("Your current password is incorrect.", "error")
    else:
        problem = core.password_problem(f.get("password", ""), u["username"], u["email"]) or (None if f.get("password") == f.get("password2") else "The two passwords don't match.")
        if problem:
            flash(problem, "error")
        else:
            run("UPDATE users SET pw_hash=?, pw_changed_at=? WHERE id=?", (_hash_pw(f["password"]), now(), u["id"]))
            core.revoke_user_sessions(u["id"], except_id=g.session["id"])
            audit("password_changed", u["id"], severity="warning")
            core.send_mail(u["email"], "Your password was changed", "Your SecureShare password was changed and other sessions were signed out.")
            flash("Password changed. Other sessions were signed out.", "ok")
    return redirect(url_for("auth.security"))


@bp.route("/security/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    u, kr = g.user, core.keyring()
    if u["totp_enabled"]:
        return redirect(url_for("auth.security"))
    aad = f"totp:{u['id']}".encode()
    if request.method == "POST":
        secret = _user_secret(u, pending=True)
        step = crypto.verify_totp(secret, request.form.get("code", "").strip().replace(" ", ""), 0) if secret else None
        if step:
            run("UPDATE users SET totp_secret_enc=totp_pending_enc, totp_pending_enc=NULL, totp_enabled=1, totp_last_step=? WHERE id=?", (step, u["id"]))
            codes = _issue_backup_codes(u["id"])
            audit("2fa_enabled", u["id"], severity="warning")
            core.send_mail(u["email"], "Two-factor authentication enabled", "2FA is now on for your SecureShare account.")
            return render_template("backup_codes.html", codes=codes, first=True)
        audit("2fa_failed", u["id"], detail="setup", severity="warning")
        flash("That code didn't match. Check your authenticator app and try again.", "error")
    secret = _user_secret(u, pending=True)
    if not secret or request.method == "GET" and request.args.get("new"):
        secret = crypto.new_totp_secret()
        run("UPDATE users SET totp_pending_enc=? WHERE id=?", (crypto.seal(kr.get("totp"), secret.encode(), aad), u["id"]))
    uri = crypto.otpauth_uri(current_app.config["ISSUER"], u["username"], secret)
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return render_template("setup_2fa.html", qr_uri=qr.svg_data_uri(uri), secret=grouped)


@bp.route("/security/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    u = g.user
    if u["role"] == "admin":
        flash("Administrators must keep two-factor authentication on.", "error")
    elif _password_and_code_ok(u, request.form.get("password"), request.form.get("code")):
        run("UPDATE users SET totp_enabled=0, totp_secret_enc=NULL, totp_pending_enc=NULL, totp_last_step=0 WHERE id=?", (u["id"],))
        run("DELETE FROM backup_codes WHERE user_id=?", (u["id"],))
        run("UPDATE devices SET trusted_until=NULL WHERE user_id=?", (u["id"],))
        audit("2fa_disabled", u["id"], severity="warning")
        core.send_mail(u["email"], "Two-factor authentication disabled", "2FA was turned off for your SecureShare account. If this wasn't you, change your password now.")
        flash("Two-factor authentication is off.", "ok")
    else:
        audit("2fa_disable_failed", u["id"], severity="warning")
        core.register_failure(u)
        flash("Your password or code was incorrect.", "error")
    return redirect(url_for("auth.security"))


@bp.route("/security/2fa/backup", methods=["POST"])
@login_required
def regenerate_backup():
    u = g.user
    if u["totp_enabled"] and _password_and_code_ok(u, request.form.get("password"), request.form.get("code")):
        audit("backup_codes_regenerated", u["id"], severity="warning")
        return render_template("backup_codes.html", codes=_issue_backup_codes(u["id"]), first=False)
    audit("backup_regen_failed", u["id"], severity="warning")
    flash("Your password or code was incorrect.", "error")
    return redirect(url_for("auth.security"))


@bp.route("/security/sessions/<sid>/revoke", methods=["POST"])
@login_required
def revoke_session(sid):
    if run("UPDATE sessions SET revoked=1 WHERE id=? AND user_id=?", (sid, g.user["id"])).rowcount:
        audit("session_revoked", g.user["id"])
        flash("Session signed out.", "ok")
    if sid == g.session["id"]:
        queue_cookie("sid", None)
        return redirect(url_for("auth.login"))
    return redirect(url_for("auth.security"))


@bp.route("/security/sessions/revoke-others", methods=["POST"])
@login_required
def revoke_others():
    core.revoke_user_sessions(g.user["id"], except_id=g.session["id"])
    audit("sessions_revoked_all", g.user["id"])
    flash("All other sessions were signed out.", "ok")
    return redirect(url_for("auth.security"))


@bp.route("/security/devices/<int:did>/remove", methods=["POST"])
@login_required
def remove_device(did):
    if one("SELECT 1 FROM devices WHERE id=? AND user_id=?", (did, g.user["id"])):
        run("UPDATE sessions SET revoked=1 WHERE device_id=? AND id!=?", (did, g.session["id"]))
        run("DELETE FROM devices WHERE id=? AND user_id=?", (did, g.user["id"]))
        audit("device_removed", g.user["id"])
        flash("Device forgotten. It will need to verify again next time.", "ok")
    return redirect(url_for("auth.security"))


# ---------------------------------------------------------------- profile & activity
@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    u = g.user
    if request.method == "POST":
        display = request.form.get("display_name", "").strip()[:60] or u["username"]
        email = request.form.get("email", "").strip().lower()
        if not core.EMAIL_RE.match(email):
            flash("Enter a valid email address.", "error")
        elif email != u["email"].lower() and not check_password_hash(u["pw_hash"], request.form.get("password", "")):
            flash("Enter your current password to change your email.", "error")
        else:
            try:
                run("UPDATE users SET display_name=?, email=? WHERE id=?", (display, email, u["id"]))
                audit("profile_updated", u["id"], detail="email changed" if email != u["email"].lower() else "")
                if email != u["email"].lower():
                    core.send_mail(u["email"], "Your email was changed", f"The email on your SecureShare account is now {email}.")
                flash("Profile saved.", "ok")
            except sqlite3.IntegrityError:
                flash("That email is already in use.", "error")
        return redirect(url_for("auth.profile"))
    return render_template("profile.html")


@bp.route("/activity")
@login_required
def activity():
    page = max(1, request.args.get("page", 1, type=int))
    rows = many("SELECT * FROM audit WHERE user_id=? ORDER BY id DESC LIMIT 51 OFFSET ?", (g.user["id"], (page - 1) * 50))
    alerts = many("SELECT * FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT 20", (g.user["id"],))
    return render_template("activity.html", rows=rows[:50], more=len(rows) > 50, page=page, alerts=alerts)
